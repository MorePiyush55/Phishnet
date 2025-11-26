"""
Email Forward Analyzer Service
Handles analysis of emails forwarded from mobile devices via email
"""

import email
import re
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import logging

from app.orchestrator.phishnet_orchestrator import PhishNetOrchestrator
from app.models.mongodb_models import ForwardedEmailAnalysis

logger = logging.getLogger(__name__)


class EmailForwardAnalyzerService:
    """
    Service for analyzing emails forwarded via email (mobile-friendly).
    
    Users can forward suspicious emails to phishnet@example.com from their
    mobile devices, and this service will parse and analyze them.
    """
    
    def __init__(self):
        self.orchestrator = PhishNetOrchestrator()
    
    async def analyze_forwarded_email(
        self,
        raw_email_bytes: bytes,
        forwarded_by: str
    ) -> Dict[str, Any]:
        """
        Analyze an email that was forwarded to PhishNet.
        
        Args:
            raw_email_bytes: Raw email content in bytes
            forwarded_by: Email address of user who forwarded it
            
        Returns:
            Analysis result dictionary
        """
        try:
            # Parse the forwarded email
            forwarded_message = email.message_from_bytes(raw_email_bytes)
            
            # Extract the original email from the forward
            original_email = self._extract_original_email(forwarded_message)
            
            if not original_email:
                logger.warning("Could not extract original email from forward")
                # Analyze the forwarded email itself
                original_email = forwarded_message
            
            # Extract relevant content for analysis
            email_content = self._extract_email_content(original_email)
            
            # Add forwarding metadata
            email_content['forwarded_by'] = forwarded_by
            email_content['forwarded_at'] = datetime.now(timezone.utc).isoformat()
            
            # Run analysis through PhishNet orchestrator
            analysis_result = await self.orchestrator.analyze_email(email_content)
            
            # Store the analysis with consent (user forwarded it)
            await self._store_analysis(
                forwarded_by=forwarded_by,
                email_content=email_content,
                analysis_result=analysis_result,
                raw_email=raw_email_bytes
            )
            
            return {
                "success": True,
                "analysis": analysis_result,
                "email_metadata": {
                    "sender": email_content.get("sender"),
                    "subject": email_content.get("subject"),
                    "date": email_content.get("date"),
                    "forwarded_by": forwarded_by
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze forwarded email: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to analyze forwarded email"
            }
    
    def _extract_original_email(self, forwarded_message: email.message.Message) -> Optional[email.message.Message]:
        """
        Extract the original email from a forwarded message.
        
        Forwarded emails typically include the original email as:
        1. An attached .eml file
        2. As message/rfc822 part
        3. In the body as quoted text
        
        Args:
            forwarded_message: The forwarded email message
            
        Returns:
            Original email message or None
        """
        # Check for .eml attachment
        for part in forwarded_message.walk():
            content_type = part.get_content_type()
            filename = part.get_filename() or ""
            
            # Look for message/rfc822 parts
            if content_type == "message/rfc822":
                payload = part.get_payload()
                if isinstance(payload, list) and len(payload) > 0:
                    return payload[0]
            
            # Look for .eml attachments
            if filename.endswith('.eml'):
                payload = part.get_payload(decode=True)
                if payload:
                    return email.message_from_bytes(payload)
        
        # If no embedded message found, return None
        # (caller will analyze the forwarded message itself)
        return None
    
    def _extract_email_content(self, message: email.message.Message) -> Dict[str, Any]:
        """
        Extract relevant content from email message for analysis.
        
        Args:
            message: Email message object
            
        Returns:
            Dictionary with extracted content
        """
        # Extract headers
        sender = message.get("From", "")
        subject = message.get("Subject", "")
        to = message.get("To", "")
        date = message.get("Date", "")
        message_id = message.get("Message-ID", "")
        
        # Extract body content
        body_text = ""
        body_html = ""
        
        if message.is_multipart():
            for part in message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            body_text += payload.decode("utf-8", errors="ignore")
                        except Exception as e:
                            logger.warning(f"Failed to decode text/plain part: {e}")
                
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            body_html += payload.decode("utf-8", errors="ignore")
                        except Exception as e:
                            logger.warning(f"Failed to decode text/html part: {e}")
        else:
            # Single part message
            payload = message.get_payload(decode=True)
            if payload:
                content_type = message.get_content_type()
                try:
                    if content_type == "text/html":
                        body_html = payload.decode("utf-8", errors="ignore")
                    else:
                        body_text = payload.decode("utf-8", errors="ignore")
                except Exception as e:
                    logger.warning(f"Failed to decode message payload: {e}")
        
        # Extract all headers for analysis
        headers_dict = {}
        for key, value in message.items():
            headers_dict[key] = value
        
        return {
            "sender": sender,
            "subject": subject,
            "to": to,
            "date": date,
            "message_id": message_id,
            "body": body_text or body_html,  # Use text if available, otherwise HTML
            "body_text": body_text,
            "body_html": body_html,
            "headers": headers_dict,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    async def _store_analysis(
        self,
        forwarded_by: str,
        email_content: Dict[str, Any],
        analysis_result: Dict[str, Any],
        raw_email: bytes
    ):
        """
        Store the analysis result in MongoDB.
        
        Args:
            forwarded_by: Email address of user who forwarded
            email_content: Extracted email content
            analysis_result: Analysis results
            raw_email: Raw email bytes
        """
        try:
            # Extract user_id from email (or create anonymous ID)
            user_id = self._extract_user_id_from_email(forwarded_by)
            
            analysis_doc = ForwardedEmailAnalysis(
                user_id=user_id,
                forwarded_by=forwarded_by,
                original_sender=email_content.get("sender", ""),
                original_subject=email_content.get("subject", ""),
                threat_score=analysis_result.get("threat_score", 0.0),
                risk_level=analysis_result.get("risk_level", "UNKNOWN"),
                analysis_result=analysis_result,
                email_metadata={
                    "sender": email_content.get("sender"),
                    "subject": email_content.get("subject"),
                    "date": email_content.get("date"),
                    "message_id": email_content.get("message_id"),
                },
                raw_email_content=email_content,
                consent_given=True,  # User forwarded the email
                created_at=datetime.now(timezone.utc)
            )
            
            await analysis_doc.save()
            logger.info(f"Stored forwarded email analysis for {forwarded_by}")
            
        except Exception as e:
            logger.error(f"Failed to store forwarded email analysis: {e}")
            # Don't fail the request if storage fails
    
    def _extract_user_id_from_email(self, email_address: str) -> str:
        """
        Extract or create a user ID from email address.
        
        Args:
            email_address: User's email address
            
        Returns:
            User ID string
        """
        # Simple implementation: use email as user_id
        # In production, you might want to look up or create a user record
        email_match = re.search(r'[\w\.-]+@[\w\.-]+', email_address)
        if email_match:
            return email_match.group(0)
        return email_address
    
    async def generate_reply_email(
        self,
        analysis_result: Dict[str, Any],
        recipient_email: str,
        original_subject: str
    ) -> str:
        """
        Generate a reply email with analysis results.
        
        Args:
            analysis_result: Analysis results
            recipient_email: Email address to send reply to
            original_subject: Subject of original email
            
        Returns:
            Email body text
        """
        threat_score = analysis_result.get("threat_score", 0.0)
        risk_level = analysis_result.get("risk_level", "UNKNOWN")
        reasons = analysis_result.get("reasons", [])
        recommendations = analysis_result.get("recommendations", [])
        
        # Generate risk assessment text
        if risk_level == "CRITICAL" or threat_score >= 0.9:
            risk_text = "🚨 CRITICAL THREAT - DO NOT INTERACT with this email!"
        elif risk_level == "HIGH" or threat_score >= 0.7:
            risk_text = "⚠️ HIGH RISK - This email is likely a phishing attempt"
        elif risk_level == "MEDIUM" or threat_score >= 0.5:
            risk_text = "⚠️ MEDIUM RISK - Exercise caution with this email"
        elif risk_level == "LOW" or threat_score >= 0.3:
            risk_text = "ℹ️ LOW RISK - Minor concerns detected"
        else:
            risk_text = "✅ SAFE - No significant threats detected"
        
        # Build email body
        email_body = f"""
PhishNet Analysis Results
{'=' * 50}

Subject: {original_subject}
Risk Level: {risk_level}
Threat Score: {threat_score:.2f}/1.00

{risk_text}

{'=' * 50}

ANALYSIS FINDINGS:
{self._format_reasons(reasons)}

{'=' * 50}

RECOMMENDATIONS:
{self._format_recommendations(recommendations)}

{'=' * 50}

This analysis was performed by PhishNet - Privacy-First Email Security
For more details, visit your PhishNet dashboard

---
PhishNet Team
https://phishnet.example.com
"""
        
        return email_body.strip()
    
    def _format_reasons(self, reasons: list) -> str:
        """Format reasons list for email display."""
        if not reasons:
            return "• No specific threats identified"
        
        formatted = []
        for i, reason in enumerate(reasons[:5], 1):  # Limit to top 5
            formatted.append(f"{i}. {reason}")
        
        return "\n".join(formatted)
    
    def _format_recommendations(self, recommendations: list) -> str:
        """Format recommendations list for email display."""
        if not recommendations:
            return "• Continue to exercise normal email caution"
        
        formatted = []
        for i, rec in enumerate(recommendations[:5], 1):  # Limit to top 5
            formatted.append(f"{i}. {rec}")
        
        return "\n".join(formatted)


# Singleton instance
email_forward_analyzer = EmailForwardAnalyzerService()
