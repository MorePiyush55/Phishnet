"""
Email Polling Service
Background service that periodically checks IMAP for new forwarded emails
and triggers analysis automatically.
"""

import asyncio
import logging
from typing import Optional

from app.config.settings import get_settings
from app.services.quick_imap import QuickIMAPService
from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer
from app.api.v1.imap_emails import send_analysis_notification

logger = logging.getLogger(__name__)
settings = get_settings()

class EmailPollingService:
    """
    Background service to poll IMAP for new emails.
    """
    
    def __init__(self):
        self.imap_service = QuickIMAPService()
        self.phishing_analyzer = EnhancedPhishingAnalyzer()
        self.is_running = False
        self.poll_interval = getattr(settings, 'IMAP_POLL_INTERVAL', 60)
        
    async def start(self):
        """Start the polling service."""
        if not getattr(settings, 'IMAP_ENABLED', False):
            logger.info("IMAP polling disabled in settings")
            return
            
        if self.is_running:
            return
            
        self.is_running = True
        logger.info(f"Starting Email Polling Service (Interval: {self.poll_interval}s)")
        
        while self.is_running:
            try:
                await self.poll_and_analyze()
            except Exception as e:
                logger.error(f"Error in email polling loop: {e}")
            
            # Wait for next poll
            await asyncio.sleep(self.poll_interval)
            
    async def stop(self):
        """Stop the polling service."""
        self.is_running = False
        logger.info("Stopping Email Polling Service")
        
    async def poll_and_analyze(self):
        """Check for pending emails and analyze them."""
        try:
            # Get RECENT emails (both SEEN and UNSEEN) - robust against accidental reads
            email_limit = getattr(settings, 'IMAP_BATCH_SIZE', 50)
            recent_emails = await asyncio.to_thread(self.imap_service.get_recent_emails, email_limit)
            
            if not recent_emails:
                return
                
            logger.info(f"Checking {len(recent_emails)} recent emails for new submissions...")
            
            # Use ForwardedEmailAnalysis model to check for duplicates
            from app.models.mongodb_models import ForwardedEmailAnalysis
            
            processed_count = 0
            
            for email_meta in recent_emails:
                try:
                    uid = email_meta['uid']
                    message_id = email_meta['message_id']
                    
                    if not message_id:
                        logger.warning(f"Email UID {uid} has no Message-ID, skipping deduplication check")
                        continue
                        
                    # Check if already processed
                    exists = await ForwardedEmailAnalysis.find_one({"email_metadata.message_id": message_id})
                    
                    if exists:
                        # Already analyzed - Skip
                        continue
                        
                    logger.info(f"Found NEW unanalyzed email: {email_meta['subject']} (UID {uid})")
                    await self.process_email(uid, message_id)
                    processed_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to process email {email_meta.get('uid')}: {e}")
            
            if processed_count > 0:
                logger.info(f"Successfully processed {processed_count} new emails")
                
        except Exception as e:
            logger.error(f"Error during poll_and_analyze: {e}")
                
    async def process_email(self, uid: str, message_id: str):
        """Process a single email by UID."""
        logger.info(f"Processing email UID {uid}")
        
        # 1. Fetch and parse
        email_data = await asyncio.to_thread(self.imap_service.fetch_email_for_analysis, uid)
        
        if not email_data:
            logger.warning(f"Could not fetch data for email {uid}")
            return
            
        # 2. Analyze (Technical)
        # Note: analyze_email is synchronous in EnhancedPhishingAnalyzer, run in thread
        analysis_result = await asyncio.to_thread(
            self.phishing_analyzer.analyze_email, 
            email_data['raw_email']
        )
        
        # 3. Interpret (Gemini AI)
        technical_report = {
            "subject": email_data['subject'],
            "verdict": analysis_result.final_verdict,
            "total_score": analysis_result.total_score,
            "sender_mismatch": analysis_result.sender.indicators,
            "malicious_links": len([l for l in analysis_result.links.indicators if 'malicious' in l.lower()]),
            "spf_status": analysis_result.authentication.spf_result,
            "dkim_status": analysis_result.authentication.dkim_result,
            "risk_factors": analysis_result.risk_factors
        }
        
        from app.services.gemini import create_gemini_client
        gemini_client = create_gemini_client()
        
        if gemini_client.is_available:
            try:
                interpretation = await gemini_client.interpret_technical_findings(technical_report)
                logger.info(f"Gemini interpretation complete: {interpretation.verdict}")
            except Exception as e:
                logger.error(f"Gemini interpretation failed: {e}")
                interpretation = None
        else:
            interpretation = None
        
        # 4. Store Result in DB (Using ForwardedEmailAnalysis)
        # This is CRITICAL for the deduplication to work next time
        try:
            from app.models.mongodb_models import ForwardedEmailAnalysis
            from datetime import datetime
            
            # Serialize analysis result for storage
            # Assuming analysis_result can be dumped to dict roughly, otherwise we need a helper
            # For now, let's store the top-level scores and verdicts
            
            analysis_doc = ForwardedEmailAnalysis(
                user_id=email_data['forwarded_by'], # Using email as ID for now
                forwarded_by=email_data['forwarded_by'],
                original_sender=email_data['from'],
                original_subject=email_data['subject'],
                threat_score=float(analysis_result.total_score) / 100.0,
                risk_level=analysis_result.final_verdict,
                analysis_result={
                    "verdict": analysis_result.final_verdict,
                    "score": analysis_result.total_score,
                    "confidence": analysis_result.confidence,
                    "risk_factors": analysis_result.risk_factors
                },
                email_metadata={
                    "message_id": message_id,
                    "subject": email_data['subject'],
                    "date": email_data['received_date'].isoformat() if email_data['received_date'] else None
                },
                reply_sent=True,
                reply_sent_at=datetime.utcnow()
            )
            await analysis_doc.save()
            logger.info(f"Stored analysis for {message_id} in MongoDB")
            
        except Exception as e:
            logger.error(f"Failed to store analysis in MongoDB: {e}")
            # Do NOT return, still try to send notification
        
        # 4. Send Notification
        await send_analysis_notification(
            recipient_email=email_data['forwarded_by'],
            original_subject=email_data['subject'],
            analysis_result=analysis_result,
            interpretation=interpretation  # Pass the AI result
        )
        
        logger.info(f"Completed analysis for email {uid} from {email_data['forwarded_by']}")

# Singleton instance
email_polling_service = EmailPollingService()
