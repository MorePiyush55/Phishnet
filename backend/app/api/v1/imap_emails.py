"""
Quick IMAP API Endpoints - ThePhish-style Email Analysis
Simple API for forwarded email analysis workflow
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Dict, Any
from datetime import datetime

from app.core.database import get_db
from app.api.auth import get_current_active_user, require_analyst
from app.models.user import User
from app.services.quick_imap import QuickIMAPService
from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/imap-emails", tags=["IMAP Email Analysis"])

# Initialize services
imap_service = QuickIMAPService()
phishing_analyzer = EnhancedPhishingAnalyzer()


@router.get("/test-connection")
async def test_imap_connection(
    current_user: User = Depends(require_analyst)
):
    """
    Test IMAP connection to forwarding inbox.
    
    This verifies that PhishNet can connect to the email account
    where users forward suspicious emails.
    """
    try:
        success = imap_service.test_connection()
        
        if success:
            return {
                "success": True,
                "message": "IMAP connection successful",
                "status": "connected"
            }
        else:
            return {
                "success": False,
                "message": "IMAP connection failed - check credentials",
                "status": "error"
            }
    except Exception as e:
        logger.error(f"IMAP connection test error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Connection test failed: {str(e)}"
        )


@router.post("/debug/verify-smtp")
async def verify_smtp_config(
   target_email: str,
   current_user: User = Depends(require_analyst) 
):
    """
    Send a test email to verify SMTP settings on the server.
    """
    try:
        from app.services.email_sender import send_email
        success = await send_email(
            to_email=target_email,
            subject="PhishNet SMTP Verification",
            body="If you see this, the backend can successfully send emails!",
            html=False
        )
        return {"success": success, "recipient": target_email}
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.get("/pending")
async def list_pending_forwarded_emails(
    current_user: User = Depends(require_analyst)
):
    """
    List pending forwarded emails waiting for analysis.
    
    These are suspicious emails forwarded by users to the PhishNet inbox.
    Analysts can review and select emails for analysis.
    
    Returns:
        List of email metadata (uid, from, subject, date)
    """
    try:
        emails = imap_service.get_pending_emails()
        
        return {
            "success": True,
            "count": len(emails),
            "emails": emails,
            "message": f"Found {len(emails)} emails waiting for analysis"
        }
    except Exception as e:
        logger.error(f"Failed to list pending emails: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve pending emails: {str(e)}"
        )


@router.post("/analyze/{mail_uid}")
async def analyze_forwarded_email(
    mail_uid: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db)
):
    """
    Analyze a forwarded email selected by analyst.
    
    Complete ThePhish-style workflow:
    1. Fetch email from IMAP by UID
    2. Extract .eml attachment if present
    3. Parse email content and headers
    4. Run enhanced phishing analysis (5 modules)
    5. Store results in database
    6. Send notification to user who forwarded it
    
    Args:
        mail_uid: IMAP UID of the email to analyze
        
    Returns:
        Complete analysis results with verdict and section scores
    """
    try:
        logger.info(f"Starting analysis of forwarded email {mail_uid}")
        
        # Step 1: Fetch and parse email from IMAP
        email_data = imap_service.fetch_email_for_analysis(mail_uid)
        
        if not email_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Email {mail_uid} not found or already analyzed"
            )
        
        logger.info(f"Fetched email from {email_data['from']} - Subject: {email_data['subject']}")
        
        # Step 2: Run enhanced phishing analysis
        analysis_result = phishing_analyzer.analyze_email(email_data['raw_email'])
        
        logger.info(f"Analysis complete: {analysis_result.final_verdict} (Score: {analysis_result.total_score}%)")
        
        # Step 3: Prepare response
        response_data = {
            "success": True,
            "mail_uid": mail_uid,
            "analyzed_at": datetime.utcnow().isoformat(),
            "analyzed_by": current_user.email,
            
            # Email metadata
            "email": {
                "forwarded_by": email_data['forwarded_by'],
                "subject": email_data['subject'],
                "from": email_data['from'],
                "to": email_data['to'],
                "received_date": email_data.get('received_date'),
                "attachment_count": len(email_data['attachments'])
            },
            
            # Overall verdict
            "verdict": analysis_result.final_verdict,
            "total_score": analysis_result.total_score,
            "confidence": analysis_result.confidence,
            "risk_factors": analysis_result.risk_factors,
            
            # Section scores (5 modules)
            "sections": {
                "sender": {
                    "score": analysis_result.sender.score,
                    "display_name": analysis_result.sender.display_name,
                    "email_address": analysis_result.sender.email_address,
                    "similarity": analysis_result.sender.name_email_similarity,
                    "sender_ip": analysis_result.sender.sender_ip,
                    "indicators": analysis_result.sender.indicators
                },
                "content": {
                    "score": analysis_result.content.score,
                    "keyword_count": analysis_result.content.keyword_count,
                    "urgency_level": analysis_result.content.urgency_level,
                    "keywords_found": analysis_result.content.phishing_keywords_found[:20],  # First 20
                    "indicators": analysis_result.content.indicators
                },
                "links": {
                    "score": analysis_result.links.overall_score,
                    "total_links": analysis_result.links.total_links,
                    "https_links": analysis_result.links.https_links,
                    "http_links": analysis_result.links.http_links,
                    "encoded_links": analysis_result.links.encoded_links,
                    "redirect_links": analysis_result.links.redirect_links,
                    "suspicious_tlds": analysis_result.links.suspicious_tlds,
                    "https_score": analysis_result.links.https_score,
                    "encoding_score": analysis_result.links.encoding_score,
                    "redirect_score": analysis_result.links.redirect_score,
                    "indicators": analysis_result.links.indicators
                },
                "authentication": {
                    "score": analysis_result.authentication.overall_score,
                    "spf_result": analysis_result.authentication.spf_result,
                    "spf_score": analysis_result.authentication.spf_score,
                    "spf_description": analysis_result.authentication.spf_description,
                    "dkim_result": analysis_result.authentication.dkim_result,
                    "dkim_score": analysis_result.authentication.dkim_score,
                    "dkim_description": analysis_result.authentication.dkim_description,
                    "dmarc_result": analysis_result.authentication.dmarc_result,
                    "dmarc_score": analysis_result.authentication.dmarc_score,
                    "dmarc_description": analysis_result.authentication.dmarc_description,
                    "indicators": analysis_result.authentication.indicators
                },
                "attachments": {
                    "score": analysis_result.attachments.score,
                    "total_attachments": analysis_result.attachments.total_attachments,
                    "attachment_names": analysis_result.attachments.attachment_names,
                    "attachment_types": analysis_result.attachments.attachment_types,
                    "dangerous_extensions": analysis_result.attachments.dangerous_extensions,
                    "indicators": analysis_result.attachments.indicators
                }
            }
        }
        
        # Step 4: Background task - Send notification to user who forwarded
        background_tasks.add_task(
            send_analysis_notification,
            email_data['forwarded_by'],
            email_data['subject'],
            analysis_result
        )
        
        # Step 5: Background task - Store in database (optional)
        # background_tasks.add_task(store_analysis_result, db, response_data)
        
        logger.info(f"Successfully analyzed forwarded email {mail_uid}")
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to analyze email {mail_uid}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@router.get("/stats")
async def get_forwarding_stats(
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db)
):
    """
    Get statistics about forwarded email analysis.
    
    Returns:
        Stats like total analyzed, pending, verdicts breakdown
    """
    try:
        # Get pending count
        pending_emails = imap_service.get_pending_emails()
        pending_count = len(pending_emails)
        
        # TODO: Get stats from database
        # - Total analyzed today/week/month
        # - Verdict breakdown (SAFE/SUSPICIOUS/PHISHING)
        # - Top forwarders
        # - Average analysis time
        
        return {
            "success": True,
            "stats": {
                "pending_analysis": pending_count,
                "analyzed_today": 0,  # TODO: From DB
                "analyzed_this_week": 0,  # TODO: From DB
                "phishing_detected": 0,  # TODO: From DB
                "suspicious_detected": 0,  # TODO: From DB
                "safe_emails": 0  # TODO: From DB
            }
        }
    except Exception as e:
        logger.error(f"Failed to get stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve stats: {str(e)}"
        )


@router.post("/debug/trigger-poll")
async def manual_trigger_poll(
    current_user: User = Depends(require_analyst)
):
    """
    Manually trigger one email polling cycle for debugging.
    
    This forces the system to check IMAP, analyze pending emails,
    and send notifications immediately, skipping the schedule.
    """
    try:
        from app.services.email_poller import email_polling_service
        
        # Determine if we can run it safely
        if email_polling_service.is_running:
            return {
                "success": False,
                "message": "Polling service is already running in background. Check logs."
            }
            
        # Run one cycle
        logger.info("Manually triggering email poll")
        # We call the internal logic directly
        await email_polling_service.poll_and_analyze()
        
        return {
            "success": True,
            "message": "Manual polling cycle completed successfully."
        }
    except Exception as e:
        logger.error(f"Manual poll failed: {str(e)}")
        return {
            "success": False, 
            "message": f"Manual poll failed: {str(e)}"
        }

# Helper functions

async def send_analysis_notification(
    recipient_email: str,
    original_subject: str,
    analysis_result,
    interpretation=None
):
    """
    Send email notification with analysis verdict to user who forwarded the email.
    Uses Gemini interpretation if available, otherwise falls back to technical summary.
    """
    try:
        logger.info(f"Sending analysis notification to {recipient_email}")
        
        verdict_emoji = {
            "SAFE": "✅",
            "SUSPICIOUS": "⚠️",
            "PHISHING": "🚨"
        }
        
        # Determine Verdict and Explanation Source
        if interpretation:
            final_verdict = interpretation.verdict.upper()
            reasons = interpretation.explanation_snippets
            action = interpretation.detected_techniques[0] if interpretation.detected_techniques else "Use caution."
            explanation_source = "AI Analysis"
        else:
            final_verdict = analysis_result.final_verdict
            reasons = analysis_result.risk_factors[:3] if analysis_result.risk_factors else ["No specific risk factors found."]
            action = "Please review the details below."
            explanation_source = "Automated Rules"

        # Format bullet points
        reasons_text = chr(10).join(f"  • {r}" for r in reasons)
        
        email_body = f"""
PhishNet Security Analysis
{'='*50}

Subject: {original_subject}

VERDICT: {verdict_emoji.get(final_verdict, '❓')} {final_verdict}

RECOMMENDED ACTION:
👉 {action}

KEY REASONS ({explanation_source}):
{reasons_text}

{'='*50}
TECHNICAL DETAILS
Confidence: {analysis_result.confidence:.1%}
Total Risk Score: {analysis_result.total_score}%

Section Scores:
  • Sender: {analysis_result.sender.score}%
  • Content: {analysis_result.content.score}%
  • Links: {analysis_result.links.overall_score}%
  • Attachments: {analysis_result.attachments.score}%

View full dashboard: https://phishnet.ai/dashboard
{'='*50}
This is an automated message from PhishNet.
"""
        
        # Send email via SMTP
        from app.services.email_sender import send_email
        await send_email(to_email=recipient_email, subject=f"Analysis Result: {original_subject}", body=email_body)
        
        logger.info(f"Notification sent to {recipient_email}")
        
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")


async def store_analysis_result(db: Session, analysis_data: Dict[str, Any]):
    """
    Store analysis result in database for historical tracking.
    """
    try:
        # TODO: Implement database storage
        # Create EmailAnalysis record
        # Link to user who forwarded
        # Store section scores
        pass
    except Exception as e:
        logger.error(f"Failed to store analysis result: {str(e)}")
