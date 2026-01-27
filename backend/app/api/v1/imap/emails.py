"""
IMAP Email Routes
=================

Endpoints for listing and managing forwarded emails in the IMAP inbox.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from pydantic import BaseModel, Field

from app.modes.dependencies import get_imap_service_dep
from app.modes.imap.service import IMAPEmailService
from app.api.auth import require_analyst
from app.models.user import User
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/emails", tags=["IMAP Emails"])


# ============================================================================
# Response Models
# ============================================================================

class EmailSummary(BaseModel):
    """Summary of an email in the inbox."""
    uid: str
    subject: str
    sender: str
    date: str
    size: Optional[int] = None
    has_attachments: bool = False


class PendingEmailsResponse(BaseModel):
    """Response for pending emails listing."""
    success: bool
    count: int
    emails: List[EmailSummary]
    message: str


class EmailDetailResponse(BaseModel):
    """Response for detailed email content."""
    success: bool
    uid: str
    subject: str
    sender: str
    recipients: List[str]
    date: str
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    headers: dict = {}
    attachments: List[dict] = []


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/pending", response_model=PendingEmailsResponse)
async def list_pending_emails(
    current_user: User = Depends(require_analyst),
    imap_service: IMAPEmailService = Depends(get_imap_service_dep)
):
    """
    List pending forwarded emails waiting for analysis.
    
    These are suspicious emails forwarded by users to the PhishNet inbox.
    Analysts can review and select emails for analysis.
    
    Requires: Analyst role
    
    Returns:
        List of email metadata (uid, from, subject, date)
    """
    try:
        emails = await imap_service.list_pending()
        
        summaries = [
            EmailSummary(
                uid=email.get("uid", ""),
                subject=email.get("subject", "(no subject)"),
                sender=email.get("from", "unknown"),
                date=email.get("date", ""),
                has_attachments=email.get("has_attachments", False)
            )
            for email in emails
        ]
        
        return PendingEmailsResponse(
            success=True,
            count=len(summaries),
            emails=summaries,
            message=f"Found {len(summaries)} emails waiting for analysis"
        )
    except Exception as e:
        logger.error(f"Failed to list pending emails: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list pending emails: {str(e)}"
        )


@router.get("/{email_uid}", response_model=EmailDetailResponse)
async def get_email_detail(
    email_uid: str,
    current_user: User = Depends(require_analyst),
    imap_service: IMAPEmailService = Depends(get_imap_service_dep)
):
    """
    Get detailed content of a specific forwarded email.
    
    Fetches the full email content including headers, body, and attachments.
    Use this to review an email before triggering analysis.
    
    Requires: Analyst role
    
    Args:
        email_uid: The IMAP UID of the email
        
    Returns:
        Full email details
    """
    try:
        email = await imap_service.fetch_email(email_uid)
        
        if not email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Email with UID {email_uid} not found"
            )
        
        return EmailDetailResponse(
            success=True,
            uid=email_uid,
            subject=email.subject or "(no subject)",
            sender=email.sender or "unknown",
            recipients=email.recipients or [],
            date=email.date.isoformat() if email.date else "",
            body_text=email.body_text,
            body_html=email.body_html,
            headers=email.headers,
            attachments=[
                {"filename": a.get("filename"), "content_type": a.get("content_type")}
                for a in email.attachments
            ]
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch email {email_uid}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch email: {str(e)}"
        )


@router.post("/{email_uid}/mark-processed")
async def mark_email_processed(
    email_uid: str,
    move_to_folder: Optional[str] = None,
    current_user: User = Depends(require_analyst),
    imap_service: IMAPEmailService = Depends(get_imap_service_dep)
):
    """
    Mark an email as processed after analysis.
    
    This moves/flags the email to indicate it has been analyzed,
    preventing it from appearing in the pending list again.
    
    Requires: Analyst role
    
    Args:
        email_uid: The IMAP UID of the email
        move_to_folder: Optional folder to move the email to
        
    Returns:
        Success confirmation
    """
    try:
        success = await imap_service.mark_processed(email_uid, move_to_folder)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to mark email {email_uid} as processed"
            )
        
        return {
            "success": True,
            "uid": email_uid,
            "message": f"Email {email_uid} marked as processed"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to mark email {email_uid} as processed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to mark email as processed: {str(e)}"
        )


@router.get("/search")
async def search_emails(
    subject_contains: Optional[str] = None,
    sender_contains: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(require_analyst),
    imap_service: IMAPEmailService = Depends(get_imap_service_dep)
):
    """
    Search for emails in the IMAP inbox.
    
    Requires: Analyst role
    
    Args:
        subject_contains: Filter by subject containing text
        sender_contains: Filter by sender containing text
        limit: Maximum number of results
        
    Returns:
        List of matching emails
    """
    try:
        # Build search criteria
        criteria = []
        if subject_contains:
            criteria.append(f'SUBJECT "{subject_contains}"')
        if sender_contains:
            criteria.append(f'FROM "{sender_contains}"')
        
        emails = await imap_service.list_pending(
            folder="INBOX",
            limit=limit
        )
        
        # Client-side filter if criteria specified
        if subject_contains:
            emails = [e for e in emails if subject_contains.lower() in e.get("subject", "").lower()]
        if sender_contains:
            emails = [e for e in emails if sender_contains.lower() in e.get("from", "").lower()]
        
        return {
            "success": True,
            "count": len(emails),
            "emails": emails[:limit]
        }
    except Exception as e:
        logger.error(f"Email search failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}"
        )
