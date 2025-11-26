"""
Email Forward Analysis API
Endpoints for analyzing emails forwarded via email
"""

from fastapi import APIRouter, HTTPException, status, Request, BackgroundTasks
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, Any
import base64

from app.services.email_forward_analyzer import email_forward_analyzer
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()


class EmailForwardRequest(BaseModel):
    """Request to analyze a forwarded email."""
    forwarded_by: EmailStr = Field(..., description="Email address that forwarded the email")
    raw_email_base64: str = Field(..., description="Base64-encoded raw email content")


class EmailForwardResponse(BaseModel):
    """Response from forwarded email analysis."""
    success: bool
    analysis: Optional[Dict[str, Any]] = None
    email_metadata: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    error: Optional[str] = None


@router.post("/analyze-forwarded", response_model=EmailForwardResponse)
async def analyze_forwarded_email(
    request: EmailForwardRequest,
    background_tasks: BackgroundTasks
):
    """
    Analyze an email that was forwarded to PhishNet.
    
    This endpoint accepts a forwarded email in raw format (base64-encoded)
    and returns the phishing analysis results.
    
    Use case: Mobile users forward suspicious emails to phishnet@example.com,
    and this API processes them.
    """
    try:
        # Decode base64 email
        try:
            raw_email_bytes = base64.b64decode(request.raw_email_base64)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 email content: {str(e)}"
            )
        
        # Analyze the forwarded email
        result = await email_forward_analyzer.analyze_forwarded_email(
            raw_email_bytes=raw_email_bytes,
            forwarded_by=request.forwarded_by
        )
        
        if result.get("success"):
            # Schedule reply email in background
            background_tasks.add_task(
                _send_reply_email,
                analysis_result=result.get("analysis"),
                recipient_email=request.forwarded_by,
                original_subject=result.get("email_metadata", {}).get("subject", "")
            )
        
        return EmailForwardResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Forwarded email analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@router.get("/history/{user_email}")
async def get_forwarded_email_history(
    user_email: EmailStr,
    limit: int = 50
):
    """
    Get history of forwarded email analyses for a user.
    
    Returns recent analyses of emails forwarded by the specified email address.
    """
    try:
        from app.models.mongodb_models import ForwardedEmailAnalysis
        
        history = await ForwardedEmailAnalysis.find(
            ForwardedEmailAnalysis.forwarded_by == user_email
        ).sort("-created_at").limit(limit).to_list()
        
        return {
            "success": True,
            "count": len(history),
            "history": history
        }
    except Exception as e:
        logger.error(f"Failed to fetch forwarded email history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


async def _send_reply_email(
    analysis_result: Dict[str, Any],
    recipient_email: str,
    original_subject: str
):
    """
    Send reply email with analysis results.
    
    This is a background task that sends the analysis results back to the user.
    """
    try:
        # Generate reply email content
        email_body = await email_forward_analyzer.generate_reply_email(
            analysis_result=analysis_result,
            recipient_email=recipient_email,
            original_subject=original_subject
        )
        
        # TODO: Integrate with actual email sending service (SMTP, SendGrid, etc.)
        logger.info(f"Would send reply email to {recipient_email}")
        logger.debug(f"Email body:\n{email_body}")
        
        # For now, just log the email content
        # In production, use an email service:
        # await email_service.send_email(
        #     to=recipient_email,
        #     subject=f"PhishNet Analysis: {original_subject}",
        #     body=email_body
        # )
        
    except Exception as e:
        logger.error(f"Failed to send reply email: {e}")
        # Don't raise - this is a background task
