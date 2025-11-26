"""Email management API endpoints."""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, and_, or_

from app.core.database import get_db
from app.api.auth import get_current_active_user, require_viewer, require_analyst
from app.models.user import User
from app.models.core.email import Email, EmailStatus
from app.models.analysis.detection import Detection
from src.common.constants import ThreatLevel
from app.schemas.email import (
    EmailResponse, EmailListResponse, EmailDetailResponse,
    EmailFilterParams, EmailAnalysisRequest
)
from app.services.gmail import gmail_service
from app.orchestrator.utils import email_orchestrator
from app.services.sanitizer import content_sanitizer
from app.config.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()


@router.get("/", response_model=EmailListResponse)
async def list_emails(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, le=100),
    status: Optional[EmailStatus] = None,
    threat_level: Optional[ThreatLevel] = None,
    sender: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    phishing_only: bool = False,
    sort_by: str = Query("received_at", pattern="^(received_at|score|created_at)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    current_user: User = Depends(require_viewer),
    db: Session = Depends(get_db)
):
    """List user's emails with filtering and pagination."""
    try:
        query = db.query(Email).filter(Email.user_id == current_user.id)
        
        # Apply filters
        if status:
            query = query.filter(Email.status == status)
        
        if sender:
            query = query.filter(Email.sender.ilike(f"%{sender}%"))
        
        if date_from:
            query = query.filter(Email.received_at >= date_from)
        
        if date_to:
            query = query.filter(Email.received_at <= date_to)
        
        if phishing_only:
            # Join with detections to filter phishing emails
            query = query.join(Detection).filter(Detection.is_phishing == True)
        
        if threat_level:
            query = query.join(Detection).filter(Detection.threat_level == threat_level)
        
        # Apply sorting
        if sort_order == "desc":
            query = query.order_by(desc(getattr(Email, sort_by)))
        else:
            query = query.order_by(asc(getattr(Email, sort_by)))
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        emails = query.offset(skip).limit(limit).all()
        
        # Convert to response format
        email_responses = []
        for email in emails:
            # Get latest detection for this email
            detection = db.query(Detection).filter(
                Detection.email_id == email.id
            ).order_by(desc(Detection.created_at)).first()
            
            email_responses.append(EmailResponse(
                id=email.id,
                sender=email.sender,
                subject=email.subject or "",
                received_at=email.received_at,
                status=email.status,
                score=email.score,
                is_phishing=detection.is_phishing if detection else False,
                threat_level=detection.threat_level if detection else None,
                created_at=email.created_at
            ))
        
        return EmailListResponse(
            emails=email_responses,
            total=total,
            skip=skip,
            limit=limit
        )
        
    except Exception as e:
        logger.error(f"Failed to list emails: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve emails"
        )


@router.get("/{email_id}", response_model=EmailDetailResponse)
async def get_email(
    email_id: int,
    current_user: User = Depends(require_viewer),
    db: Session = Depends(get_db)
):
    """Get detailed email information."""
    try:
        email = db.query(Email).filter(
            Email.id == email_id,
            Email.user_id == current_user.id
        ).first()
        
        if not email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Email not found"
            )
        
        # Get detection results
        detection = db.query(Detection).filter(
            Detection.email_id == email.id
        ).order_by(desc(Detection.created_at)).first()
        
        # Prepare response
        response_data = {
            "id": email.id,
            "sender": email.sender,
            "recipients": email.recipients,
            "subject": email.subject or "",
            "received_at": email.received_at,
            "status": email.status,
            "score": email.score,
            "size_bytes": email.size_bytes,
            "sanitized_html": email.sanitized_html,
            "raw_text": email.raw_text,
            "created_at": email.created_at,
            "analyzed_at": email.analyzed_at
        }
        
        if detection:
            response_data.update({
                "is_phishing": detection.is_phishing,
                "threat_level": detection.threat_level,
                "confidence_score": detection.confidence_score,
                "indicators": detection.indicators,
                "analysis_metadata": detection.analysis_metadata
            })
        
        return EmailDetailResponse(**response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get email {email_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve email"
        )


@router.get("/{email_id}/content", response_class=HTMLResponse)
async def get_email_content(
    email_id: int,
    current_user: User = Depends(require_viewer),
    db: Session = Depends(get_db)
):
    """Get sanitized email content for safe rendering."""
    try:
        email = db.query(Email).filter(
            Email.id == email_id,
            Email.user_id == current_user.id
        ).first()
        
        if not email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Email not found"
            )
        
        # Return sanitized HTML content
        content = email.sanitized_html or email.raw_text or "No content available"
        
        # Add CSP headers for additional security
        html_response = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="Content-Security-Policy" content="{content_sanitizer.get_content_security_policy()}">
            <title>Email Content</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <div class="warning">
                <strong>Security Notice:</strong> This email content has been sanitized for safe viewing.
                External links have been rewritten for your protection.
            </div>
            <div id="email-content">
                {content}
            </div>
        </body>
        </html>
        """
        
        return HTMLResponse(content=html_response)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get email content {email_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve email content"
        )


@router.post("/{email_id}/quarantine")
async def quarantine_email(
    email_id: int,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db)
):
    """Manually quarantine an email."""
    try:
        email = db.query(Email).filter(
            Email.id == email_id,
            Email.user_id == current_user.id
        ).first()
        
        if not email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Email not found"
            )
        
        if email.status == EmailStatus.QUARANTINED:
            return {"message": "Email is already quarantined"}
        
        # Update email status
        email.status = EmailStatus.QUARANTINED
        db.commit()
        
        # Log action
        logger.info(
            f"Email {email_id} manually quarantined by user {current_user.id}",
            extra={
                "email_id": email_id,
                "user_id": current_user.id,
                "action": "manual_quarantine"
            }
        )
        
        return {"message": "Email quarantined successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to quarantine email {email_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to quarantine email"
        )


@router.post("/{email_id}/unquarantine")
async def unquarantine_email(
    email_id: int,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db)
):
    """Remove email from quarantine."""
    try:
        email = db.query(Email).filter(
            Email.id == email_id,
            Email.user_id == current_user.id
        ).first()
        
        if not email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Email not found"
            )
        
        if email.status != EmailStatus.QUARANTINED:
            return {"message": "Email is not quarantined"}
        
        # Update email status
        email.status = EmailStatus.SAFE
        db.commit()
        
        # Log action
        logger.info(
            f"Email {email_id} removed from quarantine by user {current_user.id}",
            extra={
                "email_id": email_id,
                "user_id": current_user.id,
                "action": "unquarantine"
            }
        )
        
        return {"message": "Email removed from quarantine successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unquarantine email {email_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unquarantine email"
        )


@router.post("/{email_id}/reanalyze")
async def reanalyze_email(
    email_id: int,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db)
):
    """Trigger reanalysis of an email."""
    try:
        email = db.query(Email).filter(
            Email.id == email_id,
            Email.user_id == current_user.id
        ).first()
        
        if not email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Email not found"
            )
        
        # Reset email status and trigger reanalysis
        email.status = EmailStatus.PENDING
        email.analyzed_at = None
        email.score = None
        db.commit()
        
        # Add to processing queue
        await email_orchestrator.process_email(email_id)
        
        logger.info(
            f"Email {email_id} queued for reanalysis by user {current_user.id}",
            extra={
                "email_id": email_id,
                "user_id": current_user.id,
                "action": "reanalyze"
            }
        )
        
        return {"message": "Email queued for reanalysis"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reanalyze email {email_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reanalyze email"
        )


@router.get("/stats/summary")
async def get_email_stats(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(require_viewer),
    db: Session = Depends(get_db)
):
    """Get email statistics summary."""
    try:
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Base query for user's emails in date range
        base_query = db.query(Email).filter(
            Email.user_id == current_user.id,
            Email.received_at >= start_date,
            Email.received_at <= end_date
        )
        
        # Get counts by status
        status_counts = {}
        for status in EmailStatus:
            count = base_query.filter(Email.status == status).count()
            status_counts[status.value] = count
        
        # Get phishing detection stats
        phishing_query = base_query.join(Detection).filter(Detection.is_phishing == True)
        phishing_count = phishing_query.count()
        
        # Get threat level distribution
        threat_level_counts = {}
        for threat_level in ThreatLevel:
            count = base_query.join(Detection).filter(
                Detection.threat_level == threat_level
            ).count()
            threat_level_counts[threat_level.value] = count
        
        return {
            "period_days": days,
            "total_emails": base_query.count(),
            "phishing_detected": phishing_count,
            "status_distribution": status_counts,
            "threat_level_distribution": threat_level_counts,
            "last_scan": current_user.last_email_scan.isoformat() if current_user.last_email_scan else None
        }
        
    except Exception as e:
        logger.error(f"Failed to get email stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve email statistics"
        )
