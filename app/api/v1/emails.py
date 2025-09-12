"""
Emails API v1 - Email management endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from pydantic import BaseModel
from datetime import datetime

from app.core.database import get_db
from app.models.email import Email
from app.models.user import User
from app.api.v1.auth import get_current_user
from app.schemas.email import EmailResponse, EmailDetailResponse

router = APIRouter()

# Request/Response Models
class EmailListResponse(BaseModel):
    items: List[EmailResponse]
    total: int
    page: int
    limit: int
    has_next: bool

class ActionResult(BaseModel):
    success: bool
    message: str
    action: str
    email_id: int
    timestamp: datetime

class JobResult(BaseModel):
    job_id: str
    status: str
    message: str
    email_id: int
    timestamp: datetime

# Endpoints
@router.get("", response_model=EmailListResponse)
async def get_emails(
    status: Optional[str] = Query(None, description="Filter by status: pending, analyzed, quarantined, safe"),
    q: Optional[str] = Query(None, description="Search query for subject, sender, or content"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get paginated list of emails with filtering
    
    **Contract**: GET /api/v1/emails?status=&q=&page=&limit=
    - Output: { items:[Email], total, page, limit, has_next }
    """
    
    # Build query
    query = db.query(Email)
    
    # Apply status filter
    if status:
        if status not in ["pending", "analyzed", "quarantined", "safe"]:
            raise HTTPException(status_code=400, detail="Invalid status filter")
        query = query.filter(Email.status == status)
    
    # Apply search filter
    if q:
        search_filter = or_(
            Email.subject.ilike(f"%{q}%"),
            Email.sender.ilike(f"%{q}%"),
            Email.body_text.ilike(f"%{q}%")
        )
        query = query.filter(search_filter)
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * limit
    emails = query.order_by(Email.received_at.desc()).offset(offset).limit(limit).all()
    
    # Calculate has_next
    has_next = offset + limit < total
    
    return EmailListResponse(
        items=[EmailResponse.from_orm(email) for email in emails],
        total=total,
        page=page,
        limit=limit,
        has_next=has_next
    )

@router.get("/{email_id}", response_model=EmailDetailResponse)
async def get_email_detail(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed email information including analysis results
    
    **Contract**: GET /api/v1/emails/{id} → EmailDetail
    """
    
    email = db.query(Email).filter(Email.id == email_id).first()
    
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    return EmailDetailResponse.from_orm(email)

@router.post("/{email_id}/quarantine", response_model=ActionResult)
async def quarantine_email(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Quarantine an email
    
    **Contract**: POST /api/v1/emails/{id}/quarantine → ActionResult
    """
    
    email = db.query(Email).filter(Email.id == email_id).first()
    
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    if email.status == "quarantined":
        raise HTTPException(status_code=400, detail="Email is already quarantined")
    
    # Update email status
    email.status = "quarantined"
    email.quarantined_at = datetime.utcnow()
    email.quarantined_by = current_user.id
    
    # Add action to audit log (would be implemented in audit service)
    # audit_service.log_action(
    #     user_id=current_user.id,
    #     action="email_quarantined",
    #     resource_type="email",
    #     resource_id=email_id
    # )
    
    db.commit()
    
    return ActionResult(
        success=True,
        message="Email quarantined successfully",
        action="quarantine",
        email_id=email_id,
        timestamp=datetime.utcnow()
    )

@router.post("/{email_id}/rescan", response_model=JobResult)
async def rescan_email(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Trigger email re-analysis
    
    **Contract**: POST /api/v1/emails/{id}/rescan → JobResult
    """
    
    email = db.query(Email).filter(Email.id == email_id).first()
    
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    # Generate job ID
    import uuid
    job_id = str(uuid.uuid4())
    
    # In a real implementation, this would:
    # 1. Queue the email for re-analysis
    # 2. Update email status to 'rescanning'
    # 3. Return job ID for tracking
    
    # For now, simulate job creation
    email.status = "pending"
    email.last_analyzed = None
    
    # Add action to audit log
    # audit_service.log_action(
    #     user_id=current_user.id,
    #     action="email_rescan_requested",
    #     resource_type="email",
    #     resource_id=email_id
    # )
    
    db.commit()
    
    return JobResult(
        job_id=job_id,
        status="queued",
        message="Email queued for re-analysis",
        email_id=email_id,
        timestamp=datetime.utcnow()
    )

@router.post("/{email_id}/safe", response_model=ActionResult)
async def mark_safe(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Mark email as safe (false positive)
    """
    
    email = db.query(Email).filter(Email.id == email_id).first()
    
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    # Update email status
    email.status = "safe"
    email.marked_safe_at = datetime.utcnow()
    email.marked_safe_by = current_user.id
    
    db.commit()
    
    return ActionResult(
        success=True,
        message="Email marked as safe",
        action="mark_safe",
        email_id=email_id,
        timestamp=datetime.utcnow()
    )

@router.delete("/{email_id}", response_model=ActionResult)
async def delete_email(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Delete email (admin only)
    """
    
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    email = db.query(Email).filter(Email.id == email_id).first()
    
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    db.delete(email)
    db.commit()
    
    return ActionResult(
        success=True,
        message="Email deleted successfully",
        action="delete",
        email_id=email_id,
        timestamp=datetime.utcnow()
    )
