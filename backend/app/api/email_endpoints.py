"""
PhishNet Phase 2: Email API Endpoints
Email list/detail endpoints for the SOC Dashboard
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.models.complete_schema import Email, User, EmailStatus
from app.core.security import get_current_user

# Create router
router = APIRouter(prefix="/api/v1/emails", tags=["emails"])

# Pydantic models for API
class EmailSummary(BaseModel):
    """Email summary for list view"""
    id: int
    gmail_msg_id: str
    from_addr: str
    to_addr: str
    subject: str
    received_at: datetime
    status: str
    score: Optional[float] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

class EmailDetail(BaseModel):
    """Full email details"""
    id: int
    gmail_msg_id: str
    thread_id: Optional[str] = None
    from_addr: str
    to_addr: str
    subject: str
    received_at: datetime
    raw_headers: dict
    raw_text: Optional[str] = None
    sanitized_html: Optional[str] = None
    score: Optional[float] = None
    status: str
    created_at: datetime
    last_analyzed: Optional[datetime] = None
    analysis_version: Optional[str] = None
    processing_time_ms: Optional[int] = None
    
    class Config:
        from_attributes = True

class EmailListResponse(BaseModel):
    """Paginated email list response"""
    emails: List[EmailSummary]
    total: int
    page: int
    limit: int
    has_next: bool
    has_prev: bool

class EmailStatusUpdate(BaseModel):
    """Email status update request"""
    status: str = Field(..., description="New status for the email")
    score: Optional[float] = Field(None, description="Analysis score")
    analysis_version: Optional[str] = Field(None, description="Analysis version")

# Email endpoints
@router.get("/", response_model=EmailListResponse)
async def list_emails(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status"),
    from_addr: Optional[str] = Query(None, description="Filter by sender"),
    search: Optional[str] = Query(None, description="Search in subject"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List emails with pagination and filters
    Requires authentication
    """
    offset = (page - 1) * limit
    
    # Build query
    query = db.query(Email)
    
    # Apply filters
    if status:
        if status not in [s.value for s in EmailStatus]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {[s.value for s in EmailStatus]}"
            )
        query = query.filter(Email.status == status)
    
    if from_addr:
        query = query.filter(Email.from_addr.ilike(f"%{from_addr}%"))
    
    if search:
        query = query.filter(Email.subject.ilike(f"%{search}%"))
    
    # Get total count
    total = query.count()
    
    # Get paginated results
    emails = query.order_by(Email.received_at.desc()).offset(offset).limit(limit).all()
    
    # Convert to response models
    email_summaries = [EmailSummary.from_orm(email) for email in emails]
    
    return EmailListResponse(
        emails=email_summaries,
        total=total,
        page=page,
        limit=limit,
        has_next=(offset + limit) < total,
        has_prev=page > 1
    )

@router.get("/{email_id}", response_model=EmailDetail)
async def get_email_detail(
    email_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get detailed email information by ID
    Requires authentication
    """
    email = db.query(Email).filter(Email.id == email_id).first()
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Email not found"
        )
    
    return EmailDetail.from_orm(email)

@router.put("/{email_id}/status", response_model=EmailDetail)
async def update_email_status(
    email_id: int,
    status_update: EmailStatusUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update email status (quarantine, release, etc.)
    Requires authentication
    """
    # Check user permissions (admin/analyst can update)
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to update email status"
        )
    
    email = db.query(Email).filter(Email.id == email_id).first()
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Email not found"
        )
    
    # Validate status
    if status_update.status not in [s.value for s in EmailStatus]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {[s.value for s in EmailStatus]}"
        )
    
    # Update email
    email.status = status_update.status
    email.last_analyzed = datetime.utcnow()
    
    if status_update.score is not None:
        email.score = status_update.score
    
    if status_update.analysis_version:
        email.analysis_version = status_update.analysis_version
    
    db.commit()
    db.refresh(email)
    
    return EmailDetail.from_orm(email)

@router.get("/stats/summary")
async def get_email_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get email statistics summary
    Requires authentication
    """
    from sqlalchemy import func
    
    # Get status counts
    status_counts = db.query(
        Email.status,
        func.count(Email.id).label('count')
    ).group_by(Email.status).all()
    
    # Get total count
    total_emails = db.query(Email).count()
    
    # Get average score
    avg_score = db.query(func.avg(Email.score)).filter(Email.score.isnot(None)).scalar()
    
    # Get recent activity (last 24 hours)
    from datetime import timedelta
    recent_cutoff = datetime.utcnow() - timedelta(hours=24)
    recent_count = db.query(Email).filter(Email.created_at >= recent_cutoff).count()
    
    return {
        "total_emails": total_emails,
        "status_breakdown": {status: count for status, count in status_counts},
        "average_score": round(avg_score, 3) if avg_score else None,
        "recent_24h": recent_count,
        "updated_at": datetime.utcnow().isoformat()
    }
