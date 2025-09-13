"""
Audits API v1 - Audit log and system activity endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from pydantic import BaseModel
from datetime import datetime, date

from app.core.database import get_db
from app.models.user import User
from app.api.v1.auth import get_current_user

router = APIRouter()

# Request/Response Models
class AuditEntry(BaseModel):
    id: int
    timestamp: datetime
    actor: str  # user email or system
    action: str
    resource_type: str
    resource_id: Optional[int] = None
    details: Optional[dict] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

class AuditListResponse(BaseModel):
    items: List[AuditEntry]
    total: int
    page: int
    limit: int
    has_next: bool

# Mock audit data - in production this would be a proper audit table
MOCK_AUDIT_DATA = [
    {
        "id": 1,
        "timestamp": datetime.utcnow(),
        "actor": "admin@company.com",
        "action": "email_quarantined",
        "resource_type": "email",
        "resource_id": 123,
        "details": {"reason": "high_risk_score", "score": 0.95},
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    },
    {
        "id": 2,
        "timestamp": datetime.utcnow(),
        "actor": "analyst@company.com",
        "action": "email_marked_safe",
        "resource_type": "email", 
        "resource_id": 124,
        "details": {"previous_status": "quarantined"},
        "ip_address": "192.168.1.101",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    },
    {
        "id": 3,
        "timestamp": datetime.utcnow(),
        "actor": "system",
        "action": "email_analyzed",
        "resource_type": "email",
        "resource_id": 125,
        "details": {"risk_score": 0.23, "analysis_time_ms": 2847},
        "ip_address": None,
        "user_agent": None
    }
]

# Endpoints
@router.get("", response_model=AuditListResponse)
async def get_audit_logs(
    actor: Optional[str] = Query(None, description="Filter by actor (user email or 'system')"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    from_date: Optional[date] = Query(None, alias="from", description="Start date filter"),
    to_date: Optional[date] = Query(None, alias="to", description="End date filter"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get paginated audit logs with filtering
    
    **Contract**: GET /api/v1/audits?actor=&action=&from=&to=
    - Output: { items, total }
    """
    
    # In production, this would query the actual audit table
    # For now, filter mock data
    
    filtered_data = MOCK_AUDIT_DATA.copy()
    
    # Apply filters
    if actor:
        filtered_data = [entry for entry in filtered_data if entry["actor"] == actor]
    
    if action:
        filtered_data = [entry for entry in filtered_data if entry["action"] == action]
    
    if from_date:
        filtered_data = [entry for entry in filtered_data 
                        if entry["timestamp"].date() >= from_date]
    
    if to_date:
        filtered_data = [entry for entry in filtered_data 
                        if entry["timestamp"].date() <= to_date]
    
    # Calculate pagination
    total = len(filtered_data)
    offset = (page - 1) * limit
    paginated_data = filtered_data[offset:offset + limit]
    has_next = offset + limit < total
    
    # Convert to response models
    items = [AuditEntry(**entry) for entry in paginated_data]
    
    return AuditListResponse(
        items=items,
        total=total,
        page=page,
        limit=limit,
        has_next=has_next
    )

@router.get("/actions")
async def get_available_actions(
    current_user: User = Depends(get_current_user)
):
    """
    Get list of available audit action types for filtering
    """
    
    # In production, this would query distinct actions from audit table
    actions = [
        "email_analyzed",
        "email_quarantined", 
        "email_marked_safe",
        "email_deleted",
        "email_rescan_requested",
        "user_login",
        "user_logout",
        "settings_updated",
        "system_health_check",
        "api_key_generated",
        "api_key_revoked"
    ]
    
    return {"actions": sorted(actions)}

@router.get("/actors")
async def get_available_actors(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get list of available actors (users + system) for filtering
    """
    
    # Get all users from database
    users = db.query(User.email).filter(User.is_active == True).all()
    user_emails = [user.email for user in users]
    
    # Add system actor
    actors = ["system"] + sorted(user_emails)
    
    return {"actors": actors}

@router.get("/stats")
async def get_audit_stats(
    current_user: User = Depends(get_current_user)
):
    """
    Get audit activity statistics
    """
    
    # In production, this would calculate from actual audit data
    return {
        "total_events": 1247,
        "events_today": 23,
        "events_this_week": 156,
        "top_actions": [
            {"action": "email_analyzed", "count": 892},
            {"action": "email_quarantined", "count": 45},
            {"action": "user_login", "count": 78},
            {"action": "email_marked_safe", "count": 23},
            {"action": "settings_updated", "count": 12}
        ],
        "top_actors": [
            {"actor": "system", "count": 892},
            {"actor": "admin@company.com", "count": 89},
            {"actor": "analyst@company.com", "count": 67},
            {"actor": "security@company.com", "count": 45}
        ]
    }
