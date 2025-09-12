"""API endpoints for scoring and response management."""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_

from app.core.database import get_db
from app.models.core.email import Email, EmailStatus
from app.models.analysis.scoring import EmailAction, ActionType, ActionStatus, EmailScore, AuditLog, AuditEventType
from app.schemas.email import EmailAnalysisResponse
from app.schemas.detection import DetectionResponse
from app.services.scoring import scoring_engine, response_engine, score_and_respond_email, manual_action
from app.services.audit import AuditService
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/analysis", tags=["analysis"])
audit_service = AuditService()


# Response Models
from pydantic import BaseModel

class EmailScoreResponse(BaseModel):
    email_id: int
    sanitization_score: float
    link_score: float
    ai_score: float
    threat_intel_score: float
    final_score: float
    risk_level: str
    is_phishing: bool
    confidence: float
    created_at: datetime
    
    class Config:
        from_attributes = True


class EmailActionResponse(BaseModel):
    id: int
    email_id: int
    action_type: str
    status: str
    parameters: Dict[str, Any]
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    retry_count: int
    
    class Config:
        from_attributes = True


class EmailScoreRequest(BaseModel):
    email_id: int
    user_id: int = 1  # Default for demo


class ManualActionRequest(BaseModel):
    email_id: int
    action_type: ActionType
    parameters: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    user_id: int = 1


class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    entity_type: str
    entity_id: str
    user_id: int
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    
    class Config:
        from_attributes = True


# Scoring Endpoints
@router.post("/score", response_model=EmailScoreResponse)
async def score_email(
    request: EmailScoreRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Score an email and optionally take automated actions."""
    try:
        # Check if email exists
        email = db.query(Email).filter(Email.id == request.email_id).first()
        if not email:
            raise HTTPException(status_code=404, detail="Email not found")
        
        # Calculate score
        email_score = scoring_engine.calculate_score(request.email_id, db)
        
        # Log scoring event
        await audit_service.log_email_scored(
            request.email_id,
            email_score.final_score,
            email_score.risk_level,
            request.user_id,
            db
        )
        
        # Schedule automated response actions in background
        if email_score.final_score >= 0.5:  # Only take action for significant threats
            background_tasks.add_task(
                _background_response_actions,
                request.email_id,
                request.user_id
            )
        
        return EmailScoreResponse.from_orm(email_score)
        
    except Exception as e:
        logger.error(f"Failed to score email {request.email_id}: {str(e)}")
        await audit_service.log_system_error(
            "scoring_error",
            str(e),
            request.user_id,
            {"email_id": request.email_id},
            db
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/score/{email_id}", response_model=EmailScoreResponse)
async def get_email_score(email_id: int, db: Session = Depends(get_db)):
    """Get existing score for an email."""
    email_score = db.query(EmailScore).filter(EmailScore.email_id == email_id).first()
    if not email_score:
        raise HTTPException(status_code=404, detail="Email score not found")
    
    return EmailScoreResponse.from_orm(email_score)


@router.post("/score-and-respond", response_model=Dict[str, Any])
async def score_and_respond(
    request: EmailScoreRequest,
    db: Session = Depends(get_db)
):
    """Score an email and immediately take response actions."""
    try:
        # Score and respond
        email_score, actions = await score_and_respond_email(
            request.email_id,
            request.user_id
        )
        
        return {
            "score": EmailScoreResponse.from_orm(email_score),
            "actions": [EmailActionResponse.from_orm(action) for action in actions],
            "message": f"Email scored {email_score.final_score:.2f} ({email_score.risk_level}), {len(actions)} actions taken"
        }
        
    except Exception as e:
        logger.error(f"Failed to score and respond to email {request.email_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Action Endpoints
@router.post("/action", response_model=EmailActionResponse)
async def take_manual_action(
    request: ManualActionRequest,
    db: Session = Depends(get_db)
):
    """Manually trigger an action on an email."""
    try:
        # Add reason to parameters
        parameters = request.parameters or {}
        if request.reason:
            parameters['reason'] = request.reason
            parameters['manual'] = True
        
        action = await manual_action(
            request.email_id,
            request.action_type,
            request.user_id,
            parameters
        )
        
        # Log manual action
        await audit_service.log_action_taken(
            action.id,
            request.action_type.value,
            request.email_id,
            request.user_id,
            automatic=False,
            db=db
        )
        
        return EmailActionResponse.from_orm(action)
        
    except Exception as e:
        logger.error(f"Failed to take manual action: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/actions/{email_id}", response_model=List[EmailActionResponse])
async def get_email_actions(email_id: int, db: Session = Depends(get_db)):
    """Get all actions taken on an email."""
    actions = db.query(EmailAction).filter(
        EmailAction.email_id == email_id
    ).order_by(desc(EmailAction.created_at)).all()
    
    return [EmailActionResponse.from_orm(action) for action in actions]


@router.get("/actions", response_model=List[EmailActionResponse])
async def get_recent_actions(
    limit: int = Query(50, le=100),
    status: Optional[ActionStatus] = None,
    action_type: Optional[ActionType] = None,
    db: Session = Depends(get_db)
):
    """Get recent actions with optional filtering."""
    query = db.query(EmailAction)
    
    if status:
        query = query.filter(EmailAction.status == status)
    
    if action_type:
        query = query.filter(EmailAction.action_type == action_type)
    
    actions = query.order_by(desc(EmailAction.created_at)).limit(limit).all()
    
    return [EmailActionResponse.from_orm(action) for action in actions]


# Audit Endpoints
@router.get("/audit/email/{email_id}", response_model=List[AuditLogResponse])
async def get_email_audit_trail(email_id: int, db: Session = Depends(get_db)):
    """Get complete audit trail for an email."""
    logs = await audit_service.get_email_audit_trail(email_id, db)
    
    return [
        AuditLogResponse(
            id=log.id,
            timestamp=log.timestamp,
            event_type=log.event_type.value,
            entity_type=log.entity_type,
            entity_id=log.entity_id,
            user_id=log.user_id,
            details=log.details,
            ip_address=log.ip_address
        )
        for log in logs
    ]


@router.get("/audit/user/{user_id}", response_model=Dict[str, Any])
async def get_user_activity(
    user_id: int,
    days: int = Query(30, le=90),
    db: Session = Depends(get_db)
):
    """Get user activity summary."""
    activity = await audit_service.get_user_activity(user_id, days, db)
    return activity


@router.get("/audit/logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    entity_type: Optional[str] = None,
    user_id: Optional[int] = None,
    event_type: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db)
):
    """Get audit logs with filtering."""
    # Convert string event_type to enum if provided
    event_type_enum = None
    if event_type:
        try:
            event_type_enum = AuditEventType(event_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid event_type: {event_type}")
    
    logs = await audit_service.get_audit_logs(
        entity_type=entity_type,
        user_id=user_id,
        event_type=event_type_enum,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        db=db
    )
    
    return [
        AuditLogResponse(
            id=log.id,
            timestamp=log.timestamp,
            event_type=log.event_type.value,
            entity_type=log.entity_type,
            entity_id=log.entity_id,
            user_id=log.user_id,
            details=log.details,
            ip_address=log.ip_address
        )
        for log in logs
    ]


# Statistics Endpoints
@router.get("/stats/dashboard", response_model=Dict[str, Any])
async def get_dashboard_stats(
    days: int = Query(7, le=30),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics."""
    try:
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Email statistics
        total_emails = db.query(Email).filter(Email.created_at >= start_date).count()
        analyzed_emails = db.query(Email).filter(
            and_(Email.created_at >= start_date, Email.status != EmailStatus.PENDING)
        ).count()
        
        quarantined_emails = db.query(Email).filter(
            and_(Email.created_at >= start_date, Email.status == EmailStatus.QUARANTINED)
        ).count()
        
        # Score statistics
        scores = db.query(EmailScore).join(Email).filter(
            Email.created_at >= start_date
        ).all()
        
        if scores:
            avg_score = sum(score.final_score for score in scores) / len(scores)
            high_risk_count = len([s for s in scores if s.final_score >= 0.7])
            medium_risk_count = len([s for s in scores if 0.5 <= s.final_score < 0.7])
            low_risk_count = len([s for s in scores if s.final_score < 0.5])
        else:
            avg_score = 0.0
            high_risk_count = medium_risk_count = low_risk_count = 0
        
        # Action statistics
        total_actions = db.query(EmailAction).filter(EmailAction.created_at >= start_date).count()
        successful_actions = db.query(EmailAction).filter(
            and_(
                EmailAction.created_at >= start_date,
                EmailAction.status == ActionStatus.COMPLETED
            )
        ).count()
        
        # Recent activity
        recent_logs = await audit_service.get_audit_logs(
            start_date=start_date,
            limit=10,
            db=db
        )
        
        return {
            "period_days": days,
            "email_stats": {
                "total_received": total_emails,
                "total_analyzed": analyzed_emails,
                "quarantined": quarantined_emails,
                "analysis_rate": (analyzed_emails / total_emails * 100) if total_emails > 0 else 0
            },
            "threat_stats": {
                "average_risk_score": round(avg_score, 3),
                "high_risk": high_risk_count,
                "medium_risk": medium_risk_count,
                "low_risk": low_risk_count,
                "total_scored": len(scores)
            },
            "action_stats": {
                "total_actions": total_actions,
                "successful_actions": successful_actions,
                "success_rate": (successful_actions / total_actions * 100) if total_actions > 0 else 0
            },
            "recent_activity": [
                {
                    "timestamp": log.timestamp.isoformat(),
                    "event_type": log.event_type.value,
                    "entity_type": log.entity_type,
                    "entity_id": log.entity_id
                }
                for log in recent_logs
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get dashboard stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Background task functions
async def _background_response_actions(email_id: int, user_id: int):
    """Execute response actions in background."""
    try:
        db = Session()
        email_score = db.query(EmailScore).filter(EmailScore.email_id == email_id).first()
        if email_score:
            await response_engine.process_email_score(email_score, user_id, db)
        db.close()
    except Exception as e:
        logger.error(f"Background response action failed for email {email_id}: {str(e)}")


# Export endpoint
@router.get("/export/audit")
async def export_audit_logs(
    format: str = Query("json", pattern="^(json)$"),
    entity_type: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    """Export audit logs for compliance."""
    try:
        filters = {}
        if entity_type:
            filters['entity_type'] = entity_type
        if start_date:
            filters['start_date'] = start_date
        if end_date:
            filters['end_date'] = end_date
        
        export_data = await audit_service.export_audit_logs(filters, format, db)
        
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(
            export_data,
            media_type="application/json" if format == "json" else "text/plain",
            headers={
                "Content-Disposition": f"attachment; filename=audit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to export audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
