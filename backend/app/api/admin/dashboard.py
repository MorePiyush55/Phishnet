"""Dashboard API endpoints with real-time updates."""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, desc
import json
import asyncio

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.core.email import Email
from app.models.analysis.detection import Detection
from app.models.analysis.scoring import EmailScore, EmailAction, AuditLog
from app.schemas.email import EmailResponse, EmailSummary
from app.schemas.detection import DetectionResponse
from app.schemas.scoring import EmailScoreResponse
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()
security = HTTPBearer()

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Failed to send personal message: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Failed to broadcast to connection: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)

manager = ConnectionManager()


@router.get("/kpis")
async def get_dashboard_kpis(
    timeframe: str = Query("today", pattern="^(today|week|month)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get dashboard KPIs for specified timeframe."""
    try:
        # Calculate time range
        now = datetime.now(timezone.utc)
        if timeframe == "today":
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif timeframe == "week":
            start_date = now - timedelta(days=7)
        else:  # month
            start_date = now - timedelta(days=30)
        
        # Total emails processed
        total_emails = db.query(func.count(Email.id)).filter(
            Email.created_at >= start_date
        ).scalar() or 0
        
        # Flagged emails (risk score > 0.5)
        flagged_emails = db.query(func.count(Email.id)).join(EmailScore).filter(
            and_(
                Email.created_at >= start_date,
                EmailScore.risk_score > 0.5
            )
        ).scalar() or 0
        
        # Quarantined emails
        quarantined_emails = db.query(func.count(EmailAction.id)).filter(
            and_(
                EmailAction.created_at >= start_date,
                EmailAction.action == "quarantine"
            )
        ).scalar() or 0
        
        # High-risk emails (risk score > 0.8)
        high_risk_emails = db.query(func.count(Email.id)).join(EmailScore).filter(
            and_(
                Email.created_at >= start_date,
                EmailScore.risk_score > 0.8
            )
        ).scalar() or 0
        
        # Threat detections by type
        threat_detections = db.query(
            Detection.threat_type,
            func.count(Detection.id).label('count')
        ).join(Email).filter(
            Email.created_at >= start_date
        ).group_by(Detection.threat_type).all()
        
        threat_breakdown = {detection.threat_type: detection.count for detection in threat_detections}
        
        # Average processing time
        avg_processing_time = db.query(
            func.avg(EmailScore.processing_time)
        ).join(Email).filter(
            Email.created_at >= start_date
        ).scalar() or 0
        
        # Detection accuracy (emails correctly flagged)
        # This would need feedback mechanism in real implementation
        detection_accuracy = 95.2  # Placeholder
        
        return {
            "timeframe": timeframe,
            "period": {
                "start": start_date.isoformat(),
                "end": now.isoformat()
            },
            "kpis": {
                "total_emails": total_emails,
                "flagged_emails": flagged_emails,
                "quarantined_emails": quarantined_emails,
                "high_risk_emails": high_risk_emails,
                "detection_accuracy": round(detection_accuracy, 1),
                "avg_processing_time": round(float(avg_processing_time), 2)
            },
            "threat_breakdown": threat_breakdown,
            "trends": {
                "flagged_rate": round((flagged_emails / total_emails * 100) if total_emails > 0 else 0, 1),
                "quarantine_rate": round((quarantined_emails / total_emails * 100) if total_emails > 0 else 0, 1),
                "high_risk_rate": round((high_risk_emails / total_emails * 100) if total_emails > 0 else 0, 1)
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting dashboard KPIs: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve KPIs")


@router.get("/emails")
async def get_recent_emails(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    risk_filter: Optional[str] = Query(None, pattern="^(low|medium|high)$"),
    threat_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get recent emails with filtering and pagination."""
    try:
        query = db.query(Email).outerjoin(EmailScore).outerjoin(Detection)
        
        # Apply risk filter
        if risk_filter:
            if risk_filter == "low":
                query = query.filter(EmailScore.risk_score <= 0.3)
            elif risk_filter == "medium":
                query = query.filter(and_(EmailScore.risk_score > 0.3, EmailScore.risk_score <= 0.7))
            else:  # high
                query = query.filter(EmailScore.risk_score > 0.7)
        
        # Apply threat type filter
        if threat_type:
            query = query.filter(Detection.threat_type == threat_type)
        
        # Get total count for pagination
        total_count = query.count()
        
        # Apply pagination and ordering
        emails = query.order_by(desc(Email.created_at)).offset(offset).limit(limit).all()
        
        # Format response
        email_list = []
        for email in emails:
            email_score = db.query(EmailScore).filter(EmailScore.email_id == email.id).first()
            detections = db.query(Detection).filter(Detection.email_id == email.id).all()
            
            email_data = {
                "id": str(email.id),
                "subject": email.subject,
                "sender": email.sender,
                "recipient": email.recipient,
                "created_at": email.created_at.isoformat(),
                "risk_score": email_score.risk_score if email_score else 0.0,
                "status": "quarantined" if any(action.action == "quarantine" for action in email.actions) else "flagged" if email_score and email_score.risk_score > 0.5 else "clean",
                "threat_types": [d.threat_type for d in detections],
                "processing_time": email_score.processing_time if email_score else None
            }
            email_list.append(email_data)
        
        return {
            "emails": email_list,
            "pagination": {
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "has_more": offset + limit < total_count
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting recent emails: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve emails")


@router.get("/emails/{email_id}")
async def get_email_detail(
    email_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed email analysis results."""
    try:
        email = db.query(Email).filter(Email.id == email_id).first()
        if not email:
            raise HTTPException(status_code=404, detail="Email not found")
        
        # Get associated data
        email_score = db.query(EmailScore).filter(EmailScore.email_id == email.id).first()
        detections = db.query(Detection).filter(Detection.email_id == email.id).all()
        actions = db.query(EmailAction).filter(EmailAction.email_id == email.id).all()
        
        # Get link analysis if available
        from app.models.analysis.link_analysis import LinkAnalysis
        link_analyses = db.query(LinkAnalysis).filter(LinkAnalysis.email_id == email.id).all()
        
        return {
            "email": {
                "id": str(email.id),
                "subject": email.subject,
                "sender": email.sender,
                "recipient": email.recipient,
                "body": email.body,  # This should be sanitized in production
                "headers": email.headers,
                "created_at": email.created_at.isoformat(),
                "attachments": email.attachments or []
            },
            "analysis": {
                "risk_score": email_score.risk_score if email_score else 0.0,
                "confidence": email_score.confidence if email_score else 0.0,
                "processing_time": email_score.processing_time if email_score else None,
                "ai_analysis": email_score.ai_analysis if email_score else None,
                "threat_intel": email_score.threat_intel if email_score else None
            },
            "detections": [
                {
                    "threat_type": d.threat_type,
                    "confidence": d.confidence,
                    "description": d.description,
                    "indicators": d.indicators
                }
                for d in detections
            ],
            "link_analysis": [
                {
                    "url": la.original_url,
                    "final_url": la.final_url,
                    "redirect_chain": la.redirect_chain,
                    "status_code": la.status_code,
                    "is_suspicious": la.is_suspicious,
                    "risk_factors": la.risk_factors
                }
                for la in link_analyses
            ],
            "actions": [
                {
                    "action": action.action,
                    "reason": action.reason,
                    "created_at": action.created_at.isoformat(),
                    "executed": action.executed
                }
                for action in actions
            ]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting email detail: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve email details")


@router.get("/threat-stats")
async def get_threat_statistics(
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get threat statistics over time."""
    try:
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Daily threat counts
        daily_stats = db.query(
            func.date(Email.created_at).label('date'),
            func.count(Email.id).label('total_emails'),
            func.count(
                func.case([(EmailScore.risk_score > 0.5, 1)])
            ).label('flagged_emails'),
            func.count(
                func.case([(EmailScore.risk_score > 0.8, 1)])
            ).label('high_risk_emails')
        ).outerjoin(EmailScore).filter(
            Email.created_at >= start_date
        ).group_by(func.date(Email.created_at)).all()
        
        # Threat type distribution
        threat_distribution = db.query(
            Detection.threat_type,
            func.count(Detection.id).label('count')
        ).join(Email).filter(
            Email.created_at >= start_date
        ).group_by(Detection.threat_type).all()
        
        return {
            "period": {
                "start": start_date.isoformat(),
                "end": datetime.now(timezone.utc).isoformat(),
                "days": days
            },
            "daily_stats": [
                {
                    "date": stat.date.isoformat(),
                    "total_emails": stat.total_emails,
                    "flagged_emails": stat.flagged_emails,
                    "high_risk_emails": stat.high_risk_emails
                }
                for stat in daily_stats
            ],
            "threat_distribution": {
                threat.threat_type: threat.count
                for threat in threat_distribution
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting threat statistics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve threat statistics")


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            
            # Echo back for heartbeat
            await manager.send_personal_message(
                json.dumps({"type": "heartbeat", "timestamp": datetime.now(timezone.utc).isoformat()}),
                websocket
            )
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


async def broadcast_email_update(email_data: Dict[str, Any]):
    """Broadcast email update to all connected clients."""
    message = json.dumps({
        "type": "email_update",
        "data": email_data,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    await manager.broadcast(message)


async def broadcast_threat_alert(threat_data: Dict[str, Any]):
    """Broadcast threat alert to all connected clients."""
    message = json.dumps({
        "type": "threat_alert",
        "data": threat_data,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    await manager.broadcast(message)


# Legacy endpoints for backward compatibility
@router.get("/stats")
async def get_dashboard_stats(
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get dashboard statistics for the specified number of days."""
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    
    # Total emails analyzed
    total_emails = db.query(func.count(Email.id)).filter(
        Email.created_at >= start_date
    ).scalar()
    
    # Phishing emails detected
    phishing_count = db.query(func.count(Detection.id)).join(Email).filter(
        and_(
            Email.created_at >= start_date,
            Detection.threat_type == "phishing"
        )
    ).scalar()
    
    # Spam emails detected
    spam_count = db.query(func.count(Detection.id)).join(Email).filter(
        and_(
            Email.created_at >= start_date,
            Detection.threat_type == "spam"
        )
    ).scalar()
    
    # Malware emails detected
    malware_count = db.query(func.count(Detection.id)).join(Email).filter(
        and_(
            Email.created_at >= start_date,
            Detection.threat_type == "malware"
        )
    ).scalar()
    
    # Daily breakdown
    daily_stats = db.query(
        func.date(Email.created_at).label('date'),
        func.count(Email.id).label('total'),
        func.count(Detection.id).label('threats')
    ).outerjoin(Detection).filter(
        Email.created_at >= start_date
    ).group_by(func.date(Email.created_at)).all()
    
    return {
        "period": {
            "start": start_date.isoformat(),
            "end": end_date.isoformat(),
            "days": days
        },
        "summary": {
            "total_emails": total_emails or 0,
            "phishing_detected": phishing_count or 0,
            "spam_detected": spam_count or 0,
            "malware_detected": malware_count or 0,
            "clean_emails": (total_emails or 0) - (phishing_count or 0) - (spam_count or 0) - (malware_count or 0)
        },
        "daily_breakdown": [
            {
                "date": stat.date.isoformat(),
                "total_emails": stat.total,
                "threats_detected": stat.threats or 0
            }
            for stat in daily_stats
        ]
    }
