"""Enhanced API endpoints for production-ready PhishNet system."""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import json

from fastapi import APIRouter, Depends, HTTPException, status, Request, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db
from app.core.auth import get_current_user, TokenPayload
from app.models.email_scan import (
    EmailScanRequest, ThreatResult, QuarantineAction, 
    UserConsent, AuditLog, ScanStatus, ThreatLevel
)
from app.models.user import User
from app.services.gmail_secure import gmail_service
from app.services.quarantine_manager import quarantine_manager, policy_engine
from app.services.gdpr_compliance import gdpr_manager
from app.services.websocket_manager import websocket_manager, websocket_endpoint

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["phishnet-v1"])
security = HTTPBearer()


# Pydantic models for API
class OAuthInitRequest(BaseModel):
    """OAuth initialization request."""
    scopes: Optional[List[str]] = None
    redirect_uri: Optional[str] = None


class OAuthCallbackRequest(BaseModel):
    """OAuth callback request."""
    code: str
    state: str
    csrf_token: Optional[str] = None


class QuarantineActionRequest(BaseModel):
    """Quarantine action request."""
    action_type: str = Field(..., description="Action type: quarantine, approve, label")
    scan_request_id: str = Field(..., description="Scan request ID")


class DataDeletionRequest(BaseModel):
    """Data deletion request."""
    deletion_type: str = Field(default="complete", description="complete, partial, specific")
    specific_data_types: Optional[List[str]] = None
    confirmation: bool = Field(..., description="User confirmation")


class ConsentUpdateRequest(BaseModel):
    """Consent update request."""
    consent_type: str
    granted: bool
    purposes: Optional[List[str]] = None


# OAuth Endpoints
@router.post("/auth/gmail/init")
async def init_gmail_oauth(
    request: Request,
    oauth_request: OAuthInitRequest,
    current_user: TokenPayload = Depends(get_current_user)
):
    """Initialize Gmail OAuth flow with enhanced security."""
    try:
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "unknown")
        
        redirect_uri = oauth_request.redirect_uri or f"{settings.BASE_URL}/api/v1/auth/gmail/callback"
        scopes = oauth_request.scopes or [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.modify"
        ]
        
        # Generate OAuth URL
        oauth_url, csrf_token = await gmail_service.generate_oauth_url(
            user_id=current_user.sub,
            redirect_uri=redirect_uri
        )
        
        logger.info(f"Gmail OAuth initialized for user {current_user.sub}")
        
        return {
            "authorization_url": oauth_url,
            "csrf_token": csrf_token,
            "scopes": scopes,
            "expires_in": 300  # 5 minutes
        }
        
    except Exception as e:
        logger.error(f"Gmail OAuth init failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth initialization failed"
        )


@router.get("/auth/gmail/callback")
async def gmail_oauth_callback(
    request: Request,
    code: str,
    state: str,
    csrf_token: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Handle Gmail OAuth callback with security validation."""
    try:
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Extract user ID from state (done in gmail_service)
        import base64
        state_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
        user_id = state_data["user_id"]
        
        # Handle OAuth callback
        result = await gmail_service.handle_oauth_callback(
            code=code,
            state=state,
            user_id=user_id,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        if result["success"]:
            # Record consent
            await gdpr_manager.handle_consent_granted(
                user_id=user_id,
                consent_type="gmail_scanning",
                scopes=result["scopes"],
                purposes=["email_threat_analysis", "phishing_detection"],
                ip_address=client_ip,
                user_agent=user_agent
            )
            
            return {
                "message": "Gmail OAuth completed successfully",
                "gmail_address": result["gmail_address"],
                "scopes": result["scopes"],
                "watch_enabled": result["watch_enabled"]
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OAuth callback failed"
            )
            
    except Exception as e:
        logger.error(f"Gmail OAuth callback error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth callback failed: {str(e)}"
        )


@router.delete("/auth/gmail/revoke")
async def revoke_gmail_access(
    request: Request,
    current_user: TokenPayload = Depends(get_current_user)
):
    """Revoke Gmail access and clean up data."""
    try:
        client_ip = request.client.host
        
        # Revoke access
        success = await gmail_service.revoke_access(
            user_id=current_user.sub,
            ip_address=client_ip
        )
        
        if success:
            # Handle consent revocation
            await gdpr_manager.handle_consent_revoked(
                user_id=current_user.sub,
                consent_type="gmail_scanning",
                ip_address=client_ip
            )
            
            return {"message": "Gmail access revoked successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to revoke access"
            )
            
    except Exception as e:
        logger.error(f"Gmail revoke failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Access revocation failed"
        )


# Email Scanning Endpoints
@router.get("/scans")
async def get_email_scans(
    limit: int = 50,
    offset: int = 0,
    status_filter: Optional[str] = None,
    threat_level_filter: Optional[str] = None,
    current_user: TokenPayload = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get email scan history for user."""
    try:
        query = db.query(EmailScanRequest).filter(
            EmailScanRequest.user_id == current_user.sub
        )
        
        # Apply filters
        if status_filter:
            query = query.filter(EmailScanRequest.status == status_filter)
        
        if threat_level_filter:
            query = query.join(ThreatResult).filter(
                ThreatResult.threat_level == threat_level_filter
            )
        
        # Get results with pagination
        scans = query.order_by(
            EmailScanRequest.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        # Format results
        results = []
        for scan in scans:
            scan_data = {
                "id": str(scan.id),
                "gmail_message_id": scan.gmail_message_id,
                "sender_domain": scan.sender_domain,
                "status": scan.status,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "threat_result": None
            }
            
            if scan.threat_result:
                scan_data["threat_result"] = {
                    "threat_level": scan.threat_result.threat_level,
                    "threat_score": scan.threat_result.threat_score,
                    "confidence": scan.threat_result.confidence,
                    "explanation": scan.threat_result.explanation,
                    "recommendations": scan.threat_result.recommendations,
                    "phishing_indicators": scan.threat_result.phishing_indicators
                }
            
            results.append(scan_data)
        
        return {
            "scans": results,
            "total": len(results),
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Failed to get email scans for user {current_user.sub}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve email scans"
        )


@router.get("/scans/{scan_id}")
async def get_scan_details(
    scan_id: str,
    current_user: TokenPayload = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed scan results."""
    try:
        scan = db.query(EmailScanRequest).filter(
            EmailScanRequest.id == scan_id,
            EmailScanRequest.user_id == current_user.sub
        ).first()
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        
        result = {
            "id": str(scan.id),
            "gmail_message_id": scan.gmail_message_id,
            "sender_domain": scan.sender_domain,
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "threat_result": None,
            "component_results": [],
            "quarantine_actions": []
        }
        
        # Add threat result details
        if scan.threat_result:
            result["threat_result"] = {
                "threat_level": scan.threat_result.threat_level,
                "threat_score": scan.threat_result.threat_score,
                "confidence": scan.threat_result.confidence,
                "explanation": scan.threat_result.explanation,
                "recommendations": scan.threat_result.recommendations,
                "phishing_indicators": scan.threat_result.phishing_indicators,
                "malicious_links": scan.threat_result.malicious_links,
                "analysis_duration": scan.threat_result.analysis_duration_seconds,
                "component_scores": {
                    "link_analysis": scan.threat_result.link_analysis_score,
                    "content_analysis": scan.threat_result.content_analysis_score,
                    "sender_reputation": scan.threat_result.sender_reputation_score,
                    "llm_analysis": scan.threat_result.llm_analysis_score
                }
            }
            
            # Add component results
            for component in scan.threat_result.component_results:
                result["component_results"].append({
                    "component_name": component.component_name,
                    "verdict": component.verdict,
                    "score": component.score,
                    "confidence": component.confidence,
                    "findings": component.findings,
                    "indicators": component.indicators,
                    "execution_time_ms": component.execution_time_ms
                })
        
        # Add quarantine actions
        quarantine_actions = db.query(QuarantineAction).filter(
            QuarantineAction.scan_request_id == scan.id
        ).all()
        
        for action in quarantine_actions:
            result["quarantine_actions"].append({
                "action_type": action.action_type,
                "action_method": action.action_method,
                "successful": action.gmail_action_successful,
                "requested_at": action.requested_at.isoformat() if action.requested_at else None,
                "executed_at": action.executed_at.isoformat() if action.executed_at else None,
                "policy_rule": action.policy_rule
            })
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan details {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan details"
        )


# Quarantine Management Endpoints
@router.post("/quarantine/action")
async def execute_quarantine_action(
    action_request: QuarantineActionRequest,
    current_user: TokenPayload = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Execute manual quarantine action."""
    try:
        # Validate scan belongs to user
        scan = db.query(EmailScanRequest).filter(
            EmailScanRequest.id == action_request.scan_request_id,
            EmailScanRequest.user_id == current_user.sub
        ).first()
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        
        # Queue manual action
        success = await quarantine_manager.queue_manual_action(
            scan_request_id=action_request.scan_request_id,
            user_id=current_user.sub,
            action_type=action_request.action_type,
            user_override=True
        )
        
        if success:
            return {
                "message": f"{action_request.action_type.title()} action queued successfully",
                "scan_id": action_request.scan_request_id,
                "action_type": action_request.action_type
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to queue action"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Quarantine action failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Action execution failed"
        )


@router.get("/quarantine/stats")
async def get_quarantine_stats(
    current_user: TokenPayload = Depends(get_current_user)
):
    """Get quarantine statistics for user."""
    try:
        stats = await quarantine_manager.get_quarantine_stats(current_user.sub)
        return stats
        
    except Exception as e:
        logger.error(f"Failed to get quarantine stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve quarantine statistics"
        )


# GDPR and Privacy Endpoints
@router.get("/privacy/consents")
async def get_user_consents(
    current_user: TokenPayload = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's consent records."""
    try:
        consents = db.query(UserConsent).filter(
            UserConsent.user_id == current_user.sub
        ).all()
        
        return {
            "consents": [
                {
                    "consent_type": consent.consent_type,
                    "granted": consent.granted,
                    "scopes": consent.scopes,
                    "purposes": consent.purposes,
                    "granted_at": consent.granted_at.isoformat() if consent.granted_at else None,
                    "revoked_at": consent.revoked_at.isoformat() if consent.revoked_at else None,
                    "expires_at": consent.expires_at.isoformat() if consent.expires_at else None
                }
                for consent in consents
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get consents: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve consent information"
        )


@router.post("/privacy/consents")
async def update_consent(
    request: Request,
    consent_request: ConsentUpdateRequest,
    current_user: TokenPayload = Depends(get_current_user)
):
    """Update user consent."""
    try:
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "unknown")
        
        if consent_request.granted:
            success = await gdpr_manager.handle_consent_granted(
                user_id=current_user.sub,
                consent_type=consent_request.consent_type,
                scopes=["gmail_scanning"],
                purposes=consent_request.purposes or ["email_threat_analysis"],
                ip_address=client_ip,
                user_agent=user_agent
            )
        else:
            success = await gdpr_manager.handle_consent_revoked(
                user_id=current_user.sub,
                consent_type=consent_request.consent_type,
                ip_address=client_ip,
                user_agent=user_agent
            )
        
        if success:
            return {
                "message": f"Consent {'granted' if consent_request.granted else 'revoked'} successfully",
                "consent_type": consent_request.consent_type,
                "granted": consent_request.granted
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update consent"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Consent update failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Consent update failed"
        )


@router.get("/privacy/export")
async def export_user_data(
    request: Request,
    current_user: TokenPayload = Depends(get_current_user)
):
    """Export user data (GDPR Right to Data Portability)."""
    try:
        client_ip = request.client.host
        
        export_data = await gdpr_manager.export_user_data(
            user_id=current_user.sub,
            ip_address=client_ip
        )
        
        return export_data
        
    except Exception as e:
        logger.error(f"Data export failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Data export failed"
        )


@router.post("/privacy/delete")
async def request_data_deletion(
    request: Request,
    deletion_request: DataDeletionRequest,
    current_user: TokenPayload = Depends(get_current_user)
):
    """Request data deletion (GDPR Right to Erasure)."""
    try:
        if not deletion_request.confirmation:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Data deletion requires explicit confirmation"
            )
        
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "unknown")
        
        result = await gdpr_manager.handle_data_deletion_request(
            user_id=current_user.sub,
            deletion_type=deletion_request.deletion_type,
            specific_data_types=deletion_request.specific_data_types,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Data deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Data deletion request failed"
        )


# WebSocket Endpoint
@router.websocket("/ws/{user_id}")
async def websocket_connection(websocket: WebSocket, user_id: int):
    """WebSocket endpoint for real-time updates."""
    await websocket_endpoint(websocket, user_id)


# Dashboard Endpoints
@router.get("/dashboard/stats")
async def get_dashboard_stats(
    current_user: TokenPayload = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics for user."""
    try:
        # Get scan statistics
        total_scans = db.query(EmailScanRequest).filter(
            EmailScanRequest.user_id == current_user.sub
        ).count()
        
        recent_scans = db.query(EmailScanRequest).filter(
            EmailScanRequest.user_id == current_user.sub,
            EmailScanRequest.created_at >= datetime.utcnow() - timedelta(days=30)
        ).count()
        
        # Get threat level distribution
        threat_levels = db.query(ThreatResult.threat_level, db.func.count(ThreatResult.id)).join(
            EmailScanRequest
        ).filter(
            EmailScanRequest.user_id == current_user.sub
        ).group_by(ThreatResult.threat_level).all()
        
        threat_distribution = {level: count for level, count in threat_levels}
        
        # Get recent high-threat emails
        high_threat_scans = db.query(EmailScanRequest).join(ThreatResult).filter(
            EmailScanRequest.user_id == current_user.sub,
            ThreatResult.threat_level.in_([ThreatLevel.HIGH, ThreatLevel.CRITICAL])
        ).order_by(EmailScanRequest.created_at.desc()).limit(10).all()
        
        recent_threats = []
        for scan in high_threat_scans:
            recent_threats.append({
                "id": str(scan.id),
                "sender_domain": scan.sender_domain,
                "threat_level": scan.threat_result.threat_level,
                "threat_score": scan.threat_result.threat_score,
                "created_at": scan.created_at.isoformat() if scan.created_at else None
            })
        
        # Get quarantine statistics
        quarantine_stats = await quarantine_manager.get_quarantine_stats(current_user.sub)
        
        return {
            "scan_stats": {
                "total_scans": total_scans,
                "recent_scans": recent_scans,
                "threat_distribution": threat_distribution
            },
            "recent_threats": recent_threats,
            "quarantine_stats": quarantine_stats,
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Dashboard stats failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard statistics"
        )


# System Status Endpoints
@router.get("/status")
async def get_system_status():
    """Get system status and health."""
    try:
        # Check WebSocket connections
        ws_stats = websocket_manager.get_connection_stats()
        
        # Check quarantine queue health
        from app.core.redis_client import redis_client
        email_queue_length = await redis_client.llen("email_processing_queue")
        threat_queue_length = await redis_client.llen("threat_analysis_queue")
        quarantine_queue_length = await redis_client.llen("quarantine_actions_queue")
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "websocket_stats": ws_stats,
            "queue_stats": {
                "email_processing": email_queue_length,
                "threat_analysis": threat_queue_length,
                "quarantine_actions": quarantine_queue_length
            },
            "version": "2.0.0"
        }
        
    except Exception as e:
        logger.error(f"System status check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
