"""Production API endpoints with MongoDB persistence."""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPBearer
from pydantic import BaseModel, EmailStr

from app.db.production_persistence import (
    get_production_db, 
    get_persistent_sessions, 
    get_email_persistence,
    production_db_manager
)
from app.repositories.production_repositories import (
    get_user_repo,
    get_email_analysis_repo,
    get_threat_intel_repo,
    get_analysis_job_repo,
    get_audit_log_repo
)
from app.services.production_gmail_oauth import production_gmail_oauth_service
from app.core.production_oauth_security import production_oauth_security_manager

router = APIRouter(prefix="/api/v1/production", tags=["production"])
security = HTTPBearer()

# Pydantic models for requests/responses
class UserCreateRequest(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    password: str

class EmailAnalysisResponse(BaseModel):
    id: str
    gmail_message_id: str
    subject: str
    sender: str
    threat_level: Optional[str]
    confidence_score: Optional[float]
    status: str
    analyzed_at: Optional[datetime]
    created_at: datetime

class ThreatStatisticsResponse(BaseModel):
    total_emails_analyzed: int
    recent_activity_7_days: int
    threat_level_breakdown: List[Dict[str, Any]]
    query_timestamp: str

class DatabaseHealthResponse(BaseModel):
    status: str
    ping_ms: Optional[float]
    database: str
    collections: int
    data_size_mb: float
    storage_size_mb: float
    indexes: int

# User Management Endpoints

@router.post("/users/create")
async def create_user_production(
    user_data: UserCreateRequest,
    request: Request,
    user_repo = Depends(get_user_repo),
    audit_repo = Depends(get_audit_log_repo)
):
    """Create a new user with production validation."""
    try:
        # Hash password
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        hashed_password = pwd_context.hash(user_data.password)
        
        # Create user
        user_dict = {
            "email": user_data.email,
            "username": user_data.username,
            "full_name": user_data.full_name,
            "hashed_password": hashed_password,
            "is_active": True,
            "is_verified": False
        }
        
        user = await user_repo.create_user(user_dict)
        
        # Log user creation
        await audit_repo.log_event({
            "event_type": "user_creation",
            "user_id": str(user.id),
            "action": "user_created",
            "description": f"User {user.username} created successfully",
            "ip_address": request.client.host if request.client else "unknown",
            "metadata": {
                "email": user.email,
                "username": user.username
            }
        })
        
        return {
            "success": True,
            "user_id": str(user.id),
            "username": user.username,
            "email": user.email,
            "created_at": user.created_at
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

@router.get("/users/{user_id}")
async def get_user_production(
    user_id: str,
    user_repo = Depends(get_user_repo)
):
    """Get user by ID with production security."""
    try:
        user = await user_repo.get_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "created_at": user.created_at,
            "has_gmail_tokens": bool(user.gmail_access_token)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get user: {str(e)}")

# OAuth Endpoints

@router.post("/oauth/gmail/authorize")
async def gmail_oauth_authorize_production(
    user_id: str,
    request: Request,
    audit_repo = Depends(get_audit_log_repo)
):
    """Initiate Gmail OAuth with production security."""
    try:
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Check rate limiting
        if not production_oauth_security_manager.check_rate_limit(
            f"oauth_start:{client_ip}", 3, 60
        ):
            production_oauth_security_manager.record_failed_attempt(f"oauth_start:{client_ip}")
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        # Generate OAuth URL
        oauth_result = await production_gmail_oauth_service.generate_auth_url_production(
            user_id=user_id,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return {
            "success": True,
            "auth_url": oauth_result["auth_url"],
            "state": oauth_result["state"],
            "expires_in": oauth_result["expires_in"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        # Log the error
        await audit_repo.log_event({
            "event_type": "oauth_error",
            "action": "authorize_failed",
            "description": f"OAuth authorization failed: {str(e)}",
            "ip_address": request.client.host if request.client else "unknown",
            "metadata": {"error": str(e), "user_id": user_id}
        })
        
        raise HTTPException(status_code=500, detail=f"OAuth authorization failed: {str(e)}")

@router.post("/oauth/gmail/callback")
async def gmail_oauth_callback_production(
    code: str,
    state: str,
    request: Request
):
    """Handle Gmail OAuth callback with production security."""
    try:
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Exchange code for tokens
        token_result = await production_gmail_oauth_service.exchange_code_for_tokens_production(
            code=code,
            state=state,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return {
            "success": True,
            "user_id": token_result["user_id"],
            "token_type": token_result["token_type"],
            "expires_in": token_result["expires_in"],
            "scope": token_result["scope"]
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OAuth callback failed: {str(e)}")

@router.post("/oauth/gmail/{user_id}/refresh")
async def refresh_gmail_tokens_production(
    user_id: str,
    request: Request
):
    """Refresh Gmail OAuth tokens with production security."""
    try:
        result = await production_gmail_oauth_service.refresh_access_token_production(user_id)
        
        if not result:
            raise HTTPException(status_code=404, detail="No refresh token found or refresh failed")
        
        return {
            "success": True,
            "expires_in": result["expires_in"],
            "token_type": result["token_type"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token refresh failed: {str(e)}")

@router.delete("/oauth/gmail/{user_id}/revoke")
async def revoke_gmail_tokens_production(
    user_id: str,
    request: Request
):
    """Revoke Gmail OAuth tokens with production security."""
    try:
        success = await production_gmail_oauth_service.revoke_tokens_production(user_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="No tokens found to revoke")
        
        return {"success": True, "message": "Tokens revoked successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token revocation failed: {str(e)}")

# Email Analysis Endpoints

@router.get("/emails/{user_id}/analyses", response_model=List[EmailAnalysisResponse])
async def get_user_email_analyses_production(
    user_id: str,
    limit: int = 50,
    skip: int = 0,
    email_repo = Depends(get_email_analysis_repo)
):
    """Get email analyses for a user with production pagination."""
    try:
        analyses = await email_repo.get_user_analyses(user_id, limit, skip)
        
        return [
            EmailAnalysisResponse(
                id=str(analysis.id),
                gmail_message_id=analysis.gmail_message_id,
                subject=analysis.subject,
                sender=analysis.sender,
                threat_level=analysis.threat_level,
                confidence_score=analysis.confidence_score,
                status=analysis.status,
                analyzed_at=analysis.analyzed_at,
                created_at=analysis.created_at
            )
            for analysis in analyses
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get email analyses: {str(e)}")

@router.get("/emails/{user_id}/statistics", response_model=ThreatStatisticsResponse)
async def get_threat_statistics_production(
    user_id: str,
    email_repo = Depends(get_email_analysis_repo)
):
    """Get threat statistics for a user with production analytics."""
    try:
        stats = await email_repo.get_threat_statistics(user_id)
        
        return ThreatStatisticsResponse(
            total_emails_analyzed=stats.get("total_analyses", 0),
            recent_activity_7_days=stats.get("recent_analyses_7_days", 0),
            threat_level_breakdown=stats.get("threat_breakdown", []),
            query_timestamp=stats.get("query_timestamp", datetime.now(timezone.utc).isoformat())
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat statistics: {str(e)}")

@router.post("/emails/analyze")
async def store_email_analysis_production(
    analysis_data: Dict[str, Any],
    request: Request,
    email_repo = Depends(get_email_analysis_repo),
    audit_repo = Depends(get_audit_log_repo)
):
    """Store email analysis with production validation."""
    try:
        # Validate required fields
        required_fields = ["user_id", "gmail_message_id", "subject", "sender", "recipient"]
        for field in required_fields:
            if field not in analysis_data:
                raise ValueError(f"Missing required field: {field}")
        
        # Add metadata
        analysis_data["status"] = "completed"
        analysis_data["analyzer_version"] = "2.0.0"
        analysis_data["received_at"] = datetime.now(timezone.utc)
        
        # Store analysis
        analysis = await email_repo.create_or_update_analysis(analysis_data)
        
        # Log analysis storage
        await audit_repo.log_event({
            "event_type": "email_analysis",
            "user_id": analysis_data["user_id"],
            "action": "analysis_stored",
            "description": f"Email analysis stored for message {analysis_data['gmail_message_id']}",
            "ip_address": request.client.host if request.client else "unknown",
            "metadata": {
                "gmail_message_id": analysis_data["gmail_message_id"],
                "threat_level": analysis_data.get("threat_level"),
                "confidence_score": analysis_data.get("confidence_score")
            }
        })
        
        return {
            "success": True,
            "analysis_id": str(analysis.id),
            "gmail_message_id": analysis.gmail_message_id,
            "threat_level": analysis.threat_level,
            "confidence_score": analysis.confidence_score
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store email analysis: {str(e)}")

# Database Management Endpoints

@router.get("/database/health", response_model=DatabaseHealthResponse)
async def get_database_health_production(
    db_manager = Depends(get_production_db)
):
    """Get database health status with production metrics."""
    try:
        health_data = await db_manager.health_check()
        
        if health_data["status"] == "healthy":
            return DatabaseHealthResponse(
                status=health_data["status"],
                ping_ms=health_data.get("ping_ms"),
                database=health_data["database"],
                collections=health_data["collections"],
                data_size_mb=health_data["data_size_mb"],
                storage_size_mb=health_data["storage_size_mb"],
                indexes=health_data["indexes"]
            )
        else:
            raise HTTPException(status_code=503, detail=f"Database unhealthy: {health_data.get('error')}")
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@router.get("/database/collections/stats")
async def get_collection_statistics_production(
    db_manager = Depends(get_production_db)
):
    """Get collection statistics with production metrics."""
    try:
        stats = await db_manager.get_collection_stats()
        return {"success": True, "statistics": stats}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get collection stats: {str(e)}")

@router.post("/database/maintenance/cleanup")
async def perform_database_cleanup_production(
    request: Request,
    persistent_sessions = Depends(get_persistent_sessions),
    threat_repo = Depends(get_threat_intel_repo),
    audit_repo = Depends(get_audit_log_repo)
):
    """Perform database cleanup with production safety."""
    try:
        cleanup_results = {}
        
        # Clean up expired sessions
        expired_sessions = await persistent_sessions.cleanup_expired_sessions()
        cleanup_results["expired_sessions"] = expired_sessions
        
        # Clean up expired threat intelligence
        expired_threats = await threat_repo.cleanup_expired_threats()
        cleanup_results["expired_threats"] = expired_threats
        
        # Clean up old audit logs (keep 90 days)
        old_logs = await audit_repo.cleanup_old_logs(90)
        cleanup_results["old_audit_logs"] = old_logs
        
        # Log cleanup operation
        await audit_repo.log_event({
            "event_type": "database_maintenance",
            "action": "cleanup_performed",
            "description": "Database cleanup completed successfully",
            "ip_address": request.client.host if request.client else "unknown",
            "metadata": cleanup_results
        })
        
        return {
            "success": True,
            "cleanup_results": cleanup_results,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database cleanup failed: {str(e)}")

# Session Management Endpoints

@router.get("/sessions/{user_id}")
async def get_user_sessions_production(
    user_id: str,
    persistent_sessions = Depends(get_persistent_sessions)
):
    """Get active sessions for a user with production security."""
    try:
        sessions = await persistent_sessions.get_user_sessions(user_id)
        
        # Remove sensitive data
        safe_sessions = []
        for session in sessions:
            safe_sessions.append({
                "session_id": session.get("session_id"),
                "created_at": session.get("created_at"),
                "last_accessed": session.get("last_accessed"),
                "expires_at": session.get("expires_at"),
                "ip_address": session.get("ip_address"),
                "active": session.get("active")
            })
        
        return {"success": True, "sessions": safe_sessions}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get user sessions: {str(e)}")

# Audit Log Endpoints

@router.get("/audit/{user_id}/events")
async def get_user_audit_events_production(
    user_id: str,
    limit: int = 100,
    audit_repo = Depends(get_audit_log_repo)
):
    """Get audit events for a user with production security."""
    try:
        events = await audit_repo.get_user_events(user_id, limit)
        
        return {
            "success": True,
            "events": [
                {
                    "event_type": event.event_type,
                    "action": event.action,
                    "description": event.description,
                    "timestamp": event.timestamp,
                    "ip_address": event.ip_address,
                    "metadata": event.metadata
                }
                for event in events
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get audit events: {str(e)}")

# Add security headers to all responses
@router.middleware("http")
async def add_security_headers_production(request: Request, call_next):
    """Add production security headers to all responses."""
    response = await call_next(request)
    
    # Get security headers from OAuth manager
    security_headers = production_oauth_security_manager.get_security_headers()
    
    for header, value in security_headers.items():
        response.headers[header] = value
    
    return response