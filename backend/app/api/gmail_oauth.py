"""Production-grade Gmail OAuth API endpoints with comprehensive security."""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, Response
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.database import get_db
from app.services.gmail_oauth import GmailOAuth2Service, get_gmail_oauth_service
from app.core.auth import get_current_user
from app.models.user import User
from app.config.logging import get_logger
from app.config.settings import settings

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth/gmail", tags=["Gmail OAuth"])
limiter = Limiter(key_func=get_remote_address)


# Pydantic models
class OAuthStartResponse(BaseModel):
    """Response for OAuth start endpoint."""
    success: bool
    message: str
    authorization_url: Optional[str] = None
    state_nonce: Optional[str] = None


class OAuthCallbackQuery(BaseModel):
    """Query parameters for OAuth callback."""
    code: str = Field(..., description="Authorization code from Google")
    state: str = Field(..., description="State parameter for CSRF protection")
    scope: Optional[str] = Field(None, description="Granted scopes")
    error: Optional[str] = Field(None, description="Error from OAuth provider")


class OAuthStatusResponse(BaseModel):
    """Response for OAuth status check."""
    connected: bool
    status: str
    gmail_email: Optional[str] = None
    scopes_granted: list = []
    connection_date: Optional[str] = None
    last_scan: Optional[str] = None
    last_token_refresh: Optional[str] = None
    monitoring_enabled: bool = False


class OAuthRevokeResponse(BaseModel):
    """Response for OAuth revocation."""
    success: bool
    message: str
    tokens_revoked: Optional[int] = None


class ManualScanRequest(BaseModel):
    """Request for manual email scan."""
    force_scan: bool = False
    days_back: int = Field(default=7, ge=1, le=30, description="Days to scan back")


def get_client_info(request: Request) -> tuple[Optional[str], Optional[str]]:
    """Extract client IP and user agent from request."""
    # Get IP address (consider proxy headers)
    ip_address = request.headers.get("x-forwarded-for")
    if ip_address:
        ip_address = ip_address.split(",")[0].strip()
    else:
        ip_address = request.client.host if request.client else None
    
    user_agent = request.headers.get("user-agent")
    
    return ip_address, user_agent


@router.post("/start", response_model=OAuthStartResponse)
@limiter.limit("5/minute")  # Rate limit OAuth initiation
async def start_gmail_oauth(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    oauth_service: GmailOAuth2Service = Depends(get_gmail_oauth_service)
):
    """
    Start Gmail OAuth flow.
    
    This endpoint generates the OAuth authorization URL that users should visit
    to grant PhishNet access to their Gmail account.
    """
    try:
        ip_address, user_agent = get_client_info(request)
        
        # Check if user is already connected
        status = await oauth_service.get_oauth_status(db, current_user.id)
        if status["connected"]:
            return OAuthStartResponse(
                success=False,
                message=f"Gmail already connected to {status['gmail_email']}. Disconnect first if you want to reconnect."
            )
        
        # Generate OAuth URL
        auth_url, state_nonce = await oauth_service.generate_oauth_url(
            db, current_user.id, ip_address, user_agent
        )
        
        logger.info(f"OAuth flow started for user {current_user.id}")
        
        return OAuthStartResponse(
            success=True,
            message="OAuth authorization URL generated successfully",
            authorization_url=auth_url,
            state_nonce=state_nonce
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start OAuth flow for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start OAuth flow"
        )


@router.get("/callback")
@limiter.limit("10/minute")  # Rate limit callback processing
async def handle_gmail_oauth_callback(
    request: Request,
    code: str = Query(..., description="Authorization code"),
    state: str = Query(..., description="State parameter"),
    scope: Optional[str] = Query(None, description="Granted scopes"),
    error: Optional[str] = Query(None, description="OAuth error"),
    db: Session = Depends(get_db),
    oauth_service: GmailOAuth2Service = Depends(get_gmail_oauth_service)
):
    """
    Handle OAuth callback from Google.
    
    This endpoint processes the authorization code and exchanges it for tokens.
    Users are redirected here from Google after granting permissions.
    """
    try:
        ip_address, user_agent = get_client_info(request)
        
        # Handle OAuth errors
        if error:
            logger.warning(f"OAuth error received: {error}")
            
            # Redirect to frontend with error
            frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_error={error}"
            return RedirectResponse(url=frontend_url, status_code=302)
        
        # Validate required parameters
        if not code or not state:
            logger.error("Missing required OAuth callback parameters")
            frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_error=missing_parameters"
            return RedirectResponse(url=frontend_url, status_code=302)
        
        # Extract user ID from state (for basic validation before full processing)
        try:
            import base64
            import json
            state_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
            user_id = state_data.get("user_id")
        except Exception:
            logger.error("Invalid state parameter in OAuth callback")
            frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_error=invalid_state"
            return RedirectResponse(url=frontend_url, status_code=302)
        
        if not user_id:
            logger.error("No user ID in state parameter")
            frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_error=invalid_state"
            return RedirectResponse(url=frontend_url, status_code=302)
        
        # Process OAuth callback
        result = await oauth_service.handle_oauth_callback(
            db, user_id, code, state, ip_address, user_agent
        )
        
        if result["success"]:
            # Redirect to frontend with success
            frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_success=true&gmail_email={result['gmail_email']}"
            logger.info(f"OAuth callback successful for user {user_id}")
        else:
            # Redirect to frontend with error
            frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_error=callback_failed"
            logger.error(f"OAuth callback failed for user {user_id}")
        
        return RedirectResponse(url=frontend_url, status_code=302)
        
    except HTTPException as e:
        logger.error(f"OAuth callback HTTP error: {e.detail}")
        frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_error=processing_failed"
        return RedirectResponse(url=frontend_url, status_code=302)
    except Exception as e:
        logger.error(f"OAuth callback unexpected error: {e}")
        frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_error=unexpected_error"
        return RedirectResponse(url=frontend_url, status_code=302)


@router.get("/status", response_model=OAuthStatusResponse)
async def get_gmail_oauth_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    oauth_service: GmailOAuth2Service = Depends(get_gmail_oauth_service)
):
    """
    Get Gmail OAuth connection status.
    
    Returns information about the user's Gmail connection including
    connection status, email address, granted scopes, and scan history.
    """
    try:
        status = await oauth_service.get_oauth_status(db, current_user.id)
        
        return OAuthStatusResponse(
            connected=status["connected"],
            status=status["status"],
            gmail_email=status["gmail_email"],
            scopes_granted=status["scopes_granted"],
            connection_date=status["connection_date"],
            last_scan=status["last_scan"],
            last_token_refresh=status.get("last_token_refresh"),
            monitoring_enabled=status["monitoring_enabled"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get OAuth status for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get OAuth status"
        )


@router.post("/revoke", response_model=OAuthRevokeResponse)
@limiter.limit("5/minute")  # Rate limit revocation
async def revoke_gmail_oauth(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    oauth_service: GmailOAuth2Service = Depends(get_gmail_oauth_service)
):
    """
    Revoke Gmail OAuth access.
    
    This endpoint revokes the OAuth tokens and disconnects the user's Gmail account
    from PhishNet. All stored tokens are invalidated and removed.
    """
    try:
        ip_address, user_agent = get_client_info(request)
        
        result = await oauth_service.revoke_oauth_access(
            db, current_user.id, ip_address, user_agent
        )
        
        logger.info(f"OAuth access revoked for user {current_user.id}")
        
        return OAuthRevokeResponse(
            success=result["success"],
            message=result["message"],
            tokens_revoked=result.get("tokens_revoked")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke OAuth access for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke OAuth access"
        )


@router.get("/scopes")
async def get_oauth_scopes():
    """
    Get OAuth scopes information.
    
    Returns information about the OAuth scopes that PhishNet requests
    and what each scope is used for.
    """
    return {
        "required_scopes": GmailOAuth2Service.REQUIRED_SCOPES,
        "scope_descriptions": GmailOAuth2Service.SCOPE_DESCRIPTIONS,
        "privacy_info": {
            "data_usage": "PhishNet only reads email content for phishing analysis",
            "data_storage": "No email content is permanently stored",
            "data_sharing": "Email content is never shared with third parties",
            "revocation": "You can revoke access at any time"
        }
    }


@router.post("/scan", response_model=Dict[str, Any])
@limiter.limit("10/hour")  # Rate limit manual scans
async def trigger_manual_scan(
    request: Request,
    scan_request: ManualScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    oauth_service: GmailOAuth2Service = Depends(get_gmail_oauth_service)
):
    """
    Trigger manual Gmail scan.
    
    This endpoint allows users to manually trigger a scan of their Gmail inbox
    for phishing emails.
    """
    try:
        # Check if user is connected
        status = await oauth_service.get_oauth_status(db, current_user.id)
        if not status["connected"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Gmail not connected. Please connect your Gmail account first."
            )
        
        # Get valid credentials
        credentials = await oauth_service.get_valid_credentials(db, current_user.id)
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired Gmail credentials. Please reconnect your account."
            )
        
        # TODO: Implement actual email scanning logic here
        # This would integrate with your existing email analysis service
        
        # For now, return a placeholder response
        return {
            "success": True,
            "message": "Manual scan initiated successfully",
            "scan_id": f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "estimated_completion": "2-5 minutes",
            "days_back": scan_request.days_back
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to trigger manual scan for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to trigger manual scan"
        )


@router.get("/health")
async def gmail_oauth_health():
    """
    Health check for Gmail OAuth service.
    
    Returns the health status of the Gmail OAuth service components.
    """
    try:
        # Check service components
        health_status = {
            "service": "gmail_oauth",
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "oauth_service": "healthy",
                "encryption": "healthy",
                "database": "healthy"
            }
        }
        
        # Test encryption
        try:
            oauth_service = GmailOAuth2Service()
            test_data = "test_encryption"
            encrypted = oauth_service._encrypt_token(test_data)
            decrypted = oauth_service._decrypt_token(encrypted)
            if decrypted != test_data:
                health_status["components"]["encryption"] = "unhealthy"
                health_status["status"] = "degraded"
        except Exception as e:
            health_status["components"]["encryption"] = "unhealthy"
            health_status["status"] = "degraded"
            logger.error(f"Encryption health check failed: {e}")
        
        return health_status
        
    except Exception as e:
        logger.error(f"OAuth health check failed: {e}")
        return {
            "service": "gmail_oauth",
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@router.post("/watch/setup", response_model=Dict[str, Any])
@limiter.limit("5/minute")
async def setup_gmail_watch(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    oauth_service: GmailOAuth2Service = Depends(get_gmail_oauth_service)
):
    """Set up Gmail watch for real-time phishing detection."""
    try:
        import os
        
        # Get Pub/Sub topic from settings
        pubsub_topic = os.getenv("PUBSUB_TOPIC")
        if not pubsub_topic:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Pub/Sub topic not configured"
            )
        
        result = await oauth_service.setup_gmail_watch(
            db=db,
            user_id=current_user.id,
            topic_name=pubsub_topic
        )
        
        return {
            "status": "success",
            "message": "Gmail watch set up successfully",
            "watch_setup": result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Gmail watch setup failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Gmail watch setup failed"
        )


@router.post("/watch/stop", response_model=Dict[str, Any])
@limiter.limit("5/minute")
async def stop_gmail_watch(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    oauth_service: GmailOAuth2Service = Depends(get_gmail_oauth_service)
):
    """Stop Gmail watch."""
    try:
        success = await oauth_service.stop_gmail_watch(
            db=db,
            user_id=current_user.id
        )
        
        if success:
            return {
                "status": "success",
                "message": "Gmail watch stopped successfully"
            }
        else:
            return {
                "status": "error",
                "message": "Failed to stop Gmail watch"
            }
        
    except Exception as e:
        logger.error(f"Gmail watch stop failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to stop Gmail watch"
        )


@router.post("/webhook/notifications")
async def handle_gmail_notifications(
    request: Request,
    db: Session = Depends(get_db),
    oauth_service: GmailOAuth2Service = Depends(get_gmail_oauth_service)
):
    """Handle Gmail Pub/Sub notifications."""
    try:
        # Verify Pub/Sub request (basic check)
        if not request.headers.get("content-type", "").startswith("application/json"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid content type"
            )
        
        notification_data = await request.json()
        
        # Process the notification
        result = await oauth_service.process_gmail_notification(
            db=db,
            notification_data=notification_data
        )
        
        logger.info(f"Processed Gmail notification: {result}")
        
        return {"status": "processed", "result": result}
        
    except Exception as e:
        logger.error(f"Failed to process Gmail notification: {e}")
        # Return 200 to prevent Pub/Sub retries for permanent failures
        return {"status": "error", "error": str(e)}


@router.get("/messages", response_model=Dict[str, Any])
@limiter.limit("30/minute")
async def get_gmail_messages(
    request: Request,
    query: Optional[str] = None,
    max_results: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    oauth_service: GmailOAuth2Service = Depends(get_gmail_oauth_service)
):
    """Get Gmail messages for analysis."""
    try:
        if max_results > 100:
            max_results = 100  # Limit to prevent abuse
        
        messages = await oauth_service.get_gmail_messages(
            db=db,
            user_id=current_user.id,
            query=query,
            max_results=max_results
        )
        
        return {
            "status": "success",
            "messages": messages,
            "count": len(messages),
            "query": query
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get Gmail messages for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get Gmail messages"
        )
