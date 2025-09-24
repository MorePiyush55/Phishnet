"""Enhanced OAuth API endpoints with comprehensive security hardening."""

import time
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, Response
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.services.secure_gmail_oauth import secure_gmail_oauth_service
from app.core.oauth_security_hardened import oauth_security_manager
from app.config.logging import get_logger
from app.config.settings import settings

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth/secure", tags=["Secure OAuth"])
limiter = Limiter(key_func=get_remote_address)

# Pydantic models
class SecureOAuthStartRequest(BaseModel):
    """Request for starting secure OAuth flow."""
    scope_level: str = Field(default="minimal", description="Scope level: minimal or enhanced")
    remember_device: bool = Field(default=False, description="Remember this device")
    
class SecureOAuthStartResponse(BaseModel):
    """Response for OAuth start endpoint."""
    success: bool
    message: str
    authorization_url: Optional[str] = None
    state_token: Optional[str] = None
    session_id: Optional[str] = None
    security_level: str
    expires_in: int

class OAuthCallbackResponse(BaseModel):
    """Response for OAuth callback."""
    success: bool
    message: str
    user_info: Optional[Dict] = None
    session_token: Optional[str] = None
    scopes_granted: Optional[list] = None
    security_warnings: Optional[list] = None

class TokenValidationResponse(BaseModel):
    """Response for token validation."""
    valid: bool
    expires_in: Optional[int] = None
    needs_refresh: bool = False
    security_score: int
    recommendations: list = []

@router.post("/start", response_model=SecureOAuthStartResponse)
@limiter.limit("3/minute")  # Strict rate limiting for OAuth initiation
async def start_secure_oauth(
    request: Request,
    oauth_request: SecureOAuthStartRequest,
    user_id: str = Query(..., description="User identifier")
):
    """Start secure OAuth flow with enhanced security measures."""
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    try:
        # Security pre-checks
        if not oauth_security_manager.check_rate_limit(f"oauth_start:{client_ip}", 5, 3600):
            oauth_security_manager.record_failed_attempt(f"oauth_start:{client_ip}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many OAuth initiation attempts. Please try again later."
            )
        
        # Validate scope level
        if oauth_request.scope_level not in ["minimal", "enhanced"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid scope level. Must be 'minimal' or 'enhanced'."
            )
        
        # Create secure session
        session_token = oauth_security_manager.create_secure_session(
            user_id=user_id,
            ip_address=client_ip,
            user_agent=user_agent,
            additional_claims={
                "oauth_flow": True,
                "scope_level": oauth_request.scope_level,
                "remember_device": oauth_request.remember_device
            }
        )
        
        # Create authorization URL
        authorization_url, state_token = await secure_gmail_oauth_service.create_authorization_url(
            user_id=user_id,
            ip_address=client_ip,
            user_agent=user_agent,
            scope_level=oauth_request.scope_level
        )
        
        # Log successful initiation
        logger.info(
            f"Secure OAuth flow initiated for user {user_id} "
            f"from {client_ip} with {oauth_request.scope_level} scope"
        )
        
        response = SecureOAuthStartResponse(
            success=True,
            message="OAuth flow initiated successfully",
            authorization_url=authorization_url,
            state_token=state_token,
            session_id=session_token[:16] + "...",  # Partial session ID for logging
            security_level=oauth_request.scope_level,
            expires_in=600  # 10 minutes
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth initiation failed: {e}")
        oauth_security_manager.record_failed_attempt(f"oauth_start:{client_ip}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth flow initiation failed"
        )

@router.get("/callback")
@limiter.limit("10/minute")  # Rate limit callback processing
async def handle_secure_oauth_callback(
    request: Request,
    code: str = Query(..., description="Authorization code from Google"),
    state: str = Query(..., description="State parameter for security"),
    scope: Optional[str] = Query(None, description="Granted scopes"),
    error: Optional[str] = Query(None, description="Error from OAuth provider")
):
    """Handle OAuth callback with enhanced security validation."""
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    try:
        # Handle OAuth errors
        if error:
            logger.warning(f"OAuth callback error: {error} from {client_ip}")
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/auth/error?error={error}",
                status_code=302
            )
        
        # Validate required parameters
        if not code or not state:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing required OAuth parameters"
            )
        
        # Process callback with security validation
        result = await secure_gmail_oauth_service.handle_oauth_callback(
            code=code,
            state=state,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        if not result["success"]:
            logger.warning(f"OAuth callback failed for state {state} from {client_ip}")
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/auth/error?error=callback_failed",
                status_code=302
            )
        
        # Create secure session for authenticated user
        session_token = oauth_security_manager.create_secure_session(
            user_id=result["user_info"]["email"],
            ip_address=client_ip,
            user_agent=user_agent,
            additional_claims={
                "oauth_completed": True,
                "gmail_connected": True,
                "scopes": result["scopes_granted"]
            }
        )
        
        # Clear any failed attempts
        oauth_security_manager.clear_failed_attempts(f"oauth_callback:{client_ip}")
        
        # Success redirect with session token
        success_url = (
            f"{settings.FRONTEND_URL}/auth/success"
            f"?session_token={session_token}"
            f"&email={result['user_info']['email']}"
        )
        
        logger.info(
            f"OAuth callback successful for {result['user_info']['email']} "
            f"from {client_ip}"
        )
        
        return RedirectResponse(url=success_url, status_code=302)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth callback processing failed: {e}")
        oauth_security_manager.record_failed_attempt(f"oauth_callback:{client_ip}")
        return RedirectResponse(
            url=f"{settings.FRONTEND_URL}/auth/error?error=processing_failed",
            status_code=302
        )

@router.post("/validate-token", response_model=TokenValidationResponse)
@limiter.limit("30/minute")  # Moderate rate limiting for token validation
async def validate_oauth_token(
    request: Request,
    encrypted_tokens: str = Query(..., description="Encrypted OAuth tokens")
):
    """Validate OAuth tokens and provide security assessment."""
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    try:
        # Validate session context
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session token required for validation"
            )
        
        session_token = auth_header.split(" ")[1]
        session_data = oauth_security_manager.validate_session(
            session_token=session_token,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session"
            )
        
        # Validate tokens
        validation_result = await secure_gmail_oauth_service.validate_token_security(
            encrypted_tokens=encrypted_tokens
        )
        
        # Calculate security score
        security_score = 100
        recommendations = []
        
        if not validation_result["valid"]:
            security_score = 0
            recommendations.append("Tokens are invalid or corrupted")
        elif validation_result.get("needs_refresh"):
            security_score = 60
            recommendations.append("Tokens need refresh soon")
        
        # Check session security
        session_age = (datetime.utcnow() - datetime.fromisoformat(session_data["iat"])).total_seconds()
        if session_age > 3600:  # 1 hour
            security_score -= 20
            recommendations.append("Session is getting old, consider re-authentication")
        
        response = TokenValidationResponse(
            valid=validation_result["valid"],
            expires_in=validation_result.get("expires_in"),
            needs_refresh=validation_result.get("needs_refresh", False),
            security_score=max(0, security_score),
            recommendations=recommendations
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token validation failed"
        )

@router.post("/refresh-token")
@limiter.limit("10/minute")  # Rate limit token refresh
async def refresh_oauth_token(
    request: Request,
    encrypted_tokens: str = Query(..., description="Encrypted OAuth tokens")
):
    """Refresh OAuth tokens with security validation."""
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    try:
        # Validate session
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session token required"
            )
        
        session_token = auth_header.split(" ")[1]
        session_data = oauth_security_manager.validate_session(
            session_token=session_token,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session"
            )
        
        # Refresh tokens
        refresh_result = await secure_gmail_oauth_service.refresh_access_token(
            encrypted_tokens=encrypted_tokens
        )
        
        if not refresh_result["success"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token refresh failed"
            )
        
        logger.info(f"OAuth tokens refreshed for user from {client_ip}")
        
        return {
            "success": True,
            "message": "Tokens refreshed successfully",
            "encrypted_tokens": refresh_result["encrypted_tokens"],
            "expires_at": refresh_result["expires_at"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )

@router.post("/revoke")
@limiter.limit("5/minute")  # Rate limit revocation
async def revoke_oauth_tokens(
    request: Request,
    encrypted_tokens: str = Query(..., description="Encrypted OAuth tokens")
):
    """Revoke OAuth tokens and clean up session."""
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    try:
        # Validate session
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session_token = auth_header.split(" ")[1]
            oauth_security_manager.revoke_session(session_token)
        
        # Revoke tokens
        revocation_success = await secure_gmail_oauth_service.revoke_tokens(
            encrypted_tokens=encrypted_tokens
        )
        
        logger.info(f"OAuth tokens revoked from {client_ip}, success: {revocation_success}")
        
        return {
            "success": revocation_success,
            "message": "OAuth access revoked successfully" if revocation_success else "Revocation completed with warnings"
        }
        
    except Exception as e:
        logger.error(f"Token revocation failed: {e}")
        return {
            "success": False,
            "message": "Revocation completed with errors"
        }

@router.get("/security-status")
@limiter.limit("20/minute")
async def get_oauth_security_status(request: Request):
    """Get OAuth security status and recommendations."""
    
    client_ip = request.client.host if request.client else "unknown"
    
    try:
        # Check current security posture
        security_headers = oauth_security_manager.get_security_headers()
        
        # Cleanup expired sessions
        oauth_security_manager.cleanup_expired_sessions()
        
        # Rate limit status
        rate_limit_ok = oauth_security_manager.check_rate_limit(f"security_check:{client_ip}", 50, 3600)
        
        status_info = {
            "security_enabled": True,
            "rate_limiting_active": rate_limit_ok,
            "encryption_active": True,
            "session_management": "active",
            "security_headers": len(security_headers),
            "recommendations": [
                "Use HTTPS for all OAuth flows",
                "Regularly rotate client secrets",
                "Monitor for suspicious activity",
                "Keep tokens encrypted at rest"
            ]
        }
        
        return status_info
        
    except Exception as e:
        logger.error(f"Security status check failed: {e}")
        return {
            "security_enabled": False,
            "error": "Security status unavailable"
        }