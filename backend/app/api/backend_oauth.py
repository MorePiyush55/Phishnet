"""
Backend OAuth API endpoints for Render deployment
Implements secure OAuth flow with proper session management
"""

import logging
from typing import Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_db
from app.core.auth import get_current_user, get_current_user_optional
from app.services.backend_oauth import BackendOAuthService, get_backend_oauth_service
from app.models.user import User
from app.config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/auth", tags=["Backend OAuth"])


class OAuthStartResponse(BaseModel):
    """Response for OAuth start endpoint."""
    success: bool
    authorization_url: str
    session_id: str


class OAuthStatusResponse(BaseModel):
    """Response for OAuth status check."""
    connected: bool
    status: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    connected_at: Optional[datetime] = None
    scopes_granted: list = []


@router.get("/start", response_model=OAuthStartResponse)
async def start_oauth_flow(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
    oauth_service: BackendOAuthService = Depends(get_backend_oauth_service)
):
    """
    Start OAuth flow - GET /auth/start
    
    Generates secure state, PKCE values, and redirects to Google OAuth.
    Implements all security requirements for Render deployment.
    """
    try:
        user_id = current_user.id if current_user else None
        
        result = await oauth_service.generate_oauth_url(
            request=request,
            response=response,
            db=db,
            user_id=user_id
        )
        
        if result["success"]:
            # Redirect to Google OAuth URL
            return RedirectResponse(
                url=result["authorization_url"],
                status_code=status.HTTP_302_FOUND
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate OAuth URL"
            )
            
    except Exception as e:
        logger.error(f"OAuth start failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start OAuth flow"
        )


@router.get("/oauth2callback")
async def oauth_callback(
    request: Request,
    db: Session = Depends(get_db),
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    oauth_service: BackendOAuthService = Depends(get_backend_oauth_service)
):
    """
    OAuth callback handler - GET /oauth2callback
    
    Handles Google OAuth callback with comprehensive validation.
    Returns success page or redirects to frontend with results.
    """
    try:
        if not code or not state:
            return HTMLResponse(
                content=_generate_error_page("Invalid OAuth callback parameters"),
                status_code=400
            )
        
        result = await oauth_service.handle_oauth_callback(
            request=request,
            db=db,
            code=code,
            state=state,
            error=error
        )
        
        if result["success"]:
            # Redirect to frontend with success
            frontend_url = settings.FRONTEND_URL
            redirect_url = f"{frontend_url}/dashboard?oauth_success=true&email={result['email']}"
            
            return RedirectResponse(
                url=redirect_url,
                status_code=status.HTTP_302_FOUND
            )
        else:
            return HTMLResponse(
                content=_generate_error_page("OAuth flow failed"),
                status_code=400
            )
            
    except HTTPException as e:
        # Return user-friendly error page
        error_message = e.detail if hasattr(e, 'detail') else str(e)
        return HTMLResponse(
            content=_generate_error_page(error_message),
            status_code=e.status_code if hasattr(e, 'status_code') else 400
        )
    except Exception as e:
        logger.error(f"OAuth callback failed: {e}")
        return HTMLResponse(
            content=_generate_error_page("An unexpected error occurred"),
            status_code=500
        )


@router.post("/revoke")
async def revoke_oauth_access(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    oauth_service: BackendOAuthService = Depends(get_backend_oauth_service)
):
    """
    Revoke OAuth access - POST /auth/revoke
    
    Revokes tokens and cleans up user associations.
    Requires authentication.
    """
    try:
        success = await oauth_service.revoke_oauth_access(
            db=db,
            user_id=current_user.id,
            request=request
        )
        
        if success:
            return {
                "success": True,
                "message": "OAuth access revoked successfully"
            }
        else:
            return {
                "success": False,
                "message": "Failed to revoke OAuth access"
            }
            
    except Exception as e:
        logger.error(f"OAuth revocation failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke OAuth access"
        )


@router.get("/status", response_model=OAuthStatusResponse)
async def get_oauth_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get OAuth connection status for current user.
    """
    try:
        # Get OAuth credentials
        from app.models.user import OAuthCredential
        oauth_cred = db.query(OAuthCredential).filter(
            OAuthCredential.user_id == current_user.id,
            OAuthCredential.is_active == True
        ).first()
        
        connected = bool(oauth_cred and current_user.status == "connected")
        
        scopes_granted = []
        if oauth_cred:
            import json
            scopes_granted = json.loads(oauth_cred.scopes)
        
        return OAuthStatusResponse(
            connected=connected,
            status=current_user.status,
            email=current_user.gmail_email,
            display_name=current_user.display_name,
            connected_at=current_user.connected_at,
            scopes_granted=scopes_granted
        )
        
    except Exception as e:
        logger.error(f"Failed to get OAuth status for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get OAuth status"
        )


@router.get("/health")
async def oauth_health_check(
    db: Session = Depends(get_db),
    oauth_service: BackendOAuthService = Depends(get_backend_oauth_service)
):
    """
    Health check for OAuth service.
    """
    try:
        health_status = {
            "service": "backend_oauth",
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "database": "healthy",
                "redis": "healthy", 
                "encryption": "healthy",
                "google_oauth": "healthy"
            }
        }
        
        # Test database connection
        try:
            db.execute("SELECT 1")
        except Exception:
            health_status["components"]["database"] = "unhealthy"
            health_status["status"] = "degraded"
        
        # Test Redis connection
        try:
            await oauth_service.redis_client.ping()
        except Exception:
            health_status["components"]["redis"] = "unhealthy"
            health_status["status"] = "degraded"
        
        # Test encryption
        try:
            test_data = "test_encryption"
            encrypted = oauth_service._encrypt_token(test_data)
            decrypted = oauth_service._decrypt_token(encrypted)
            if decrypted != test_data:
                health_status["components"]["encryption"] = "unhealthy"
                health_status["status"] = "degraded"
        except Exception:
            health_status["components"]["encryption"] = "unhealthy"
            health_status["status"] = "degraded"
        
        return health_status
        
    except Exception as e:
        logger.error(f"OAuth health check failed: {e}")
        return {
            "service": "backend_oauth",
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


def _generate_error_page(error_message: str) -> str:
    """Generate user-friendly error page."""
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PhishNet - OAuth Error</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
            }}
            .container {{
                background: white;
                padding: 2rem;
                border-radius: 10px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.1);
                text-align: center;
                max-width: 500px;
                margin: 1rem;
            }}
            .icon {{
                font-size: 3rem;
                color: #e74c3c;
                margin-bottom: 1rem;
            }}
            h1 {{
                color: #2c3e50;
                margin-bottom: 1rem;
            }}
            p {{
                color: #7f8c8d;
                line-height: 1.6;
                margin-bottom: 2rem;
            }}
            .button {{
                background: #3498db;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 5px;
                text-decoration: none;
                display: inline-block;
                font-weight: 500;
                transition: background 0.3s;
            }}
            .button:hover {{
                background: #2980b9;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="icon">⚠️</div>
            <h1>OAuth Error</h1>
            <p>{error_message}</p>
            <p>Please try connecting your Gmail account again.</p>
            <a href="{settings.FRONTEND_URL}/dashboard" class="button">Return to Dashboard</a>
        </div>
    </body>
    </html>
    """


def _generate_success_page(user_email: str) -> str:
    """Generate success page."""
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PhishNet - Gmail Connected</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
            }}
            .container {{
                background: white;
                padding: 2rem;
                border-radius: 10px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.1);
                text-align: center;
                max-width: 500px;
                margin: 1rem;
            }}
            .icon {{
                font-size: 3rem;
                color: #27ae60;
                margin-bottom: 1rem;
            }}
            h1 {{
                color: #2c3e50;
                margin-bottom: 1rem;
            }}
            p {{
                color: #7f8c8d;
                line-height: 1.6;
                margin-bottom: 2rem;
            }}
            .email {{
                background: #ecf0f1;
                padding: 0.5rem 1rem;
                border-radius: 5px;
                font-family: monospace;
                color: #2c3e50;
                margin: 1rem 0;
            }}
            .button {{
                background: #27ae60;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 5px;
                text-decoration: none;
                display: inline-block;
                font-weight: 500;
                transition: background 0.3s;
            }}
            .button:hover {{
                background: #229954;
            }}
        </style>
        <script>
            // Auto-redirect after 5 seconds
            setTimeout(function() {{
                window.location.href = '{settings.FRONTEND_URL}/dashboard?oauth_success=true&email={user_email}';
            }}, 5000);
        </script>
    </head>
    <body>
        <div class="container">
            <div class="icon">✅</div>
            <h1>Gmail Connected Successfully!</h1>
            <p>Your Gmail account has been securely connected to PhishNet:</p>
            <div class="email">{user_email}</div>
            <p>You can now monitor your emails for phishing threats in real-time.</p>
            <p>Redirecting to dashboard in 5 seconds...</p>
            <a href="{settings.FRONTEND_URL}/dashboard?oauth_success=true&email={user_email}" class="button">Go to Dashboard Now</a>
        </div>
    </body>
    </html>
    """
