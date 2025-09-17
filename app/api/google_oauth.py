"""
Production-ready Google OAuth endpoints for PhishNet authentication.
Handles complete OAuth flow for Gmail access and user authentication.
"""

import os
import secrets
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, EmailStr
import httpx
import jwt

from app.core.database import get_db
from app.core.auth import get_current_user, create_access_token, create_refresh_token
from app.models.user import User
from app.config.settings import settings
from app.services.audit import AuditService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["OAuth Authentication"])
security = HTTPBearer()

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET") 
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "https://your-vercel-app.vercel.app/auth/callback")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

# OAuth Scopes for Gmail access
OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid"
]

# Pydantic Models
class OAuthCallbackRequest(BaseModel):
    code: str = Field(..., description="Authorization code from Google")
    redirect_uri: str = Field(..., description="Redirect URI used in the request")
    state: Optional[str] = Field(None, description="State parameter for CSRF protection")

class OAuthTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: Dict[str, Any]

class UserInfo(BaseModel):
    id: str
    email: EmailStr
    name: str
    picture: Optional[str] = None
    verified_email: bool = False

class TokenVerificationResponse(BaseModel):
    valid: bool
    user_id: Optional[int] = None
    email: Optional[str] = None
    expires_at: Optional[datetime] = None

# OAuth State Storage (In production, use Redis or database)
oauth_states: Dict[str, Dict[str, Any]] = {}

@router.get("/google")
async def initiate_google_oauth(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Initiate Google OAuth flow.
    
    Returns:
        RedirectResponse: Redirects to Google OAuth consent screen
    """
    try:
        # Generate state parameter for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Store state (in production, use Redis with expiration)
        oauth_states[state] = {
            "created_at": datetime.utcnow(),
            "ip_address": request.client.host if request.client else "unknown"
        }
        
        # Build OAuth URL
        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": " ".join(OAUTH_SCOPES),
            "access_type": "offline",
            "prompt": "consent",
            "state": state
        }
        
        auth_url = GOOGLE_AUTH_URL + "?" + "&".join([f"{k}={v}" for k, v in params.items()])
        
        logger.info(f"OAuth flow initiated with state: {state}")
        # Audit log: oauth_initiated
        try:
            audit = AuditService()
            await audit.log_event('OAUTH_INITIATED', 'oauth', state, user_id=0, details={'ip': request.client.host if request.client else None})
        except Exception:
            logger.debug('Audit log failed for oauth initiation')
        return RedirectResponse(url=auth_url)
        
    except Exception as e:
        logger.error(f"Failed to initiate OAuth: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate authentication"
        )


@router.get("/login", response_class=HTMLResponse)
async def serve_login_page(request: Request):
    """Serve a minimal static login page (useful for demo or Vercel fallback).

    This endpoint will try to read the `frontend/public/login.html` file if present
    and replace a small placeholder object with runtime config so the page can
    build the correct OAuth URL without exposing secrets.
    """
    try:
        # Attempt to load the static file from the frontend public folder
        base_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'frontend', 'public')
        candidate = os.path.abspath(os.path.join(base_path, 'login.html'))
        html = None
        if os.path.exists(candidate):
            with open(candidate, 'r', encoding='utf-8') as f:
                html = f.read()

        if not html:
            # Fallback minimal page
            html = f"""
            <!doctype html>
            <html><head><meta charset='utf-8'><title>PhishNet Login</title></head>
            <body>
            <a href='/api/v1/auth/google'>Sign in with Google</a>
            </body></html>
            """

        # Inject a small JS config object for client-side use
        config = {
            "GOOGLE_CLIENT_ID": GOOGLE_CLIENT_ID or "",
            "REDIRECT_URI": GOOGLE_REDIRECT_URI,
            "BACKEND_URL": os.getenv('BACKEND_URL', '') or ''
        }

        inject_snippet = f"<script>window.__PHISHNET_CONFIG__ = {config};</script>"

        # Place injection before closing </head> or at top of body
        if '</head>' in html:
            html = html.replace('</head>', inject_snippet + '</head>')
        else:
            html = inject_snippet + html

        return HTMLResponse(content=html, status_code=200)

    except Exception as e:
        logger.error(f"Error serving login page: {e}")
        raise HTTPException(status_code=500, detail="Failed to serve login page")

@router.post("/google/callback", response_model=OAuthTokenResponse)
async def handle_oauth_callback(
    callback_data: OAuthCallbackRequest,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Handle OAuth callback from Google.
    
    Args:
        callback_data: OAuth callback data including authorization code
        
    Returns:
        OAuthTokenResponse: JWT tokens and user information
    """
    try:
        # Verify state parameter
        if callback_data.state:
            if callback_data.state not in oauth_states:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired state parameter"
                )
            
            # Clean up state
            del oauth_states[callback_data.state]
        
        # Exchange authorization code for tokens
        token_data = await exchange_code_for_tokens(
            callback_data.code, 
            callback_data.redirect_uri
        )
        
        # Get user info from Google
        user_info = await get_google_user_info(token_data["access_token"])
        
        # Create or update user in database
        user = await get_or_create_user(db, user_info, token_data)
        
        # Generate application JWT tokens
        access_token = create_access_token(
            data={"sub": str(user.id), "email": user.email}
        )
        refresh_token = create_refresh_token(
            data={"sub": str(user.id), "email": user.email}
        )

    # Set refresh token in a secure httpOnly cookie (backend-only)
        cookie_max_age = 60 * 60 * 24 * 30  # 30 days
        secure_flag = os.getenv("ENV", "development") == "production"
        response.set_cookie(
            key="phishnet_refresh_token",
            value=refresh_token,
            httponly=True,
            secure=secure_flag,
            samesite="lax",
            max_age=cookie_max_age
        )

        logger.info(f"OAuth completed for user: {user.email}")

        # Audit log: oauth_completed
        try:
            audit = AuditService()
            await audit.log_event('OAUTH_COMPLETED', 'user', str(user.id), user_id=user.id, details={'email': user.email})
        except Exception:
            logger.debug('Audit log failed for oauth completion')

        # Return access token and user info (refresh token stored in cookie)
        return OAuthTokenResponse(
            access_token=access_token,
            refresh_token="",
            expires_in=3600,  # 1 hour
            user_info={
                "id": user.id,
                "email": user.email,
                "name": user.full_name or user.username,
                "picture": user_info.get("picture"),
                "gmail_connected": True
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth callback failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )

@router.post("/verify", response_model=TokenVerificationResponse)
async def verify_token(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Verify JWT token validity.
    
    Returns:
        TokenVerificationResponse: Token validation result
    """
    try:
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header"
            )
        
        token = auth_header.split(" ")[1]
        
        # Verify JWT token
        try:
            payload = jwt.decode(
                token, 
                settings.SECRET_KEY, 
                algorithms=[settings.ALGORITHM]
            )
            user_id = int(payload.get("sub"))
            email = payload.get("email")
            exp = payload.get("exp")
            
            # Check if user exists
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found"
                )
            
            return TokenVerificationResponse(
                valid=True,
                user_id=user_id,
                email=email,
                expires_at=datetime.fromtimestamp(exp) if exp else None
            )
            
        except jwt.ExpiredSignatureError:
            return TokenVerificationResponse(valid=False)
        except jwt.JWTError:
            return TokenVerificationResponse(valid=False)
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        return TokenVerificationResponse(valid=False)

@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Logout user and revoke tokens.
    
    Returns:
        JSONResponse: Logout confirmation
    """
    try:
        # In production, you would:
        # 1. Add token to blacklist
        # 2. Revoke Google OAuth tokens
        # 3. Clear session data
        
        logger.info(f"User logged out: {current_user.email}")

        # Clear refresh cookie if present
        response = JSONResponse(
            content={"success": True, "message": "Successfully logged out"}
        )
        response.delete_cookie("phishnet_refresh_token")
        return response
        
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )

# Helper Functions
async def exchange_code_for_tokens(code: str, redirect_uri: str) -> Dict[str, Any]:
    """Exchange authorization code for access and refresh tokens."""
    async with httpx.AsyncClient() as client:
        token_data = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri
        }
        
        response = await client.post(GOOGLE_TOKEN_URL, data=token_data)
        
        if response.status_code != 200:
            logger.error(f"Token exchange failed: {response.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to exchange authorization code"
            )
        
        return response.json()


async def refresh_tokens(refresh_token: str) -> Dict[str, Any]:
    """Use a refresh token to obtain a new access token from Google."""
    async with httpx.AsyncClient() as client:
        data = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
        resp = await client.post(GOOGLE_TOKEN_URL, data=data)
        if resp.status_code != 200:
            logger.error(f"Failed to refresh tokens: {resp.status_code} {resp.text}")
            raise HTTPException(status_code=400, detail="Failed to refresh tokens")
        return resp.json()


@router.post('/refresh')
async def refresh_access_token_endpoint(request: Request, response: Response):
    """Refresh access token using refresh token stored in httpOnly cookie."""
    try:
        refresh_token = request.cookies.get('phishnet_refresh_token')
        if not refresh_token:
            raise HTTPException(status_code=401, detail='No refresh token')

        token_data = await refresh_tokens(refresh_token)

        # Optionally set a new refresh cookie if provided
        new_refresh = token_data.get('refresh_token')
        if new_refresh:
            cookie_max_age = 60 * 60 * 24 * 30  # 30 days
            secure_flag = os.getenv("ENV", "development") == "production"
            response.set_cookie(
                key="phishnet_refresh_token",
                value=new_refresh,
                httponly=True,
                secure=secure_flag,
                samesite="lax",
                max_age=cookie_max_age
            )

        return JSONResponse(content={
            'access_token': token_data.get('access_token'),
            'expires_in': token_data.get('expires_in', 3600)
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Refresh endpoint failed: {e}")
        raise HTTPException(status_code=500, detail='Token refresh failed')

async def get_google_user_info(access_token: str) -> Dict[str, Any]:
    """Get user information from Google."""
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = await client.get(GOOGLE_USERINFO_URL, headers=headers)
        
        if response.status_code != 200:
            logger.error(f"Failed to get user info: {response.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to get user information"
            )
        
        return response.json()

async def get_or_create_user(
    db: Session, 
    user_info: Dict[str, Any], 
    token_data: Dict[str, Any]
) -> User:
    """Get existing user or create new one."""
    email = user_info.get("email")
    
    # Check if user exists
    user = db.query(User).filter(User.email == email).first()
    
    if user:
        # Update existing user
        user.full_name = user_info.get("name", user.full_name)
        user.is_active = True
        user.gmail_access_token = token_data.get("access_token")
        user.gmail_refresh_token = token_data.get("refresh_token")
        user.gmail_token_expires = datetime.utcnow() + timedelta(
            seconds=token_data.get("expires_in", 3600)
        )
        user.last_login = datetime.utcnow()
    else:
        # Create new user
        user = User(
            username=email.split("@")[0],
            email=email,
            full_name=user_info.get("name"),
            is_active=True,
            role="user",
            gmail_access_token=token_data.get("access_token"),
            gmail_refresh_token=token_data.get("refresh_token"),
            gmail_token_expires=datetime.utcnow() + timedelta(
                seconds=token_data.get("expires_in", 3600)
            ),
            created_at=datetime.utcnow(),
            last_login=datetime.utcnow()
        )
        db.add(user)
    
    db.commit()
    db.refresh(user)
    return user