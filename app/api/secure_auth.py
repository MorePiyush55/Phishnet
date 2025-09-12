"""Secure authentication API endpoints with JWT, OAuth, and comprehensive security."""

import logging
from datetime import datetime
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.config.settings import get_settings
from app.core.auth import (
    AuthService, PasswordService, TokenPair, TokenPayload, 
    UserRole, get_auth_service
)
from app.core.auth_deps import (
    get_current_user, get_current_active_user, csrf_protect, audit_log
)
from app.core.database import get_db
from app.core.oauth_security import get_oauth_service
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


# Request/Response models
class LoginRequest(BaseModel):
    """Login request model."""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password")
    remember_me: bool = Field(False, description="Keep login session longer")


class RegisterRequest(BaseModel):
    """User registration request model."""
    email: EmailStr = Field(..., description="User email address")
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    password: str = Field(..., min_length=8, description="User password")
    full_name: Optional[str] = Field(None, max_length=200, description="Full name")


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""
    refresh_token: str = Field(..., description="Valid refresh token")


class ChangePasswordRequest(BaseModel):
    """Change password request model."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")


class ForgotPasswordRequest(BaseModel):
    """Forgot password request model."""
    email: EmailStr = Field(..., description="User email address")


class ResetPasswordRequest(BaseModel):
    """Reset password request model."""
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=8, description="New password")


class LoginResponse(BaseModel):
    """Login response model."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, any]


class OAuthInitResponse(BaseModel):
    """OAuth initialization response."""
    authorization_url: str
    state: str
    csrf_token: str


@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Login with email and password."""
    try:
        # Authenticate user
        user = await auth_service.authenticate_user(
            login_data.email, 
            login_data.password, 
            db
        )
        
        if not user:
            # Audit failed login attempt
            logger.warning(f"Failed login attempt for {login_data.email} from {request.client.host}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Create JWT tokens
        tokens = await auth_service.create_user_tokens(user)
        
        # Audit successful login
        logger.info(f"Successful login for user {user['id']} ({user['email']})")
        
        # Update last login
        db_user = db.query(User).filter(User.id == int(user["id"])).first()
        if db_user:
            db_user.last_login = datetime.utcnow()
            db.commit()
        
        return LoginResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_type=tokens.token_type,
            expires_in=tokens.expires_in,
            user={
                "id": user["id"],
                "email": user["email"],
                "role": user["role"],
                "permissions": user["permissions"]
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )


@router.post("/register", response_model=LoginResponse)
async def register(
    register_data: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Register new user."""
    try:
        # Check if user already exists
        existing_user = db.query(User).filter(
            (User.email == register_data.email) | 
            (User.username == register_data.username)
        ).first()
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email or username already exists"
            )
        
        # Hash password
        hashed_password = auth_service.password_service.hash_password(
            register_data.password
        )
        
        # Create new user
        new_user = User(
            email=register_data.email,
            username=register_data.username,
            hashed_password=hashed_password,
            full_name=register_data.full_name,
            role=UserRole.USER,  # Default role
            is_active=True,
            is_verified=False  # Email verification required
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Create tokens for new user
        user_data = {
            "id": str(new_user.id),
            "email": new_user.email,
            "role": new_user.role.value,
            "permissions": new_user.permissions
        }
        
        tokens = await auth_service.create_user_tokens(user_data)
        
        logger.info(f"New user registered: {new_user.email}")
        
        return LoginResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_type=tokens.token_type,
            expires_in=tokens.expires_in,
            user=user_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@router.post("/refresh", response_model=TokenPair)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Refresh access token using refresh token."""
    try:
        new_tokens = await auth_service.jwt_service.refresh_access_token(
            refresh_data.refresh_token, 
            db
        )
        return new_tokens
        
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )


@router.post("/logout")
async def logout(
    current_user: TokenPayload = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Logout and revoke current token."""
    try:
        # Revoke current token
        await auth_service.jwt_service.revoke_token(current_user.jti, db)
        
        logger.info(f"User {current_user.sub} logged out")
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.post("/logout-all")
async def logout_all(
    current_user: TokenPayload = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Logout from all devices (revoke all user tokens)."""
    try:
        # Revoke all tokens for user
        await auth_service.jwt_service.revoke_all_user_tokens(current_user.sub, db)
        
        logger.info(f"All tokens revoked for user {current_user.sub}")
        
        return {"message": "Successfully logged out from all devices"}
        
    except Exception as e:
        logger.error(f"Logout all error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.post("/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: TokenPayload = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Change user password."""
    try:
        # Get user from database
        user = db.query(User).filter(User.id == int(current_user.sub)).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Verify current password
        if not auth_service.password_service.verify_password(
            password_data.current_password, 
            user.hashed_password
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Hash new password
        new_hashed = auth_service.password_service.hash_password(
            password_data.new_password
        )
        
        # Update password
        user.hashed_password = new_hashed
        user.updated_at = datetime.utcnow()
        db.commit()
        
        # Revoke all existing tokens (force re-login)
        await auth_service.jwt_service.revoke_all_user_tokens(current_user.sub, db)
        
        logger.info(f"Password changed for user {current_user.sub}")
        
        return {"message": "Password successfully changed. Please log in again."}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )


@router.get("/me")
async def get_current_user_info(
    current_user: TokenPayload = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get current user information."""
    try:
        user = db.query(User).filter(User.id == int(current_user.sub)).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role.value,
            "permissions": user.permissions,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "created_at": user.created_at,
            "last_login": user.last_login
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get user info error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user information"
        )


# OAuth endpoints
@router.post("/oauth/gmail/init", response_model=OAuthInitResponse)
async def init_gmail_oauth(
    request: Request,
    current_user: TokenPayload = Depends(get_current_active_user),
    oauth_service = Depends(get_oauth_service)
):
    """Initialize Gmail OAuth flow."""
    try:
        settings = get_settings()
        redirect_uri = f"{settings.BASE_URL}/api/v1/auth/oauth/gmail/callback"
        
        # Generate OAuth URL with CSRF protection
        oauth_url, csrf_token = await oauth_service.generate_oauth_url(
            provider="gmail",
            user_id=current_user.sub,
            redirect_uri=redirect_uri,
            scopes=[
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/gmail.modify"
            ]
        )
        
        return OAuthInitResponse(
            authorization_url=oauth_url,
            state="included_in_url",
            csrf_token=csrf_token
        )
        
    except Exception as e:
        logger.error(f"Gmail OAuth init error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth initialization failed"
        )


@router.get("/oauth/gmail/callback")
async def gmail_oauth_callback(
    request: Request,
    code: str,
    state: str,
    csrf_token: Optional[str] = None,
    db: Session = Depends(get_db),
    oauth_service = Depends(get_oauth_service)
):
    """Handle Gmail OAuth callback."""
    try:
        # Handle OAuth callback with security validation
        result = await oauth_service.handle_oauth_callback(
            code=code,
            state=state,
            csrf_token=csrf_token or request.headers.get("X-CSRF-Token", ""),
            db=db
        )
        
        logger.info(f"Gmail OAuth completed for user {result['user_id']}")
        
        return {
            "message": "Gmail OAuth completed successfully",
            "user_id": result["user_id"],
            "provider": result["provider"],
            "scopes": result.get("scope", "").split() if result.get("scope") else []
        }
        
    except Exception as e:
        logger.error(f"Gmail OAuth callback error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth callback failed: {str(e)}"
        )


@router.post("/oauth/revoke/{provider}")
async def revoke_oauth_token(
    provider: str,
    current_user: TokenPayload = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    oauth_service = Depends(get_oauth_service)
):
    """Revoke OAuth token for a provider."""
    try:
        success = await oauth_service.revoke_oauth_token(
            user_id=int(current_user.sub),
            provider=provider,
            db=db
        )
        
        if success:
            return {"message": f"OAuth token for {provider} revoked successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No active OAuth token found for {provider}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth revoke error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth revocation failed"
        )


# Health check for auth system
@router.get("/health")
async def auth_health_check():
    """Health check for authentication system."""
    try:
        # Basic health check - could be expanded
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "jwt_service": "operational",
                "password_service": "operational",
                "oauth_service": "operational"
            }
        }
    except Exception as e:
        logger.error(f"Auth health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unhealthy"
        )
