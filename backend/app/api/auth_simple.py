"""
Simple Authentication Router for PhishNet
MongoDB-based user registration and login
"""

from datetime import timedelta
from fastapi import APIRouter, HTTPException, Depends, status

from app.core.auth_simple import (
    UserCreate, UserLogin, TokenResponse, UserResponse,
    create_user, authenticate_user, create_access_token,
    get_current_user
)
from app.config.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    """Register a new user."""
    try:
        user = await create_user(user_data)
        return UserResponse(
            id=str(user.id),
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            is_active=user.is_active,
            created_at=user.created_at
        )
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@router.post("/login", response_model=TokenResponse)
async def login(user_credentials: UserLogin):
    """Login and get access token."""
    user = await authenticate_user(user_credentials.email, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(hours=24)
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=access_token_expires
    )
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=int(access_token_expires.total_seconds())
    )

@router.get("/me", response_model=UserResponse)
async def get_me(current_user = Depends(get_current_user)):
    """Get current user information."""
    return UserResponse(
        id=str(current_user.id),
        email=current_user.email,
        username=current_user.username,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        created_at=current_user.created_at
    )

@router.get("/test")
async def auth_test():
    """Test endpoint to verify auth router is working."""
    return {
        "message": "Authentication router is working",
        "endpoints": [
            "POST /api/auth/register - Register new user",
            "POST /api/auth/login - Login and get token",
            "GET /api/auth/me - Get current user info"
        ]
    }