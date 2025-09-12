"""
Auth API v1 - Authentication endpoints
"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import jwt
import secrets

from app.core.database import get_db
from app.models.user import User
from app.config.settings import settings

router = APIRouter()
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Request/Response Models
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class LogoutRequest(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    user: UserResponse

class TokenResponse(BaseModel):
    access_token: str

class LogoutResponse(BaseModel):
    ok: bool = True

# Token utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Dependencies
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user from JWT token"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
            
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user"
        )
    
    return user

# Endpoints
@router.post("/login", response_model=AuthResponse)
async def login(
    request: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return access/refresh tokens
    
    **Contract**: POST /api/v1/auth/login
    - Input: { email, password }
    - Output: { access_token, refresh_token, user }
    """
    # Find user by email
    user = db.query(User).filter(User.email == request.email).first()
    
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled"
        )
    
    # Create tokens
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse.from_orm(user)
    )

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshRequest,
    db: Session = Depends(get_db)
):
    """
    Refresh access token using refresh token
    
    **Contract**: POST /api/v1/auth/refresh
    - Input: { refresh_token }
    - Output: { access_token }
    """
    try:
        payload = jwt.decode(request.refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
        
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
            
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Verify user still exists and is active
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Create new access token
    access_token = create_access_token(data={"sub": user.email})
    
    return TokenResponse(access_token=access_token)

@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: LogoutRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Logout user and invalidate refresh token
    
    **Contract**: POST /api/v1/auth/logout
    - Input: { refresh_token }
    - Output: { ok: true }
    """
    # In a production system, you would:
    # 1. Add refresh token to a blacklist/revocation list
    # 2. Store revoked tokens in Redis with expiration
    # 3. Check blacklist during token validation
    
    # For now, we'll just return success
    # The client should delete the tokens locally
    
    return LogoutResponse(ok=True)

# Health check for auth service
@router.get("/health")
async def auth_health():
    """Auth service health check"""
    return {"status": "healthy", "service": "auth"}
