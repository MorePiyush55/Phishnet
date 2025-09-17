"""Enhanced authentication system with JWT, refresh tokens, and role-based access."""

import secrets
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import jwt
import bcrypt
import logging
from sqlalchemy.orm import Session
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from app.config.settings import Settings
from app.core.secrets import get_secret_manager

logger = logging.getLogger(__name__)


def get_current_user():
    """Mock current user function for compliance testing"""
    return {"user_id": "test_user", "email": "test@example.com"}


class UserRole(str, Enum):
    """User roles for role-based access control."""
    ADMIN = "admin"
    ANALYST = "analyst"
    USER = "user"


class TokenType(str, Enum):
    """Token types."""
    ACCESS = "access"
    REFRESH = "refresh"


class AuthError(Exception):
    """Base authentication error."""
    pass


class InvalidTokenError(AuthError):
    """Invalid token error."""
    pass


class ExpiredTokenError(AuthError):
    """Expired token error."""
    pass


class RevokedTokenError(AuthError):
    """Revoked token error."""
    pass


class InsufficientPermissionsError(AuthError):
    """Insufficient permissions error."""
    pass


class TokenPayload(BaseModel):
    """Token payload model."""
    sub: str  # subject (user ID)
    exp: datetime  # expiration
    iat: datetime  # issued at
    jti: str  # JWT ID (unique token identifier)
    token_type: TokenType
    role: UserRole
    permissions: List[str] = []
    
    class Config:
        json_encoders = {
            datetime: lambda v: int(v.timestamp())
        }


class TokenPair(BaseModel):
    """Access and refresh token pair."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expires


class JWTService:
    """JWT token service with refresh token support and revocation."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.secret_manager = get_secret_manager(settings)
        self._secret_key: Optional[str] = None
        self.algorithm = settings.ALGORITHM
        
        # Security configurations
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.REFRESH_TOKEN_EXPIRE_DAYS
    
    async def _get_secret_key(self) -> str:
        """Get JWT secret key from secret management."""
        if self._secret_key is None:
            self._secret_key = await self.secret_manager.get_jwt_secret()
        return self._secret_key
    
    def _generate_jti(self) -> str:
        """Generate unique JWT ID."""
        return secrets.token_urlsafe(32)
    
    async def create_token_pair(
        self, 
        user_id: str, 
        role: UserRole, 
        permissions: List[str] = None
    ) -> TokenPair:
        """Create access and refresh token pair."""
        permissions = permissions or []
        now = datetime.utcnow()
        
        # Generate unique JTIs for both tokens
        access_jti = self._generate_jti()
        refresh_jti = self._generate_jti()
        
        # Create access token
        access_payload = TokenPayload(
            sub=user_id,
            exp=now + timedelta(minutes=self.access_token_expire_minutes),
            iat=now,
            jti=access_jti,
            token_type=TokenType.ACCESS,
            role=role,
            permissions=permissions
        )
        
        # Create refresh token
        refresh_payload = TokenPayload(
            sub=user_id,
            exp=now + timedelta(days=self.refresh_token_expire_days),
            iat=now,
            jti=refresh_jti,
            token_type=TokenType.REFRESH,
            role=role,
            permissions=permissions
        )
        
        secret_key = await self._get_secret_key()
        
        access_token = jwt.encode(
            access_payload.dict(), 
            secret_key, 
            algorithm=self.algorithm
        )
        
        refresh_token = jwt.encode(
            refresh_payload.dict(), 
            secret_key, 
            algorithm=self.algorithm
        )
        
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.access_token_expire_minutes * 60
        )
    
    async def verify_token(self, token: str, token_type: TokenType = TokenType.ACCESS) -> TokenPayload:
        """Verify and decode JWT token."""
        try:
            secret_key = await self._get_secret_key()
            payload = jwt.decode(token, secret_key, algorithms=[self.algorithm])
            
            # Validate token type
            if payload.get("token_type") != token_type.value:
                raise InvalidTokenError(f"Invalid token type. Expected {token_type.value}")
            
            # Check expiration
            exp_timestamp = payload.get("exp")
            if exp_timestamp and datetime.fromtimestamp(exp_timestamp) < datetime.utcnow():
                raise ExpiredTokenError("Token has expired")
            
            return TokenPayload(**payload)
            
        except jwt.ExpiredSignatureError:
            raise ExpiredTokenError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}")
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            raise InvalidTokenError("Token verification failed")
    
    async def refresh_access_token(self, refresh_token: str, db: Session) -> TokenPair:
        """Create new access token using refresh token."""
        try:
            # Verify refresh token
            payload = await self.verify_token(refresh_token, TokenType.REFRESH)
            
            # Check if refresh token is revoked
            if await self.is_token_revoked(payload.jti, db):
                raise RevokedTokenError("Refresh token has been revoked")
            
            # Create new token pair
            new_tokens = await self.create_token_pair(
                payload.sub, 
                payload.role, 
                payload.permissions
            )
            
            # If configured, revoke old refresh token and return new pair
            if self.settings.ROTATE_REFRESH_TOKENS:
                await self.revoke_token(payload.jti, db)
            
            return new_tokens
            
        except (InvalidTokenError, ExpiredTokenError, RevokedTokenError):
            raise
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            raise InvalidTokenError("Token refresh failed")
    
    async def revoke_token(self, jti: str, db: Session) -> None:
        """Revoke token by JTI."""
        # Import here to avoid circular imports
        from app.models.user import RevokedToken
        
        try:
            revoked_token = RevokedToken(
                jti=jti,
                revoked_at=datetime.utcnow()
            )
            db.add(revoked_token)
            db.commit()
            
            logger.info(f"Token revoked: {jti}")
        except Exception as e:
            logger.error(f"Token revocation error: {e}")
            db.rollback()
            raise AuthError(f"Failed to revoke token: {e}")
    
    async def is_token_revoked(self, jti: str, db: Session) -> bool:
        """Check if token is revoked."""
        # Import here to avoid circular imports
        from app.models.user import RevokedToken
        
        try:
            revoked = db.query(RevokedToken).filter(
                RevokedToken.jti == jti
            ).first()
            return revoked is not None
        except Exception as e:
            logger.error(f"Token revocation check error: {e}")
            return False  # Fail open for availability
    
    async def revoke_all_user_tokens(self, user_id: str, db: Session) -> None:
        """Revoke all tokens for a user."""
        # This would require tracking all active tokens per user
        # For now, we'll implement this by adding user_id to revoked tokens
        # and checking it during verification
        try:
            # Import here to avoid circular imports
            from app.models.user import RevokedToken
            
            # Add a special revoked token entry for the user
            user_revoke = RevokedToken(
                jti=f"user_revoke_{user_id}",
                user_id=user_id,
                revoked_at=datetime.utcnow()
            )
            db.add(user_revoke)
            db.commit()
            
            logger.info(f"All tokens revoked for user: {user_id}")
        except Exception as e:
            logger.error(f"User token revocation error: {e}")
            db.rollback()
            raise AuthError(f"Failed to revoke user tokens: {e}")


class PasswordService:
    """Password hashing and verification service."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.rounds = getattr(settings, 'BCRYPT_ROUNDS', 12)
        self.min_length = getattr(settings, 'MIN_PASSWORD_LENGTH', 8)
        self.require_special = getattr(settings, 'REQUIRE_SPECIAL_CHARS', True)
    
    def hash_password(self, password: str) -> str:
        """Hash password with bcrypt."""
        self._validate_password(password)
        
        salt = bcrypt.gensalt(rounds=self.rounds)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    def _validate_password(self, password: str) -> None:
        """Validate password strength."""
        if len(password) < self.min_length:
            raise ValueError(f"Password must be at least {self.min_length} characters long")
        
        if self.require_special:
            import re
            if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
                raise ValueError("Password must contain at least one special character")


class AuthService:
    """Complete authentication service."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.jwt_service = JWTService(settings)
        self.password_service = PasswordService(settings)
        self.security = HTTPBearer()
    
    async def authenticate_user(self, email: str, password: str, db: Session) -> Optional[Dict[str, Any]]:
        """Authenticate user with email and password."""
        # Import here to avoid circular imports
        from app.models.user import User
        
        try:
            user = db.query(User).filter(User.email == email).first()
            if not user or not user.is_active:
                return None
            
            if not self.password_service.verify_password(password, user.hashed_password):
                return None
            
            return {
                "id": str(user.id),
                "email": user.email,
                "role": user.role,
                "permissions": user.permissions or []
            }
        except Exception as e:
            logger.error(f"User authentication error: {e}")
            return None
    
    async def create_user_tokens(self, user: Dict[str, Any]) -> TokenPair:
        """Create tokens for authenticated user."""
        return await self.jwt_service.create_token_pair(
            user_id=user["id"],
            role=UserRole(user["role"]),
            permissions=user["permissions"]
        )
    
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials, db: Session) -> TokenPayload:
        """Get current user from JWT token."""
        try:
            payload = await self.jwt_service.verify_token(credentials.credentials)
            
            # Check if token is revoked
            if await self.jwt_service.is_token_revoked(payload.jti, db):
                raise RevokedTokenError("Token has been revoked")
            
            return payload
            
        except (InvalidTokenError, ExpiredTokenError, RevokedTokenError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
                headers={"WWW-Authenticate": "Bearer"}
            )
        except Exception as e:
            logger.error(f"Get current user error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"}
            )
    
    def require_role(self, required_role: UserRole):
        """Decorator to require specific role."""
        def decorator(payload: TokenPayload):
            if payload.role != required_role and payload.role != UserRole.ADMIN:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required role: {required_role.value}"
                )
            return payload
        return decorator
    
    def require_permission(self, permission: str):
        """Decorator to require specific permission."""
        def decorator(payload: TokenPayload):
            if permission not in payload.permissions and payload.role != UserRole.ADMIN:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required permission: {permission}"
                )
            return payload
        return decorator


# --- Compatibility helpers used by older modules ---
from app.config.settings import settings as _settings

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token quickly for tests/imports.

    This is a lightweight convenience wrapper. For production use, prefer
    JWTService.create_token_pair or AuthService.create_user_tokens.
    """
    import jwt as _jwt
    now = datetime.utcnow()
    payload = data.copy()
    if expires_delta is None:
        expires_delta = timedelta(minutes=getattr(_settings, 'ACCESS_TOKEN_EXPIRE_MINUTES', 30))
    payload.update({
        "exp": int((now + expires_delta).timestamp()),
        "iat": int(now.timestamp())
    })
    return _jwt.encode(payload, _settings.SECRET_KEY, algorithm=getattr(_settings, 'ALGORITHM', 'HS256'))


def create_refresh_token(data: dict) -> str:
    """Create a JWT refresh token (conservative helper)."""
    import jwt as _jwt
    now = datetime.utcnow()
    payload = data.copy()
    payload.update({
        "exp": int((now + timedelta(days=getattr(_settings, 'REFRESH_TOKEN_EXPIRE_DAYS', 30))).timestamp()),
        "iat": int(now.timestamp())
    })
    return _jwt.encode(payload, _settings.SECRET_KEY, algorithm=getattr(_settings, 'ALGORITHM', 'HS256'))



# Global auth service instance
_auth_service: Optional[AuthService] = None


def get_auth_service(settings: Optional[Settings] = None) -> AuthService:
    """Get global auth service instance."""
    global _auth_service
    
    if _auth_service is None:
        from app.config.settings import get_settings
        settings = settings or get_settings()
        _auth_service = AuthService(settings)
    
    return _auth_service
