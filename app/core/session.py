"""
Session management and JWT token system for backend OAuth
Implements secure session handling with httpOnly cookies and short-lived JWTs
"""

import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import secrets

from fastapi import Request, Response, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.redis_client import get_redis_client
from app.models.user import User, AuditLog
from app.config.settings import get_settings

settings = get_settings()
security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class SessionManager:
    """Secure session management for OAuth and API access."""
    
    def __init__(self):
        self.redis_client = get_redis_client()
        self.jwt_secret = settings.SECRET_KEY
        self.jwt_algorithm = getattr(settings, 'JWT_ALGORITHM', 'HS256')
        self.jwt_expire_minutes = getattr(settings, 'JWT_EXPIRE_MINUTES', 30)
        self.refresh_token_expire_days = getattr(settings, 'REFRESH_TOKEN_EXPIRE_DAYS', 7)

    async def create_session(
        self,
        request: Request,
        response: Response,
        user: User,
        db: Session
    ) -> Dict[str, Any]:
        """
        Create secure session with httpOnly cookies and JWT token.
        
        Returns both session cookie and JWT for API access.
        """
        
        # Generate session ID
        session_id = secrets.token_urlsafe(32)
        
        # Create JWT token for API access
        jwt_payload = {
            "sub": str(user.id),
            "email": user.email,
            "role": user.role.value if user.role else "viewer",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=self.jwt_expire_minutes),
            "type": "access"
        }
        
        access_token = jwt.encode(jwt_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        # Create refresh token
        refresh_payload = {
            "sub": str(user.id),
            "session_id": session_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=self.refresh_token_expire_days),
            "type": "refresh"
        }
        
        refresh_token = jwt.encode(refresh_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        # Store session data in Redis
        session_data = {
            "user_id": user.id,
            "email": user.email,
            "role": user.role.value if user.role else "viewer",
            "created_at": datetime.utcnow().isoformat(),
            "ip_address": self._get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "refresh_token": refresh_token
        }
        
        # Store session with expiration
        await self.redis_client.setex(
            f"session:{session_id}",
            int(timedelta(days=self.refresh_token_expire_days).total_seconds()),
            json.dumps(session_data, default=str)
        )
        
        # Set httpOnly secure cookie
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            secure=True,  # HTTPS only
            samesite="lax",  # CSRF protection
            max_age=int(timedelta(days=self.refresh_token_expire_days).total_seconds())
        )
        
        # Update user last login
        user.last_login = datetime.utcnow()
        db.commit()
        
        # Audit log
        await self._log_audit_event(
            db=db,
            user_id=user.id,
            action="session_created",
            success=True,
            ip_address=session_data["ip_address"],
            user_agent=session_data["user_agent"],
            metadata={"session_id": session_id}
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.jwt_expire_minutes * 60,
            "session_id": session_id
        }

    async def get_current_user_from_jwt(
        self,
        credentials: Optional[HTTPAuthorizationCredentials],
        db: Session
    ) -> Optional[User]:
        """
        Get current user from JWT token.
        
        For API requests with Authorization header.
        """
        
        if not credentials:
            return None
        
        try:
            payload = jwt.decode(
                credentials.credentials,
                self.jwt_secret,
                algorithms=[self.jwt_algorithm]
            )
            
            # Verify token type
            if payload.get("type") != "access":
                return None
            
            user_id = int(payload.get("sub"))
            user = db.query(User).filter(
                User.id == user_id,
                User.is_active == True,
                User.disabled == False
            ).first()
            
            return user
            
        except (JWTError, ValueError, AttributeError):
            return None

    async def get_current_user_from_session(
        self,
        request: Request,
        db: Session
    ) -> Optional[User]:
        """
        Get current user from session cookie.
        
        For web requests with session cookies.
        """
        
        session_id = request.cookies.get("session_id")
        if not session_id:
            return None
        
        try:
            # Get session data from Redis
            session_data_str = await self.redis_client.get(f"session:{session_id}")
            if not session_data_str:
                return None
            
            session_data = json.loads(session_data_str)
            user_id = session_data.get("user_id")
            
            if not user_id:
                return None
            
            user = db.query(User).filter(
                User.id == user_id,
                User.is_active == True,
                User.disabled == False
            ).first()
            
            return user
            
        except (json.JSONDecodeError, ValueError, AttributeError):
            return None

    async def refresh_access_token(
        self,
        refresh_token: str,
        db: Session
    ) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.
        """
        
        try:
            payload = jwt.decode(
                refresh_token,
                self.jwt_secret,
                algorithms=[self.jwt_algorithm]
            )
            
            # Verify token type
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token"
                )
            
            user_id = int(payload.get("sub"))
            session_id = payload.get("session_id")
            
            # Verify session exists
            session_data_str = await self.redis_client.get(f"session:{session_id}")
            if not session_data_str:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session expired"
                )
            
            # Get user
            user = db.query(User).filter(
                User.id == user_id,
                User.is_active == True,
                User.disabled == False
            ).first()
            
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found"
                )
            
            # Create new access token
            jwt_payload = {
                "sub": str(user.id),
                "email": user.email,
                "role": user.role.value if user.role else "viewer",
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(minutes=self.jwt_expire_minutes),
                "type": "access"
            }
            
            new_access_token = jwt.encode(jwt_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
            
            # Audit log
            await self._log_audit_event(
                db=db,
                user_id=user.id,
                action="token_refreshed",
                success=True,
                metadata={"session_id": session_id}
            )
            
            return {
                "access_token": new_access_token,
                "token_type": "bearer",
                "expires_in": self.jwt_expire_minutes * 60
            }
            
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

    async def revoke_session(
        self,
        request: Request,
        response: Response,
        db: Session
    ) -> bool:
        """
        Revoke current session and clear cookies.
        """
        
        session_id = request.cookies.get("session_id")
        if not session_id:
            return True
        
        try:
            # Get session data for audit
            session_data_str = await self.redis_client.get(f"session:{session_id}")
            if session_data_str:
                session_data = json.loads(session_data_str)
                user_id = session_data.get("user_id")
                
                # Audit log
                await self._log_audit_event(
                    db=db,
                    user_id=user_id,
                    action="session_revoked",
                    success=True,
                    ip_address=self._get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    metadata={"session_id": session_id}
                )
            
            # Delete session from Redis
            await self.redis_client.delete(f"session:{session_id}")
            
            # Clear cookie
            response.delete_cookie(
                key="session_id",
                httponly=True,
                secure=True,
                samesite="lax"
            )
            
            return True
            
        except Exception as e:
            return False

    async def validate_rbac_permission(
        self,
        user: User,
        required_role: str,
        resource: Optional[str] = None
    ) -> bool:
        """
        Validate RBAC permissions for user.
        
        Args:
            user: Current user
            required_role: Minimum required role
            resource: Optional resource being accessed
        """
        
        # Role hierarchy: admin > analyst > viewer
        role_hierarchy = {
            "admin": 3,
            "analyst": 2,
            "viewer": 1
        }
        
        user_role_level = role_hierarchy.get(user.role.value if user.role else "viewer", 1)
        required_role_level = role_hierarchy.get(required_role, 1)
        
        # Check if user has sufficient role level
        has_permission = user_role_level >= required_role_level
        
        # Additional resource-specific checks can be added here
        if resource and not has_permission:
            # Check for resource-specific permissions
            pass
        
        return has_permission

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check for forwarded IP (Render/proxy setup)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"

    async def _log_audit_event(
        self,
        db: Session,
        action: str,
        success: bool,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Log audit event."""
        
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            actor="user" if user_id else "system",
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            metadata=metadata,
            error_message=error_message
        )
        
        db.add(audit_log)
        db.commit()


# Global session manager instance
session_manager = SessionManager()


# FastAPI dependencies
async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user (required).
    
    Checks both JWT token and session cookie.
    """
    
    # Try JWT first (for API requests)
    user = await session_manager.get_current_user_from_jwt(credentials, db)
    
    # Fall back to session cookie (for web requests)
    if not user:
        user = await session_manager.get_current_user_from_session(request, db)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Get current authenticated user (optional).
    
    Returns None if not authenticated.
    """
    
    # Try JWT first (for API requests)
    user = await session_manager.get_current_user_from_jwt(credentials, db)
    
    # Fall back to session cookie (for web requests)
    if not user:
        user = await session_manager.get_current_user_from_session(request, db)
    
    return user


def require_role(required_role: str):
    """
    Decorator for RBAC protection.
    
    Usage:
        @router.get("/admin")
        @require_role("admin")
        async def admin_endpoint(current_user: User = Depends(get_current_user)):
            ...
    """
    
    def role_dependency(current_user: User = Depends(get_current_user)):
        if not session_manager.validate_rbac_permission(current_user, required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' required"
            )
        return current_user
    
    return role_dependency


# Session management endpoints
async def create_session(
    request: Request,
    response: Response,
    user: User,
    db: Session
) -> Dict[str, Any]:
    """Create session for user."""
    return await session_manager.create_session(request, response, user, db)


async def refresh_token(refresh_token: str, db: Session) -> Dict[str, Any]:
    """Refresh access token."""
    return await session_manager.refresh_access_token(refresh_token, db)


async def logout_session(request: Request, response: Response, db: Session) -> bool:
    """Logout current session."""
    return await session_manager.revoke_session(request, response, db)
