"""Authentication dependencies for protecting API endpoints."""

import logging
from typing import Callable, Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.auth import AuthService, TokenPayload, UserRole, get_auth_service
from app.core.database import get_db
from app.config.settings import Settings, get_settings

logger = logging.getLogger(__name__)

# HTTP Bearer for extracting JWT tokens
security = HTTPBearer()


# Dependency for getting current authenticated user
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(get_auth_service)
) -> TokenPayload:
    """Get current authenticated user from JWT token."""
    return await auth_service.get_current_user(credentials, db)


# Dependency for getting current active user (additional checks)
async def get_current_active_user(
    current_user: TokenPayload = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> TokenPayload:
    """Get current active user with additional validation."""
    # Import here to avoid circular imports
    from app.models.user import User
    
    try:
        # Verify user still exists and is active
        user = db.query(User).filter(User.id == int(current_user.sub)).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user"
            )
        
        return current_user
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user ID in token"
        )
    except Exception as e:
        logger.error(f"User validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User validation failed"
        )


# Role-based access control dependencies
def require_admin(
    current_user: TokenPayload = Depends(get_current_active_user)
) -> TokenPayload:
    """Require admin role."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


def require_analyst_or_admin(
    current_user: TokenPayload = Depends(get_current_active_user)
) -> TokenPayload:
    """Require analyst or admin role."""
    if current_user.role not in [UserRole.ANALYST, UserRole.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or admin access required"
        )
    return current_user


# Permission-based access control
def require_permission(permission: str):
    """Create dependency that requires specific permission."""
    def permission_checker(
        current_user: TokenPayload = Depends(get_current_active_user)
    ) -> TokenPayload:
        if permission not in current_user.permissions and current_user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission}"
            )
        return current_user
    
    return permission_checker


# Optional authentication (for endpoints that work with or without auth)
async def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(get_auth_service)
) -> Optional[TokenPayload]:
    """Get current user if authenticated, otherwise None."""
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        token = auth_header.split(" ")[1]
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token
        )
        
        return await auth_service.get_current_user(credentials, db)
    except Exception:
        # Authentication failed, but that's okay for optional auth
        return None


# WebSocket authentication helper
async def authenticate_websocket(
    token: str,
    db: Session,
    auth_service: AuthService = None
) -> TokenPayload:
    """Authenticate WebSocket connection using JWT token."""
    if not auth_service:
        auth_service = get_auth_service()
    
    try:
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token
        )
        
        return await auth_service.get_current_user(credentials, db)
    except Exception as e:
        logger.error(f"WebSocket authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="WebSocket authentication failed"
        )


# Rate limiting dependencies (can be combined with auth)
class RateLimitError(HTTPException):
    """Rate limit exceeded error."""
    def __init__(self, detail: str = "Rate limit exceeded"):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers={"Retry-After": "60"}
        )


def rate_limit_user(requests_per_minute: int = 60):
    """Rate limit per authenticated user."""
    from collections import defaultdict
    from datetime import datetime, timedelta
    
    user_requests = defaultdict(list)
    
    def rate_limiter(
        current_user: TokenPayload = Depends(get_current_active_user)
    ) -> TokenPayload:
        now = datetime.utcnow()
        user_id = current_user.sub
        
        # Clean old requests
        user_requests[user_id] = [
            req_time for req_time in user_requests[user_id]
            if now - req_time < timedelta(minutes=1)
        ]
        
        # Check rate limit
        if len(user_requests[user_id]) >= requests_per_minute:
            raise RateLimitError(
                f"Rate limit exceeded: {requests_per_minute} requests per minute"
            )
        
        # Record this request
        user_requests[user_id].append(now)
        
        return current_user
    
    return rate_limiter


# CSRF protection for state-changing operations
def csrf_protect():
    """CSRF protection for POST/PUT/DELETE operations."""
    def csrf_checker(request: Request) -> None:
        # Check for CSRF token in header or form data
        csrf_token = (
            request.headers.get("X-CSRF-Token") or 
            request.headers.get("X-Requested-With")
        )
        
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            if not csrf_token:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF protection: missing CSRF token"
                )
    
    return csrf_checker


# Audit logging for sensitive operations
def audit_log(operation: str, resource: str = "unknown"):
    """Audit log dependency for tracking sensitive operations."""
    def audit_logger(
        request: Request,
        current_user: TokenPayload = Depends(get_current_active_user)
    ) -> TokenPayload:
        try:
            # Import here to avoid circular imports
            from app.services.audit import get_audit_service
            
            audit_service = get_audit_service()
            audit_service.log_user_action(
                user_id=int(current_user.sub),
                action=operation,
                resource=resource,
                ip_address=request.client.host,
                user_agent=request.headers.get("User-Agent", "Unknown")
            )
        except Exception as e:
            logger.error(f"Audit logging failed: {e}")
            # Don't fail the request due to audit logging issues
        
        return current_user
    
    return audit_logger


# Combine multiple auth requirements
def require_auth_and_permission(permission: str, audit_operation: str = None):
    """Combine authentication, permission check, and audit logging."""
    def combined_auth(
        current_user: TokenPayload = Depends(require_permission(permission)),
        request: Request = None
    ) -> TokenPayload:
        # Audit logging if specified
        if audit_operation and request:
            try:
                from app.services.audit import get_audit_service
                
                audit_service = get_audit_service()
                audit_service.log_user_action(
                    user_id=int(current_user.sub),
                    action=audit_operation,
                    resource=permission,
                    ip_address=request.client.host if request.client else "unknown",
                    user_agent=request.headers.get("User-Agent", "Unknown") if request else "Unknown"
                )
            except Exception as e:
                logger.error(f"Audit logging failed: {e}")
        
        return current_user
    
    return combined_auth


# Export commonly used dependencies
__all__ = [
    "get_current_user",
    "get_current_active_user", 
    "get_current_user_optional",
    "require_admin",
    "require_analyst_or_admin",
    "require_permission",
    "authenticate_websocket",
    "rate_limit_user",
    "csrf_protect",
    "audit_log",
    "require_auth_and_permission"
]
