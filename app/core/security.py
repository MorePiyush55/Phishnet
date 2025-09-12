"""
Enhanced Security Module for PhishNet
Handles JWT authentication, role-based authorization, password hashing, and security middleware
"""

import bcrypt
import jwt
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from enum import Enum
from fastapi import HTTPException, Request, Response, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db

from app.core.database import get_db

logger = get_logger(__name__)

# Enhanced User Roles with detailed permissions
class UserRole(str, Enum):
    ADMIN = "admin"           # Full system access
    ANALYST = "analyst"       # Analysis and reporting access  
    VIEWER = "viewer"         # Read-only access
    READONLY = "readonly"     # Limited read access
    
class Permission(str, Enum):
    READ_EMAILS = "read_emails"
    ANALYZE_EMAILS = "analyze_emails" 
    MANAGE_USERS = "manage_users"
    VIEW_REPORTS = "view_reports"
    MANAGE_SETTINGS = "manage_settings"
    ACCESS_API = "access_api"
    BULK_OPERATIONS = "bulk_operations"
    EXPORT_DATA = "export_data"

# Role-based permissions mapping
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        Permission.READ_EMAILS, Permission.ANALYZE_EMAILS, Permission.MANAGE_USERS,
        Permission.VIEW_REPORTS, Permission.MANAGE_SETTINGS, Permission.ACCESS_API,
        Permission.BULK_OPERATIONS, Permission.EXPORT_DATA
    ],
    UserRole.ANALYST: [
        Permission.READ_EMAILS, Permission.ANALYZE_EMAILS, Permission.VIEW_REPORTS,
        Permission.ACCESS_API, Permission.EXPORT_DATA
    ],
    UserRole.VIEWER: [
        Permission.READ_EMAILS, Permission.VIEW_REPORTS, Permission.ACCESS_API
    ],
    UserRole.READONLY: [
        Permission.READ_EMAILS
    ]
}

# Security bearer for JWT tokens
security = HTTPBearer()


class SecurityManager:
    """Enhanced security management for PhishNet with role-based access control"""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or settings.SECRET_KEY
        self.algorithm = "HS256"
        self.expire_minutes = 30
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token with role and permissions"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.expire_minutes)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        })
        
        # Add permissions based on role
        user_role = data.get("role", UserRole.READONLY)
        permissions = ROLE_PERMISSIONS.get(UserRole(user_role), [])
        to_encode["permissions"] = [p.value for p in permissions]
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, user_id: int) -> str:
        """Create refresh token for token renewal"""
        to_encode = {
            "user_id": user_id,
            "type": "refresh",
            "exp": datetime.utcnow() + timedelta(days=7),
            "iat": datetime.utcnow()
        }
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"}
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"}
            )
    
    def check_permission(self, user_permissions: List[str], required_permission: Permission) -> bool:
        """Check if user has required permission"""
        return required_permission.value in user_permissions
    
    def get_user_permissions(self, role: UserRole) -> List[str]:
        """Get permissions for a user role"""
        permissions = ROLE_PERMISSIONS.get(role, [])
        return [p.value for p in permissions]


# Global security manager instance
security_manager = SecurityManager()

# Authentication dependency functions
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), 
                          db: Session = Depends(get_db)):
    """Get current authenticated user"""
    try:
        payload = security_manager.verify_token(credentials.credentials)
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )
        
        # In a real implementation, you'd fetch user from database
        # For now, return user data from token payload
        user_data = {
            "id": user_id,
            "email": payload.get("email"),
            "role": payload.get("role", UserRole.READONLY),
            "permissions": payload.get("permissions", []),
            "organization_id": payload.get("organization_id")
        }
        
        return user_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

def require_permission(permission: Permission):
    """Decorator factory for permission-based access control"""
    def permission_checker(current_user: dict = Depends(get_current_user)):
        user_permissions = current_user.get("permissions", [])
        
        if not security_manager.check_permission(user_permissions, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {permission.value}"
            )
        
        return current_user
    
    return permission_checker

def require_role(required_role: UserRole):
    """Decorator factory for role-based access control"""
    def role_checker(current_user: dict = Depends(get_current_user)):
        user_role = UserRole(current_user.get("role", UserRole.READONLY))
        
        # Role hierarchy: admin > analyst > viewer > readonly
        role_hierarchy = {
            UserRole.READONLY: 0,
            UserRole.VIEWER: 1, 
            UserRole.ANALYST: 2,
            UserRole.ADMIN: 3
        }
        
        if role_hierarchy.get(user_role, 0) < role_hierarchy.get(required_role, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role. Required: {required_role.value}, Current: {user_role.value}"
            )
        
        return current_user
    
    return role_checker

# Convenience dependency for common roles
require_admin = require_role(UserRole.ADMIN)
require_analyst = require_role(UserRole.ANALYST) 
require_viewer = require_role(UserRole.VIEWER)

# Convenience dependency for common permissions
require_email_analysis = require_permission(Permission.ANALYZE_EMAILS)
require_user_management = require_permission(Permission.MANAGE_USERS)
require_reports_access = require_permission(Permission.VIEW_REPORTS)
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    def get_current_user(self, credentials: HTTPAuthorizationCredentials) -> Dict[str, Any]:
        """Get current user from JWT token"""
        token = credentials.credentials
        return self.verify_token(token)
    
    def check_role_permission(self, user_role: UserRole, required_role: UserRole) -> bool:
        """Check if user role has permission for required role"""
        role_hierarchy = {
            UserRole.USER: 1,
            UserRole.ANALYST: 2,
            UserRole.ADMIN: 3,
            UserRole.SYSTEM: 4
        }
        
        return role_hierarchy.get(user_role, 0) >= role_hierarchy.get(required_role, 0)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for adding security headers and protection"""
    
    async def dispatch(self, request: Request, call_next):
        # Process request
        response = await call_next(request)
        
        # Add security headers
        for header, value in Constants.SECURITY_HEADERS.items():
            response.headers[header] = value
        
        # Add HSTS header for HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Add CSP header
        response.headers["Content-Security-Policy"] = Constants.CSP_POLICY
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware (placeholder - would integrate with Redis)"""
    
    def __init__(self, app, redis_client=None):
        super().__init__(app)
        self.redis_client = redis_client
    
    async def dispatch(self, request: Request, call_next):
        # For now, just pass through
        # In production, implement Redis-based rate limiting
        if self.redis_client:
            # TODO: Implement rate limiting logic
            pass
        
        return await call_next(request)


# Global security manager instance (to be initialized with secret key)
_security_manager: Optional[SecurityManager] = None


def init_security(secret_key: str) -> SecurityManager:
    """Initialize global security manager"""
    global _security_manager
    _security_manager = SecurityManager(secret_key)
    return _security_manager


def get_security_manager() -> SecurityManager:
    """Get global security manager instance"""
    if _security_manager is None:
        raise RuntimeError("Security manager not initialized. Call init_security() first.")
    return _security_manager


# Convenience functions for backward compatibility
def hash_password(password: str) -> str:
    """Hash password using global security manager"""
    return get_security_manager().hash_password(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify password using global security manager"""
    return get_security_manager().verify_password(password, hashed)


def create_access_token(data: Dict[str, Any]) -> str:
    """Create access token using global security manager"""
    return get_security_manager().create_access_token(data)


def verify_token(token: str) -> Dict[str, Any]:
    """Verify token using global security manager"""
    return get_security_manager().verify_token(token)


def get_current_user(credentials: HTTPAuthorizationCredentials) -> Dict[str, Any]:
    """Get current user using global security manager"""
    return get_security_manager().get_current_user(credentials)


def check_role_permission(user_role: UserRole, required_role: UserRole) -> bool:
    """Check role permission using global security manager"""
    return get_security_manager().check_role_permission(user_role, required_role)
