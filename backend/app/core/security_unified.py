"""
Unified Security Module for PhishNet
Handles authentication, authorization, password hashing, and security middleware
"""

import bcrypt
import jwt
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

from src.common.constants import UserRole, Constants

logger = logging.getLogger(__name__)

# Security bearer for JWT tokens
security = HTTPBearer()


class SecurityManager:
    """Central security management for PhishNet"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.algorithm = Constants.JWT_ALGORITHM
        self.expire_minutes = Constants.JWT_EXPIRE_MINUTES
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=Constants.BCRYPT_ROUNDS)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def create_access_token(self, data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.expire_minutes)
        to_encode.update({"exp": expire})
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
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
