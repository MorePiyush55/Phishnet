"""
Enhanced Security Posture - Production-grade security implementation
CSP, HSTS, secure cookies, JWT validation, input validation, rate limiting
"""

import hashlib
import hmac
import secrets
import time
import json
import logging
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
import jwt
import bcrypt
from fastapi import HTTPException, Request, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class EnhancedSecurityConfig:
    """Enhanced security configuration"""
    # JWT settings
    jwt_secret_key: str = secrets.token_urlsafe(32)
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7
    
    # Password settings
    bcrypt_rounds: int = 12
    min_password_length: int = 12
    require_special_chars: bool = True
    
    # Rate limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_auth_requests_per_minute: int = 5
    rate_limit_api_requests_per_minute: int = 1000
    
    # Security headers
    enable_hsts: bool = True
    hsts_max_age: int = 31536000  # 1 year
    enable_csp: bool = True
    csp_policy: str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    
    # Cookie settings
    secure_cookies: bool = True
    httponly_cookies: bool = True
    samesite_cookies: str = "strict"
    
    # Input validation
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    max_json_depth: int = 10
    max_array_length: int = 1000
    
    # Security level
    security_level: SecurityLevel = SecurityLevel.HIGH

class EnhancedSecurityError(Exception):
    """Security-related error"""
    def __init__(self, message: str, error_code: str = "SECURITY_ERROR"):
        super().__init__(message)
        self.message = message
        self.error_code = error_code

# Pydantic models for input validation
class ValidatedEmailInput(BaseModel):
    """Validated email input"""
    subject: str = Field(..., min_length=1, max_length=998)  # RFC 5322 limit
    sender: str = Field(..., min_length=3, max_length=320, pattern=r'^[^@]+@[^@]+\.[^@]+$')
    recipient: str = Field(..., min_length=3, max_length=320, pattern=r'^[^@]+@[^@]+\.[^@]+$')
    content: str = Field(..., max_length=100000)  # 100KB limit
    headers: Optional[Dict[str, str]] = Field(default_factory=dict)
    
    @validator('headers')
    def validate_headers(cls, v):
        if v and len(v) > 50:  # Limit header count
            raise ValueError('Too many headers')
        return v
    
    @validator('content')
    def validate_content(cls, v):
        # Check for suspicious patterns
        suspicious_patterns = ['<script', 'javascript:', 'vbscript:', 'data:text/html']
        content_lower = v.lower()
        for pattern in suspicious_patterns:
            if pattern in content_lower:
                logger.warning(f"Suspicious pattern detected: {pattern}")
        return v

class ValidatedURLInput(BaseModel):
    """Validated URL input"""
    url: str = Field(..., min_length=7, max_length=2048)
    
    @validator('url')
    def validate_url(cls, v):
        try:
            parsed = urlparse(v)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError('Invalid URL format')
            if parsed.scheme not in ['http', 'https']:
                raise ValueError('Only HTTP/HTTPS URLs allowed')
            return v
        except Exception:
            raise ValueError('Invalid URL')

class EnhancedJWTHandler:
    """Enhanced JWT token handling"""
    
    def __init__(self, config: EnhancedSecurityConfig):
        self.config = config
        self.security = HTTPBearer()
    
    def create_access_token(self, data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        try:
            # Add standard claims
            to_encode = data.copy()
            expire = datetime.utcnow() + timedelta(minutes=self.config.jwt_access_token_expire_minutes)
            to_encode.update({
                "exp": expire,
                "iat": datetime.utcnow(),
                "type": "access",
                "jti": secrets.token_urlsafe(16)  # JWT ID for revocation
            })
            
            encoded_jwt = jwt.encode(
                to_encode, 
                self.config.jwt_secret_key, 
                algorithm=self.config.jwt_algorithm
            )
            return encoded_jwt
        except Exception as e:
            logger.error(f"Token creation failed: {e}")
            raise EnhancedSecurityError("Token creation failed")
    
    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create JWT refresh token"""
        try:
            to_encode = data.copy()
            expire = datetime.utcnow() + timedelta(days=self.config.jwt_refresh_token_expire_days)
            to_encode.update({
                "exp": expire,
                "iat": datetime.utcnow(),
                "type": "refresh",
                "jti": secrets.token_urlsafe(16)
            })
            
            encoded_jwt = jwt.encode(
                to_encode, 
                self.config.jwt_secret_key, 
                algorithm=self.config.jwt_algorithm
            )
            return encoded_jwt
        except Exception as e:
            logger.error(f"Refresh token creation failed: {e}")
            raise EnhancedSecurityError("Refresh token creation failed")
    
    def verify_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token, 
                self.config.jwt_secret_key, 
                algorithms=[self.config.jwt_algorithm]
            )
            
            # Verify token type
            if payload.get("type") != token_type:
                raise EnhancedSecurityError("Invalid token type")
            
            return payload
        except jwt.ExpiredSignatureError:
            raise EnhancedSecurityError("Token has expired", "TOKEN_EXPIRED")
        except jwt.InvalidTokenError as e:
            raise EnhancedSecurityError(f"Invalid token: {e}", "INVALID_TOKEN")

class EnhancedPasswordManager:
    """Enhanced password management with bcrypt"""
    
    def __init__(self, config: EnhancedSecurityConfig):
        self.config = config
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        if len(password) < self.config.min_password_length:
            raise EnhancedSecurityError(f"Password must be at least {self.config.min_password_length} characters")
        
        salt = bcrypt.gensalt(rounds=self.config.bcrypt_rounds)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False
    
    def validate_password_strength(self, password: str) -> bool:
        """Validate password strength"""
        if len(password) < self.config.min_password_length:
            return False
        
        if self.config.require_special_chars:
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
            
            return all([has_upper, has_lower, has_digit, has_special])
        
        return True

class EnhancedSecurityMiddleware(BaseHTTPMiddleware):
    """Enhanced security middleware for FastAPI"""
    
    def __init__(self, app, config: EnhancedSecurityConfig):
        super().__init__(app)
        self.config = config
        self.rate_limits = {}  # Simple in-memory rate limiting
    
    async def dispatch(self, request: Request, call_next: Callable):
        """Process request through security middleware"""
        
        # Rate limiting (simple implementation)
        client_ip = request.client.host
        current_time = time.time()
        
        # Clean old entries
        self.rate_limits = {
            ip: times for ip, times in self.rate_limits.items()
            if any(t > current_time - 60 for t in times)  # Keep last minute
        }
        
        # Check rate limit
        if client_ip in self.rate_limits:
            recent_requests = [t for t in self.rate_limits[client_ip] if t > current_time - 60]
            if len(recent_requests) >= self.config.rate_limit_requests_per_minute:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"}
                )
            self.rate_limits[client_ip] = recent_requests + [current_time]
        else:
            self.rate_limits[client_ip] = [current_time]
        
        # Request size validation
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.config.max_request_size:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request too large"}
            )
        
        # Process request
        response = await call_next(request)
        
        # Add security headers
        self._add_security_headers(response)
        
        return response
    
    def _add_security_headers(self, response: Response):
        """Add security headers to response"""
        
        # HSTS
        if self.config.enable_hsts:
            response.headers["Strict-Transport-Security"] = f"max-age={self.config.hsts_max_age}; includeSubDomains"
        
        # CSP
        if self.config.enable_csp:
            response.headers["Content-Security-Policy"] = self.config.csp_policy
        
        # Additional security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

class EnhancedInputValidator:
    """Enhanced input validation"""
    
    def __init__(self, config: EnhancedSecurityConfig):
        self.config = config
    
    def validate_json_depth(self, data: Any, current_depth: int = 0) -> bool:
        """Validate JSON nesting depth"""
        if current_depth > self.config.max_json_depth:
            return False
        
        if isinstance(data, dict):
            return all(self.validate_json_depth(v, current_depth + 1) for v in data.values())
        elif isinstance(data, list):
            if len(data) > self.config.max_array_length:
                return False
            return all(self.validate_json_depth(item, current_depth + 1) for item in data)
        
        return True
    
    def sanitize_string(self, value: str) -> str:
        """Sanitize string input"""
        # Remove null bytes and control characters
        value = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
        
        # Limit length
        if len(value) > 10000:
            value = value[:10000]
        
        return value.strip()
    
    def validate_email_content(self, content: str) -> bool:
        """Validate email content for security"""
        # Check for extremely long lines
        lines = content.split('\n')
        for line in lines:
            if len(line) > 1000:
                logger.warning("Email content contains very long lines")
                return False
        
        # Check for suspicious byte patterns
        suspicious_patterns = [
            '\x00',  # Null bytes
            '\xff\xfe',  # UTF-16 BOM
            '\xfe\xff',  # UTF-16 BE BOM
        ]
        
        for pattern in suspicious_patterns:
            if pattern in content:
                logger.warning(f"Suspicious pattern detected: {pattern}")
                return False
        
        return True

class EnhancedSecurityAuditLogger:
    """Enhanced security event audit logging"""
    
    def __init__(self):
        self.logger = logging.getLogger('security_audit')
        
        # Configure separate handler for security logs
        if not self.logger.handlers:
            handler = logging.FileHandler('security_audit.log')
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def log_authentication_attempt(self, email: str, success: bool, ip: str, user_agent: str = ""):
        """Log authentication attempt"""
        self.logger.info(f"AUTH_ATTEMPT: email={email}, success={success}, ip={ip}, user_agent={user_agent}")
    
    def log_authorization_failure(self, user_id: str, resource: str, action: str, ip: str = ""):
        """Log authorization failure"""
        self.logger.warning(f"AUTH_FAILURE: user={user_id}, resource={resource}, action={action}, ip={ip}")
    
    def log_rate_limit_exceeded(self, ip: str, endpoint: str, user_agent: str = ""):
        """Log rate limit exceeded"""
        self.logger.warning(f"RATE_LIMIT: ip={ip}, endpoint={endpoint}, user_agent={user_agent}")
    
    def log_input_validation_failure(self, input_type: str, error: str, ip: str, user_id: str = ""):
        """Log input validation failure"""
        self.logger.warning(f"INPUT_VALIDATION: type={input_type}, error={error}, ip={ip}, user={user_id}")
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log general security event"""
        details_str = json.dumps(details, default=str)
        self.logger.info(f"SECURITY_EVENT: type={event_type}, details={details_str}")

class EnhancedPhishNetSecurity:
    """Enhanced centralized security manager for PhishNet"""
    
    def __init__(self, config: Optional[EnhancedSecurityConfig] = None):
        self.config = config or EnhancedSecurityConfig()
        self.jwt_handler = EnhancedJWTHandler(self.config)
        self.password_manager = EnhancedPasswordManager(self.config)
        self.input_validator = EnhancedInputValidator(self.config)
        self.audit_logger = EnhancedSecurityAuditLogger()
    
    def get_security_middleware(self):
        """Get enhanced security middleware for FastAPI"""
        return lambda app: EnhancedSecurityMiddleware(app, self.config)
    
    def require_permission(self, required_permission: str):
        """Decorator to require specific permission"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract current user from kwargs
                current_user = kwargs.get('current_user')
                if not current_user:
                    raise HTTPException(status_code=401, detail="Authentication required")
                
                permissions = current_user.get('permissions', [])
                if required_permission not in permissions and 'admin' not in permissions:
                    self.audit_logger.log_authorization_failure(
                        current_user.get('user_id'),
                        required_permission,
                        func.__name__
                    )
                    raise HTTPException(status_code=403, detail="Insufficient permissions")
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    def validate_and_sanitize_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize input data"""
        if not self.input_validator.validate_json_depth(input_data):
            raise EnhancedSecurityError("Input data too deeply nested")
        
        # Recursively sanitize strings
        def sanitize_recursive(obj):
            if isinstance(obj, str):
                return self.input_validator.sanitize_string(obj)
            elif isinstance(obj, dict):
                return {k: sanitize_recursive(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [sanitize_recursive(item) for item in obj]
            return obj
        
        return sanitize_recursive(input_data)
    
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
        """Get current user from JWT token"""
        try:
            payload = self.jwt_handler.verify_token(credentials.credentials)
            user_id = payload.get("sub")
            if user_id is None:
                raise EnhancedSecurityError("Invalid token payload")
            
            # Log successful token validation
            self.audit_logger.log_security_event("token_validation", {
                "user_id": user_id,
                "success": True
            })
            
            return {
                "user_id": user_id,
                "email": payload.get("email"),
                "role": payload.get("role"),
                "permissions": payload.get("permissions", [])
            }
        except EnhancedSecurityError as e:
            self.audit_logger.log_security_event("token_validation", {
                "error": str(e),
                "success": False
            })
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")

# Global enhanced security instance
_enhanced_security_instance = None

def get_enhanced_security() -> EnhancedPhishNetSecurity:
    """Get global enhanced security instance"""
    global _enhanced_security_instance
    if _enhanced_security_instance is None:
        _enhanced_security_instance = EnhancedPhishNetSecurity()
    return _enhanced_security_instance

# Convenience functions for enhanced security
def require_enhanced_auth():
    """Dependency for requiring authentication with enhanced security"""
    return Depends(get_enhanced_security().get_current_user)

def require_enhanced_admin():
    """Dependency for requiring admin role with enhanced security"""
    async def admin_required(current_user = Depends(require_enhanced_auth())):
        if current_user.get('role') != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        return current_user
    return Depends(admin_required)

# Example usage
def example_enhanced_security_usage():
    """Example of using enhanced security features"""
    
    # Initialize enhanced security with custom config
    config = EnhancedSecurityConfig(
        security_level=SecurityLevel.CRITICAL,
        rate_limit_requests_per_minute=30,
        jwt_access_token_expire_minutes=5,
        bcrypt_rounds=14
    )
    
    security = EnhancedPhishNetSecurity(config)
    
    # Hash password with bcrypt
    password_hash = security.password_manager.hash_password("SecureP@ssw0rd123!")
    print(f"Bcrypt password hash: {password_hash}")
    
    # Verify password
    is_valid = security.password_manager.verify_password("SecureP@ssw0rd123!", password_hash)
    print(f"Password valid: {is_valid}")
    
    # Create JWT token
    token_data = {"sub": "user123", "email": "user@example.com", "role": "admin"}
    access_token = security.jwt_handler.create_access_token(token_data)
    print(f"Enhanced access token: {access_token}")
    
    # Validate input
    test_input = {"email": "test@example.com", "content": "Safe content"}
    sanitized = security.validate_and_sanitize_input(test_input)
    print(f"Sanitized input: {sanitized}")

# Example usage is now available via CLI: python phishnet-cli.py demo security
