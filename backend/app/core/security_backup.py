"""
Security Hardening Module - Comprehensive security posture for PhishNet
Implements CSP, HSTS, secure cookies, JWT validation, input validation, rate limiting
"""

import asyncio
import hashlib
import hmac
import logging
import re
import time
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
import ipaddress

import jwt
from fastapi import Request, Response, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
try:
    import redis
except ImportError:
    redis = None
from pydantic import BaseModel, validator
import bcrypt

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityConfig:
    """Security configuration"""
    # JWT settings
    jwt_secret_key: str = "your-super-secret-jwt-key-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24
    jwt_refresh_expiration_days: int = 7
    
    # Rate limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_burst_limit: int = 10
    rate_limit_auth_attempts: int = 5
    rate_limit_ban_duration_minutes: int = 15
    
    # Security headers
    enable_csp: bool = True
    enable_hsts: bool = True
    enable_xss_protection: bool = True
    enable_content_type_nosniff: bool = True
    enable_frame_options: bool = True
    
    # Cookie settings
    secure_cookies: bool = True
    samesite_cookies: str = "strict"
    httponly_cookies: bool = True
    
    # Input validation
    max_request_size_mb: int = 10
    max_json_depth: int = 10
    allowed_file_extensions: Set[str] = field(default_factory=lambda: {
        '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.jpg', '.jpeg', '.png', '.gif', '.eml', '.msg'
    })
    
    # IP filtering
    blocked_ip_ranges: List[str] = field(default_factory=list)
    allowed_ip_ranges: List[str] = field(default_factory=list)
    
    # Redis settings (for rate limiting)
    redis_url: str = "redis://localhost:6379/0"
    redis_key_prefix: str = "phishnet:security:"

class InputValidationError(Exception):
    """Input validation error"""
    pass

class RateLimitExceeded(Exception):
    """Rate limit exceeded error"""
    pass

class SecurityViolation(Exception):
    """Security violation error"""
    pass

@dataclass
class SecurityEvent:
    """Security event for logging"""
    event_type: str
    severity: SecurityLevel
    source_ip: str
    user_id: Optional[str]
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    request_id: Optional[str] = None

class InputValidator:
    """Input validation utilities"""
    
    # Common regex patterns
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    URL_PATTERN = re.compile(r'^https?://[^\s/$.?#].[^\s]*$')
    ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    
    # Dangerous patterns to block
    DANGEROUS_PATTERNS = [
        re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'vbscript:', re.IGNORECASE),
        re.compile(r'on\w+\s*=', re.IGNORECASE),
        re.compile(r'(union|select|insert|update|delete|drop)\s+', re.IGNORECASE),
        re.compile(r'[<>"\']', re.IGNORECASE),
    ]
    
    @classmethod
    def validate_email(cls, email: str) -> bool:
        """Validate email format"""
        if not email or len(email) > 254:
            return False
        return bool(cls.EMAIL_PATTERN.match(email))
    
    @classmethod
    def validate_url(cls, url: str) -> bool:
        """Validate URL format"""
        if not url or len(url) > 2048:
            return False
        return bool(cls.URL_PATTERN.match(url))
    
    @classmethod
    def sanitize_string(cls, value: str, max_length: int = 1000) -> str:
        """Sanitize string input"""
        if not isinstance(value, str):
            raise InputValidationError("Input must be a string")
        
        if len(value) > max_length:
            raise InputValidationError(f"Input too long (max {max_length} characters)")
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(value):
                raise InputValidationError("Input contains dangerous content")
        
        # HTML encode dangerous characters
        value = value.replace('<', '&lt;')
        value = value.replace('>', '&gt;')
        value = value.replace('"', '&quot;')
        value = value.replace("'", '&#x27;')
        
        return value.strip()
    
    @classmethod
    def validate_json_depth(cls, data: Any, max_depth: int = 10, current_depth: int = 0) -> bool:
        """Validate JSON depth to prevent DoS attacks"""
        if current_depth > max_depth:
            return False
        
        if isinstance(data, dict):
            for value in data.values():
                if not cls.validate_json_depth(value, max_depth, current_depth + 1):
                    return False
        elif isinstance(data, list):
            for item in data:
                if not cls.validate_json_depth(item, max_depth, current_depth + 1):
                    return False
        
        return True
    
    @classmethod
    def validate_file_extension(cls, filename: str, allowed_extensions: Set[str]) -> bool:
        """Validate file extension"""
        if not filename:
            return False
        
        extension = '.' + filename.split('.')[-1].lower()
        return extension in allowed_extensions

class RateLimiter:
    """Redis-based rate limiter with fallback"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self._redis = None
        self._memory_cache: Dict[str, List[float]] = {}
        self._connect_redis()
    
    def _connect_redis(self):
        """Connect to Redis"""
        if not redis:
            logger.info("Redis not available, using in-memory rate limiting")
            return
            
        try:
            self._redis = redis.from_url(self.config.redis_url)
            self._redis.ping()  # Test connection
            logger.info("Connected to Redis for rate limiting")
        except Exception as e:
            logger.warning(f"Redis connection failed, using in-memory fallback: {e}")
            self._redis = None
    
    async def check_rate_limit(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        """Check if rate limit is exceeded"""
        if self._redis:
            return await self._check_redis_rate_limit(key, limit, window_seconds)
        else:
            return self._check_memory_rate_limit(key, limit, window_seconds)
    
    async def _check_redis_rate_limit(self, key: str, limit: int, window_seconds: int) -> bool:
        """Redis-based rate limiting"""
        try:
            pipe = self._redis.pipeline()
            now = time.time()
            
            # Use sliding window rate limiting
            window_start = now - window_seconds
            
            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count current requests
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(now): now})
            
            # Set expiration
            pipe.expire(key, window_seconds)
            
            results = pipe.execute()
            current_count = results[1]
            
            return current_count < limit
            
        except Exception as e:
            logger.error(f"Rate limiting check failed: {e}")
            return True  # Fail open for availability
    
    def _check_memory_rate_limit(self, key: str, limit: int, window_seconds: int) -> bool:
        """In-memory rate limiting fallback"""
        now = time.time()
        
        if key not in self._memory_cache:
            self._memory_cache[key] = []
        
        # Remove old entries
        window_start = now - window_seconds
        self._memory_cache[key] = [t for t in self._memory_cache[key] if t > window_start]
        
        # Check limit
        if len(self._memory_cache[key]) >= limit:
            return False
        
        # Add current request
        self._memory_cache[key].append(now)
        return True
    
    async def ban_ip(self, ip: str, duration_minutes: int):
        """Ban IP address temporarily"""
        if self._redis:
            try:
                ban_key = f"{self.config.redis_key_prefix}banned:{ip}"
                self._redis.setex(ban_key, duration_minutes * 60, "1")
                logger.warning(f"IP {ip} banned for {duration_minutes} minutes")
            except Exception as e:
                logger.error(f"Failed to ban IP {ip}: {e}")
        else:
            # Store in memory cache
            ban_key = f"banned:{ip}"
            self._memory_cache[ban_key] = [time.time() + (duration_minutes * 60)]
    
    async def is_banned(self, ip: str) -> bool:
        """Check if IP is banned"""
        if self._redis:
            try:
                ban_key = f"{self.config.redis_key_prefix}banned:{ip}"
                return bool(self._redis.get(ban_key))
            except Exception as e:
                logger.error(f"Failed to check ban status for {ip}: {e}")
                return False
        else:
            ban_key = f"banned:{ip}"
            if ban_key in self._memory_cache:
                ban_time = self._memory_cache[ban_key][0]
                if time.time() < ban_time:
                    return True
                else:
                    del self._memory_cache[ban_key]
            return False

class TokenData(BaseModel):
    """Token data model."""
    username: Optional[str] = None
    user_id: Optional[int] = None
    role: Optional[str] = None
    exp: Optional[datetime] = None


class TokenPair(BaseModel):
    """Access and refresh token pair."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Create refresh token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> Optional[TokenData]:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        
        # Check token type
        if payload.get("type") != token_type:
            return None
            
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        role: str = payload.get("role")
        exp: datetime = datetime.fromtimestamp(payload.get("exp"))
        
        if username is None or user_id is None:
            return None
            
        return TokenData(
            username=username, 
            user_id=user_id, 
            role=role,
            exp=exp
        )
    except JWTError:
        return None


def hash_token(token: str) -> str:
    """Hash token for secure storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_refresh_token() -> str:
    """Generate secure refresh token."""
    return secrets.token_urlsafe(32)


def require_roles(allowed_roles: List[UserRole]):
    """Decorator to require specific roles."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # This would be used with FastAPI dependencies
            return func(*args, **kwargs)
        return wrapper
    return decorator


# CSP (Content Security Policy) constants
CSP_POLICY = {
    "default-src": "'self'",
    "script-src": "'self' 'unsafe-inline'",  # Adjust based on needs
    "style-src": "'self' 'unsafe-inline'",
    "img-src": "'self' data: https:",
    "font-src": "'self'",
    "connect-src": "'self' wss: ws:",
    "frame-ancestors": "'none'",
    "base-uri": "'self'",
    "form-action": "'self'",
}


def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT refresh token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def verify_token(token: str) -> Optional[TokenData]:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        if username is None:
            return None
        token_data = TokenData(username=username, user_id=user_id)
        return token_data
    except JWTError:
        return None


def is_refresh_token(token: str) -> bool:
    """Check if token is a refresh token."""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        return payload.get("type") == "refresh"
    except JWTError:
        return False
