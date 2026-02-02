"""
CSRF Protection Middleware for FastAPI

Implements Cross-Site Request Forgery protection using double-submit cookie pattern.
"""

from fastapi import Request, HTTPException, status
from fastapi.responses import Response
from typing import Callable
import secrets
import hashlib
import hmac


class CSRFProtection:
    """
    CSRF protection using double-submit cookie pattern.
    
    How it works:
    1. Server generates CSRF token and sends it in cookie
    2. Client must include same token in request header
    3. Server validates both match
    """
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode()
        self.cookie_name = "csrf_token"
        self.header_name = "X-CSRF-Token"
    
    def generate_token(self) -> str:
        """Generate a new CSRF token."""
        random_bytes = secrets.token_bytes(32)
        return secrets.token_urlsafe(32)
    
    def create_token_hash(self, token: str) -> str:
        """Create HMAC hash of token for validation."""
        return hmac.new(
            self.secret_key,
            token.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def validate_token(self, cookie_token: str, header_token: str) -> bool:
        """
        Validate CSRF token.
        
        Args:
            cookie_token: Token from cookie
            header_token: Token from request header
        
        Returns:
            True if tokens match and are valid
        """
        if not cookie_token or not header_token:
            return False
        
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(cookie_token, header_token)


class CSRFMiddleware:
    """
    FastAPI middleware for CSRF protection.
    """
    
    def __init__(self, app, secret_key: str):
        self.app = app
        self.csrf = CSRFProtection(secret_key)
        
        # Methods that require CSRF protection
        self.protected_methods = {"POST", "PUT", "PATCH", "DELETE"}
        
        # Paths to exclude from CSRF protection
        self.excluded_paths = {
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/health",
            "/health/detailed",
            "/docs",
            "/redoc",
            "/openapi.json",
        }
    
    async def __call__(self, request: Request, call_next: Callable):
        # Skip CSRF for excluded paths
        if request.url.path in self.excluded_paths:
            return await call_next(request)
        
        # Skip CSRF for safe methods (GET, HEAD, OPTIONS)
        if request.method not in self.protected_methods:
            response = await call_next(request)
            
            # Set CSRF token cookie for safe requests
            if self.csrf.cookie_name not in request.cookies:
                token = self.csrf.generate_token()
                response.set_cookie(
                    key=self.csrf.cookie_name,
                    value=token,
                    httponly=True,
                    secure=True,  # HTTPS only
                    samesite="strict",
                    max_age=3600 * 24,  # 24 hours
                )
            
            return response
        
        # Validate CSRF token for protected methods
        cookie_token = request.cookies.get(self.csrf.cookie_name)
        header_token = request.headers.get(self.csrf.header_name)
        
        if not self.csrf.validate_token(cookie_token, header_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token validation failed"
            )
        
        # Token is valid, proceed with request
        response = await call_next(request)
        return response


# ==================== Helper Functions ====================

def get_csrf_token(request: Request) -> str:
    """
    Get CSRF token from request cookie.
    
    Usage in templates:
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    """
    return request.cookies.get("csrf_token", "")


def set_csrf_cookie(response: Response, token: str):
    """
    Set CSRF token cookie on response.
    
    Args:
        response: FastAPI Response object
        token: CSRF token to set
    """
    response.set_cookie(
        key="csrf_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=3600 * 24,  # 24 hours
    )


# ==================== Usage Example ====================

"""
# In main.py:

from app.middleware.csrf_protection import CSRFMiddleware
from app.core.config import settings

app = FastAPI()

# Add CSRF middleware
app.add_middleware(CSRFMiddleware, secret_key=settings.SECRET_KEY)


# In frontend (JavaScript):

// Get CSRF token from cookie
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// Include CSRF token in requests
const csrfToken = getCookie('csrf_token');

fetch('/api/v1/inbox/emails', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,  // Include token in header
    },
    body: JSON.stringify(data),
});
"""
