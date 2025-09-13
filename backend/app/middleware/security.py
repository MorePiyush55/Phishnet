"""
Security Headers Middleware for FastAPI

Adds comprehensive security headers to protect against various web vulnerabilities:
- XSS attacks
- Clickjacking
- MIME sniffing
- Information disclosure
- CSRF attacks
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Callable
import time


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all HTTP responses.
    
    This middleware adds essential security headers to protect against
    common web vulnerabilities and improve the overall security posture
    of the application.
    """
    
    def __init__(self, app, strict_csp: bool = False, enable_hsts: bool = True):
        """
        Initialize security headers middleware.
        
        Args:
            app: FastAPI application instance
            strict_csp: Whether to use strict Content Security Policy
            enable_hsts: Whether to enable HTTP Strict Transport Security
        """
        super().__init__(app)
        self.strict_csp = strict_csp
        self.enable_hsts = enable_hsts
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and add security headers to response.
        """
        
        # Process the request
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Add security headers
        self._add_security_headers(response, request)
        
        # Add performance header for monitoring
        response.headers["X-Process-Time"] = str(process_time)
        
        return response
    
    def _add_security_headers(self, response: Response, request: Request):
        """
        Add comprehensive security headers to the response.
        """
        
        # X-Content-Type-Options: Prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # X-Frame-Options: Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # X-XSS-Protection: Enable browser XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer-Policy: Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # X-Permitted-Cross-Domain-Policies: Restrict cross-domain policies
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        
        # X-DNS-Prefetch-Control: Control DNS prefetching
        response.headers["X-DNS-Prefetch-Control"] = "off"
        
        # Content Security Policy
        csp_policy = self._get_content_security_policy(request)
        if csp_policy:
            response.headers["Content-Security-Policy"] = csp_policy
        
        # HTTP Strict Transport Security (HSTS)
        if self.enable_hsts and request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        
        # Cross-Origin policies
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-site"
        
        # Remove server information
        response.headers.pop("Server", None)
        
        # Cache control for sensitive endpoints
        if self._is_sensitive_endpoint(request.url.path):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        # API-specific headers
        if request.url.path.startswith("/api/"):
            response.headers["X-API-Version"] = "1.0"
            response.headers["X-Rate-Limit-Remaining"] = "1000"  # Placeholder
    
    def _get_content_security_policy(self, request: Request) -> str:
        """
        Generate Content Security Policy based on request and configuration.
        """
        
        if self.strict_csp:
            # Strict CSP for production
            return (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "media-src 'none'; "
                "object-src 'none'; "
                "child-src 'none'; "
                "frame-src 'none'; "
                "worker-src 'none'; "
                "frame-ancestors 'none'; "
                "form-action 'self'; "
                "base-uri 'self'; "
                "manifest-src 'self'"
            )
        else:
            # Development-friendly CSP
            return (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https: blob:; "
                "font-src 'self' data:; "
                "connect-src 'self' ws: wss:; "
                "media-src 'self'; "
                "object-src 'none'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'"
            )
    
    def _is_sensitive_endpoint(self, path: str) -> bool:
        """
        Check if the endpoint contains sensitive data that shouldn't be cached.
        """
        sensitive_patterns = [
            "/api/v1/auth/",
            "/api/v1/users/",
            "/api/v1/audit/",
            "/api/v1/admin/",
            "/api/v1/keys/"
        ]
        
        return any(pattern in path for pattern in sensitive_patterns)


class CORSSecurityMiddleware(BaseHTTPMiddleware):
    """
    Secure CORS middleware with strict controls.
    """
    
    def __init__(
        self, 
        app, 
        allowed_origins: list = None,
        allowed_methods: list = None,
        allowed_headers: list = None,
        expose_headers: list = None,
        max_age: int = 600
    ):
        super().__init__(app)
        self.allowed_origins = allowed_origins or ["http://localhost:3000"]
        self.allowed_methods = allowed_methods or ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        self.allowed_headers = allowed_headers or [
            "Content-Type", 
            "Authorization", 
            "X-Requested-With",
            "X-CSRF-Token"
        ]
        self.expose_headers = expose_headers or [
            "X-Total-Count",
            "X-Process-Time"
        ]
        self.max_age = max_age
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Handle CORS with security considerations.
        """
        
        origin = request.headers.get("origin")
        
        # Handle preflight requests
        if request.method == "OPTIONS":
            if origin in self.allowed_origins:
                response = Response()
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allowed_methods)
                response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allowed_headers)
                response.headers["Access-Control-Max-Age"] = str(self.max_age)
                response.headers["Access-Control-Allow-Credentials"] = "true"
                return response
            else:
                return Response(status_code=403)
        
        # Process the request
        response = await call_next(request)
        
        # Add CORS headers for allowed origins
        if origin in self.allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Expose-Headers"] = ", ".join(self.expose_headers)
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple rate limiting middleware for API protection.
    """
    
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.client_requests = {}  # In production, use Redis or similar
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Apply rate limiting based on client IP.
        """
        
        client_ip = self._get_client_ip(request)
        current_time = time.time()
        
        # Clean old entries (simple cleanup)
        cutoff_time = current_time - 60  # 1 minute ago
        self.client_requests = {
            ip: timestamps for ip, timestamps in self.client_requests.items()
            if any(t > cutoff_time for t in timestamps)
        }
        
        # Update client requests
        if client_ip not in self.client_requests:
            self.client_requests[client_ip] = []
        
        # Remove old timestamps for this client
        self.client_requests[client_ip] = [
            t for t in self.client_requests[client_ip] if t > cutoff_time
        ]
        
        # Check rate limit
        if len(self.client_requests[client_ip]) >= self.requests_per_minute:
            response = Response(
                content="Rate limit exceeded", 
                status_code=429,
                headers={
                    "X-RateLimit-Limit": str(self.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(current_time + 60)),
                    "Retry-After": "60"
                }
            )
            return response
        
        # Record this request
        self.client_requests[client_ip].append(current_time)
        
        # Process the request
        response = await call_next(request)
        
        # Add rate limit headers
        remaining = max(0, self.requests_per_minute - len(self.client_requests[client_ip]))
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(current_time + 60))
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Extract client IP address from request.
        """
        # Check for forwarded headers (proxy/load balancer)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"


# Utility function to add all security middleware to FastAPI app
def add_security_middleware(app, config: dict = None):
    """
    Add all security middleware to FastAPI application.
    
    Args:
        app: FastAPI application instance
        config: Configuration dictionary with middleware settings
    """
    
    if config is None:
        config = {}
    
    # Add rate limiting (outermost middleware)
    app.add_middleware(
        RateLimitMiddleware,
        requests_per_minute=config.get("rate_limit", 60)
    )
    
    # Add CORS security
    app.add_middleware(
        CORSSecurityMiddleware,
        allowed_origins=config.get("allowed_origins", ["http://localhost:3000"]),
        allowed_methods=config.get("allowed_methods", ["GET", "POST", "PUT", "DELETE", "OPTIONS"]),
        max_age=config.get("cors_max_age", 600)
    )
    
    # Add security headers (innermost middleware)
    app.add_middleware(
        SecurityHeadersMiddleware,
        strict_csp=config.get("strict_csp", False),
        enable_hsts=config.get("enable_hsts", True)
    )


# Example usage for app initialization
"""
from app.middleware.security import add_security_middleware

# Create FastAPI app
app = FastAPI()

# Add security middleware
security_config = {
    "rate_limit": 100,  # requests per minute
    "allowed_origins": ["http://localhost:3000", "https://yourdomain.com"],
    "strict_csp": False,  # Set to True for production
    "enable_hsts": True
}

add_security_middleware(app, security_config)
"""
