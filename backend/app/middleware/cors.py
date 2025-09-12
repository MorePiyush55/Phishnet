"""CORS and security middleware."""

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

from app.config.settings import settings
from app.services.sanitizer import content_sanitizer


def add_cors_middleware(app: FastAPI):
    """Add CORS middleware with strict configuration."""
    
    # Define allowed origins
    allowed_origins = [
        "http://localhost:3000",  # React development server
        "http://localhost:8080",  # Alternative frontend port
        settings.BASE_URL
    ]
    
    if settings.DEBUG:
        # Allow all origins in development
        allowed_origins = ["*"]
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Content-Type",
            "Authorization",
            "X-Requested-With",
            "X-CSRF-Token"
        ],
        expose_headers=["X-Request-ID", "X-Rate-Limit-Remaining"]
    )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Content Security Policy
        response.headers["Content-Security-Policy"] = content_sanitizer.get_content_security_policy()
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # HSTS (only in production with HTTPS)
        if not settings.DEBUG and request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Remove server header
        response.headers.pop("server", None)
        
        return response


def add_security_middleware(app: FastAPI):
    """Add security middleware to the application."""
    app.add_middleware(SecurityHeadersMiddleware)
