"""Middleware for FastAPI application."""

import time
from typing import Optional

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import redis.asyncio as redis
from starlette.middleware.base import BaseHTTPMiddleware

from app.config.settings import settings
from app.config.logging import get_logger

logger = get_logger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis."""
    
    def __init__(self, app: FastAPI, redis_client: redis.Redis):
        super().__init__(app)
        self.redis = redis_client
    
    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting."""
        client_ip = request.client.host
        user_id = getattr(request.state, "user_id", None)
        
        # Create rate limit key
        key = f"rate_limit:{user_id or client_ip}"
        
        # Check rate limit
        current = await self.redis.get(key)
        if current and int(current) >= settings.RATE_LIMIT_PER_MINUTE:
            logger.warning(
                "Rate limit exceeded",
                client_ip=client_ip,
                user_id=user_id,
                current=current,
            )
            return Response(
                content="Rate limit exceeded",
                status_code=429,
                headers={"Retry-After": "60"},
            )
        
        # Increment counter
        pipe = self.redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, 60)  # 1 minute window
        await pipe.execute()
        
        response = await call_next(request)
        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """Request logging middleware."""
    
    async def dispatch(self, request: Request, call_next):
        """Log request and response."""
        start_time = time.time()
        
        # Log request
        logger.info(
            "Request started",
            method=request.method,
            url=str(request.url),
            client_ip=request.client.host,
            user_agent=request.headers.get("user-agent"),
        )
        
        response = await call_next(request)
        
        # Log response
        process_time = time.time() - start_time
        logger.info(
            "Request completed",
            method=request.method,
            url=str(request.url),
            status_code=response.status_code,
            process_time=process_time,
        )
        
        # Add process time header
        response.headers["X-Process-Time"] = str(process_time)
        return response


def setup_middleware(app: FastAPI, redis_client: Optional[redis.Redis] = None) -> None:
    """Setup all middleware for the FastAPI application."""
    # CORS middleware - ensure CORS_ORIGINS is a list and not a wildcard in production
    cors_origins = settings.CORS_ORIGINS
    # Accept comma-separated env var strings as well
    if isinstance(cors_origins, str):
        cors_origins = [o.strip() for o in cors_origins.split(',') if o.strip()]

    # In production, do not allow '*' for origins
    if not settings.DEBUG and any(o == '*' for o in cors_origins):
        logger.warning('CORS_ORIGINS contains wildcard "*" in production; this will be ignored for safety')
        cors_origins = [o for o in cors_origins if o != '*']

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=settings.CORS_ALLOW_METHODS,
        allow_headers=settings.CORS_ALLOW_HEADERS,
    )

    # Trusted host middleware - include FRONTEND_URL when provided and not DEBUG
    trusted = ["localhost", "127.0.0.1"] if not settings.DEBUG else ["*"]
    try:
        frontend = settings.FRONTEND_URL
        if frontend and not settings.DEBUG:
            # extract hostname
            from urllib.parse import urlparse
            host = urlparse(frontend).hostname
            if host:
                trusted.append(host)
    except Exception:
        logger.debug('Unable to parse FRONTEND_URL for TrustedHostMiddleware')

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=trusted,
    )
    
    # Custom middleware
    app.add_middleware(LoggingMiddleware)
    
    if redis_client:
        app.add_middleware(RateLimitMiddleware, redis_client=redis_client)

