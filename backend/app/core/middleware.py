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
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=settings.CORS_ALLOW_METHODS,
        allow_headers=settings.CORS_ALLOW_HEADERS,
    )
    
    # Trusted host middleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"] if settings.DEBUG else ["localhost", "127.0.0.1"],
    )
    
    # Custom middleware
    app.add_middleware(LoggingMiddleware)
    
    if redis_client:
        app.add_middleware(RateLimitMiddleware, redis_client=redis_client)

