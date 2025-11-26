import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limit: int = 100, window: int = 60):
        super().__init__(app)
        self.limit = limit
        self.window = window

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health checks and static files
        if request.url.path in ["/health", "/metrics", "/docs", "/redoc", "/openapi.json", "/favicon.ico"]:
            return await call_next(request)
            
        redis = getattr(request.app.state, "redis", None)
        if not redis:
            # If Redis is not available, skip rate limiting (fail open)
            return await call_next(request)

        try:
            client_ip = request.client.host if request.client else "unknown"
            # Use a simpler key structure to avoid high cardinality if path varies wildly
            # But for API endpoints, path is usually good.
            key = f"rate_limit:{client_ip}"
            
            # Increment count
            current = await redis.incr(key)
            
            # Set expiry on first request
            if current == 1:
                await redis.expire(key, self.window)
            
            if current > self.limit:
                logger.warning(f"Rate limit exceeded for {client_ip}")
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Please try again later."}
                )
                
            response = await call_next(request)
            
            # Add headers
            response.headers["X-RateLimit-Limit"] = str(self.limit)
            response.headers["X-RateLimit-Remaining"] = str(max(0, self.limit - current))
            
            return response
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            # Fail open on error
            return await call_next(request)
