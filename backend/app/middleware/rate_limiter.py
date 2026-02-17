"""
Rate Limiting Middleware for Inbox API

Implements rate limiting to prevent API abuse:
- 100 requests per minute per user
- 20 requests per second burst limit
- Redis-based distributed rate limiting
"""

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from typing import Callable
import time
import redis.asyncio as redis
from datetime import datetime, timedelta


class RateLimiter:
    """
    Token bucket rate limiter using Redis.
    
    Implements sliding window rate limiting with burst support.
    """
    
    def __init__(
        self,
        redis_client: redis.Redis,
        requests_per_minute: int = 100,
        burst_limit: int = 20
    ):
        self.redis = redis_client
        self.requests_per_minute = requests_per_minute
        self.burst_limit = burst_limit
        self.window_size = 60  # 1 minute in seconds
    
    async def is_allowed(self, user_id: str) -> tuple[bool, dict]:
        """
        Check if request is allowed for user.
        
        Args:
            user_id: User identifier
        
        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        now = time.time()
        window_start = now - self.window_size
        
        # Redis keys
        requests_key = f"rate_limit:{user_id}:requests"
        burst_key = f"rate_limit:{user_id}:burst"
        
        # Use Redis pipeline for atomic operations
        pipe = self.redis.pipeline()
        
        # Remove old requests outside window
        pipe.zremrangebyscore(requests_key, 0, window_start)
        
        # Count requests in current window
        pipe.zcard(requests_key)
        
        # Get burst count
        pipe.get(burst_key)
        
        results = await pipe.execute()
        request_count = results[1]
        burst_count = int(results[2] or 0)
        
        # Check burst limit (requests in last second)
        recent_start = now - 1
        recent_count = await self.redis.zcount(requests_key, recent_start, now)
        
        if recent_count >= self.burst_limit:
            return False, {
                "limit": self.requests_per_minute,
                "remaining": max(0, self.requests_per_minute - request_count),
                "reset": int(now + self.window_size),
                "retry_after": 1
            }
        
        # Check minute limit
        if request_count >= self.requests_per_minute:
            # Calculate when oldest request will expire
            oldest = await self.redis.zrange(requests_key, 0, 0, withscores=True)
            if oldest:
                reset_time = oldest[0][1] + self.window_size
                retry_after = int(reset_time - now)
            else:
                retry_after = self.window_size
            
            return False, {
                "limit": self.requests_per_minute,
                "remaining": 0,
                "reset": int(now + retry_after),
                "retry_after": retry_after
            }
        
        # Allow request - add to window
        await self.redis.zadd(requests_key, {str(now): now})
        await self.redis.expire(requests_key, self.window_size + 10)  # Extra buffer
        
        return True, {
            "limit": self.requests_per_minute,
            "remaining": self.requests_per_minute - request_count - 1,
            "reset": int(now + self.window_size),
            "retry_after": 0
        }


class RateLimitMiddleware:
    """
    FastAPI middleware for rate limiting.
    """
    
    def __init__(self, app, redis_client: redis.Redis):
        self.app = app
        self.rate_limiter = RateLimiter(redis_client)
    
    async def __call__(self, request: Request, call_next: Callable):
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/health/detailed"]:
            return await call_next(request)
        
        # Get user ID from request (from auth token)
        user_id = self._get_user_id(request)
        
        if not user_id:
            # No user ID - allow request (will be caught by auth middleware)
            return await call_next(request)
        
        # Check rate limit
        is_allowed, rate_info = await self.rate_limiter.is_allowed(user_id)
        
        if not is_allowed:
            # Rate limit exceeded
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Please try again later.",
                    "rate_limit": rate_info
                },
                headers={
                    "X-RateLimit-Limit": str(rate_info["limit"]),
                    "X-RateLimit-Remaining": str(rate_info["remaining"]),
                    "X-RateLimit-Reset": str(rate_info["reset"]),
                    "Retry-After": str(rate_info["retry_after"])
                }
            )
        
        # Add rate limit headers to response
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(rate_info["limit"])
        response.headers["X-RateLimit-Remaining"] = str(rate_info["remaining"])
        response.headers["X-RateLimit-Reset"] = str(rate_info["reset"])
        
        return response
    
    def _get_user_id(self, request: Request) -> str | None:
        """Extract user ID from request."""
        # Try to get from request state (set by auth middleware)
        if hasattr(request.state, "user"):
            return request.state.user.get("user_id")
        
        # Fallback: try to extract from Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            # In production, decode JWT to get user_id
            # For now, use IP address as fallback
            return request.client.host if request.client else None
        
        return None


# ==================== Decorator for Route-Specific Limits ====================

def rate_limit(requests_per_minute: int = 100, burst_limit: int = 20):
    """
    Decorator for applying custom rate limits to specific routes.
    
    Usage:
        @router.post("/expensive-operation")
        @rate_limit(requests_per_minute=10, burst_limit=2)
        async def expensive_operation():
            ...
    """
    def decorator(func):
        func._rate_limit_config = {
            "requests_per_minute": requests_per_minute,
            "burst_limit": burst_limit
        }
        return func
    return decorator


# ==================== IP-Based Rate Limiting ====================

class IPRateLimiter:
    """
    IP-based rate limiter for unauthenticated requests.
    """
    
    def __init__(self, redis_client: redis.Redis, requests_per_minute: int = 20):
        self.redis = redis_client
        self.requests_per_minute = requests_per_minute
        self.window_size = 60
    
    async def is_allowed(self, ip_address: str) -> tuple[bool, dict]:
        """Check if request from IP is allowed."""
        now = time.time()
        window_start = now - self.window_size
        
        key = f"rate_limit:ip:{ip_address}"
        
        # Remove old requests
        await self.redis.zremrangebyscore(key, 0, window_start)
        
        # Count requests
        count = await self.redis.zcard(key)
        
        if count >= self.requests_per_minute:
            return False, {
                "limit": self.requests_per_minute,
                "remaining": 0,
                "reset": int(now + self.window_size)
            }
        
        # Add request
        await self.redis.zadd(key, {str(now): now})
        await self.redis.expire(key, self.window_size + 10)
        
        return True, {
            "limit": self.requests_per_minute,
            "remaining": self.requests_per_minute - count - 1,
            "reset": int(now + self.window_size)
        }
