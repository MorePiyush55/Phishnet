"""Security middleware for Gmail OAuth endpoints."""

import json
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import ipaddress

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import redis.asyncio as redis

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.redis_client import redis_client

logger = get_logger(__name__)


class GmailOAuthSecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware specifically for Gmail OAuth endpoints."""
    
    def __init__(
        self,
        app: ASGIApp,
        rate_limit_requests: int = 20,
        rate_limit_window: int = 3600,  # 1 hour
        max_attempts_per_user: int = 5,
        attempt_window: int = 900  # 15 minutes
    ):
        super().__init__(app)
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window = rate_limit_window
        self.max_attempts_per_user = max_attempts_per_user
        self.attempt_window = attempt_window
        
    async def dispatch(self, request: Request, call_next):
        """Process Gmail OAuth requests with enhanced security."""
        
        # Only apply to Gmail OAuth endpoints
        if not self._is_gmail_oauth_endpoint(request):
            return await call_next(request)
        
        # Get client information
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        user_id = await self._get_user_id_from_request(request)
        
        try:
            # Apply security checks
            await self._check_rate_limits(client_ip, user_id)
            await self._check_suspicious_patterns(request, client_ip, user_agent)
            await self._validate_request_integrity(request)
            
            # Process request
            response = await call_next(request)
            
            # Log successful request
            await self._log_oauth_security_event(
                event_type="oauth_request_allowed",
                client_ip=client_ip,
                user_agent=user_agent,
                user_id=user_id,
                endpoint=str(request.url.path),
                success=True
            )
            
            return response
            
        except HTTPException as e:
            # Log security violation
            await self._log_oauth_security_event(
                event_type="oauth_security_violation",
                client_ip=client_ip,
                user_agent=user_agent,
                user_id=user_id,
                endpoint=str(request.url.path),
                success=False,
                details={"error": e.detail, "status_code": e.status_code}
            )
            
            # Increment failure counter
            if user_id:
                await self._increment_user_failures(user_id)
            
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail, "type": "security_error"}
            )
        except Exception as e:
            logger.error(f"OAuth security middleware error: {e}")
            await self._log_oauth_security_event(
                event_type="oauth_middleware_error",
                client_ip=client_ip,
                user_agent=user_agent,
                user_id=user_id,
                endpoint=str(request.url.path),
                success=False,
                details={"error": str(e)}
            )
            
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Security check failed", "type": "security_error"}
            )
    
    def _is_gmail_oauth_endpoint(self, request: Request) -> bool:
        """Check if request is for Gmail OAuth endpoint."""
        path = request.url.path
        oauth_paths = [
            "/api/v1/auth/gmail/start",
            "/api/v1/auth/gmail/callback", 
            "/api/v1/auth/gmail/revoke",
            "/api/v1/auth/gmail/scan"
        ]
        return any(path.startswith(oauth_path) for oauth_path in oauth_paths)
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address considering proxy headers."""
        # Check common proxy headers
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Take the first IP in the chain
            ip = forwarded_for.split(",")[0].strip()
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                pass
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            try:
                ipaddress.ip_address(real_ip)
                return real_ip
            except ValueError:
                pass
        
        # Fallback to direct connection
        if request.client:
            return request.client.host
        
        return "unknown"
    
    async def _get_user_id_from_request(self, request: Request) -> Optional[int]:
        """Extract user ID from JWT token if present."""
        try:
            auth_header = request.headers.get("authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return None
            
            # Extract user ID from JWT token (simplified)
            # In a real implementation, you'd decode and validate the JWT
            token = auth_header.split(" ")[1]
            
            # This is a placeholder - you'd use your JWT validation logic
            # For now, we'll try to get it from the request state if available
            if hasattr(request.state, "user_id"):
                return request.state.user_id
                
            return None
        except Exception:
            return None
    
    async def _check_rate_limits(self, client_ip: str, user_id: Optional[int]):
        """Check IP-based and user-based rate limits."""
        current_time = int(time.time())
        
        # IP-based rate limiting
        ip_key = f"oauth_rate_limit:ip:{client_ip}"
        ip_requests = await redis_client.get(ip_key)
        
        if ip_requests:
            if int(ip_requests) >= self.rate_limit_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many OAuth requests from this IP address"
                )
        
        # Increment IP counter
        await redis_client.incr(ip_key)
        await redis_client.expire(ip_key, self.rate_limit_window)
        
        # User-based rate limiting (if authenticated)
        if user_id:
            user_key = f"oauth_rate_limit:user:{user_id}"
            user_requests = await redis_client.get(user_key)
            
            if user_requests:
                if int(user_requests) >= self.max_attempts_per_user:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Too many OAuth attempts for this user"
                    )
            
            # Increment user counter
            await redis_client.incr(user_key)
            await redis_client.expire(user_key, self.attempt_window)
    
    async def _check_suspicious_patterns(self, request: Request, client_ip: str, user_agent: str):
        """Check for suspicious request patterns."""
        
        # Check for suspicious user agents
        suspicious_ua_patterns = [
            "bot", "crawler", "spider", "scraper", "curl", "wget",
            "python-requests", "go-http-client"
        ]
        
        if any(pattern in user_agent.lower() for pattern in suspicious_ua_patterns):
            logger.warning(f"Suspicious user agent in OAuth request: {user_agent}")
            # Don't block immediately, but log for monitoring
        
        # Check for rapid requests from same IP
        rapid_request_key = f"oauth_rapid_requests:{client_ip}"
        request_count = await redis_client.incr(rapid_request_key)
        await redis_client.expire(rapid_request_key, 60)  # 1 minute window
        
        if request_count > 10:  # More than 10 requests per minute
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Suspicious request pattern detected"
            )
        
        # Check for requests from known malicious IPs (if you have a blocklist)
        if await self._is_blocked_ip(client_ip):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Requests from this IP are blocked"
            )
    
    async def _validate_request_integrity(self, request: Request):
        """Validate request integrity and required headers."""
        
        # Check for required headers based on endpoint
        path = request.url.path
        
        if path.endswith("/start") or path.endswith("/revoke") or path.endswith("/scan"):
            # These endpoints require authentication
            auth_header = request.headers.get("authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
        
        # Validate content type for POST requests
        if request.method == "POST":
            content_type = request.headers.get("content-type", "")
            if not content_type.startswith("application/json"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid content type"
                )
    
    async def _is_blocked_ip(self, client_ip: str) -> bool:
        """Check if IP is in blocklist."""
        try:
            # Check Redis for blocked IPs
            blocked = await redis_client.get(f"blocked_ip:{client_ip}")
            return blocked is not None
        except Exception:
            return False
    
    async def _increment_user_failures(self, user_id: int):
        """Increment failure counter for user."""
        try:
            failure_key = f"oauth_failures:user:{user_id}"
            failures = await redis_client.incr(failure_key)
            await redis_client.expire(failure_key, self.attempt_window)
            
            # If too many failures, temporarily block user
            if failures >= self.max_attempts_per_user:
                block_key = f"oauth_blocked:user:{user_id}"
                await redis_client.setex(block_key, self.attempt_window, "1")
                logger.warning(f"User {user_id} temporarily blocked due to OAuth failures")
        except Exception as e:
            logger.error(f"Failed to increment user failures: {e}")
    
    async def _log_oauth_security_event(
        self,
        event_type: str,
        client_ip: str,
        user_agent: str,
        endpoint: str,
        success: bool,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log OAuth security events for monitoring."""
        try:
            event_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": event_type,
                "client_ip": client_ip,
                "user_agent": user_agent,
                "endpoint": endpoint,
                "success": success,
                "user_id": user_id,
                "details": details or {}
            }
            
            # Log to application logs
            if success:
                logger.info(f"OAuth security event: {event_type}", extra=event_data)
            else:
                logger.warning(f"OAuth security violation: {event_type}", extra=event_data)
            
            # Store in Redis for monitoring dashboard
            event_key = f"oauth_security_events:{int(time.time())}"
            await redis_client.setex(event_key, 86400, json.dumps(event_data))  # 24 hours
            
        except Exception as e:
            logger.error(f"Failed to log OAuth security event: {e}")


def create_oauth_security_middleware() -> GmailOAuthSecurityMiddleware:
    """Create OAuth security middleware with production settings."""
    return GmailOAuthSecurityMiddleware(
        app=None,  # Will be set when added to FastAPI app
        rate_limit_requests=settings.OAUTH_RATE_LIMIT_REQUESTS or 20,
        rate_limit_window=settings.OAUTH_RATE_LIMIT_WINDOW or 3600,
        max_attempts_per_user=settings.OAUTH_MAX_ATTEMPTS_PER_USER or 5,
        attempt_window=settings.OAUTH_ATTEMPT_WINDOW or 900
    )
