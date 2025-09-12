"""Error tracking and correlation middleware."""

import uuid
import traceback
import json
from typing import Any, Dict, Optional
from datetime import datetime, timezone
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config.logging import get_logger

logger = get_logger(__name__)


class ErrorTrackingMiddleware(BaseHTTPMiddleware):
    """Middleware for error tracking and correlation."""
    
    async def dispatch(self, request: Request, call_next):
        # Generate correlation ID if not present
        correlation_id = getattr(request.state, 'correlation_id', str(uuid.uuid4()))
        request.state.correlation_id = correlation_id
        
        try:
            response = await call_next(request)
            return response
            
        except HTTPException as e:
            # Handle known HTTP exceptions
            logger.warning(
                f"HTTP Exception: {e.status_code} - {e.detail}",
                extra={
                    "correlation_id": correlation_id,
                    "status_code": e.status_code,
                    "detail": e.detail,
                    "path": request.url.path,
                    "method": request.method
                }
            )
            
            # Return structured error response
            return JSONResponse(
                status_code=e.status_code,
                content={
                    "error": {
                        "code": e.status_code,
                        "message": str(e.detail),
                        "correlation_id": correlation_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": request.url.path
                    }
                }
            )
            
        except Exception as e:
            # Handle unexpected exceptions
            error_details = {
                "correlation_id": correlation_id,
                "error_type": type(e).__name__,
                "error_message": str(e),
                "path": request.url.path,
                "method": request.method,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_agent": request.headers.get("user-agent", ""),
                "ip_address": self._get_client_ip(request)
            }
            
            # Sanitize sensitive information
            sanitized_details = self._sanitize_error_details(error_details)
            
            logger.error(
                f"Unhandled exception: {type(e).__name__}: {str(e)}",
                extra=sanitized_details,
                exc_info=True
            )
            
            # Return generic error response (don't expose internal details)
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": 500,
                        "message": "Internal server error",
                        "correlation_id": correlation_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": request.url.path
                    }
                }
            )
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def _sanitize_error_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize error details to remove sensitive information."""
        sanitized = details.copy()
        
        # Remove or mask sensitive fields
        sensitive_patterns = [
            "password", "token", "key", "secret", "auth", "credential"
        ]
        
        for key in list(sanitized.keys()):
            if any(pattern in key.lower() for pattern in sensitive_patterns):
                sanitized[key] = "[REDACTED]"
        
        # Sanitize error message
        if "error_message" in sanitized:
            message = str(sanitized["error_message"])
            # Remove potential sensitive information from error messages
            for pattern in sensitive_patterns:
                if pattern in message.lower():
                    sanitized["error_message"] = "[SANITIZED] Error occurred"
                    break
        
        return sanitized


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Middleware to add correlation IDs to all requests."""
    
    async def dispatch(self, request: Request, call_next):
        # Generate or extract correlation ID
        correlation_id = (
            request.headers.get("X-Correlation-ID") or
            request.headers.get("X-Request-ID") or
            str(uuid.uuid4())
        )
        
        # Add to request state
        request.state.correlation_id = correlation_id
        
        # Process request
        response = await call_next(request)
        
        # Add correlation ID to response headers
        response.headers["X-Correlation-ID"] = correlation_id
        
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request/response logging."""
    
    def __init__(self, app, log_body: bool = False, sensitive_fields: Optional[list] = None):
        super().__init__(app)
        self.log_body = log_body
        self.sensitive_fields = sensitive_fields or [
            "password", "token", "key", "secret", "auth", "credential"
        ]
    
    async def dispatch(self, request: Request, call_next):
        correlation_id = getattr(request.state, 'correlation_id', str(uuid.uuid4()))
        
        # Log incoming request
        await self._log_request(request, correlation_id)
        
        # Process request
        response = await call_next(request)
        
        # Log outgoing response
        await self._log_response(request, response, correlation_id)
        
        return response
    
    async def _log_request(self, request: Request, correlation_id: str):
        """Log incoming request details."""
        log_data = {
            "correlation_id": correlation_id,
            "method": request.method,
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "headers": dict(request.headers),
            "client_ip": self._get_client_ip(request)
        }
        
        # Optionally log request body
        if self.log_body and request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                if body:
                    # Try to parse as JSON
                    try:
                        body_json = json.loads(body.decode())
                        log_data["body"] = self._sanitize_data(body_json)
                    except json.JSONDecodeError:
                        log_data["body"] = "[BINARY_DATA]"
            except Exception:
                log_data["body"] = "[ERROR_READING_BODY]"
        
        # Sanitize sensitive data
        log_data = self._sanitize_data(log_data)
        
        logger.info("Incoming request", extra=log_data)
    
    async def _log_response(self, request: Request, response, correlation_id: str):
        """Log outgoing response details."""
        log_data = {
            "correlation_id": correlation_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "response_headers": dict(response.headers)
        }
        
        logger.info("Outgoing response", extra=log_data)
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def _sanitize_data(self, data: Any) -> Any:
        """Recursively sanitize sensitive data."""
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                if any(sensitive in key.lower() for sensitive in self.sensitive_fields):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = self._sanitize_data(value)
            return sanitized
        
        elif isinstance(data, list):
            return [self._sanitize_data(item) for item in data]
        
        elif isinstance(data, str):
            # Check if string looks like a token or key
            if len(data) > 20 and any(char.isalnum() for char in data):
                if any(sensitive in data.lower() for sensitive in self.sensitive_fields):
                    return "[REDACTED]"
        
        return data
