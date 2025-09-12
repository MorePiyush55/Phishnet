"""
Audit middleware for automatic logging of all user actions and system events.

This middleware automatically captures and logs all HTTP requests, user actions,
and system events for comprehensive audit trail and security monitoring.
"""

import time
import uuid
import json
from typing import Callable, Optional, Dict, Any
from fastapi import Request, Response
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.security import HTTPBearer
import asyncio
from datetime import datetime

from app.services.audit_service import get_audit_service
from app.services.security_sanitizer import get_security_sanitizer
from app.config.logging import get_logger

logger = get_logger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware for comprehensive audit logging of all requests and responses.
    
    Features:
    - Automatic request/response logging
    - User action tracking
    - Security event detection
    - Performance monitoring
    - Error tracking
    """
    
    # Paths that should not be audited (to avoid log spam)
    EXCLUDED_PATHS = {
        "/health",
        "/metrics",
        "/favicon.ico",
        "/robots.txt",
        "/static/",
        "/docs",
        "/openapi.json"
    }
    
    # Sensitive headers that should be redacted
    SENSITIVE_HEADERS = {
        "authorization",
        "cookie",
        "x-api-key",
        "x-auth-token"
    }
    
    # Actions that require special security logging
    SECURITY_ACTIONS = {
        "login",
        "logout", 
        "change_password",
        "admin_action",
        "quarantine",
        "delete_email"
    }
    
    def __init__(self, app):
        """Initialize audit middleware."""
        super().__init__(app)
        self.audit_service = get_audit_service()
        self.sanitizer = get_security_sanitizer()
        
        logger.info("AuditMiddleware initialized")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and response with audit logging."""
        
        # Skip auditing for excluded paths
        if self._should_exclude_path(request.url.path):
            return await call_next(request)
        
        # Generate request ID for correlation
        request_id = f"req_{uuid.uuid4().hex[:16]}"
        request.state.request_id = request_id
        
        # Start timing
        start_time = time.time()
        
        # Extract user information
        user_info = await self._extract_user_info(request)
        
        # Log request start
        await self._log_request_start(request, request_id, user_info)
        
        # Process request
        response = None
        error = None
        
        try:
            response = await call_next(request)
            
        except Exception as e:
            error = e
            logger.error(f"Request {request_id} failed: {e}")
            
            # Create error response
            from fastapi.responses import JSONResponse
            response = JSONResponse(
                status_code=500,
                content={"error": "Internal server error", "request_id": request_id}
            )
        
        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Log request completion
        await self._log_request_completion(
            request, response, request_id, user_info, duration_ms, error
        )
        
        # Add audit headers to response
        if response:
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Audit-Logged"] = "true"
        
        return response
    
    def _should_exclude_path(self, path: str) -> bool:
        """Check if path should be excluded from auditing."""
        return any(excluded in path for excluded in self.EXCLUDED_PATHS)
    
    async def _extract_user_info(self, request: Request) -> Dict[str, Any]:
        """Extract user information from request."""
        user_info = {
            "user_id": None,
            "session_id": None,
            "user_ip": self._get_client_ip(request),
            "user_agent": request.headers.get("user-agent", "")
        }
        
        # Try to extract user from JWT token or session
        try:
            # Check for Authorization header
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                # Here you would decode JWT and extract user info
                # For now, we'll just note that auth is present
                user_info["has_auth"] = True
            
            # Check for session cookie
            session_cookie = request.cookies.get("session_id")
            if session_cookie:
                user_info["session_id"] = session_cookie[:32]  # Truncate for safety
            
            # If user is available in request state (from auth middleware)
            if hasattr(request.state, "user"):
                user_info["user_id"] = getattr(request.state.user, "id", None)
                
        except Exception as e:
            logger.warning(f"Failed to extract user info: {e}")
        
        return user_info
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address, accounting for proxies."""
        # Check X-Forwarded-For header (from load balancers/proxies)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Take first IP in case of multiple proxies
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP header (from nginx)
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        # Fall back to direct client
        if request.client:
            return request.client.host
        
        return "unknown"
    
    async def _log_request_start(
        self,
        request: Request,
        request_id: str,
        user_info: Dict[str, Any]
    ):
        """Log the start of request processing."""
        try:
            # Sanitize headers for logging
            safe_headers = self._sanitize_headers(dict(request.headers))
            
            # Extract query parameters (sanitized)
            query_params = dict(request.query_params)
            safe_query = self._sanitize_query_params(query_params)
            
            # Log request details
            details = {
                "method": request.method,
                "path": request.url.path,
                "query_params": safe_query,
                "headers": safe_headers,
                "content_type": request.headers.get("content-type"),
                "content_length": request.headers.get("content-length")
            }
            
            await self.audit_service.log_system_event(
                action="request_started",
                description=f"{request.method} {request.url.path}",
                details=details,
                request_id=request_id,
                category="http"
            )
            
        except Exception as e:
            logger.error(f"Failed to log request start: {e}")
    
    async def _log_request_completion(
        self,
        request: Request,
        response: Response,
        request_id: str,
        user_info: Dict[str, Any],
        duration_ms: int,
        error: Optional[Exception] = None
    ):
        """Log the completion of request processing."""
        try:
            # Determine action type based on path and method
            action = self._determine_action(request.method, request.url.path)
            
            # Determine severity based on status code and error
            status_code = getattr(response, "status_code", 500) if response else 500
            severity = self._determine_severity(status_code, error)
            
            # Check for security-related actions
            is_security_action = any(sec_action in action for sec_action in self.SECURITY_ACTIONS)
            
            # Prepare details
            details = {
                "status_code": status_code,
                "duration_ms": duration_ms,
                "error": str(error) if error else None,
                "path": request.url.path,
                "method": request.method
            }
            
            # Log as user action if user is identified
            if user_info.get("user_id"):
                await self.audit_service.log_user_action(
                    action=action,
                    user_id=user_info["user_id"],
                    description=f"User {action} - {request.method} {request.url.path}",
                    details=details,
                    request_id=request_id,
                    session_id=user_info.get("session_id"),
                    user_ip=user_info["user_ip"],
                    user_agent=user_info["user_agent"],
                    request_path=request.url.path,
                    request_method=request.method,
                    response_status=status_code,
                    duration_ms=duration_ms,
                    severity=severity
                )
            else:
                # Log as system event for anonymous requests
                await self.audit_service.log_system_event(
                    action=action,
                    description=f"Anonymous {action} - {request.method} {request.url.path}",
                    details={
                        **details,
                        "user_ip": user_info["user_ip"],
                        "user_agent": user_info["user_agent"]
                    },
                    request_id=request_id,
                    severity=severity,
                    category="http"
                )
            
            # Log security events for suspicious activity
            if self._is_suspicious_activity(request, response, user_info, duration_ms):
                await self._log_security_event(request, response, user_info, request_id)
            
        except Exception as e:
            logger.error(f"Failed to log request completion: {e}")
    
    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitize headers for safe logging."""
        safe_headers = {}
        
        for key, value in headers.items():
            key_lower = key.lower()
            
            if key_lower in self.SENSITIVE_HEADERS:
                safe_headers[key] = "[REDACTED]"
            else:
                # Sanitize header value
                safe_value = self.sanitizer.sanitize_text(value[:200], "header").sanitized_content
                safe_headers[key] = safe_value
        
        return safe_headers
    
    def _sanitize_query_params(self, params: Dict[str, str]) -> Dict[str, str]:
        """Sanitize query parameters for safe logging."""
        safe_params = {}
        
        for key, value in params.items():
            # Skip potentially sensitive parameters
            if any(sensitive in key.lower() for sensitive in ["password", "token", "key", "secret"]):
                safe_params[key] = "[REDACTED]"
            else:
                # Sanitize parameter value
                safe_value = self.sanitizer.sanitize_text(str(value)[:100], "query_param").sanitized_content
                safe_params[key] = safe_value
        
        return safe_params
    
    def _determine_action(self, method: str, path: str) -> str:
        """Determine action type from HTTP method and path."""
        # Map common API patterns to actions
        path_lower = path.lower()
        
        if "/login" in path_lower:
            return "login"
        elif "/logout" in path_lower:
            return "logout"
        elif "/email" in path_lower:
            if method == "GET":
                return "view_email"
            elif method == "POST":
                return "create_email"
            elif method == "DELETE":
                return "delete_email"
        elif "/scan" in path_lower:
            return "scan_email"
        elif "/quarantine" in path_lower:
            return "quarantine_email"
        elif "/admin" in path_lower:
            return "admin_action"
        
        # Default action based on method
        return f"{method.lower()}_request"
    
    def _determine_severity(self, status_code: int, error: Optional[Exception]) -> str:
        """Determine log severity based on status code and error."""
        if error:
            return "error"
        elif status_code >= 500:
            return "error"
        elif status_code >= 400:
            return "warning"
        else:
            return "info"
    
    def _is_suspicious_activity(
        self,
        request: Request,
        response: Optional[Response],
        user_info: Dict[str, Any],
        duration_ms: int
    ) -> bool:
        """Detect suspicious activity patterns."""
        
        # Check for suspicious patterns
        suspicious_indicators = []
        
        # Very long request duration (potential DoS)
        if duration_ms > 30000:  # 30 seconds
            suspicious_indicators.append("long_duration")
        
        # Multiple failed authentication attempts
        status_code = getattr(response, "status_code", 200) if response else 500
        if status_code == 401 and "/login" in request.url.path:
            suspicious_indicators.append("failed_auth")
        
        # Suspicious user agent patterns
        user_agent = user_info.get("user_agent", "").lower()
        if any(bot in user_agent for bot in ["bot", "crawler", "scanner", "curl", "wget"]):
            if not any(legit in user_agent for legit in ["googlebot", "bingbot"]):
                suspicious_indicators.append("suspicious_user_agent")
        
        # Check for XSS attempts in query parameters
        query_string = str(request.url.query)
        xss_patterns = ["<script", "javascript:", "onclick=", "onerror="]
        if any(pattern in query_string.lower() for pattern in xss_patterns):
            suspicious_indicators.append("xss_attempt")
        
        # SQL injection patterns
        sql_patterns = ["union select", "drop table", "' or '1'='1"]
        if any(pattern in query_string.lower() for pattern in sql_patterns):
            suspicious_indicators.append("sql_injection_attempt")
        
        return len(suspicious_indicators) > 0
    
    async def _log_security_event(
        self,
        request: Request,
        response: Optional[Response],
        user_info: Dict[str, Any],
        request_id: str
    ):
        """Log security-related events."""
        try:
            status_code = getattr(response, "status_code", 500) if response else 500
            
            # Determine security violation type
            violation_type = "suspicious_request"
            is_violation = False
            
            # Check query string for attacks
            query_string = str(request.url.query)
            if any(pattern in query_string.lower() for pattern in ["<script", "javascript:"]):
                violation_type = "xss_attempt"
                is_violation = True
            elif any(pattern in query_string.lower() for pattern in ["union select", "drop table"]):
                violation_type = "sql_injection_attempt"
                is_violation = True
            
            # Check for brute force
            if status_code == 401 and "/login" in request.url.path:
                violation_type = "failed_authentication"
                is_violation = True
            
            await self.audit_service.log_security_event(
                action=violation_type,
                description=f"Security event detected: {violation_type} from {user_info['user_ip']}",
                user_id=user_info.get("user_id"),
                user_ip=user_info["user_ip"],
                user_agent=user_info["user_agent"],
                details={
                    "path": request.url.path,
                    "method": request.method,
                    "query_string": query_string[:500],  # Limit length
                    "status_code": status_code
                },
                is_suspicious=True,
                security_violation=is_violation,
                request_id=request_id,
                request_path=request.url.path
            )
            
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add request context for audit correlation.
    
    This should be installed before AuditMiddleware to provide
    consistent request IDs and user context.
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add request context."""
        
        # Generate request ID if not present
        if not hasattr(request.state, "request_id"):
            request.state.request_id = f"req_{uuid.uuid4().hex[:16]}"
        
        # Add timestamp
        request.state.start_time = time.time()
        request.state.start_datetime = datetime.utcnow()
        
        # Process request
        response = await call_next(request)
        
        return response


# Audit logging decorator for specific functions
def audit_action(action: str, resource_type: Optional[str] = None):
    """
    Decorator to automatically audit function calls.
    
    Usage:
        @audit_action("email_scan", "email")
        async def scan_email(email_id: str, user_id: int):
            ...
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            audit_service = get_audit_service()
            request_id = f"func_{uuid.uuid4().hex[:16]}"
            
            # Extract common parameters
            user_id = kwargs.get("user_id")
            resource_id = kwargs.get("email_id") or kwargs.get("resource_id")
            
            start_time = time.time()
            
            try:
                # Log function start
                await audit_service.log_system_event(
                    action=f"{action}_started",
                    description=f"Started {action} function",
                    details={
                        "function": func.__name__,
                        "args_count": len(args),
                        "kwargs": list(kwargs.keys())
                    },
                    request_id=request_id,
                    resource_type=resource_type,
                    resource_id=str(resource_id) if resource_id else None,
                    category="function"
                )
                
                # Execute function
                result = await func(*args, **kwargs)
                
                # Log success
                duration_ms = int((time.time() - start_time) * 1000)
                
                await audit_service.log_system_event(
                    action=f"{action}_completed",
                    description=f"Completed {action} function successfully",
                    details={
                        "function": func.__name__,
                        "result_type": type(result).__name__ if result else None
                    },
                    request_id=request_id,
                    resource_type=resource_type,
                    resource_id=str(resource_id) if resource_id else None,
                    duration_ms=duration_ms,
                    category="function"
                )
                
                return result
                
            except Exception as e:
                # Log failure
                duration_ms = int((time.time() - start_time) * 1000)
                
                await audit_service.log_system_event(
                    action=f"{action}_failed",
                    description=f"Function {action} failed: {str(e)}",
                    details={
                        "function": func.__name__,
                        "error": str(e),
                        "error_type": type(e).__name__
                    },
                    request_id=request_id,
                    resource_type=resource_type,
                    resource_id=str(resource_id) if resource_id else None,
                    duration_ms=duration_ms,
                    severity="error",
                    category="function"
                )
                
                raise
        
        return wrapper
    return decorator


# Context manager for manual audit correlation
@asynccontextmanager
async def audit_context(action: str, user_id: Optional[int] = None, resource_id: Optional[str] = None):
    """
    Context manager for audit correlation in complex operations.
    
    Usage:
        async with audit_context("complex_scan", user_id=123, resource_id="email_456"):
            # All audit logs in this block will be correlated
            result1 = await some_operation()
            result2 = await another_operation()
    """
    audit_service = get_audit_service()
    request_id = f"ctx_{uuid.uuid4().hex[:16]}"
    start_time = time.time()
    
    try:
        # Log context start
        await audit_service.log_system_event(
            action=f"{action}_context_started",
            description=f"Started audit context for {action}",
            request_id=request_id,
            category="context"
        )
        
        yield request_id
        
        # Log context success
        duration_ms = int((time.time() - start_time) * 1000)
        await audit_service.log_system_event(
            action=f"{action}_context_completed",
            description=f"Completed audit context for {action}",
            request_id=request_id,
            duration_ms=duration_ms,
            category="context"
        )
        
    except Exception as e:
        # Log context failure
        duration_ms = int((time.time() - start_time) * 1000)
        await audit_service.log_system_event(
            action=f"{action}_context_failed",
            description=f"Audit context failed for {action}: {str(e)}",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=duration_ms,
            severity="error",
            category="context"
        )
        raise
