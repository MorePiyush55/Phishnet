"""
Correlation ID middleware for request tracking and structured logging.
Provides request correlation, structured JSON logging, and trace correlation.
"""

import json
import time
import uuid
from typing import Dict, Any, Optional
from contextvars import ContextVar

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import StreamingResponse

from app.config.logging import get_logger
from app.observability.tracing import get_tracer, traced_span

logger = get_logger(__name__)

# Context variables for request correlation
correlation_id_var: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)
request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)
span_id_var: ContextVar[Optional[str]] = ContextVar('span_id', default=None)
trace_id_var: ContextVar[Optional[str]] = ContextVar('trace_id', default=None)


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add correlation IDs to requests and responses.
    Enables request tracking across services and log correlation.
    """
    
    def __init__(self, app, header_name: str = "X-Correlation-ID"):
        super().__init__(app)
        self.header_name = header_name
    
    async def dispatch(self, request: Request, call_next):
        # Generate or extract correlation ID
        correlation_id = request.headers.get(self.header_name)
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        
        # Set context variables
        correlation_id_var.set(correlation_id)
        request_id_var.set(request_id)
        
        # Get trace context if available
        tracer = get_tracer()
        current_span = tracer.start_span(f"{request.method} {request.url.path}")
        
        try:
            with traced_span(
                f"http_request",
                {
                    "http.method": request.method,
                    "http.url": str(request.url),
                    "http.user_agent": request.headers.get("user-agent", ""),
                    "correlation_id": correlation_id,
                    "request_id": request_id
                }
            ) as span:
                # Set span context variables
                span_context = span.get_span_context()
                if span_context:
                    span_id_var.set(f"{span_context.span_id:016x}")
                    trace_id_var.set(f"{span_context.trace_id:032x}")
                
                # Add to request state
                request.state.correlation_id = correlation_id
                request.state.request_id = request_id
                
                # Process request
                start_time = time.time()
                response = await call_next(request)
                duration = time.time() - start_time
                
                # Add correlation headers to response
                response.headers[self.header_name] = correlation_id
                response.headers["X-Request-ID"] = request_id
                
                # Add timing and status to span
                span.set_attribute("http.status_code", response.status_code)
                span.set_attribute("http.response_size", 
                                 response.headers.get("content-length", "0"))
                span.set_attribute("duration_ms", duration * 1000)
                
                return response
                
        except Exception as e:
            current_span.set_attribute("error", True)
            current_span.set_attribute("error.type", type(e).__name__)
            current_span.set_attribute("error.message", str(e))
            raise
        finally:
            current_span.end()


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for structured JSON logging of HTTP requests.
    Logs all requests with correlation IDs and performance metrics.
    """
    
    def __init__(self, app, exclude_paths: Optional[list] = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or ["/health", "/metrics", "/docs", "/openapi.json"]
    
    async def dispatch(self, request: Request, call_next):
        # Skip logging for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)
        
        start_time = time.time()
        
        # Extract request information
        request_data = await self._extract_request_data(request)
        
        # Log request start
        self._log_structured({
            "event": "request_started",
            "timestamp": time.time(),
            "request": request_data,
            "correlation_id": get_correlation_id(),
            "request_id": get_request_id(),
            "span_id": get_span_id(),
            "trace_id": get_trace_id()
        })
        
        try:
            # Process request
            response = await call_next(request)
            duration = time.time() - start_time
            
            # Extract response information
            response_data = await self._extract_response_data(response, duration)
            
            # Log successful request
            self._log_structured({
                "event": "request_completed",
                "timestamp": time.time(),
                "request": request_data,
                "response": response_data,
                "duration_seconds": duration,
                "correlation_id": get_correlation_id(),
                "request_id": get_request_id(),
                "span_id": get_span_id(),
                "trace_id": get_trace_id()
            })
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            
            # Log error
            self._log_structured({
                "event": "request_failed",
                "timestamp": time.time(),
                "request": request_data,
                "error": {
                    "type": type(e).__name__,
                    "message": str(e)
                },
                "duration_seconds": duration,
                "correlation_id": get_correlation_id(),
                "request_id": get_request_id(),
                "span_id": get_span_id(),
                "trace_id": get_trace_id()
            })
            
            raise
    
    async def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract relevant request data for logging."""
        return {
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "headers": {
                "user-agent": request.headers.get("user-agent", ""),
                "content-type": request.headers.get("content-type", ""),
                "content-length": request.headers.get("content-length", "0")
            },
            "client": {
                "host": getattr(request.client, 'host', 'unknown') if request.client else 'unknown',
                "port": getattr(request.client, 'port', 0) if request.client else 0
            }
        }
    
    async def _extract_response_data(self, response: Response, duration: float) -> Dict[str, Any]:
        """Extract relevant response data for logging."""
        return {
            "status_code": response.status_code,
            "headers": {
                "content-type": response.headers.get("content-type", ""),
                "content-length": response.headers.get("content-length", "0")
            },
            "duration_ms": duration * 1000
        }
    
    def _log_structured(self, data: Dict[str, Any]) -> None:
        """Log structured data as JSON."""
        try:
            # Convert to JSON string
            log_message = json.dumps(data, default=str, ensure_ascii=False)
            
            # Log at appropriate level based on event type
            if data.get("event") == "request_failed":
                logger.error(log_message)
            elif data.get("response", {}).get("status_code", 200) >= 400:
                logger.warning(log_message)
            else:
                logger.info(log_message)
                
        except Exception as e:
            # Fallback to regular logging if JSON serialization fails
            logger.error(f"Failed to log structured data: {e}, data: {data}")


# Context variable accessors
def get_correlation_id() -> Optional[str]:
    """Get the current correlation ID."""
    return correlation_id_var.get()


def get_request_id() -> Optional[str]:
    """Get the current request ID."""
    return request_id_var.get()


def get_span_id() -> Optional[str]:
    """Get the current span ID."""
    return span_id_var.get()


def get_trace_id() -> Optional[str]:
    """Get the current trace ID."""
    return trace_id_var.get()


def get_correlation_context() -> Dict[str, Optional[str]]:
    """Get all correlation context variables."""
    return {
        "correlation_id": get_correlation_id(),
        "request_id": get_request_id(),
        "span_id": get_span_id(),
        "trace_id": get_trace_id()
    }


# Structured logger wrapper
class StructuredLogger:
    """
    Wrapper for structured logging with correlation context.
    Automatically includes correlation IDs in all log messages.
    """
    
    def __init__(self, logger_instance):
        self.logger = logger_instance
    
    def _add_context(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add correlation context to log data."""
        context = get_correlation_context()
        return {**data, **context}
    
    def info(self, message: str, **kwargs):
        """Log info message with context."""
        data = {"message": message, "level": "info", **kwargs}
        self.logger.info(json.dumps(self._add_context(data), default=str))
    
    def warning(self, message: str, **kwargs):
        """Log warning message with context."""
        data = {"message": message, "level": "warning", **kwargs}
        self.logger.warning(json.dumps(self._add_context(data), default=str))
    
    def error(self, message: str, **kwargs):
        """Log error message with context."""
        data = {"message": message, "level": "error", **kwargs}
        self.logger.error(json.dumps(self._add_context(data), default=str))
    
    def debug(self, message: str, **kwargs):
        """Log debug message with context."""
        data = {"message": message, "level": "debug", **kwargs}
        self.logger.debug(json.dumps(self._add_context(data), default=str))


def get_structured_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance."""
    return StructuredLogger(get_logger(name))


# Database audit integration
def add_correlation_to_audit(audit_data: Dict[str, Any]) -> Dict[str, Any]:
    """Add correlation context to audit log data."""
    context = get_correlation_context()
    return {
        **audit_data,
        "correlation_id": context["correlation_id"],
        "request_id": context["request_id"],
        "span_id": context["span_id"],
        "trace_id": context["trace_id"]
    }
