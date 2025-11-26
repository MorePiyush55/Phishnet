"""
FastAPI middleware for observability integration.
Provides request tracing, logging, and performance monitoring.
"""

import time
import uuid
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability import (
    get_logger, 
    tracing_manager, 
    performance_monitor,
    log_api_request
)

class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Middleware to add observability to all API requests."""
    
    def __init__(self, app, slow_request_threshold: float = 1000.0):
        super().__init__(app)
        self.logger = get_logger(__name__)
        self.slow_request_threshold = slow_request_threshold
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Start timing
        start_time = time.time()
        
        # Extract user info if available
        user_id = None
        if hasattr(request.state, 'user') and request.state.user:
            user_id = str(request.state.user.id)
        
        # Create span for the request
        span_name = f"{request.method} {request.url.path}"
        span_attributes = {
            'http.method': request.method,
            'http.url': str(request.url),
            'http.route': request.url.path,
            'http.user_agent': request.headers.get('user-agent', ''),
            'request.id': request_id,
            'user.id': user_id or 'anonymous'
        }
        
        with tracing_manager.trace(span_name, span_attributes) as span:
            try:
                # Process request
                response = await call_next(request)
                
                # Calculate duration
                duration_ms = (time.time() - start_time) * 1000
                
                # Update span with response info
                if span:
                    span.set_attribute('http.status_code', response.status_code)
                    span.set_attribute('response.duration_ms', duration_ms)
                    span.set_attribute('response.success', 200 <= response.status_code < 400)
                
                # Add response headers
                response.headers['X-Request-ID'] = request_id
                response.headers['X-Response-Time'] = f"{duration_ms:.2f}ms"
                
                # Log request completion
                log_api_request(
                    request_id=request_id,
                    method=request.method,
                    path=request.url.path,
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                    user_id=user_id
                )
                
                # Check for slow requests
                if duration_ms > self.slow_request_threshold:
                    self.logger.warning(
                        "Slow API request detected",
                        request_id=request_id,
                        method=request.method,
                        path=request.url.path,
                        duration_ms=duration_ms,
                        threshold_ms=self.slow_request_threshold
                    )
                
                return response
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                # Update span with error info
                if span:
                    span.set_attribute('http.status_code', 500)
                    span.set_attribute('response.duration_ms', duration_ms)
                    span.set_attribute('response.success', False)
                    span.set_attribute('error.message', str(e))
                
                # Log error
                self.logger.error(
                    "API request failed",
                    request_id=request_id,
                    method=request.method,
                    path=request.url.path,
                    duration_ms=duration_ms,
                    error=str(e),
                    user_id=user_id
                )
                
                # Re-raise the exception
                raise

class HealthCheckMiddleware(BaseHTTPMiddleware):
    """Middleware to handle health check requests efficiently."""
    
    def __init__(self, app, health_check_paths: list = None):
        super().__init__(app)
        self.health_check_paths = health_check_paths or ['/health', '/healthz', '/ping']
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip observability for health checks to reduce noise
        if request.url.path in self.health_check_paths:
            return await call_next(request)
        
        return await call_next(request)