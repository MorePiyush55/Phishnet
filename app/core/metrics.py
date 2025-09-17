"""Enhanced Prometheus metrics and performance tracking for PhishNet."""

import time
import uuid
from typing import Callable, Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import deque
import asyncio

from fastapi import FastAPI, Request, Response
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
import logging

from app.config.logging import get_logger
from app.core.redis_client import get_cache_manager

logger = get_logger(__name__)

# Enhanced PhishNet metrics
emails_processed = Counter('phishnet_emails_processed_total', 'Total emails processed')
cache_hits = Counter('phishnet_cache_hits_total', 'Total cache hits')
cache_misses = Counter('phishnet_cache_misses_total', 'Total cache misses')
processing_time = Histogram('phishnet_processing_time_seconds', 'Email processing time')
analysis_errors = Counter('phishnet_analysis_errors_total', 'Total analysis errors')
threat_detections = Counter('phishnet_threats_detected_total', 'Total threats detected', ['risk_level'])
false_positives = Counter('phishnet_false_positives_total', 'Total false positives reported')

# Real-time performance gauges
current_emails_per_second = Gauge('phishnet_emails_per_second', 'Current emails processed per second')
current_cache_hit_ratio = Gauge('phishnet_cache_hit_ratio', 'Current cache hit ratio')
ensemble_model_accuracy = Gauge('phishnet_ensemble_accuracy', 'Ensemble model accuracy')

# Original metrics
REQUEST_COUNT = Counter(
    'phishnet_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_DURATION = Histogram(
    'phishnet_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

ACTIVE_CONNECTIONS = Gauge(
    'phishnet_active_connections',
    'Number of active connections'
)

EMAIL_ANALYSIS_COUNT = Counter(
    'phishnet_email_analysis_total',
    'Total email analyses performed',
    ['result']
)

EMAIL_ANALYSIS_DURATION = Histogram(
    'phishnet_email_analysis_duration_seconds',
    'Email analysis duration in seconds',
    ['component']
)

THREAT_DETECTIONS = Counter(
    'phishnet_threat_detections_total',
    'Total threat detections',
    ['threat_type', 'severity']
)

API_ERRORS = Counter(
    'phishnet_api_errors_total',
    'Total API errors',
    ['endpoint', 'error_type']
)

DATABASE_CONNECTIONS = Gauge(
    'phishnet_database_connections_active',
    'Active database connections'
)

CACHE_OPERATIONS = Counter(
    'phishnet_cache_operations_total',
    'Total cache operations',
    ['operation', 'result']
)

EXTERNAL_API_CALLS = Counter(
    'phishnet_external_api_calls_total',
    'Total external API calls',
    ['service', 'status']
)

EXTERNAL_API_DURATION = Histogram(
    'phishnet_external_api_duration_seconds',
    'External API call duration',
    ['service']
)


class MetricsMiddleware:
    """Middleware for collecting HTTP request metrics."""
    
    def __init__(self, app: FastAPI):
        self.app = app
    
    async def __call__(self, request: Request, call_next: Callable) -> Response:
        # Generate correlation ID
        correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        
        # Track active connections
        ACTIVE_CONNECTIONS.inc()
        
        # Start timing
        start_time = time.time()
        
        # Get endpoint info
        method = request.method
        path = request.url.path
        
        # Sanitize path for metrics (remove IDs, etc.)
        sanitized_path = self._sanitize_path(path)
        
        try:
            # Process request
            response = await call_next(request)
            
            # Record metrics
            duration = time.time() - start_time
            status_code = str(response.status_code)
            
            REQUEST_COUNT.labels(
                method=method,
                endpoint=sanitized_path,
                status_code=status_code
            ).inc()
            
            REQUEST_DURATION.labels(
                method=method,
                endpoint=sanitized_path
            ).observe(duration)
            
            # Add correlation ID to response headers
            response.headers["X-Correlation-ID"] = correlation_id
            
            # Log request
            logger.info(
                f"{method} {path} {status_code} {duration:.3f}s",
                extra={
                    "correlation_id": correlation_id,
                    "method": method,
                    "path": path,
                    "status_code": response.status_code,
                    "duration": duration,
                    "user_agent": request.headers.get("user-agent", ""),
                    "ip_address": self._get_client_ip(request)
                }
            )
            
            return response
            
        except Exception as e:
            # Record error metrics
            duration = time.time() - start_time
            
            REQUEST_COUNT.labels(
                method=method,
                endpoint=sanitized_path,
                status_code="500"
            ).inc()
            
            API_ERRORS.labels(
                endpoint=sanitized_path,
                error_type=type(e).__name__
            ).inc()
            
            # Log error
            logger.error(
                f"{method} {path} ERROR {duration:.3f}s: {str(e)}",
                extra={
                    "correlation_id": correlation_id,
                    "method": method,
                    "path": path,
                    "duration": duration,
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "user_agent": request.headers.get("user-agent", ""),
                    "ip_address": self._get_client_ip(request)
                },
                exc_info=True
            )
            
            raise
            
        finally:
            # Decrement active connections
            ACTIVE_CONNECTIONS.dec()
    
    def _sanitize_path(self, path: str) -> str:
        """Sanitize path for metrics to avoid high cardinality."""
        # Replace UUIDs and IDs with placeholders
        import re
        
        # Replace UUIDs
        path = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/{uuid}',
            path,
            flags=re.IGNORECASE
        )
        
        # Replace numeric IDs
        path = re.sub(r'/\d+(?=/|$)', '/{id}', path)
        
        # Replace email addresses
        path = re.sub(r'/[^/]+@[^/]+(?=/|$)', '/{email}', path)
        
        return path
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check X-Forwarded-For header first (for load balancers)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to client host
        return request.client.host if request.client else "unknown"


class BusinessMetrics:
    """Business-specific metrics collection."""
    
    @staticmethod
    def record_email_analysis(result: str, duration: float, component: str = "total"):
        """Record email analysis metrics."""
        EMAIL_ANALYSIS_COUNT.labels(result=result).inc()
        EMAIL_ANALYSIS_DURATION.labels(component=component).observe(duration)
    
    @staticmethod
    def record_threat_detection(threat_type: str, severity: str):
        """Record threat detection metrics."""
        THREAT_DETECTIONS.labels(threat_type=threat_type, severity=severity).inc()
    
    @staticmethod
    def record_cache_operation(operation: str, result: str):
        """Record cache operation metrics."""
        CACHE_OPERATIONS.labels(operation=operation, result=result).inc()
    
    @staticmethod
    def record_external_api_call(service: str, status: str, duration: float):
        """Record external API call metrics."""
        EXTERNAL_API_CALLS.labels(service=service, status=status).inc()
        EXTERNAL_API_DURATION.labels(service=service).observe(duration)
    
    @staticmethod
    def set_database_connections(count: int):
        """Set active database connections gauge."""
        DATABASE_CONNECTIONS.set(count)


async def metrics_endpoint(request: Request) -> Response:
    """Prometheus metrics endpoint."""
    return Response(
        generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


def setup_metrics(app: FastAPI):
    """Setup metrics collection for FastAPI app."""
    # Add metrics middleware
    app.middleware("http")(MetricsMiddleware(app))
    
    # Add metrics endpoint
    app.add_route("/metrics", metrics_endpoint, methods=["GET"])
    
    logger.info("Metrics collection initialized")


def get_business_metrics():
    """Get business metrics instance."""
    return BusinessMetrics()


# Backwards-compatible object used by older modules/tests
class _PerformanceMetricsProxy:
    def __init__(self):
        self.emails_processed = emails_processed
        self.cache_hits = cache_hits
        self.cache_misses = cache_misses
        self.processing_time = processing_time
        self.analysis_errors = analysis_errors


performance_metrics = _PerformanceMetricsProxy()


@dataclass
class PerformanceWindow:
    """Sliding window for performance metrics."""
    window_size: int = 60  # seconds
    data: deque = field(default_factory=deque)
    
    def add_measurement(self, value: float, timestamp: Optional[float] = None):
        """Add a measurement to the window."""
        if timestamp is None:
            timestamp = time.time()
        
        self.data.append((timestamp, value))
        
        # Remove old measurements
        cutoff_time = timestamp - self.window_size
        while self.data and self.data[0][0] < cutoff_time:
            self.data.popleft()
    
    def get_rate(self) -> float:
        """Get the current rate (measurements per second)."""
        if len(self.data) < 2:
            return 0.0
        
        time_span = self.data[-1][0] - self.data[0][0]
        if time_span == 0:
            return 0.0
        
        return len(self.data) / time_span
    
    def get_average(self) -> float:
        """Get the average value in the window."""
        if not self.data:
            return 0.0
        
        return sum(value for _, value in self.data) / len(self.data)


class PerformanceTracker:
    """Real-time performance tracking system for PhishNet."""
    
    def __init__(self):
        """Initialize performance tracker."""
        self.email_processing_window = PerformanceWindow(60)  # 1 minute window
        self.response_time_window = PerformanceWindow(60)
        
        # Counters
        self.total_emails_processed = 0
        self.total_cache_hits = 0
        self.total_cache_misses = 0
        self.total_threats_detected = 0
        self.total_false_positives = 0
        
        # Performance tracking
        self.start_time = time.time()
        self._running = False
    
    def track_email_processed(self, processing_time_ms: int, is_threat: bool = False, 
                            risk_level: str = "LOW", from_cache: bool = False):
        """Track email processing metrics."""
        current_time = time.time()
        
        # Update counters
        self.total_emails_processed += 1
        if is_threat:
            self.total_threats_detected += 1
            threat_detections.labels(risk_level=risk_level).inc()
        
        if from_cache:
            self.total_cache_hits += 1
            cache_hits.inc()
        else:
            self.total_cache_misses += 1
            cache_misses.inc()
        
        # Update windows
        self.email_processing_window.add_measurement(1, current_time)
        self.response_time_window.add_measurement(processing_time_ms, current_time)
        
        # Update Prometheus metrics
        emails_processed.inc()
        processing_time.observe(processing_time_ms / 1000)
        
        # Update real-time gauges
        current_emails_per_second.set(self.email_processing_window.get_rate())
        
        total_requests = self.total_cache_hits + self.total_cache_misses
        hit_ratio = self.total_cache_hits / total_requests if total_requests > 0 else 0
        current_cache_hit_ratio.set(hit_ratio)
    
    def track_false_positive(self):
        """Track false positive report."""
        self.total_false_positives += 1
        false_positives.inc()
    
    async def get_performance_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics for dashboard."""
        current_time = time.time()
        uptime_seconds = current_time - self.start_time
        
        # Calculate rates and ratios
        emails_per_second = self.email_processing_window.get_rate()
        avg_response_time = self.response_time_window.get_average()
        
        total_cache_requests = self.total_cache_hits + self.total_cache_misses
        cache_hit_ratio = self.total_cache_hits / total_cache_requests if total_cache_requests > 0 else 0
        
        # Performance targets
        targets = {
            "emails_per_second": 167,  # 10k per minute target
            "cache_hit_ratio": 0.95,
            "response_time_ms": 1000,
            "detection_accuracy": 0.98
        }
        
        # Calculate progress toward targets
        performance_score = 0
        if emails_per_second > 0:
            performance_score += min(emails_per_second / targets["emails_per_second"], 1.0) * 25
        performance_score += min(cache_hit_ratio / targets["cache_hit_ratio"], 1.0) * 25
        if avg_response_time > 0:
            performance_score += max(0, (targets["response_time_ms"] - avg_response_time) / targets["response_time_ms"]) * 25
        performance_score += 25  # Base score for system operation
        
        dashboard_data = {
            "realtime": {
                "emails_per_second": round(emails_per_second, 2),
                "avg_response_time_ms": round(avg_response_time, 2),
                "cache_hit_ratio": round(cache_hit_ratio, 4),
                "uptime_hours": round(uptime_seconds / 3600, 2),
                "performance_score": round(performance_score, 1)
            },
            "totals": {
                "emails_processed": self.total_emails_processed,
                "threats_detected": self.total_threats_detected,
                "false_positives": self.total_false_positives,
                "cache_hits": self.total_cache_hits,
                "cache_misses": self.total_cache_misses
            },
            "targets": targets,
            "alerts": []
        }
        
        # Generate performance alerts
        if emails_per_second < targets["emails_per_second"] * 0.8:
            dashboard_data["alerts"].append({
                "type": "warning",
                "message": f"Email processing rate below 80% of target ({emails_per_second:.1f}/{targets['emails_per_second']} emails/sec)"
            })
        
        if cache_hit_ratio < targets["cache_hit_ratio"] * 0.9:
            dashboard_data["alerts"].append({
                "type": "warning", 
                "message": f"Cache hit ratio below 90% of target ({cache_hit_ratio:.3f}/{targets['cache_hit_ratio']})"
            })
        
        if avg_response_time > targets["response_time_ms"] * 1.2:
            dashboard_data["alerts"].append({
                "type": "error",
                "message": f"Response time exceeds 120% of target ({avg_response_time:.1f}ms/{targets['response_time_ms']}ms)"
            })
        
        return dashboard_data


# Global performance tracker instance
performance_tracker = PerformanceTracker()
