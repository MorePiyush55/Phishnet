"""
OpenTelemetry instrumentation and tracing configuration for PhishNet.
Provides distributed tracing, metrics, and observability.
"""

import os
import logging
from typing import Optional, Dict, Any

# Make OpenTelemetry imports optional to prevent startup failures
try:
    from opentelemetry import trace, metrics
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    from opentelemetry.exporter.prometheus import PrometheusMetricReader
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    from opentelemetry.instrumentation.redis import RedisInstrumentor
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
    from opentelemetry.semconv.trace import SpanAttributes
    from opentelemetry.trace.status import Status, StatusCode
    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    OPENTELEMETRY_AVAILABLE = False
    trace = None
    metrics = None

# Optional: aiohttp instrumentation (often missing)
try:
    from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
    AIOHTTP_INSTRUMENTATION_AVAILABLE = True
except ImportError:
    AIOHTTP_INSTRUMENTATION_AVAILABLE = False
    AioHttpClientInstrumentor = None

from app.config.settings import settings
from app.config.logging import get_logger

logger = get_logger(__name__)

# Global tracer and meter instances
_tracer: Optional[trace.Tracer] = None
_meter: Optional[metrics.Meter] = None

# Metrics instruments
_emails_processed_counter: Optional[metrics.Counter] = None
_scan_latency_histogram: Optional[metrics.Histogram] = None
_api_error_counter: Optional[metrics.Counter] = None
_external_api_failures_counter: Optional[metrics.Counter] = None
_circuit_breaker_state_gauge: Optional[Any] = None


def configure_resource() -> Resource:
    """Configure OpenTelemetry resource with service information."""
    return Resource.create({
        SERVICE_NAME: "phishnet",
        SERVICE_VERSION: getattr(settings, 'VERSION', '1.0.0'),
        "service.environment": getattr(settings, 'ENVIRONMENT', 'development'),
        "service.component": "backend"
    })


def configure_tracing() -> None:
    """Configure OpenTelemetry tracing with Jaeger export."""
    global _tracer
    
    resource = configure_resource()
    
    # Configure tracer provider
    trace.set_tracer_provider(TracerProvider(resource=resource))
    
    # Configure Jaeger exporter
    jaeger_exporter = JaegerExporter(
        agent_host_name=getattr(settings, 'JAEGER_HOST', 'localhost'),
        agent_port=getattr(settings, 'JAEGER_PORT', 6831),
    )
    
    # Add span processor
    span_processor = BatchSpanProcessor(jaeger_exporter)
    trace.get_tracer_provider().add_span_processor(span_processor)
    
    # Get tracer instance
    _tracer = trace.get_tracer(__name__)
    
    logger.info("OpenTelemetry tracing configured with Jaeger export")


def configure_metrics() -> None:
    """Configure OpenTelemetry metrics with Prometheus export."""
    global _meter, _emails_processed_counter, _scan_latency_histogram
    global _api_error_counter, _external_api_failures_counter, _circuit_breaker_state_gauge
    
    resource = configure_resource()
    
    # Configure Prometheus metric reader
    prometheus_reader = PrometheusMetricReader()
    
    # Configure meter provider
    metrics.set_meter_provider(MeterProvider(
        resource=resource,
        metric_readers=[prometheus_reader]
    ))
    
    # Get meter instance
    _meter = metrics.get_meter(__name__)
    
    # Create metric instruments
    _emails_processed_counter = _meter.create_counter(
        name="emails_processed_total",
        description="Total number of emails processed",
        unit="1"
    )
    
    _scan_latency_histogram = _meter.create_histogram(
        name="scan_latency_seconds",
        description="Email scan latency distribution",
        unit="s",
        boundaries=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
    )
    
    _api_error_counter = _meter.create_counter(
        name="api_error_rate",
        description="API error rate by endpoint and status code",
        unit="1"
    )
    
    _external_api_failures_counter = _meter.create_counter(
        name="external_api_failures",
        description="External API failures by service",
        unit="1"
    )
    
    _circuit_breaker_state_gauge = _meter.create_gauge(
        name="circuit_breaker_state",
        description="Circuit breaker state (0=closed, 1=half-open, 2=open)",
        unit="1"
    )
    
    logger.info("OpenTelemetry metrics configured with Prometheus export")


def instrument_libraries() -> None:
    """Auto-instrument common libraries."""
    if not OPENTELEMETRY_AVAILABLE:
        logger.warning("OpenTelemetry not available, skipping library instrumentation")
        return
        
    try:
        # Instrument FastAPI
        FastAPIInstrumentor.instrument()
        
        # Instrument HTTP clients
        RequestsInstrumentor().instrument()
        
        # Instrument aiohttp if available
        if AIOHTTP_INSTRUMENTATION_AVAILABLE and AioHttpClientInstrumentor:
            AioHttpClientInstrumentor().instrument()
        
        # Instrument Redis
        RedisInstrumentor().instrument()
        
        # Instrument SQLAlchemy
        SQLAlchemyInstrumentor().instrument()
        
        logger.info("Libraries instrumented for tracing")
        
    except Exception as e:
        logger.error(f"Failed to instrument libraries: {e}")


def setup_observability() -> None:
    """Setup complete observability stack."""
    try:
        configure_tracing()
        configure_metrics()
        instrument_libraries()
        logger.info("OpenTelemetry observability setup complete")
        
    except Exception as e:
        logger.error(f"Failed to setup observability: {e}")
        # Don't fail application startup for observability issues
        pass


def get_tracer() -> trace.Tracer:
    """Get the configured tracer instance."""
    global _tracer
    if _tracer is None:
        # Fallback tracer if not configured
        _tracer = trace.get_tracer(__name__)
    return _tracer


def get_meter() -> metrics.Meter:
    """Get the configured meter instance."""
    global _meter
    if _meter is None:
        # Fallback meter if not configured
        _meter = metrics.get_meter(__name__)
    return _meter


# Metric recording functions
def record_email_processed(status: str, threat_level: str = "unknown") -> None:
    """Record an email processing event."""
    if _emails_processed_counter:
        _emails_processed_counter.add(1, {
            "status": status,
            "threat_level": threat_level
        })


def record_scan_latency(latency_seconds: float, scan_type: str = "full") -> None:
    """Record scan latency."""
    if _scan_latency_histogram:
        _scan_latency_histogram.record(latency_seconds, {
            "scan_type": scan_type
        })


def record_api_error(endpoint: str, status_code: int, method: str = "GET") -> None:
    """Record an API error."""
    if _api_error_counter:
        _api_error_counter.add(1, {
            "endpoint": endpoint,
            "status_code": str(status_code),
            "method": method
        })


def record_external_api_failure(service: str, error_type: str = "unknown") -> None:
    """Record external API failure."""
    if _external_api_failures_counter:
        _external_api_failures_counter.add(1, {
            "service": service,
            "error_type": error_type
        })


def record_circuit_breaker_state(service: str, state: int) -> None:
    """Record circuit breaker state (0=closed, 1=half-open, 2=open)."""
    if _circuit_breaker_state_gauge:
        _circuit_breaker_state_gauge.set(state, {"service": service})


# Tracing decorators and context managers
class traced_span:
    """Context manager for creating traced spans."""
    
    def __init__(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        self.name = name
        self.attributes = attributes or {}
        self.span = None
    
    def __enter__(self):
        tracer = get_tracer()
        self.span = tracer.start_span(self.name)
        
        # Set attributes
        for key, value in self.attributes.items():
            self.span.set_attribute(key, str(value))
        
        return self.span
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.span:
            if exc_type:
                self.span.set_status(Status(StatusCode.ERROR, str(exc_val)))
                self.span.set_attribute("error", True)
                self.span.set_attribute("error.type", exc_type.__name__)
                self.span.set_attribute("error.message", str(exc_val))
            else:
                self.span.set_status(Status(StatusCode.OK))
            
            self.span.end()


def trace_external_api_call(service: str, operation: str):
    """Decorator for tracing external API calls."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            with traced_span(
                f"{service}.{operation}",
                {
                    "service.name": service,
                    "operation": operation,
                    SpanAttributes.HTTP_METHOD: "POST"  # Most APIs use POST
                }
            ) as span:
                try:
                    result = await func(*args, **kwargs)
                    span.set_attribute("success", True)
                    return result
                    
                except Exception as e:
                    span.set_attribute("success", False)
                    record_external_api_failure(service, type(e).__name__)
                    raise
        
        return wrapper
    return decorator


def trace_orchestrator_step(step_name: str):
    """Decorator for tracing orchestrator steps."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            with traced_span(
                f"orchestrator.{step_name}",
                {
                    "component": "orchestrator",
                    "step": step_name
                }
            ) as span:
                try:
                    result = await func(*args, **kwargs)
                    span.set_attribute("success", True)
                    return result
                    
                except Exception as e:
                    span.set_attribute("success", False)
                    raise
        
        return wrapper
    return decorator


# Health check for observability
def get_observability_health() -> Dict[str, Any]:
    """Get observability system health status."""
    health = {
        "tracing_enabled": _tracer is not None,
        "metrics_enabled": _meter is not None,
        "instrumentation_active": True
    }
    
    try:
        # Test if we can create a span
        tracer = get_tracer()
        with tracer.start_span("health_check") as span:
            span.set_attribute("test", "true")
            span.end()
        health["tracing_functional"] = True
        
    except Exception as e:
        health["tracing_functional"] = False
        health["tracing_error"] = str(e)
    
    return health
