"""
OpenTelemetry Tracing - Distributed tracing and observability for PhishNet
Provides complete request tracking from Gmail fetch → orchestrator → analyzer → DB
"""

import logging
import time
import uuid
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
from contextlib import contextmanager, asynccontextmanager
from functools import wraps

from opentelemetry import trace, metrics, baggage
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.trace.status import Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

logger = logging.getLogger(__name__)

@dataclass
class TracingConfig:
    """OpenTelemetry configuration"""
    service_name: str = "phishnet"
    service_version: str = "1.0.0"
    jaeger_endpoint: str = "http://localhost:14268/api/traces"
    prometheus_port: int = 8888
    enable_jaeger: bool = True
    enable_prometheus: bool = True
    sample_rate: float = 1.0
    max_span_attributes: int = 100
    environment: str = "development"

class PhishNetTracer:
    """
    Centralized tracing for PhishNet operations
    
    Features:
    - Distributed tracing across all components
    - Request correlation with unique IDs
    - Performance metrics and timing
    - Error tracking and debugging
    - Custom attributes and context
    - Span hierarchy for operation flows
    """
    
    def __init__(self, config: Optional[TracingConfig] = None):
        self.config = config or TracingConfig()
        self._tracer = None
        self._meter = None
        self._initialized = False
        
        # Metrics
        self._request_counter = None
        self._request_duration = None
        self._error_counter = None
        self._operation_duration = None
        
        self._setup_tracing()
    
    def _setup_tracing(self):
        """Setup OpenTelemetry tracing"""
        try:
            # Create resource
            resource = Resource.create({
                SERVICE_NAME: self.config.service_name,
                SERVICE_VERSION: self.config.service_version,
                "environment": self.config.environment
            })
            
            # Setup trace provider
            trace_provider = TracerProvider(resource=resource)
            
            # Setup Jaeger exporter
            if self.config.enable_jaeger:
                jaeger_exporter = JaegerExporter(
                    endpoint=self.config.jaeger_endpoint,
                )
                span_processor = BatchSpanProcessor(jaeger_exporter)
                trace_provider.add_span_processor(span_processor)
                logger.info(f"Jaeger tracing enabled: {self.config.jaeger_endpoint}")
            
            # Set global trace provider
            trace.set_tracer_provider(trace_provider)
            self._tracer = trace.get_tracer(__name__)
            
            # Setup metrics
            if self.config.enable_prometheus:
                metric_reader = PrometheusMetricReader(port=self.config.prometheus_port)
                meter_provider = MeterProvider(
                    resource=resource,
                    metric_readers=[metric_reader]
                )
                metrics.set_meter_provider(meter_provider)
                self._meter = metrics.get_meter(__name__)
                
                # Create metrics
                self._setup_metrics()
                logger.info(f"Prometheus metrics enabled on port {self.config.prometheus_port}")
            
            # Instrument libraries
            self._instrument_libraries()
            
            self._initialized = True
            logger.info("OpenTelemetry tracing initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize tracing: {e}")
            # Create dummy tracer for fallback
            self._tracer = trace.NoOpTracer()
    
    def _setup_metrics(self):
        """Setup custom metrics"""
        if not self._meter:
            return
        
        self._request_counter = self._meter.create_counter(
            name="phishnet_requests_total",
            description="Total number of requests processed",
            unit="1"
        )
        
        self._request_duration = self._meter.create_histogram(
            name="phishnet_request_duration_seconds",
            description="Request processing duration",
            unit="s"
        )
        
        self._error_counter = self._meter.create_counter(
            name="phishnet_errors_total",
            description="Total number of errors",
            unit="1"
        )
        
        self._operation_duration = self._meter.create_histogram(
            name="phishnet_operation_duration_seconds",
            description="Operation processing duration",
            unit="s"
        )
    
    def _instrument_libraries(self):
        """Instrument third-party libraries"""
        try:
            # FastAPI instrumentation
            FastAPIInstrumentor().instrument()
            
            # Database instrumentation
            SQLAlchemyInstrumentor().instrument()
            
            # Redis instrumentation
            RedisInstrumentor().instrument()
            
            # HTTP client instrumentation
            HTTPXClientInstrumentor().instrument()
            
            logger.info("Third-party libraries instrumented")
            
        except Exception as e:
            logger.warning(f"Library instrumentation failed: {e}")
    
    def generate_request_id(self) -> str:
        """Generate unique request ID"""
        return str(uuid.uuid4())
    
    @contextmanager
    def trace_operation(self, 
                       operation_name: str,
                       attributes: Optional[Dict[str, Any]] = None,
                       request_id: Optional[str] = None):
        """
        Context manager for tracing operations
        
        Args:
            operation_name: Name of the operation
            attributes: Additional span attributes
            request_id: Request correlation ID
        """
        if not self._tracer:
            yield None
            return
        
        # Generate request ID if not provided
        if not request_id:
            request_id = self.generate_request_id()
        
        # Start span
        with self._tracer.start_as_current_span(operation_name) as span:
            try:
                # Set basic attributes
                span.set_attribute("request.id", request_id)
                span.set_attribute("operation.name", operation_name)
                span.set_attribute("timestamp", datetime.utcnow().isoformat())
                
                # Set baggage for request correlation
                baggage.set_baggage("request.id", request_id)
                
                # Set custom attributes
                if attributes:
                    for key, value in attributes.items():
                        if isinstance(value, (str, int, float, bool)):
                            span.set_attribute(key, value)
                        else:
                            span.set_attribute(key, str(value))
                
                # Record start time
                start_time = time.time()
                
                # Yield span for additional customization
                yield span
                
                # Record success
                span.set_status(Status(StatusCode.OK))
                
                # Record metrics
                duration = time.time() - start_time
                if self._operation_duration:
                    self._operation_duration.record(
                        duration,
                        {"operation": operation_name, "status": "success"}
                    )
                
                logger.debug(f"Operation {operation_name} completed in {duration:.3f}s")
                
            except Exception as e:
                # Record error
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                
                # Record error metrics
                if self._error_counter:
                    self._error_counter.add(
                        1,
                        {"operation": operation_name, "error_type": type(e).__name__}
                    )
                
                logger.error(f"Operation {operation_name} failed: {e}")
                raise
    
    @asynccontextmanager
    async def trace_async_operation(self,
                                   operation_name: str,
                                   attributes: Optional[Dict[str, Any]] = None,
                                   request_id: Optional[str] = None):
        """Async version of trace_operation"""
        if not self._tracer:
            yield None
            return
        
        # Generate request ID if not provided
        if not request_id:
            request_id = self.generate_request_id()
        
        # Start span
        with self._tracer.start_as_current_span(operation_name) as span:
            try:
                # Set basic attributes
                span.set_attribute("request.id", request_id)
                span.set_attribute("operation.name", operation_name)
                span.set_attribute("timestamp", datetime.utcnow().isoformat())
                
                # Set baggage for request correlation
                baggage.set_baggage("request.id", request_id)
                
                # Set custom attributes
                if attributes:
                    for key, value in attributes.items():
                        if isinstance(value, (str, int, float, bool)):
                            span.set_attribute(key, value)
                        else:
                            span.set_attribute(key, str(value))
                
                # Record start time
                start_time = time.time()
                
                # Yield span for additional customization
                yield span
                
                # Record success
                span.set_status(Status(StatusCode.OK))
                
                # Record metrics
                duration = time.time() - start_time
                if self._operation_duration:
                    self._operation_duration.record(
                        duration,
                        {"operation": operation_name, "status": "success"}
                    )
                
                logger.debug(f"Async operation {operation_name} completed in {duration:.3f}s")
                
            except Exception as e:
                # Record error
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                
                # Record error metrics
                if self._error_counter:
                    self._error_counter.add(
                        1,
                        {"operation": operation_name, "error_type": type(e).__name__}
                    )
                
                logger.error(f"Async operation {operation_name} failed: {e}")
                raise
    
    def trace_email_processing_pipeline(self,
                                       email_id: str,
                                       request_id: Optional[str] = None):
        """
        Trace complete email processing pipeline
        
        Creates parent span for entire pipeline with child spans for each stage
        """
        if not request_id:
            request_id = self.generate_request_id()
        
        return self.trace_operation(
            "email_processing_pipeline",
            attributes={
                "email.id": email_id,
                "pipeline.stage": "start"
            },
            request_id=request_id
        )
    
    def trace_gmail_fetch(self, batch_size: int, request_id: str):
        """Trace Gmail API fetch operation"""
        return self.trace_operation(
            "gmail_fetch",
            attributes={
                "gmail.batch_size": batch_size,
                "source": "gmail_api"
            },
            request_id=request_id
        )
    
    def trace_email_analysis(self, email_id: str, analyzer_type: str, request_id: str):
        """Trace email analysis operation"""
        return self.trace_operation(
            "email_analysis",
            attributes={
                "email.id": email_id,
                "analyzer.type": analyzer_type,
                "stage": "analysis"
            },
            request_id=request_id
        )
    
    def trace_link_extraction(self, email_id: str, url_count: int, request_id: str):
        """Trace link extraction operation"""
        return self.trace_operation(
            "link_extraction",
            attributes={
                "email.id": email_id,
                "links.count": url_count,
                "stage": "link_extraction"
            },
            request_id=request_id
        )
    
    def trace_threat_intel_lookup(self, indicators: List[str], source: str, request_id: str):
        """Trace threat intelligence lookup"""
        return self.trace_operation(
            "threat_intel_lookup",
            attributes={
                "threat_intel.source": source,
                "indicators.count": len(indicators),
                "stage": "threat_intelligence"
            },
            request_id=request_id
        )
    
    def trace_database_operation(self, operation: str, table: str, request_id: str):
        """Trace database operation"""
        return self.trace_operation(
            f"db_{operation}",
            attributes={
                "db.operation": operation,
                "db.table": table,
                "stage": "database"
            },
            request_id=request_id
        )
    
    def trace_sandbox_analysis(self, url: str, sandbox_type: str, request_id: str):
        """Trace sandbox analysis operation"""
        return self.trace_operation(
            "sandbox_analysis",
            attributes={
                "sandbox.type": sandbox_type,
                "sandbox.target": url,
                "stage": "sandbox"
            },
            request_id=request_id
        )
    
    def get_current_request_id(self) -> Optional[str]:
        """Get current request ID from baggage"""
        return baggage.get_baggage("request.id")
    
    def add_span_attribute(self, key: str, value: Any):
        """Add attribute to current span"""
        span = trace.get_current_span()
        if span and span.is_recording():
            if isinstance(value, (str, int, float, bool)):
                span.set_attribute(key, value)
            else:
                span.set_attribute(key, str(value))
    
    def record_metric(self, metric_name: str, value: float, attributes: Optional[Dict[str, str]] = None):
        """Record custom metric"""
        if metric_name == "request" and self._request_counter:
            self._request_counter.add(1, attributes or {})
        elif metric_name == "request_duration" and self._request_duration:
            self._request_duration.record(value, attributes or {})
        elif metric_name == "error" and self._error_counter:
            self._error_counter.add(1, attributes or {})
        elif metric_name == "operation_duration" and self._operation_duration:
            self._operation_duration.record(value, attributes or {})

# Global tracer instance
_tracer_instance = None

def get_tracer() -> PhishNetTracer:
    """Get global tracer instance"""
    global _tracer_instance
    if _tracer_instance is None:
        _tracer_instance = PhishNetTracer()
    return _tracer_instance

def trace_function(operation_name: Optional[str] = None,
                  attributes: Optional[Dict[str, Any]] = None):
    """
    Decorator to trace function execution
    
    Args:
        operation_name: Custom operation name (defaults to function name)
        attributes: Additional span attributes
    """
    def decorator(func):
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            tracer = get_tracer()
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            
            with tracer.trace_operation(op_name, attributes):
                return func(*args, **kwargs)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer()
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            
            async with tracer.trace_async_operation(op_name, attributes):
                return await func(*args, **kwargs)
        
        # Return appropriate wrapper based on function type
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

# WebSocket tracing helpers
class WebSocketTracer:
    """Helper for tracing WebSocket operations"""
    
    def __init__(self, connection_id: str):
        self.connection_id = connection_id
        self.tracer = get_tracer()
    
    def trace_connection(self):
        """Trace WebSocket connection"""
        return self.tracer.trace_operation(
            "websocket_connection",
            attributes={
                "websocket.connection_id": self.connection_id,
                "websocket.event": "connect"
            }
        )
    
    def trace_message(self, message_type: str, message_size: int):
        """Trace WebSocket message"""
        return self.tracer.trace_operation(
            "websocket_message",
            attributes={
                "websocket.connection_id": self.connection_id,
                "websocket.message_type": message_type,
                "websocket.message_size": message_size
            }
        )
    
    def trace_disconnect(self, reason: str = "normal"):
        """Trace WebSocket disconnection"""
        return self.tracer.trace_operation(
            "websocket_disconnect",
            attributes={
                "websocket.connection_id": self.connection_id,
                "websocket.disconnect_reason": reason
            }
        )

# Context propagation helpers
def inject_trace_context(headers: Dict[str, str]) -> Dict[str, str]:
    """Inject trace context into HTTP headers"""
    propagator = TraceContextTextMapPropagator()
    propagator.inject(headers)
    return headers

def extract_trace_context(headers: Dict[str, str]):
    """Extract trace context from HTTP headers"""
    propagator = TraceContextTextMapPropagator()
    return propagator.extract(headers)

# Example usage functions
@trace_function("example_email_processing")
async def example_email_processing(email_id: str):
    """Example of traced email processing"""
    tracer = get_tracer()
    request_id = tracer.generate_request_id()
    
    # Trace overall pipeline
    with tracer.trace_email_processing_pipeline(email_id, request_id):
        
        # Trace Gmail fetch
        with tracer.trace_gmail_fetch(10, request_id):
            # Simulate Gmail API call
            await asyncio.sleep(0.1)
        
        # Trace email analysis
        with tracer.trace_email_analysis(email_id, "ml_classifier", request_id):
            # Simulate ML analysis
            await asyncio.sleep(0.2)
        
        # Trace link extraction
        with tracer.trace_link_extraction(email_id, 3, request_id):
            # Simulate link extraction
            await asyncio.sleep(0.1)
        
        # Trace threat intel
        with tracer.trace_threat_intel_lookup(["domain1.com", "ip1"], "virustotal", request_id):
            # Simulate threat intel lookup
            await asyncio.sleep(0.3)
        
        # Trace database save
        with tracer.trace_database_operation("insert", "emails", request_id):
            # Simulate database operation
            await asyncio.sleep(0.05)

def example_tracing_setup():
    """Example of setting up tracing"""
    
    # Custom configuration
    config = TracingConfig(
        service_name="phishnet-production",
        service_version="2.0.0",
        jaeger_endpoint="http://jaeger:14268/api/traces",
        environment="production",
        sample_rate=0.1  # Sample 10% of traces in production
    )
    
    # Initialize tracer
    tracer = PhishNetTracer(config)
    
    # Example operation
    with tracer.trace_operation("user_login", {"user.id": "123", "user.role": "admin"}):
        print("Processing user login...")
        time.sleep(0.1)
    
    print("Tracing example completed")

if __name__ == "__main__":
    import asyncio
    
    # Run examples
    example_tracing_setup()
    asyncio.run(example_email_processing("email_123"))
