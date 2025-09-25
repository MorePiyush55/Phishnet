"""
Centralized Observability Infrastructure
Implements structured logging, tracing, and error capture for PhishNet.
"""

import logging
import json
import time
import traceback
from typing import Dict, Any, Optional
from datetime import datetime
from contextlib import contextmanager
import asyncio
import functools

# Third-party imports with fallbacks
try:
    import sentry_sdk
    from sentry_sdk.integrations.logging import LoggingIntegration
    from sentry_sdk.integrations.redis import RedisIntegration
    SENTRY_AVAILABLE = True
    
    # Optional SQLAlchemy integration - disabled for Python 3.13 compatibility
    try:
        # from sentry_sdk.integrations.sqlalchemy import SqlAlchemyIntegration
        SqlAlchemyIntegration = None
        SQLALCHEMY_INTEGRATION_AVAILABLE = False
    except ImportError:
        SqlAlchemyIntegration = None
        SQLALCHEMY_INTEGRATION_AVAILABLE = False
    
    # Optional Celery integration - disabled for deployment compatibility
    CeleryIntegration = None
    CELERY_INTEGRATION_AVAILABLE = False
        
except ImportError:
    SENTRY_AVAILABLE = False
    SQLALCHEMY_INTEGRATION_AVAILABLE = False
    CELERY_INTEGRATION_AVAILABLE = False

try:
    from opentelemetry import trace
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.celery import CeleryInstrumentor
    from opentelemetry.instrumentation.redis import RedisInstrumentor
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    OPENTELEMETRY_AVAILABLE = False

from app.core.config import get_settings

# Lazy loading of settings - only load when needed
_settings = None

def get_cached_settings():
    """Get cached settings, loading them only once."""
    global _settings
    if _settings is None:
        _settings = get_settings()
    return _settings

class StructuredLogger:
    """Structured JSON logger for PhishNet."""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.setup_structured_logging()
        
    def setup_structured_logging(self):
        """Configure structured JSON logging."""
        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            
        # Create JSON formatter
        formatter = StructuredFormatter()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler for production
        settings = get_cached_settings()
        if hasattr(settings, 'LOG_FILE') and settings.LOG_FILE:
            file_handler = logging.FileHandler(settings.LOG_FILE)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            
        # Set level
        settings = get_cached_settings()
        log_level = getattr(settings, 'LOG_LEVEL', 'INFO')
        self.logger.setLevel(getattr(logging, log_level))
    
    def _log_with_context(self, level: str, message: str, extra: Dict[str, Any] = None):
        """Log with structured context."""
        context = {
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'phishnet',
            'component': self.logger.name,
            'level': level,
            'message': message
        }
        
        if extra:
            context.update(extra)
            
        # Add trace context if available
        if OPENTELEMETRY_AVAILABLE:
            span = trace.get_current_span()
            if span:
                span_context = span.get_span_context()
                context['trace_id'] = format(span_context.trace_id, '032x')
                context['span_id'] = format(span_context.span_id, '016x')
        
        getattr(self.logger, level.lower())(json.dumps(context))
    
    def info(self, message: str, **kwargs):
        self._log_with_context('INFO', message, kwargs)
        
    def error(self, message: str, **kwargs):
        self._log_with_context('ERROR', message, kwargs)
        
    def warning(self, message: str, **kwargs):
        self._log_with_context('WARNING', message, kwargs)
        
    def debug(self, message: str, **kwargs):
        self._log_with_context('DEBUG', message, kwargs)
        
    def exception(self, message: str, **kwargs):
        kwargs['traceback'] = traceback.format_exc()
        self._log_with_context('ERROR', message, kwargs)

class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging."""
    
    def format(self, record):
        # If record already contains structured data, return it
        if hasattr(record, 'structured') and record.structured:
            return record.getMessage()
            
        # Otherwise, create structured format
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
            
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                          'pathname', 'filename', 'module', 'lineno', 'funcName',
                          'created', 'msecs', 'relativeCreated', 'thread',
                          'threadName', 'processName', 'process', 'getMessage',
                          'exc_info', 'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry)

class TracingManager:
    """OpenTelemetry tracing management."""
    
    def __init__(self):
        self.tracer = None
        self.setup_tracing()
        
    def setup_tracing(self):
        """Configure OpenTelemetry tracing."""
        if not OPENTELEMETRY_AVAILABLE:
            return
            
        # Set up tracer provider
        trace.set_tracer_provider(TracerProvider())
        
        # Configure Jaeger exporter
        settings = get_cached_settings()
        jaeger_exporter = JaegerExporter(
            agent_host_name=getattr(settings, 'JAEGER_HOST', 'localhost'),
            agent_port=getattr(settings, 'JAEGER_PORT', 6831),
        )
        
        # Set up span processor
        span_processor = BatchSpanProcessor(jaeger_exporter)
        trace.get_tracer_provider().add_span_processor(span_processor)
        
        # Get tracer
        self.tracer = trace.get_tracer("phishnet")
        
        # Instrument frameworks
        self._instrument_frameworks()
    
    def _instrument_frameworks(self):
        """Instrument frameworks for automatic tracing."""
        if not OPENTELEMETRY_AVAILABLE:
            return
            
        try:
            # Instrument FastAPI
            FastAPIInstrumentor().instrument()
            
            # Instrument Celery
            CeleryInstrumentor().instrument()
            
            # Instrument Redis
            RedisInstrumentor().instrument()
            
            # Instrument SQLAlchemy
            SQLAlchemyInstrumentor().instrument()
            
        except Exception as e:
            print(f"Warning: Failed to instrument some frameworks: {e}")
    
    @contextmanager
    def trace(self, name: str, attributes: Dict[str, Any] = None):
        """Create a trace span."""
        if not self.tracer:
            yield None
            return
            
        with self.tracer.start_as_current_span(name) as span:
            if attributes:
                for key, value in attributes.items():
                    span.set_attribute(key, str(value))
            
            yield span

class ErrorCapture:
    """Sentry error capture and monitoring."""
    
    def __init__(self):
        self.setup_sentry()
        
    def setup_sentry(self):
        """Configure Sentry error capture."""
        if not SENTRY_AVAILABLE:
            return
        
        settings = get_cached_settings()
        sentry_dsn = getattr(settings, 'SENTRY_DSN', None)
        if not sentry_dsn:
            return
            
        # Configure Sentry
        sentry_logging = LoggingIntegration(
            level=logging.INFO,
            event_level=logging.ERROR
        )
        
        sentry_sdk.init(
            dsn=sentry_dsn,
            environment=getattr(settings, 'ENVIRONMENT', 'development'),
            integrations=[
                sentry_logging,
                RedisIntegration()
            ] + ([CeleryIntegration()] if CELERY_INTEGRATION_AVAILABLE and CeleryIntegration else []) + 
            ([SqlAlchemyIntegration()] if SQLALCHEMY_INTEGRATION_AVAILABLE and SqlAlchemyIntegration else []),
            traces_sample_rate=getattr(settings, 'SENTRY_TRACES_SAMPLE_RATE', 0.1),
            send_default_pii=False,  # Privacy compliance
            before_send=self._filter_sensitive_data
        )
    
    def _filter_sensitive_data(self, event, hint):
        """Filter sensitive data before sending to Sentry."""
        # Remove PII from events
        if 'extra' in event:
            for key in list(event['extra'].keys()):
                if any(sensitive in key.lower() for sensitive in 
                      ['email', 'token', 'password', 'key', 'secret']):
                    event['extra'][key] = '[REDACTED]'
        
        # Remove sensitive data from breadcrumbs
        if 'breadcrumbs' in event:
            for breadcrumb in event['breadcrumbs'].get('values', []):
                if 'data' in breadcrumb:
                    for key in list(breadcrumb['data'].keys()):
                        if any(sensitive in key.lower() for sensitive in 
                              ['email', 'token', 'password', 'key', 'secret']):
                            breadcrumb['data'][key] = '[REDACTED]'
        
        return event
    
    def capture_exception(self, exception: Exception, extra: Dict[str, Any] = None):
        """Capture exception with context."""
        if SENTRY_AVAILABLE:
            with sentry_sdk.configure_scope() as scope:
                if extra:
                    for key, value in extra.items():
                        scope.set_extra(key, value)
                sentry_sdk.capture_exception(exception)
    
    def capture_message(self, message: str, level: str = 'info', extra: Dict[str, Any] = None):
        """Capture message with context."""
        if SENTRY_AVAILABLE:
            with sentry_sdk.configure_scope() as scope:
                if extra:
                    for key, value in extra.items():
                        scope.set_extra(key, value)
                sentry_sdk.capture_message(message, level)

# Global instances
tracing_manager = TracingManager()
error_capture = ErrorCapture()

def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance."""
    return StructuredLogger(name)

def trace_function(name: str = None, attributes: Dict[str, Any] = None):
    """Decorator to trace function calls."""
    def decorator(func):
        span_name = name or f"{func.__module__}.{func.__name__}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            span_attributes = attributes or {}
            span_attributes['function.name'] = func.__name__
            span_attributes['function.module'] = func.__module__
            
            with tracing_manager.trace(span_name, span_attributes) as span:
                try:
                    start_time = time.time()
                    result = func(*args, **kwargs)
                    
                    if span:
                        span.set_attribute('function.duration', time.time() - start_time)
                        span.set_attribute('function.success', True)
                    
                    return result
                    
                except Exception as e:
                    if span:
                        span.set_attribute('function.success', False)
                        span.set_attribute('function.error', str(e))
                    
                    error_capture.capture_exception(e, {
                        'function': func.__name__,
                        'module': func.__module__,
                        'args': str(args)[:500],  # Truncate for privacy
                        'kwargs': str(kwargs)[:500]
                    })
                    raise
                    
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            span_attributes = attributes or {}
            span_attributes['function.name'] = func.__name__
            span_attributes['function.module'] = func.__module__
            span_attributes['function.is_async'] = True
            
            with tracing_manager.trace(span_name, span_attributes) as span:
                try:
                    start_time = time.time()
                    result = await func(*args, **kwargs)
                    
                    if span:
                        span.set_attribute('function.duration', time.time() - start_time)
                        span.set_attribute('function.success', True)
                    
                    return result
                    
                except Exception as e:
                    if span:
                        span.set_attribute('function.success', False)
                        span.set_attribute('function.error', str(e))
                    
                    error_capture.capture_exception(e, {
                        'function': func.__name__,
                        'module': func.__module__,
                        'args': str(args)[:500],
                        'kwargs': str(kwargs)[:500]
                    })
                    raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
    return decorator

class PerformanceMonitor:
    """Performance monitoring and alerting."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        
    @contextmanager
    def monitor(self, operation: str, threshold_ms: float = 1000):
        """Monitor operation performance."""
        start_time = time.time()
        
        with tracing_manager.trace(f"performance.{operation}") as span:
            try:
                yield
                
                duration_ms = (time.time() - start_time) * 1000
                
                if span:
                    span.set_attribute('performance.duration_ms', duration_ms)
                    span.set_attribute('performance.threshold_ms', threshold_ms)
                    span.set_attribute('performance.exceeded_threshold', duration_ms > threshold_ms)
                
                # Log performance data
                self.logger.info(
                    f"Performance monitoring: {operation}",
                    operation=operation,
                    duration_ms=duration_ms,
                    threshold_ms=threshold_ms,
                    exceeded_threshold=duration_ms > threshold_ms
                )
                
                # Alert on slow operations
                if duration_ms > threshold_ms:
                    self.logger.warning(
                        f"Slow operation detected: {operation}",
                        operation=operation,
                        duration_ms=duration_ms,
                        threshold_ms=threshold_ms
                    )
                    
                    # Send to Sentry for alerting
                    error_capture.capture_message(
                        f"Slow operation: {operation} took {duration_ms:.2f}ms",
                        level='warning',
                        extra={
                            'operation': operation,
                            'duration_ms': duration_ms,
                            'threshold_ms': threshold_ms
                        }
                    )
                    
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                if span:
                    span.set_attribute('performance.duration_ms', duration_ms)
                    span.set_attribute('performance.error', str(e))
                
                self.logger.error(
                    f"Operation failed: {operation}",
                    operation=operation,
                    duration_ms=duration_ms,
                    error=str(e)
                )
                
                raise

# Module-level instances are created on first access only
_performance_monitor = None
_tracing_manager = None
_error_capture = None

def get_performance_monitor():
    """Get global performance monitor instance."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor

def get_tracing_manager():
    """Get global tracing manager instance."""
    global _tracing_manager
    if _tracing_manager is None:
        _tracing_manager = TracingManager()
    return _tracing_manager

def get_error_capture():
    """Get global error capture instance."""
    global _error_capture
    if _error_capture is None:
        _error_capture = ErrorCapture()
    return _error_capture

# Convenience functions
def log_api_request(request_id: str, method: str, path: str, status_code: int, 
                   duration_ms: float, user_id: str = None):
    """Log API request details."""
    logger = get_logger('api')
    
    logger.info(
        "API request completed",
        request_id=request_id,
        method=method,
        path=path,
        status_code=status_code,
        duration_ms=duration_ms,
        user_id=user_id,
        success=200 <= status_code < 400
    )
    
    # Alert on errors
    if status_code >= 500:
        get_error_capture().capture_message(
            f"API error: {method} {path} returned {status_code}",
            level='error',
            extra={
                'request_id': request_id,
                'method': method,
                'path': path,
                'status_code': status_code,
                'duration_ms': duration_ms
            }
        )

def log_scan_completion(scan_id: str, scan_type: str, duration_ms: float, 
                       success: bool, threat_detected: bool = False):
    """Log email scan completion."""
    logger = get_logger('scanner')
    
    logger.info(
        "Email scan completed",
        scan_id=scan_id,
        scan_type=scan_type,
        duration_ms=duration_ms,
        success=success,
        threat_detected=threat_detected
    )

def log_ml_prediction(model_name: str, prediction: float, confidence: float,
                     features_count: int, duration_ms: float):
    """Log ML model prediction."""
    logger = get_logger('ml')
    
    logger.info(
        "ML prediction made",
        model_name=model_name,
        prediction=prediction,
        confidence=confidence,
        features_count=features_count,
        duration_ms=duration_ms
    )

# Export public interface
__all__ = [
    # Main classes
    'StructuredLogger',
    'TracingManager', 
    'ErrorCapture',
    'PerformanceMonitor',
    # Functions
    'get_logger',
    'trace_function',
    'get_tracing_manager', 
    'get_error_capture',
    'get_performance_monitor',
    'log_api_request',
    'log_scan_completion',
    'log_ml_prediction',
    # Constants
    'SENTRY_AVAILABLE',
    'CELERY_INTEGRATION_AVAILABLE',
    'SQLALCHEMY_INTEGRATION_AVAILABLE'
]