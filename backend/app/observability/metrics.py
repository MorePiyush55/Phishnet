"""
Prometheus metrics collection for PhishNet observability.
Provides comprehensive application metrics for monitoring and alerting.
"""

import time
import psutil
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from enum import Enum

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Info, CollectorRegistry,
        generate_latest, CONTENT_TYPE_LATEST, multiprocess,
        push_to_gateway, delete_from_gateway
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

from backend.app.observability import get_logger

logger = get_logger(__name__)

# Metric labels and constants
class ScanType(Enum):
    EMAIL_HEADERS = "email_headers"
    EMAIL_CONTENT = "email_content"
    URL_ANALYSIS = "url_analysis"
    ATTACHMENT_SCAN = "attachment_scan"
    ML_PREDICTION = "ml_prediction"

class ThreatLevel(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    MALWARE = "malware"

class PhishNetMetrics:
    """Centralized Prometheus metrics collector for PhishNet."""
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry or CollectorRegistry()
        self._initialize_metrics()
        
    def _initialize_metrics(self):
        """Initialize all Prometheus metrics."""
        if not PROMETHEUS_AVAILABLE:
            logger.warning("Prometheus client not available, metrics disabled")
            return
            
        # API Metrics
        self.http_requests_total = Counter(
            'phishnet_http_requests_total',
            'Total number of HTTP requests',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry
        )
        
        self.http_request_duration = Histogram(
            'phishnet_http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'endpoint'],
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
            registry=self.registry
        )
        
        self.http_requests_in_progress = Gauge(
            'phishnet_http_requests_in_progress',
            'Number of HTTP requests currently being processed',
            registry=self.registry
        )
        
        # Email Scanning Metrics
        self.email_scans_total = Counter(
            'phishnet_email_scans_total',
            'Total number of email scans performed',
            ['scan_type', 'result', 'user_id'],
            registry=self.registry
        )
        
        self.email_scan_duration = Histogram(
            'phishnet_email_scan_duration_seconds',
            'Email scan duration in seconds',
            ['scan_type'],
            buckets=(1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0),
            registry=self.registry
        )
        
        self.threats_detected_total = Counter(
            'phishnet_threats_detected_total',
            'Total number of threats detected',
            ['threat_type', 'confidence_level'],
            registry=self.registry
        )
        
        # ML Model Metrics
        self.ml_predictions_total = Counter(
            'phishnet_ml_predictions_total',
            'Total ML predictions made',
            ['model_name', 'prediction_result'],
            registry=self.registry
        )
        
        self.ml_prediction_duration = Histogram(
            'phishnet_ml_prediction_duration_seconds',
            'ML prediction duration in seconds',
            ['model_name'],
            buckets=(0.1, 0.25, 0.5, 1.0, 2.0, 5.0),
            registry=self.registry
        )
        
        self.ml_model_accuracy = Gauge(
            'phishnet_ml_model_accuracy',
            'Current ML model accuracy score',
            ['model_name'],
            registry=self.registry
        )
        
        self.ml_model_drift = Gauge(
            'phishnet_ml_model_drift_score',
            'ML model drift detection score',
            ['model_name'],
            registry=self.registry
        )
        
        # Queue and Background Task Metrics
        self.queue_size = Gauge(
            'phishnet_queue_size',
            'Current size of processing queues',
            ['queue_name'],
            registry=self.registry
        )
        
        self.tasks_processed_total = Counter(
            'phishnet_tasks_processed_total',
            'Total background tasks processed',
            ['task_name', 'status'],
            registry=self.registry
        )
        
        self.task_duration = Histogram(
            'phishnet_task_duration_seconds',
            'Background task processing duration',
            ['task_name'],
            buckets=(1.0, 5.0, 10.0, 30.0, 60.0, 300.0),
            registry=self.registry
        )
        
        # Database Metrics
        self.db_connections = Gauge(
            'phishnet_db_connections',
            'Current number of database connections',
            ['database_type'],
            registry=self.registry
        )
        
        self.db_query_duration = Histogram(
            'phishnet_db_query_duration_seconds',
            'Database query duration',
            ['operation', 'collection'],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5),
            registry=self.registry
        )
        
        # System Resource Metrics
        self.system_cpu_usage = Gauge(
            'phishnet_system_cpu_usage_percent',
            'System CPU usage percentage',
            registry=self.registry
        )
        
        self.system_memory_usage = Gauge(
            'phishnet_system_memory_usage_bytes',
            'System memory usage in bytes',
            ['type'],  # used, available, total
            registry=self.registry
        )
        
        self.system_disk_usage = Gauge(
            'phishnet_system_disk_usage_bytes',
            'System disk usage in bytes',
            ['type'],  # used, free, total
            registry=self.registry
        )
        
        # Business Metrics
        self.active_users = Gauge(
            'phishnet_active_users',
            'Number of active users',
            ['time_period'],  # 1h, 24h, 7d
            registry=self.registry
        )
        
        self.user_sessions = Gauge(
            'phishnet_user_sessions',
            'Current number of active user sessions',
            registry=self.registry
        )
        
        self.oauth_tokens_total = Counter(
            'phishnet_oauth_tokens_total',
            'OAuth tokens issued/refreshed',
            ['provider', 'action'],  # google, refresh/issue
            registry=self.registry
        )
        
        # Error and Alert Metrics
        self.errors_total = Counter(
            'phishnet_errors_total',
            'Total application errors',
            ['error_type', 'component'],
            registry=self.registry
        )
        
        self.alerts_total = Counter(
            'phishnet_alerts_total',
            'Total alerts generated',
            ['alert_type', 'severity'],
            registry=self.registry
        )
        
        # Application Info
        self.app_info = Info(
            'phishnet_app_info',
            'Application information',
            registry=self.registry
        )
        
        # Set application info
        self.app_info.info({
            'version': '2.0.0',
            'build_date': datetime.now().isoformat(),
            'python_version': '3.13',
            'environment': 'production'
        })
    
    # API Metrics Methods
    def record_http_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record HTTP request metrics."""
        if not PROMETHEUS_AVAILABLE:
            return
            
        self.http_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code
        ).inc()
        
        self.http_request_duration.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
    
    def track_request_in_progress(self):
        """Context manager to track requests in progress."""
        if not PROMETHEUS_AVAILABLE:
            return nullcontext()
            
        return self.http_requests_in_progress.track_inprogress()
    
    # Email Scanning Metrics Methods  
    def record_email_scan(self, scan_type: ScanType, result: ThreatLevel, 
                         duration: float, user_id: str = "anonymous"):
        """Record email scan completion."""
        if not PROMETHEUS_AVAILABLE:
            return
            
        self.email_scans_total.labels(
            scan_type=scan_type.value,
            result=result.value,
            user_id=user_id
        ).inc()
        
        self.email_scan_duration.labels(
            scan_type=scan_type.value
        ).observe(duration)
        
        # Record threat if detected
        if result != ThreatLevel.SAFE:
            confidence = "high" if result == ThreatLevel.PHISHING else "medium"
            self.threats_detected_total.labels(
                threat_type=result.value,
                confidence_level=confidence
            ).inc()
    
    # ML Model Metrics Methods
    def record_ml_prediction(self, model_name: str, prediction_result: str, 
                           duration: float, confidence: float = None):
        """Record ML model prediction."""
        if not PROMETHEUS_AVAILABLE:
            return
            
        self.ml_predictions_total.labels(
            model_name=model_name,
            prediction_result=prediction_result
        ).inc()
        
        self.ml_prediction_duration.labels(
            model_name=model_name
        ).observe(duration)
    
    def update_model_accuracy(self, model_name: str, accuracy: float):
        """Update ML model accuracy metric."""
        if PROMETHEUS_AVAILABLE:
            self.ml_model_accuracy.labels(model_name=model_name).set(accuracy)
    
    def update_model_drift(self, model_name: str, drift_score: float):
        """Update ML model drift metric."""
        if PROMETHEUS_AVAILABLE:
            self.ml_model_drift.labels(model_name=model_name).set(drift_score)
    
    # Queue and Task Metrics Methods
    def update_queue_size(self, queue_name: str, size: int):
        """Update queue size metric."""
        if PROMETHEUS_AVAILABLE:
            self.queue_size.labels(queue_name=queue_name).set(size)
    
    def record_task_completion(self, task_name: str, status: str, duration: float):
        """Record background task completion."""
        if not PROMETHEUS_AVAILABLE:
            return
            
        self.tasks_processed_total.labels(
            task_name=task_name,
            status=status
        ).inc()
        
        self.task_duration.labels(task_name=task_name).observe(duration)
    
    # Database Metrics Methods
    def update_db_connections(self, database_type: str, count: int):
        """Update database connection count."""
        if PROMETHEUS_AVAILABLE:
            self.db_connections.labels(database_type=database_type).set(count)
    
    def record_db_query(self, operation: str, collection: str, duration: float):
        """Record database query duration."""
        if PROMETHEUS_AVAILABLE:
            self.db_query_duration.labels(
                operation=operation,
                collection=collection
            ).observe(duration)
    
    # System Metrics Methods
    def update_system_metrics(self):
        """Update system resource metrics."""
        if not PROMETHEUS_AVAILABLE:
            return
            
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.system_cpu_usage.set(cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.system_memory_usage.labels(type="used").set(memory.used)
            self.system_memory_usage.labels(type="available").set(memory.available)
            self.system_memory_usage.labels(type="total").set(memory.total)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            self.system_disk_usage.labels(type="used").set(disk.used)
            self.system_disk_usage.labels(type="free").set(disk.free)
            self.system_disk_usage.labels(type="total").set(disk.total)
            
        except Exception as e:
            logger.error("Failed to update system metrics", error=str(e))
    
    # Business Metrics Methods
    def update_active_users(self, count: int, time_period: str):
        """Update active users metric."""
        if PROMETHEUS_AVAILABLE:
            self.active_users.labels(time_period=time_period).set(count)
    
    def update_user_sessions(self, count: int):
        """Update active sessions metric."""
        if PROMETHEUS_AVAILABLE:
            self.user_sessions.set(count)
    
    def record_oauth_token(self, provider: str, action: str):
        """Record OAuth token operation."""
        if PROMETHEUS_AVAILABLE:
            self.oauth_tokens_total.labels(provider=provider, action=action).inc()
    
    # Error Metrics Methods
    def record_error(self, error_type: str, component: str):
        """Record application error."""
        if PROMETHEUS_AVAILABLE:
            self.errors_total.labels(error_type=error_type, component=component).inc()
    
    def record_alert(self, alert_type: str, severity: str):
        """Record alert generation."""
        if PROMETHEUS_AVAILABLE:
            self.alerts_total.labels(alert_type=alert_type, severity=severity).inc()
    
    def get_metrics(self) -> str:
        """Get metrics in Prometheus format."""
        if not PROMETHEUS_AVAILABLE:
            return "# Prometheus client not available\n"
            
        return generate_latest(self.registry)

# Context manager for null operations when Prometheus is not available
class nullcontext:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass

# Global metrics instance
metrics = PhishNetMetrics()

# Convenience functions for common operations
def record_api_request(method: str, endpoint: str, status_code: int, duration: float):
    """Record API request metrics."""
    metrics.record_http_request(method, endpoint, status_code, duration)

def record_scan_completion(scan_type: str, result: str, duration: float, user_id: str = "anonymous"):
    """Record email scan completion."""
    try:
        scan_type_enum = ScanType(scan_type)
        result_enum = ThreatLevel(result)
        metrics.record_email_scan(scan_type_enum, result_enum, duration, user_id)
    except ValueError as e:
        logger.warning(f"Invalid scan metrics values: {e}")

def record_ml_prediction(model_name: str, prediction: str, duration: float):
    """Record ML prediction."""
    metrics.record_ml_prediction(model_name, prediction, duration)

def update_queue_length(queue_name: str, length: int):
    """Update queue length metric."""
    metrics.update_queue_size(queue_name, length)

def record_error(component: str, error_type: str):
    """Record application error."""
    metrics.record_error(error_type, component)

# Export public interface
__all__ = [
    'metrics',
    'ScanType',
    'ThreatLevel', 
    'PhishNetMetrics',
    'record_api_request',
    'record_scan_completion',
    'record_ml_prediction',
    'update_queue_length',
    'record_error'
]