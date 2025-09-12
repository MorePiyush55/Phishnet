"""
Comprehensive Logging and Monitoring for Sandbox Infrastructure

Implements structured logging, security event tracking, container health monitoring,
and alerting for the sandbox system.
"""

import asyncio
import json
import logging
import os
import psutil
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import uuid

import structlog
import redis
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import aiohttp

logger = structlog.get_logger(__name__)


# Prometheus metrics
SANDBOX_JOBS_TOTAL = Counter('sandbox_jobs_total', 'Total sandbox jobs processed', ['status', 'worker_id'])
SANDBOX_DURATION = Histogram('sandbox_duration_seconds', 'Sandbox job duration in seconds')
SANDBOX_MEMORY_USAGE = Gauge('sandbox_memory_usage_bytes', 'Memory usage of sandbox worker')
SANDBOX_CPU_USAGE = Gauge('sandbox_cpu_usage_percent', 'CPU usage of sandbox worker')
SANDBOX_ACTIVE_WORKERS = Gauge('sandbox_active_workers', 'Number of active sandbox workers')
SANDBOX_QUEUE_SIZE = Gauge('sandbox_queue_size', 'Number of jobs in sandbox queue')

SECURITY_EVENTS_TOTAL = Counter('sandbox_security_events_total', 'Security events detected', 
                               ['event_type', 'severity'])
BLOCKED_REQUESTS_TOTAL = Counter('sandbox_blocked_requests_total', 'Blocked network requests', 
                                ['domain', 'reason'])
ARTIFACTS_STORED_TOTAL = Counter('sandbox_artifacts_stored_total', 'Artifacts stored', 
                                ['artifact_type', 'storage_backend'])


class SecurityEventType:
    """Security event type constants."""
    SUSPICIOUS_NETWORK = "suspicious_network"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVATE_NETWORK_ACCESS = "private_network_access"
    METADATA_ACCESS = "metadata_access"
    EXCESSIVE_RESOURCE_USAGE = "excessive_resource_usage"
    MALICIOUS_JAVASCRIPT = "malicious_javascript"
    UNAUTHORIZED_FILE_ACCESS = "unauthorized_file_access"
    CONTAINER_ESCAPE_ATTEMPT = "container_escape_attempt"


class SecurityEventSeverity:
    """Security event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent:
    """Security event data structure."""
    
    def __init__(self, 
                 event_type: str,
                 severity: str,
                 description: str,
                 source_ip: str = None,
                 target_url: str = None,
                 job_id: str = None,
                 worker_id: str = None,
                 additional_data: Dict[str, Any] = None):
        self.event_id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow()
        self.event_type = event_type
        self.severity = severity
        self.description = description
        self.source_ip = source_ip
        self.target_url = target_url
        self.job_id = job_id
        self.worker_id = worker_id
        self.additional_data = additional_data or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "severity": self.severity,
            "description": self.description,
            "source_ip": self.source_ip,
            "target_url": self.target_url,
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "additional_data": self.additional_data
        }


class SecurityEventLogger:
    """Centralized security event logging."""
    
    def __init__(self, redis_client=None):
        self.redis_client = redis_client
        self.security_log = structlog.get_logger("security")
    
    def log_event(self, event: SecurityEvent):
        """Log a security event."""
        # Log to structured logger
        self.security_log.warning(
            "Security event detected",
            **event.to_dict()
        )
        
        # Update Prometheus metrics
        SECURITY_EVENTS_TOTAL.labels(
            event_type=event.event_type,
            severity=event.severity
        ).inc()
        
        # Store in Redis for real-time monitoring
        if self.redis_client:
            try:
                self.redis_client.lpush(
                    "security_events",
                    json.dumps(event.to_dict())
                )
                # Keep only last 1000 events
                self.redis_client.ltrim("security_events", 0, 999)
            except Exception as e:
                logger.warning("Failed to store security event in Redis", error=str(e))
    
    def log_blocked_request(self, domain: str, reason: str, job_id: str = None):
        """Log a blocked network request."""
        event = SecurityEvent(
            event_type=SecurityEventType.SUSPICIOUS_NETWORK,
            severity=SecurityEventSeverity.MEDIUM,
            description=f"Network request blocked: {domain}",
            target_url=domain,
            job_id=job_id,
            additional_data={"reason": reason}
        )
        
        self.log_event(event)
        
        # Update blocked requests metric
        BLOCKED_REQUESTS_TOTAL.labels(
            domain=domain,
            reason=reason
        ).inc()
    
    def log_credential_access_attempt(self, url: str, job_id: str = None):
        """Log attempt to access credential endpoints."""
        event = SecurityEvent(
            event_type=SecurityEventType.CREDENTIAL_ACCESS,
            severity=SecurityEventSeverity.HIGH,
            description=f"Attempt to access credential endpoint: {url}",
            target_url=url,
            job_id=job_id
        )
        
        self.log_event(event)
    
    def log_private_network_access(self, target_ip: str, job_id: str = None):
        """Log attempt to access private network."""
        event = SecurityEvent(
            event_type=SecurityEventType.PRIVATE_NETWORK_ACCESS,
            severity=SecurityEventSeverity.HIGH,
            description=f"Attempt to access private network: {target_ip}",
            target_url=target_ip,
            job_id=job_id
        )
        
        self.log_event(event)
    
    def log_resource_abuse(self, resource_type: str, usage: float, limit: float, job_id: str = None):
        """Log excessive resource usage."""
        event = SecurityEvent(
            event_type=SecurityEventType.EXCESSIVE_RESOURCE_USAGE,
            severity=SecurityEventSeverity.MEDIUM,
            description=f"Excessive {resource_type} usage: {usage} > {limit}",
            job_id=job_id,
            additional_data={
                "resource_type": resource_type,
                "usage": usage,
                "limit": limit
            }
        )
        
        self.log_event(event)


class HealthMonitor:
    """Container and worker health monitoring."""
    
    def __init__(self, worker_id: str, redis_client=None):
        self.worker_id = worker_id
        self.redis_client = redis_client
        self.start_time = time.time()
        self.monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self):
        """Start health monitoring in background thread."""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Health monitoring started", worker_id=self.worker_id)
    
    def stop_monitoring(self):
        """Stop health monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info("Health monitoring stopped", worker_id=self.worker_id)
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                self._collect_metrics()
                self._update_heartbeat()
                time.sleep(10)  # Monitor every 10 seconds
                
            except Exception as e:
                logger.error("Health monitoring error", worker_id=self.worker_id, error=str(e))
                time.sleep(30)  # Back off on errors
    
    def _collect_metrics(self):
        """Collect system metrics."""
        try:
            # Memory usage
            memory_info = psutil.virtual_memory()
            memory_usage = memory_info.used
            SANDBOX_MEMORY_USAGE.set(memory_usage)
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            SANDBOX_CPU_USAGE.set(cpu_percent)
            
            # Process info
            process = psutil.Process()
            process_memory = process.memory_info().rss
            process_cpu = process.cpu_percent()
            
            logger.debug("System metrics collected",
                        worker_id=self.worker_id,
                        memory_usage=memory_usage,
                        cpu_percent=cpu_percent,
                        process_memory=process_memory,
                        process_cpu=process_cpu)
            
            # Check for resource abuse
            if memory_usage > 1024 * 1024 * 1024:  # 1GB
                self._log_resource_abuse("memory", memory_usage, 1024 * 1024 * 1024)
            
            if cpu_percent > 80:
                self._log_resource_abuse("cpu", cpu_percent, 80)
                
        except Exception as e:
            logger.warning("Failed to collect metrics", worker_id=self.worker_id, error=str(e))
    
    def _update_heartbeat(self):
        """Update worker heartbeat in Redis."""
        if not self.redis_client:
            return
        
        try:
            heartbeat_data = {
                "worker_id": self.worker_id,
                "timestamp": datetime.utcnow().isoformat(),
                "uptime": time.time() - self.start_time,
                "memory_usage": psutil.virtual_memory().used,
                "cpu_percent": psutil.cpu_percent(),
                "status": "healthy"
            }
            
            self.redis_client.hset(
                f"worker_heartbeat:{self.worker_id}",
                mapping=heartbeat_data
            )
            
            # Set expiration to detect dead workers
            self.redis_client.expire(f"worker_heartbeat:{self.worker_id}", 60)
            
        except Exception as e:
            logger.warning("Failed to update heartbeat", worker_id=self.worker_id, error=str(e))
    
    def _log_resource_abuse(self, resource_type: str, usage: float, limit: float):
        """Log resource abuse event."""
        security_logger = SecurityEventLogger(self.redis_client)
        security_logger.log_resource_abuse(resource_type, usage, limit)


class LogAggregator:
    """Aggregates logs from multiple sources."""
    
    def __init__(self, redis_client=None):
        self.redis_client = redis_client
        self.log_buffer = []
        self.buffer_size = 100
        self.flush_interval = 30  # seconds
        self.last_flush = time.time()
    
    def add_log_entry(self, level: str, message: str, context: Dict[str, Any] = None):
        """Add a log entry to the buffer."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            "context": context or {},
            "source": "sandbox_worker"
        }
        
        self.log_buffer.append(entry)
        
        # Flush if buffer is full or enough time has passed
        if (len(self.log_buffer) >= self.buffer_size or 
            time.time() - self.last_flush > self.flush_interval):
            self.flush_logs()
    
    def flush_logs(self):
        """Flush log buffer to Redis."""
        if not self.log_buffer or not self.redis_client:
            return
        
        try:
            # Send logs in batch
            pipeline = self.redis_client.pipeline()
            for entry in self.log_buffer:
                pipeline.lpush("sandbox_logs", json.dumps(entry))
            
            # Keep only last 10000 log entries
            pipeline.ltrim("sandbox_logs", 0, 9999)
            pipeline.execute()
            
            logger.debug("Flushed log entries", count=len(self.log_buffer))
            
            self.log_buffer.clear()
            self.last_flush = time.time()
            
        except Exception as e:
            logger.warning("Failed to flush logs", error=str(e))


class AlertManager:
    """Manages alerts and notifications."""
    
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or os.getenv('ALERT_WEBHOOK_URL')
        self.alert_thresholds = {
            'high_memory_usage': 0.8,
            'high_cpu_usage': 0.8,
            'security_events_per_minute': 10,
            'failed_jobs_per_minute': 5
        }
    
    async def send_alert(self, alert_type: str, message: str, severity: str = "medium"):
        """Send an alert notification."""
        if not self.webhook_url:
            logger.warning("No webhook URL configured for alerts")
            return
        
        alert_data = {
            "alert_type": alert_type,
            "message": message,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "source": "phishnet_sandbox"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=alert_data,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        logger.info("Alert sent successfully", alert_type=alert_type)
                    else:
                        logger.warning("Alert webhook failed", 
                                     status=response.status, 
                                     alert_type=alert_type)
                        
        except Exception as e:
            logger.error("Failed to send alert", alert_type=alert_type, error=str(e))
    
    def check_alert_conditions(self, metrics: Dict[str, float]):
        """Check if any alert conditions are met."""
        alerts = []
        
        # High memory usage
        if metrics.get('memory_usage_percent', 0) > self.alert_thresholds['high_memory_usage']:
            alerts.append({
                'type': 'high_memory_usage',
                'message': f"High memory usage: {metrics['memory_usage_percent']:.1%}",
                'severity': 'high'
            })
        
        # High CPU usage
        if metrics.get('cpu_usage_percent', 0) > self.alert_thresholds['high_cpu_usage']:
            alerts.append({
                'type': 'high_cpu_usage',
                'message': f"High CPU usage: {metrics['cpu_usage_percent']:.1%}",
                'severity': 'high'
            })
        
        return alerts


class MonitoringDashboard:
    """Simple HTTP dashboard for monitoring."""
    
    def __init__(self, port: int = 8080, redis_client=None):
        self.port = port
        self.redis_client = redis_client
        self.app = None
    
    async def start_dashboard(self):
        """Start the monitoring dashboard."""
        from aiohttp import web, web_response
        
        async def handle_health(request):
            """Health check endpoint."""
            return web_response.json_response({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})
        
        async def handle_metrics(request):
            """Metrics endpoint."""
            metrics = await self._get_metrics()
            return web_response.json_response(metrics)
        
        async def handle_security_events(request):
            """Security events endpoint."""
            events = await self._get_security_events()
            return web_response.json_response(events)
        
        async def handle_workers(request):
            """Worker status endpoint."""
            workers = await self._get_worker_status()
            return web_response.json_response(workers)
        
        self.app = web.Application()
        self.app.router.add_get('/health', handle_health)
        self.app.router.add_get('/metrics', handle_metrics)
        self.app.router.add_get('/security-events', handle_security_events)
        self.app.router.add_get('/workers', handle_workers)
        
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        site = web.TCPSite(runner, '0.0.0.0', self.port)
        await site.start()
        
        logger.info("Monitoring dashboard started", port=self.port)
    
    async def _get_metrics(self) -> Dict[str, Any]:
        """Get current metrics."""
        return {
            "memory_usage": psutil.virtual_memory()._asdict(),
            "cpu_usage": psutil.cpu_percent(interval=1),
            "disk_usage": psutil.disk_usage('/')._asdict(),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _get_security_events(self) -> List[Dict[str, Any]]:
        """Get recent security events."""
        if not self.redis_client:
            return []
        
        try:
            events = self.redis_client.lrange("security_events", 0, 99)
            return [json.loads(event) for event in events]
        except Exception as e:
            logger.warning("Failed to get security events", error=str(e))
            return []
    
    async def _get_worker_status(self) -> List[Dict[str, Any]]:
        """Get worker status information."""
        if not self.redis_client:
            return []
        
        try:
            workers = []
            for key in self.redis_client.scan_iter(match="worker_heartbeat:*"):
                worker_data = self.redis_client.hgetall(key)
                if worker_data:
                    workers.append(worker_data)
            return workers
        except Exception as e:
            logger.warning("Failed to get worker status", error=str(e))
            return []


def setup_monitoring(worker_id: str, enable_prometheus: bool = True, enable_dashboard: bool = True):
    """Set up comprehensive monitoring for sandbox worker."""
    
    # Configure structured logging
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Initialize Redis client
    redis_client = None
    try:
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        redis_client = redis.from_url(redis_url, decode_responses=True)
        redis_client.ping()
        logger.info("Redis client initialized for monitoring")
    except Exception as e:
        logger.warning("Failed to initialize Redis for monitoring", error=str(e))
    
    # Start Prometheus metrics server
    if enable_prometheus:
        try:
            prometheus_port = int(os.getenv('PROMETHEUS_PORT', '9090'))
            start_http_server(prometheus_port)
            logger.info("Prometheus metrics server started", port=prometheus_port)
        except Exception as e:
            logger.warning("Failed to start Prometheus server", error=str(e))
    
    # Start health monitoring
    health_monitor = HealthMonitor(worker_id, redis_client)
    health_monitor.start_monitoring()
    
    # Start monitoring dashboard
    if enable_dashboard:
        try:
            dashboard_port = int(os.getenv('DASHBOARD_PORT', '8080'))
            dashboard = MonitoringDashboard(dashboard_port, redis_client)
            
            # Start dashboard in event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(dashboard.start_dashboard())
            
        except Exception as e:
            logger.warning("Failed to start monitoring dashboard", error=str(e))
    
    return {
        'health_monitor': health_monitor,
        'security_logger': SecurityEventLogger(redis_client),
        'log_aggregator': LogAggregator(redis_client),
        'alert_manager': AlertManager()
    }


if __name__ == "__main__":
    # Set up monitoring for testing
    worker_id = os.getenv('WORKER_ID', 'test-worker')
    monitoring = setup_monitoring(worker_id)
    
    # Keep the monitoring running
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down monitoring")
        if 'health_monitor' in monitoring:
            monitoring['health_monitor'].stop_monitoring()
