"""
Celery Configuration for PhishNet Background Workers
Handles task queuing, prioritization, and distributed processing.
"""

import os
from celery import Celery
from kombu import Queue, Exchange
from app.core.config import get_settings

# Get settings
settings = get_settings()

# Initialize Celery app
celery_app = Celery(
    "phishnet_worker",
    broker=settings.redis_url or "redis://localhost:6379/1",
    backend=settings.redis_url or "redis://localhost:6379/2",
    include=[
        "backend.app.tasks.scan_tasks",
        "backend.app.tasks.analysis_tasks", 
        "backend.app.tasks.notification_tasks",
        "backend.app.tasks.cleanup_tasks"
    ]
)

# Celery Configuration
celery_app.conf.update(
    # Task routing and queues
    task_routes={
        # Real-time priority queue (< 10s tasks)
        "backend.app.tasks.scan_tasks.quick_email_scan": {"queue": "realtime"},
        "backend.app.tasks.scan_tasks.link_safety_check": {"queue": "realtime"},
        "backend.app.tasks.analysis_tasks.basic_threat_analysis": {"queue": "realtime"},
        
        # Standard priority queue (10-60s tasks)  
        "backend.app.tasks.scan_tasks.full_email_scan": {"queue": "standard"},
        "backend.app.tasks.analysis_tasks.ml_threat_detection": {"queue": "standard"},
        "backend.app.tasks.analysis_tasks.reputation_lookup": {"queue": "standard"},
        
        # Heavy processing queue (>60s tasks)
        "backend.app.tasks.scan_tasks.sandbox_analysis": {"queue": "heavy"},
        "backend.app.tasks.scan_tasks.deep_attachment_scan": {"queue": "heavy"},
        "backend.app.tasks.analysis_tasks.advanced_ml_analysis": {"queue": "heavy"},
        
        # Low priority background tasks
        "backend.app.tasks.cleanup_tasks.*": {"queue": "background"},
        "backend.app.tasks.notification_tasks.*": {"queue": "background"}
    },
    
    # Queue definitions with priorities
    task_queue_config={
        # High priority real-time queue
        Queue("realtime", Exchange("realtime"), routing_key="realtime", queue_arguments={
            "x-max-priority": 10,
            "x-message-ttl": 30000,  # 30 seconds TTL
            "x-max-length": 1000     # Max 1000 jobs
        }),
        
        # Standard priority queue  
        Queue("standard", Exchange("standard"), routing_key="standard", queue_arguments={
            "x-max-priority": 5,
            "x-message-ttl": 300000,  # 5 minutes TTL
            "x-max-length": 5000      # Max 5000 jobs
        }),
        
        # Heavy processing queue
        Queue("heavy", Exchange("heavy"), routing_key="heavy", queue_arguments={
            "x-max-priority": 3,
            "x-message-ttl": 3600000,  # 1 hour TTL  
            "x-max-length": 500        # Max 500 heavy jobs
        }),
        
        # Background tasks queue
        Queue("background", Exchange("background"), routing_key="background", queue_arguments={
            "x-max-priority": 1,
            "x-message-ttl": 86400000,  # 24 hours TTL
            "x-max-length": 10000       # Max 10000 background jobs
        }),
        
        # Dead Letter Queue
        Queue("dlq", Exchange("dlq"), routing_key="dlq", queue_arguments={
            "x-message-ttl": 604800000,  # 7 days TTL for failed jobs
            "x-max-length": 50000        # Max 50000 failed jobs
        })
    },
    
    # Task execution settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json", 
    timezone="UTC",
    enable_utc=True,
    
    # Task result settings
    result_expires=3600,  # Results expire after 1 hour
    result_backend_transport_options={
        "master_name": "mymaster",
        "retry_policy": {
            "timeout": 5.0
        }
    },
    
    # Worker settings
    worker_prefetch_multiplier=1,  # One task per worker at a time
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks
    worker_disable_rate_limits=False,
    worker_log_format="[%(asctime)s: %(levelname)s/%(processName)s] %(message)s",
    worker_task_log_format="[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s",
    
    # Task retry settings
    task_acks_late=True,  # Acknowledge tasks after completion
    task_reject_on_worker_lost=True,  # Reject tasks if worker dies
    task_default_retry_delay=60,  # Default 60 second retry delay
    task_max_retries=3,  # Max 3 retries by default
    
    # Rate limiting
    task_annotations={
        "backend.app.tasks.scan_tasks.sandbox_analysis": {
            "rate_limit": "10/m"  # Max 10 sandbox analyses per minute
        },
        "backend.app.tasks.analysis_tasks.reputation_lookup": {
            "rate_limit": "100/m"  # Max 100 reputation lookups per minute  
        }
    },
    
    # Monitoring and introspection
    worker_send_task_events=True,
    task_send_sent_event=True,
    
    # Error handling
    task_soft_time_limit=300,  # 5 minute soft limit
    task_time_limit=600,       # 10 minute hard limit
    
    # Beat scheduler settings (for periodic tasks)
    beat_schedule={
        "cleanup-expired-results": {
            "task": "backend.app.tasks.cleanup_tasks.cleanup_expired_results",
            "schedule": 3600.0,  # Every hour
            "options": {"queue": "background"}
        },
        "health-check-workers": {
            "task": "backend.app.tasks.cleanup_tasks.health_check_workers", 
            "schedule": 300.0,  # Every 5 minutes
            "options": {"queue": "background"}
        },
        "cleanup-old-jobs": {
            "task": "backend.app.tasks.cleanup_tasks.cleanup_old_jobs",
            "schedule": 86400.0,  # Daily
            "options": {"queue": "background"}
        }
    }
)

# Redis connection settings
celery_app.conf.broker_transport_options = {
    "priority_steps": list(range(10)),  # Enable priority levels 0-9
    "sep": ":",
    "queue_order_strategy": "priority",
    "master_name": "mymaster"
}

# Configure result backend
celery_app.conf.result_backend_transport_options = {
    "master_name": "mymaster",
    "retry_policy": {
        "timeout": 5.0
    }
}

# Auto-scaling configuration
celery_app.conf.worker_autoscaler = "celery.worker.autoscale:Autoscaler"
celery_app.conf.worker_autoscale_max = 10  # Max 10 workers per node
celery_app.conf.worker_autoscale_min = 2   # Min 2 workers per node

# Task failure handling
@celery_app.task(bind=True)
def task_failure_handler(self, task_id, error, traceback, einfo):
    """Handle task failures and route to DLQ if needed."""
    from app.tasks.dlq_handler import handle_task_failure
    return handle_task_failure.delay(task_id, str(error), traceback)

# Custom task base class for enhanced error handling
from celery import Task
from typing import Any, Dict
import logging

logger = logging.getLogger(__name__)

class PhishNetTask(Task):
    """Base task class with enhanced error handling and logging."""
    
    autoretry_for = (Exception,)
    retry_kwargs = {"max_retries": 3, "countdown": 60}
    retry_backoff = True
    retry_backoff_max = 600  # Max 10 minutes between retries
    retry_jitter = True
    
    def on_success(self, retval: Any, task_id: str, args: tuple, kwargs: Dict[str, Any]) -> None:
        """Log successful task completion."""
        logger.info(f"Task {self.name}[{task_id}] succeeded: {retval}")
    
    def on_failure(self, exc: Exception, task_id: str, args: tuple, kwargs: Dict[str, Any], einfo) -> None:
        """Handle task failure and route to DLQ if max retries exceeded."""
        logger.error(f"Task {self.name}[{task_id}] failed: {exc}")
        
        # If max retries exceeded, send to DLQ
        if self.request.retries >= self.max_retries:
            task_failure_handler.delay(task_id, str(exc), str(einfo.traceback), einfo)
    
    def on_retry(self, exc: Exception, task_id: str, args: tuple, kwargs: Dict[str, Any], einfo) -> None:
        """Log task retry attempts."""
        logger.warning(f"Task {self.name}[{task_id}] retry {self.request.retries}: {exc}")

# Set the custom task base class
celery_app.Task = PhishNetTask

# Utility functions for task management
def get_queue_stats():
    """Get statistics for all queues."""
    inspect = celery_app.control.inspect()
    return {
        "active": inspect.active(),
        "scheduled": inspect.scheduled(),
        "reserved": inspect.reserved(),
        "stats": inspect.stats(),
        "registered": inspect.registered()
    }

def purge_queue(queue_name: str):
    """Purge all messages from a specific queue."""
    return celery_app.control.purge()

def get_task_info(task_id: str):
    """Get detailed information about a specific task."""
    result = celery_app.AsyncResult(task_id)
    return {
        "task_id": task_id,
        "status": result.status,
        "result": result.result,
        "traceback": result.traceback,
        "info": result.info
    }

def cancel_task(task_id: str):
    """Cancel a running or pending task."""
    celery_app.control.revoke(task_id, terminate=True)

def get_worker_stats():
    """Get comprehensive worker statistics."""
    inspect = celery_app.control.inspect()
    return {
        "stats": inspect.stats(),
        "active_queues": inspect.active_queues(), 
        "ping": inspect.ping(),
        "conf": inspect.conf()
    }

# Celery Beat Schedule for periodic tasks
from celery.schedules import crontab

celery_app.conf.beat_schedule = {
    'collect-queue-metrics': {
        'task': 'backend.app.tasks.collect_queue_metrics',
        'schedule': crontab(minute=0),  # Every hour at minute 0
        'options': {'queue': 'background'}
    },
    'collect-job-stats': {
        'task': 'backend.app.tasks.collect_job_stats', 
        'schedule': crontab(minute=30),  # Every hour at minute 30
        'options': {'queue': 'background'}
    }
}

# Set timezone for beat schedule
celery_app.conf.timezone = 'UTC'

# Export the configured Celery app
__all__ = ["celery_app", "get_queue_stats", "get_task_info", "cancel_task", "get_worker_stats"]