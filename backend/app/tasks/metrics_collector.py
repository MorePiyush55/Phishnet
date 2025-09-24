"""
Queue Metrics Collection Task
Periodically collects and stores queue metrics for dashboard charting.
"""

import logging
from datetime import datetime
from backend.app.workers.celery_config import celery_app
from backend.app.workers.worker_manager import WorkerManager
from backend.app.core.redis_client import get_redis_client

logger = logging.getLogger(__name__)

@celery_app.task(name="backend.app.tasks.collect_queue_metrics")
def collect_queue_metrics() -> dict:
    """
    Collect and store current queue metrics.
    This task should run every hour to provide data for dashboard charts.
    """
    try:
        worker_manager = WorkerManager()
        redis_client = get_redis_client()
        
        # Get current queue metrics
        queue_metrics = worker_manager.get_queue_metrics()
        
        # Store metrics with timestamp
        timestamp = datetime.utcnow()
        hour_key = timestamp.strftime("%Y-%m-%d:%H")
        
        metrics_stored = 0
        for queue_name, metrics in queue_metrics.items():
            try:
                # Store queue depth
                depth_key = f"queue:depth:{queue_name}:{hour_key}"
                redis_client.set(depth_key, metrics.get('length', 0))
                redis_client.expire(depth_key, 86400 * 7)  # 7 days retention
                
                # Store processing rate
                rate_key = f"queue:rate:{queue_name}:{hour_key}"
                redis_client.set(rate_key, metrics.get('processing_rate', 0.0))
                redis_client.expire(rate_key, 86400 * 7)
                
                # Store wait time
                wait_key = f"queue:wait:{queue_name}:{hour_key}"
                redis_client.set(wait_key, metrics.get('avg_wait_time', 0.0))
                redis_client.expire(wait_key, 86400 * 7)
                
                metrics_stored += 1
                
            except Exception as e:
                logger.error(f"Failed to store metrics for queue {queue_name}: {str(e)}")
                continue
        
        logger.info(f"Stored metrics for {metrics_stored} queues at {timestamp}")
        
        return {
            "success": True,
            "timestamp": timestamp.isoformat(),
            "queues_processed": metrics_stored,
            "total_queues": len(queue_metrics)
        }
        
    except Exception as e:
        logger.error(f"Failed to collect queue metrics: {str(e)}")
        return {"success": False, "error": str(e)}

@celery_app.task(name="backend.app.tasks.collect_job_stats")
def collect_job_stats() -> dict:
    """
    Collect daily job completion and failure statistics.
    """
    try:
        redis_client = get_redis_client()
        
        # Get current date
        date_key = datetime.utcnow().strftime("%Y-%m-%d")
        
        # This would be called when jobs complete/fail to increment counters
        # For now, just ensure the keys exist
        if not redis_client.exists(f"jobs:completed:daily:{date_key}"):
            redis_client.set(f"jobs:completed:daily:{date_key}", 0)
            redis_client.expire(f"jobs:completed:daily:{date_key}", 86400 * 30)  # 30 days
        
        if not redis_client.exists(f"failures:daily:{date_key}"):
            redis_client.set(f"failures:daily:{date_key}", 0)
            redis_client.expire(f"failures:daily:{date_key}", 86400 * 30)
        
        return {
            "success": True,
            "date_key": date_key,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to collect job stats: {str(e)}")
        return {"success": False, "error": str(e)}

def increment_job_counter(counter_type: str, task_name: str = None, queue_name: str = None):
    """
    Increment job counters for statistics tracking.
    
    Args:
        counter_type: 'completed' or 'failed'
        task_name: Name of the task (optional)
        queue_name: Name of the queue (optional)
    """
    try:
        redis_client = get_redis_client()
        date_key = datetime.utcnow().strftime("%Y-%m-%d")
        
        # Increment overall daily counter
        redis_client.incr(f"jobs:{counter_type}:daily:{date_key}")
        redis_client.expire(f"jobs:{counter_type}:daily:{date_key}", 86400 * 30)
        
        # Increment task-specific counter
        if task_name:
            redis_client.incr(f"jobs:{counter_type}:task:{task_name}:daily:{date_key}")
            redis_client.expire(f"jobs:{counter_type}:task:{task_name}:daily:{date_key}", 86400 * 30)
        
        # Increment queue-specific counter
        if queue_name:
            redis_client.incr(f"jobs:{counter_type}:queue:{queue_name}:daily:{date_key}")
            redis_client.expire(f"jobs:{counter_type}:queue:{queue_name}:daily:{date_key}", 86400 * 30)
        
    except Exception as e:
        logger.error(f"Failed to increment job counter: {str(e)}")

# Task success/failure callback functions
def task_success_callback(sender=None, result=None, **kwargs):
    """Callback called when a task succeeds."""
    try:
        task_name = sender.name if sender else "unknown"
        # Extract queue from routing key if available
        queue_name = getattr(sender, 'queue', 'unknown') if sender else "unknown"
        
        increment_job_counter('completed', task_name, queue_name)
        logger.debug(f"Task {task_name} completed successfully")
        
    except Exception as e:
        logger.error(f"Error in task success callback: {str(e)}")

def task_failure_callback(sender=None, task_id=None, exception=None, traceback=None, einfo=None, **kwargs):
    """Callback called when a task fails."""
    try:
        task_name = sender.name if sender else "unknown"
        queue_name = getattr(sender, 'queue', 'unknown') if sender else "unknown"
        
        increment_job_counter('failed', task_name, queue_name)
        logger.debug(f"Task {task_name} failed: {str(exception)}")
        
    except Exception as e:
        logger.error(f"Error in task failure callback: {str(e)}")

# Connect the callbacks to Celery signals
from celery.signals import task_success, task_failure

task_success.connect(task_success_callback)
task_failure.connect(task_failure_callback)