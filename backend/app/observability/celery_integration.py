"""
Celery task observability integration.
Adds structured logging and tracing to background tasks.
"""

import time
import functools
from typing import Any, Dict, Optional
from celery import Task
from celery.signals import (
    task_prerun, 
    task_postrun, 
    task_failure, 
    task_retry
)

from app.observability import (
    get_logger,
    tracing_manager, 
    error_capture,
    performance_monitor
)

logger = get_logger(__name__)

class ObservableTask(Task):
    """Custom Celery task class with observability."""
    
    def __call__(self, *args, **kwargs):
        """Execute task with observability."""
        task_id = self.request.id
        task_name = self.name
        
        # Create span for task execution
        span_attributes = {
            'task.id': task_id,
            'task.name': task_name,
            'task.args_count': len(args),
            'task.kwargs_count': len(kwargs)
        }
        
        with tracing_manager.trace(f"celery.task.{task_name}", span_attributes) as span:
            start_time = time.time()
            
            try:
                logger.info(
                    f"Task started: {task_name}",
                    task_id=task_id,
                    task_name=task_name,
                    args_count=len(args),
                    kwargs_count=len(kwargs)
                )
                
                # Execute the actual task
                result = super().__call__(*args, **kwargs)
                
                duration_ms = (time.time() - start_time) * 1000
                
                if span:
                    span.set_attribute('task.success', True)
                    span.set_attribute('task.duration_ms', duration_ms)
                
                logger.info(
                    f"Task completed: {task_name}",
                    task_id=task_id,
                    task_name=task_name,
                    duration_ms=duration_ms,
                    success=True
                )
                
                return result
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                if span:
                    span.set_attribute('task.success', False)
                    span.set_attribute('task.duration_ms', duration_ms)
                    span.set_attribute('task.error', str(e))
                
                logger.error(
                    f"Task failed: {task_name}",
                    task_id=task_id,
                    task_name=task_name,
                    duration_ms=duration_ms,
                    error=str(e),
                    success=False
                )
                
                # Capture exception for monitoring
                error_capture.capture_exception(e, {
                    'task_id': task_id,
                    'task_name': task_name,
                    'duration_ms': duration_ms
                })
                
                raise

def trace_celery_task(name: str = None, attributes: Dict[str, Any] = None):
    """Decorator to add tracing to Celery tasks."""
    def decorator(func):
        span_name = name or f"celery.task.{func.__name__}"
        
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            task_id = getattr(self, 'request', {}).get('id', 'unknown')
            
            span_attributes = attributes or {}
            span_attributes.update({
                'task.id': task_id,
                'task.name': func.__name__,
                'task.retries': getattr(self, 'request', {}).get('retries', 0),
                'task.eta': str(getattr(self, 'request', {}).get('eta', None))
            })
            
            with tracing_manager.trace(span_name, span_attributes):
                return func(self, *args, **kwargs)
                
        return wrapper
    return decorator

# Celery signal handlers for observability
@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **kwds):
    """Handle task start."""
    logger.info(
        f"Task starting: {task.name}",
        task_id=task_id,
        task_name=task.name,
        queue=getattr(task, 'queue', 'default'),
        retries=getattr(task, 'request', {}).get('retries', 0)
    )

@task_postrun.connect 
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, 
                        kwargs=None, retval=None, state=None, **kwds):
    """Handle task completion."""
    logger.info(
        f"Task finished: {task.name}",
        task_id=task_id,
        task_name=task.name,
        state=state,
        success=state == 'SUCCESS'
    )

@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, 
                        einfo=None, **kwds):
    """Handle task failure."""
    task_name = sender.__name__ if sender else 'unknown'
    
    logger.error(
        f"Task failed: {task_name}",
        task_id=task_id,
        task_name=task_name,
        exception=str(exception),
        traceback=str(einfo)
    )
    
    # Send to error monitoring
    error_capture.capture_exception(exception, {
        'task_id': task_id,
        'task_name': task_name
    })

@task_retry.connect
def task_retry_handler(sender=None, task_id=None, reason=None, einfo=None, **kwds):
    """Handle task retry."""
    task_name = sender.__name__ if sender else 'unknown'
    
    logger.warning(
        f"Task retrying: {task_name}",
        task_id=task_id,
        task_name=task_name,
        reason=str(reason),
        retries=getattr(sender, 'request', {}).get('retries', 0)
    )

# Performance monitoring for specific task types
def monitor_scan_task(threshold_ms: float = 30000):
    """Decorator to monitor email scan task performance."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with performance_monitor.monitor(f"scan.{func.__name__}", threshold_ms):
                return func(*args, **kwargs)
        return wrapper
    return decorator

def monitor_ml_task(threshold_ms: float = 5000):
    """Decorator to monitor ML task performance."""  
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with performance_monitor.monitor(f"ml.{func.__name__}", threshold_ms):
                return func(*args, **kwargs)
        return wrapper
    return decorator