"""
Dead Letter Queue (DLQ) Handler
Manages failed tasks, retry policies, and error classification.
"""

import logging
import json
import traceback
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from backend.app.workers.celery_config import celery_app
from backend.app.core.database import get_db
from backend.app.core.redis_client import get_redis_client

logger = logging.getLogger(__name__)

class FailureCategory(Enum):
    """Categories of task failures."""
    TEMPORARY = "temporary"           # Retryable errors (network, timeouts)
    PERMANENT = "permanent"           # Non-retryable errors (invalid input)
    RESOURCE = "resource"             # Resource exhaustion (memory, disk)
    EXTERNAL = "external"             # External service failures
    INFRASTRUCTURE = "infrastructure" # System/infrastructure issues
    DATA = "data"                    # Data quality/corruption issues
    UNKNOWN = "unknown"              # Unclassified failures

class RetryPolicy(Enum):
    """Retry policy types."""
    EXPONENTIAL = "exponential"       # Exponential backoff
    LINEAR = "linear"                 # Linear delay increase
    FIXED = "fixed"                   # Fixed delay
    IMMEDIATE = "immediate"           # Immediate retry
    NO_RETRY = "no_retry"            # Do not retry

@dataclass
class FailedTaskInfo:
    """Information about a failed task."""
    task_id: str
    task_name: str
    args: List[Any]
    kwargs: Dict[str, Any]
    error_message: str
    error_type: str
    traceback: str
    failure_time: str
    retry_count: int
    max_retries: int
    queue: str
    failure_category: FailureCategory
    retry_policy: RetryPolicy
    next_retry_time: Optional[str] = None
    metadata: Dict[str, Any] = None

class DLQHandler:
    """Handles Dead Letter Queue operations and failed task management."""
    
    def __init__(self):
        self.redis_client = get_redis_client()
        self.failure_classifiers = self._setup_failure_classifiers()
        self.retry_policies = self._setup_retry_policies()
    
    def _setup_failure_classifiers(self) -> Dict[str, FailureCategory]:
        """Set up error patterns and their classifications."""
        return {
            # Temporary/Retryable errors
            "ConnectionError": FailureCategory.TEMPORARY,
            "TimeoutError": FailureCategory.TEMPORARY,
            "ConnectTimeout": FailureCategory.TEMPORARY,
            "ReadTimeout": FailureCategory.TEMPORARY,
            "HTTPError": FailureCategory.TEMPORARY,
            "RequestException": FailureCategory.EXTERNAL,
            
            # Permanent errors
            "ValueError": FailureCategory.PERMANENT,
            "TypeError": FailureCategory.PERMANENT,
            "KeyError": FailureCategory.DATA,
            "FileNotFoundError": FailureCategory.DATA,
            "ValidationError": FailureCategory.PERMANENT,
            
            # Resource errors
            "MemoryError": FailureCategory.RESOURCE,
            "OutOfMemoryError": FailureCategory.RESOURCE,
            "DiskSpaceError": FailureCategory.RESOURCE,
            
            # Infrastructure errors
            "DatabaseError": FailureCategory.INFRASTRUCTURE,
            "RedisError": FailureCategory.INFRASTRUCTURE,
            "SystemError": FailureCategory.INFRASTRUCTURE
        }
    
    def _setup_retry_policies(self) -> Dict[FailureCategory, RetryPolicy]:
        """Set up retry policies for different failure categories."""
        return {
            FailureCategory.TEMPORARY: RetryPolicy.EXPONENTIAL,
            FailureCategory.EXTERNAL: RetryPolicy.EXPONENTIAL,
            FailureCategory.RESOURCE: RetryPolicy.LINEAR,
            FailureCategory.INFRASTRUCTURE: RetryPolicy.EXPONENTIAL,
            FailureCategory.DATA: RetryPolicy.FIXED,
            FailureCategory.PERMANENT: RetryPolicy.NO_RETRY,
            FailureCategory.UNKNOWN: RetryPolicy.EXPONENTIAL
        }

@celery_app.task(bind=True, name="backend.app.tasks.dlq_handler.handle_task_failure")
def handle_task_failure(self, task_id: str, error_message: str, traceback_str: str, 
                       task_info: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Handle task failure and route to appropriate DLQ processing.
    
    Args:
        task_id: Failed task ID
        error_message: Error message
        traceback_str: Error traceback
        task_info: Additional task information
        
    Returns:
        DLQ processing results
    """
    try:
        dlq_handler = DLQHandler()
        
        # Get task details
        task_details = dlq_handler._get_task_details(task_id, task_info)
        
        # Classify the failure
        failure_category = dlq_handler._classify_failure(error_message, traceback_str)
        
        # Create failed task info
        failed_task = FailedTaskInfo(
            task_id=task_id,
            task_name=task_details.get("name", "unknown"),
            args=task_details.get("args", []),
            kwargs=task_details.get("kwargs", {}),
            error_message=error_message,
            error_type=dlq_handler._extract_error_type(error_message),
            traceback=traceback_str,
            failure_time=datetime.utcnow().isoformat(),
            retry_count=task_details.get("retries", 0),
            max_retries=task_details.get("max_retries", 3),
            queue=task_details.get("queue", "unknown"),
            failure_category=failure_category,
            retry_policy=dlq_handler.retry_policies.get(failure_category, RetryPolicy.EXPONENTIAL),
            metadata=task_details.get("metadata", {})
        )
        
        # Process the failure
        processing_result = dlq_handler._process_failed_task(failed_task)
        
        # Store failure information
        dlq_handler._store_failure_info(failed_task)
        
        # Update metrics
        dlq_handler._update_failure_metrics(failed_task)
        
        logger.info(f"Processed failed task {task_id}: {processing_result['action']}")
        
        return {
            "task_id": task_id,
            "processing_result": processing_result,
            "failure_category": failure_category.value,
            "retry_policy": failed_task.retry_policy.value,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"DLQ handler failed for task {task_id}: {str(e)}")
        return {"error": str(e), "task_id": task_id}

class DLQHandler:
    """Extended DLQ Handler implementation."""
    
    def _get_task_details(self, task_id: str, task_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get detailed information about the failed task."""
        try:
            # Try to get task details from Celery result backend
            result = celery_app.AsyncResult(task_id)
            
            details = {
                "name": getattr(result, "name", "unknown"),
                "args": getattr(result, "args", []),
                "kwargs": getattr(result, "kwargs", {}),
                "retries": getattr(result, "retries", 0),
                "queue": "unknown"
            }
            
            # Merge with provided task info
            if task_info:
                details.update(task_info)
            
            return details
            
        except Exception as e:
            logger.warning(f"Could not retrieve task details for {task_id}: {str(e)}")
            return task_info or {}
    
    def _classify_failure(self, error_message: str, traceback_str: str) -> FailureCategory:
        """Classify the failure based on error message and traceback."""
        try:
            # Extract error type from message
            error_type = self._extract_error_type(error_message)
            
            # Check against known classifiers
            if error_type in self.failure_classifiers:
                return self.failure_classifiers[error_type]
            
            # Pattern matching on error message
            error_lower = error_message.lower()
            
            if any(pattern in error_lower for pattern in ["timeout", "connection", "network"]):
                return FailureCategory.TEMPORARY
            
            if any(pattern in error_lower for pattern in ["memory", "disk space", "resource"]):
                return FailureCategory.RESOURCE
            
            if any(pattern in error_lower for pattern in ["database", "redis", "infrastructure"]):
                return FailureCategory.INFRASTRUCTURE
            
            if any(pattern in error_lower for pattern in ["invalid", "validation", "format"]):
                return FailureCategory.PERMANENT
            
            if any(pattern in error_lower for pattern in ["service", "api", "external"]):
                return FailureCategory.EXTERNAL
            
            # Default to unknown
            return FailureCategory.UNKNOWN
            
        except Exception as e:
            logger.warning(f"Failed to classify error: {str(e)}")
            return FailureCategory.UNKNOWN
    
    def _extract_error_type(self, error_message: str) -> str:
        """Extract error type from error message."""
        try:
            # Common patterns for extracting error type
            if ":" in error_message:
                parts = error_message.split(":")
                if len(parts) > 0:
                    error_type = parts[0].strip()
                    # Remove common prefixes
                    for prefix in ["Traceback", "Exception", "Error"]:
                        error_type = error_type.replace(prefix, "").strip()
                    return error_type
            
            # Fallback: use first word
            words = error_message.split()
            if words:
                return words[0]
            
            return "UnknownError"
            
        except Exception:
            return "UnknownError"
    
    def _process_failed_task(self, failed_task: FailedTaskInfo) -> Dict[str, Any]:
        """Process a failed task according to its retry policy."""
        try:
            # Check if task should be retried
            if failed_task.retry_count >= failed_task.max_retries:
                return self._move_to_dlq(failed_task)
            
            # Apply retry policy
            if failed_task.retry_policy == RetryPolicy.NO_RETRY:
                return self._move_to_dlq(failed_task)
            
            elif failed_task.retry_policy == RetryPolicy.IMMEDIATE:
                return self._schedule_immediate_retry(failed_task)
            
            elif failed_task.retry_policy == RetryPolicy.EXPONENTIAL:
                return self._schedule_exponential_retry(failed_task)
            
            elif failed_task.retry_policy == RetryPolicy.LINEAR:
                return self._schedule_linear_retry(failed_task)
            
            elif failed_task.retry_policy == RetryPolicy.FIXED:
                return self._schedule_fixed_retry(failed_task)
            
            else:
                return self._move_to_dlq(failed_task)
                
        except Exception as e:
            logger.error(f"Failed to process failed task {failed_task.task_id}: {str(e)}")
            return {"action": "dlq", "reason": f"processing_error: {str(e)}"}
    
    def _move_to_dlq(self, failed_task: FailedTaskInfo) -> Dict[str, Any]:
        """Move task to Dead Letter Queue."""
        try:
            dlq_key = "dlq:failed_tasks"
            task_data = asdict(failed_task)
            
            # Add to DLQ
            self.redis_client.lpush(dlq_key, json.dumps(task_data))
            
            # Set expiration for DLQ items (7 days)
            self.redis_client.expire(dlq_key, 604800)
            
            # Index by failure category for analysis
            category_key = f"dlq:category:{failed_task.failure_category.value}"
            self.redis_client.lpush(category_key, failed_task.task_id)
            self.redis_client.expire(category_key, 604800)
            
            logger.info(f"Moved task {failed_task.task_id} to DLQ")
            
            return {
                "action": "dlq",
                "reason": f"max_retries_exceeded: {failed_task.retry_count}/{failed_task.max_retries}",
                "dlq_position": self.redis_client.llen(dlq_key)
            }
            
        except Exception as e:
            logger.error(f"Failed to move task to DLQ: {str(e)}")
            return {"action": "dlq", "error": str(e)}
    
    def _schedule_immediate_retry(self, failed_task: FailedTaskInfo) -> Dict[str, Any]:
        """Schedule immediate retry."""
        try:
            # Re-enqueue the task immediately
            celery_app.send_task(
                failed_task.task_name,
                args=failed_task.args,
                kwargs=failed_task.kwargs,
                queue=failed_task.queue,
                retry=True
            )
            
            return {
                "action": "immediate_retry",
                "retry_count": failed_task.retry_count + 1,
                "next_retry": "immediate"
            }
            
        except Exception as e:
            logger.error(f"Failed to schedule immediate retry: {str(e)}")
            return {"action": "retry_failed", "error": str(e)}
    
    def _schedule_exponential_retry(self, failed_task: FailedTaskInfo) -> Dict[str, Any]:
        """Schedule retry with exponential backoff."""
        try:
            # Calculate exponential backoff delay
            base_delay = 60  # 1 minute base
            max_delay = 3600  # 1 hour max
            delay = min(base_delay * (2 ** failed_task.retry_count), max_delay)
            
            # Schedule retry
            eta = datetime.utcnow() + timedelta(seconds=delay)
            celery_app.send_task(
                failed_task.task_name,
                args=failed_task.args,
                kwargs=failed_task.kwargs,
                queue=failed_task.queue,
                eta=eta,
                retry=True
            )
            
            return {
                "action": "exponential_retry",
                "retry_count": failed_task.retry_count + 1,
                "delay_seconds": delay,
                "next_retry": eta.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to schedule exponential retry: {str(e)}")
            return {"action": "retry_failed", "error": str(e)}
    
    def _schedule_linear_retry(self, failed_task: FailedTaskInfo) -> Dict[str, Any]:
        """Schedule retry with linear delay increase."""
        try:
            # Calculate linear delay
            base_delay = 120  # 2 minutes base
            delay = base_delay * (failed_task.retry_count + 1)
            
            # Schedule retry
            eta = datetime.utcnow() + timedelta(seconds=delay)
            celery_app.send_task(
                failed_task.task_name,
                args=failed_task.args,
                kwargs=failed_task.kwargs,
                queue=failed_task.queue,
                eta=eta,
                retry=True
            )
            
            return {
                "action": "linear_retry",
                "retry_count": failed_task.retry_count + 1,
                "delay_seconds": delay,
                "next_retry": eta.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to schedule linear retry: {str(e)}")
            return {"action": "retry_failed", "error": str(e)}
    
    def _schedule_fixed_retry(self, failed_task: FailedTaskInfo) -> Dict[str, Any]:
        """Schedule retry with fixed delay."""
        try:
            # Fixed delay of 5 minutes
            delay = 300
            
            # Schedule retry
            eta = datetime.utcnow() + timedelta(seconds=delay)
            celery_app.send_task(
                failed_task.task_name,
                args=failed_task.args,
                kwargs=failed_task.kwargs,
                queue=failed_task.queue,
                eta=eta,
                retry=True
            )
            
            return {
                "action": "fixed_retry",
                "retry_count": failed_task.retry_count + 1,
                "delay_seconds": delay,
                "next_retry": eta.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to schedule fixed retry: {str(e)}")
            return {"action": "retry_failed", "error": str(e)}
    
    def _store_failure_info(self, failed_task: FailedTaskInfo):
        """Store failure information for analysis and debugging."""
        try:
            # Store in Redis for quick access
            failure_key = f"failure:{failed_task.task_id}"
            failure_data = asdict(failed_task)
            self.redis_client.hmset(failure_key, failure_data)
            self.redis_client.expire(failure_key, 86400)  # 24 hours
            
            # Store in database for long-term analysis
            # This would be implemented based on your database schema
            
            logger.debug(f"Stored failure info for task {failed_task.task_id}")
            
        except Exception as e:
            logger.error(f"Failed to store failure info: {str(e)}")
    
    def _update_failure_metrics(self, failed_task: FailedTaskInfo):
        """Update failure metrics for monitoring."""
        try:
            # Update daily failure count
            date_key = datetime.utcnow().strftime("%Y-%m-%d")
            
            # Overall failure metrics
            self.redis_client.incr(f"failures:daily:{date_key}")
            self.redis_client.incr(f"failures:task:{failed_task.task_name}:daily:{date_key}")
            self.redis_client.incr(f"failures:category:{failed_task.failure_category.value}:daily:{date_key}")
            self.redis_client.incr(f"failures:queue:{failed_task.queue}:daily:{date_key}")
            
            # Set expiration for metrics
            for key in [
                f"failures:daily:{date_key}",
                f"failures:task:{failed_task.task_name}:daily:{date_key}",
                f"failures:category:{failed_task.failure_category.value}:daily:{date_key}",
                f"failures:queue:{failed_task.queue}:daily:{date_key}"
            ]:
                self.redis_client.expire(key, 2592000)  # 30 days
            
            logger.debug(f"Updated failure metrics for task {failed_task.task_id}")
            
        except Exception as e:
            logger.error(f"Failed to update failure metrics: {str(e)}")

def get_dlq_stats() -> Dict[str, Any]:
    """Get comprehensive DLQ statistics."""
    try:
        redis_client = get_redis_client()
        
        # Get DLQ length
        dlq_length = redis_client.llen("dlq:failed_tasks")
        
        # Get failure counts by category
        category_counts = {}
        for category in FailureCategory:
            category_key = f"dlq:category:{category.value}"
            category_counts[category.value] = redis_client.llen(category_key)
        
        # Get recent failure counts
        date_key = datetime.utcnow().strftime("%Y-%m-%d")
        daily_failures = redis_client.get(f"failures:daily:{date_key}") or 0
        
        return {
            "dlq_length": dlq_length,
            "category_breakdown": category_counts,
            "daily_failures": int(daily_failures),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get DLQ stats: {str(e)}")
        return {"error": str(e)}

def replay_dlq_task(task_id: str) -> Dict[str, Any]:
    """Replay a task from the DLQ."""
    try:
        redis_client = get_redis_client()
        
        # Find task in DLQ
        dlq_items = redis_client.lrange("dlq:failed_tasks", 0, -1)
        
        for item in dlq_items:
            task_data = json.loads(item)
            if task_data.get("task_id") == task_id:
                # Re-enqueue the task
                celery_app.send_task(
                    task_data["task_name"],
                    args=task_data["args"],
                    kwargs=task_data["kwargs"],
                    queue=task_data["queue"]
                )
                
                # Remove from DLQ
                redis_client.lrem("dlq:failed_tasks", 1, item)
                
                return {
                    "success": True,
                    "task_id": task_id,
                    "action": "replayed",
                    "timestamp": datetime.utcnow().isoformat()
                }
        
        return {
            "success": False,
            "error": f"Task {task_id} not found in DLQ"
        }
        
    except Exception as e:
        logger.error(f"Failed to replay DLQ task {task_id}: {str(e)}")
        return {"success": False, "error": str(e)}