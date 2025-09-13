"""
Async task queue system using Redis for PhishNet background operations.
Handles email processing, threat analysis, and other long-running tasks.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass, asdict
import pickle
import traceback

import aioredis
from aioredis import Redis

from app.config.settings import get_settings

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"


class TaskPriority(Enum):
    """Task priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class TaskResult:
    """Task execution result."""
    task_id: str
    status: TaskStatus
    result: Any = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_time: Optional[float] = None
    retry_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        # Convert datetime objects to ISO strings
        if self.started_at:
            data['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            data['completed_at'] = self.completed_at.isoformat()
        data['status'] = self.status.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TaskResult':
        """Create from dictionary."""
        if 'started_at' in data and data['started_at']:
            data['started_at'] = datetime.fromisoformat(data['started_at'])
        if 'completed_at' in data and data['completed_at']:
            data['completed_at'] = datetime.fromisoformat(data['completed_at'])
        if 'status' in data:
            data['status'] = TaskStatus(data['status'])
        return cls(**data)


@dataclass
class Task:
    """Task definition for the queue."""
    id: str
    name: str
    args: List[Any]
    kwargs: Dict[str, Any]
    priority: TaskPriority = TaskPriority.NORMAL
    max_retries: int = 3
    retry_delay: int = 60  # seconds
    timeout: int = 300  # 5 minutes
    created_at: datetime = None
    scheduled_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['priority'] = self.priority.value
        data['created_at'] = self.created_at.isoformat()
        if self.scheduled_at:
            data['scheduled_at'] = self.scheduled_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Task':
        """Create from dictionary."""
        data['priority'] = TaskPriority(data['priority'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        if data.get('scheduled_at'):
            data['scheduled_at'] = datetime.fromisoformat(data['scheduled_at'])
        return cls(**data)


class AsyncTaskQueue:
    """Redis-backed async task queue with priority and retry support."""
    
    def __init__(self, redis_url: str, queue_name: str = "phishnet_tasks"):
        self.redis_url = redis_url
        self.queue_name = queue_name
        self.redis: Optional[Redis] = None
        
        # Queue keys
        self.task_queue_key = f"queue:{queue_name}"
        self.priority_queues = {
            TaskPriority.CRITICAL: f"queue:{queue_name}:critical",
            TaskPriority.HIGH: f"queue:{queue_name}:high",
            TaskPriority.NORMAL: f"queue:{queue_name}:normal",
            TaskPriority.LOW: f"queue:{queue_name}:low",
        }
        self.scheduled_queue_key = f"queue:{queue_name}:scheduled"
        self.processing_key = f"queue:{queue_name}:processing"
        self.results_key = f"queue:{queue_name}:results"
        
        # Task registry
        self.task_registry: Dict[str, Callable] = {}
        
    async def initialize(self) -> None:
        """Initialize Redis connection."""
        logger.info("Initializing async task queue")
        
        self.redis = await aioredis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=False,
            retry_on_timeout=True,
            socket_keepalive=True,
        )
        
        await self.redis.ping()
        logger.info("Task queue initialized successfully")
    
    async def close(self) -> None:
        """Close Redis connection."""
        if self.redis:
            await self.redis.close()
            logger.info("Task queue connection closed")
    
    def register_task(self, name: str, func: Callable) -> None:
        """Register a task function."""
        self.task_registry[name] = func
        logger.debug(f"Registered task: {name}")
    
    def task(self, name: str = None):
        """Decorator to register task functions."""
        def decorator(func: Callable) -> Callable:
            task_name = name or f"{func.__module__}.{func.__name__}"
            self.register_task(task_name, func)
            return func
        return decorator
    
    async def enqueue(
        self,
        task_name: str,
        *args,
        priority: TaskPriority = TaskPriority.NORMAL,
        max_retries: int = 3,
        retry_delay: int = 60,
        timeout: int = 300,
        scheduled_at: Optional[datetime] = None,
        **kwargs
    ) -> str:
        """Enqueue a task for execution."""
        task_id = str(uuid.uuid4())
        
        task = Task(
            id=task_id,
            name=task_name,
            args=list(args),
            kwargs=kwargs,
            priority=priority,
            max_retries=max_retries,
            retry_delay=retry_delay,
            timeout=timeout,
            scheduled_at=scheduled_at
        )
        
        # Serialize task
        task_data = pickle.dumps(task)
        
        if scheduled_at and scheduled_at > datetime.now(timezone.utc):
            # Schedule for later execution
            score = scheduled_at.timestamp()
            await self.redis.zadd(self.scheduled_queue_key, {task_data: score})
            logger.debug(f"Scheduled task {task_id} for {scheduled_at}")
        else:
            # Add to priority queue
            queue_key = self.priority_queues[priority]
            await self.redis.lpush(queue_key, task_data)
            logger.debug(f"Enqueued task {task_id} with priority {priority.name}")
        
        # Create initial task result
        result = TaskResult(task_id=task_id, status=TaskStatus.PENDING)
        await self._store_result(result)
        
        return task_id
    
    async def dequeue(self, timeout: int = 10) -> Optional[Task]:
        """Dequeue the next task for processing."""
        if not self.redis:
            return None
        
        # Check scheduled tasks first
        await self._move_scheduled_tasks()
        
        # Try to get task from priority queues (highest priority first)
        for priority in [TaskPriority.CRITICAL, TaskPriority.HIGH, TaskPriority.NORMAL, TaskPriority.LOW]:
            queue_key = self.priority_queues[priority]
            
            # Use BRPOPLPUSH for atomic dequeue with processing tracking
            task_data = await self.redis.brpoplpush(
                queue_key, 
                self.processing_key, 
                timeout=timeout
            )
            
            if task_data:
                try:
                    task = pickle.loads(task_data)
                    logger.debug(f"Dequeued task {task.id} from {priority.name} queue")
                    return task
                except Exception as e:
                    logger.error(f"Failed to deserialize task: {e}")
                    # Remove corrupted task from processing
                    await self.redis.lrem(self.processing_key, 1, task_data)
        
        return None
    
    async def execute_task(self, task: Task) -> TaskResult:
        """Execute a single task."""
        result = TaskResult(
            task_id=task.id,
            status=TaskStatus.RUNNING,
            started_at=datetime.now(timezone.utc)
        )
        await self._store_result(result)
        
        try:
            # Get task function
            if task.name not in self.task_registry:
                raise ValueError(f"Task {task.name} not registered")
            
            func = self.task_registry[task.name]
            
            # Execute with timeout
            try:
                if asyncio.iscoroutinefunction(func):
                    task_result = await asyncio.wait_for(
                        func(*task.args, **task.kwargs),
                        timeout=task.timeout
                    )
                else:
                    # Run sync function in thread pool
                    loop = asyncio.get_event_loop()
                    task_result = await asyncio.wait_for(
                        loop.run_in_executor(None, func, *task.args),
                        timeout=task.timeout
                    )
                
                result.status = TaskStatus.COMPLETED
                result.result = task_result
                logger.info(f"Task {task.id} completed successfully")
                
            except asyncio.TimeoutError:
                result.status = TaskStatus.FAILED
                result.error = f"Task timed out after {task.timeout} seconds"
                logger.error(f"Task {task.id} timed out")
            
        except Exception as e:
            result.status = TaskStatus.FAILED
            result.error = str(e)
            logger.error(f"Task {task.id} failed: {e}")
            
            # Log full traceback for debugging
            logger.debug(f"Task {task.id} traceback: {traceback.format_exc()}")
        
        finally:
            result.completed_at = datetime.now(timezone.utc)
            if result.started_at:
                result.execution_time = (
                    result.completed_at - result.started_at
                ).total_seconds()
            
            await self._store_result(result)
            
            # Remove from processing queue
            task_data = pickle.dumps(task)
            await self.redis.lrem(self.processing_key, 1, task_data)
        
        return result
    
    async def retry_task(self, task: Task, result: TaskResult) -> bool:
        """Retry a failed task if retries remaining."""
        if result.retry_count >= task.max_retries:
            logger.warning(f"Task {task.id} exceeded max retries ({task.max_retries})")
            return False
        
        # Update retry info
        result.retry_count += 1
        result.status = TaskStatus.RETRYING
        await self._store_result(result)
        
        # Schedule retry
        retry_time = datetime.now(timezone.utc) + timedelta(seconds=task.retry_delay)
        task.scheduled_at = retry_time
        
        # Re-enqueue
        task_data = pickle.dumps(task)
        score = retry_time.timestamp()
        await self.redis.zadd(self.scheduled_queue_key, {task_data: score})
        
        logger.info(f"Scheduled retry {result.retry_count} for task {task.id} at {retry_time}")
        return True
    
    async def get_result(self, task_id: str) -> Optional[TaskResult]:
        """Get task execution result."""
        key = f"{self.results_key}:{task_id}"
        data = await self.redis.get(key)
        
        if data:
            try:
                result_dict = json.loads(data.decode())
                return TaskResult.from_dict(result_dict)
            except Exception as e:
                logger.error(f"Failed to deserialize result for task {task_id}: {e}")
        
        return None
    
    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending or scheduled task."""
        # Try to remove from priority queues
        for queue_key in self.priority_queues.values():
            # This is complex with Redis - would need to scan and match task IDs
            # For now, just mark as cancelled in results
            pass
        
        # Mark as cancelled
        result = await self.get_result(task_id)
        if result and result.status in [TaskStatus.PENDING, TaskStatus.RETRYING]:
            result.status = TaskStatus.CANCELLED
            await self._store_result(result)
            return True
        
        return False
    
    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        stats = {}
        
        # Queue lengths
        for priority, queue_key in self.priority_queues.items():
            length = await self.redis.llen(queue_key)
            stats[f"{priority.name.lower()}_queue"] = length
        
        # Processing and scheduled counts
        stats["processing"] = await self.redis.llen(self.processing_key)
        stats["scheduled"] = await self.redis.zcard(self.scheduled_queue_key)
        
        return stats
    
    async def _store_result(self, result: TaskResult) -> None:
        """Store task result in Redis."""
        key = f"{self.results_key}:{result.task_id}"
        data = json.dumps(result.to_dict(), default=str)
        
        # Store with TTL (keep results for 24 hours)
        await self.redis.setex(key, 86400, data)
    
    async def _move_scheduled_tasks(self) -> None:
        """Move scheduled tasks to appropriate queues when their time comes."""
        now = datetime.now(timezone.utc).timestamp()
        
        # Get tasks ready to run
        ready_tasks = await self.redis.zrangebyscore(
            self.scheduled_queue_key, 0, now, withscores=False
        )
        
        if ready_tasks:
            pipe = self.redis.pipeline()
            
            for task_data in ready_tasks:
                try:
                    task = pickle.loads(task_data)
                    
                    # Move to appropriate priority queue
                    queue_key = self.priority_queues[task.priority]
                    pipe.lpush(queue_key, task_data)
                    pipe.zrem(self.scheduled_queue_key, task_data)
                    
                    logger.debug(f"Moved scheduled task {task.id} to {task.priority.name} queue")
                    
                except Exception as e:
                    logger.error(f"Failed to process scheduled task: {e}")
                    # Remove corrupted task
                    pipe.zrem(self.scheduled_queue_key, task_data)
            
            await pipe.execute()


class TaskWorker:
    """Async task worker that processes tasks from the queue."""
    
    def __init__(self, queue: AsyncTaskQueue, worker_name: str = None):
        self.queue = queue
        self.worker_name = worker_name or f"worker-{uuid.uuid4().hex[:8]}"
        self.running = False
        self.processed_count = 0
        self.failed_count = 0
        
    async def start(self) -> None:
        """Start the worker to process tasks."""
        logger.info(f"Starting task worker: {self.worker_name}")
        self.running = True
        
        try:
            while self.running:
                try:
                    # Get next task (with timeout to allow graceful shutdown)
                    task = await self.queue.dequeue(timeout=5)
                    
                    if task:
                        logger.debug(f"Worker {self.worker_name} processing task {task.id}")
                        
                        # Execute task
                        result = await self.queue.execute_task(task)
                        
                        if result.status == TaskStatus.COMPLETED:
                            self.processed_count += 1
                        elif result.status == TaskStatus.FAILED:
                            self.failed_count += 1
                            
                            # Retry if possible
                            if await self.queue.retry_task(task, result):
                                logger.info(f"Task {task.id} queued for retry")
                            else:
                                logger.error(f"Task {task.id} failed permanently")
                        
                except Exception as e:
                    logger.error(f"Worker {self.worker_name} error: {e}")
                    await asyncio.sleep(1)  # Brief pause before retrying
                    
        except asyncio.CancelledError:
            logger.info(f"Worker {self.worker_name} cancelled")
        finally:
            logger.info(f"Worker {self.worker_name} stopped. Processed: {self.processed_count}, Failed: {self.failed_count}")
    
    def stop(self) -> None:
        """Stop the worker."""
        logger.info(f"Stopping task worker: {self.worker_name}")
        self.running = False


# Global task queue instance
task_queue: Optional[AsyncTaskQueue] = None


async def init_task_queue() -> AsyncTaskQueue:
    """Initialize the global task queue."""
    global task_queue
    
    settings = get_settings()
    task_queue = AsyncTaskQueue(settings.REDIS_URL)
    await task_queue.initialize()
    
    return task_queue


async def get_task_queue() -> AsyncTaskQueue:
    """Get the global task queue instance."""
    if not task_queue:
        raise RuntimeError("Task queue not initialized. Call init_task_queue() first.")
    return task_queue


# Convenience functions
async def enqueue_task(task_name: str, *args, **kwargs) -> str:
    """Enqueue a task using the global queue."""
    queue = await get_task_queue()
    return await queue.enqueue(task_name, *args, **kwargs)


async def get_task_result(task_id: str) -> Optional[TaskResult]:
    """Get task result using the global queue."""
    queue = await get_task_queue()
    return await queue.get_result(task_id)


# Task decorators
def task(name: str = None, **task_options):
    """Decorator to register and configure tasks."""
    def decorator(func: Callable) -> Callable:
        # Register with global queue when it's available
        async def register_when_ready():
            queue = await get_task_queue()
            task_name = name or f"{func.__module__}.{func.__name__}"
            queue.register_task(task_name, func)
        
        # Store registration info for later
        func._task_name = name or f"{func.__module__}.{func.__name__}"
        func._task_options = task_options
        func._register = register_when_ready
        
        return func
    return decorator


# Cleanup function
async def cleanup_task_queue():
    """Cleanup task queue on application shutdown."""
    global task_queue
    if task_queue:
        await task_queue.close()
        task_queue = None
        logger.info("Task queue cleanup completed")
