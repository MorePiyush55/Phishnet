"""
Sandbox Job Queue System

Manages the queueing, scheduling, and result aggregation of sandbox analysis jobs.
Provides Redis-based job queue with worker management and result tracking.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
import structlog
import redis
from redis.exceptions import RedisError

logger = structlog.get_logger(__name__)


class JobStatus(Enum):
    """Job execution status."""
    PENDING = "pending"
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class JobPriority(Enum):
    """Job priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    URGENT = 4


@dataclass
class SandboxJob:
    """Represents a sandbox analysis job."""
    job_id: str
    target_url: str
    priority: JobPriority = JobPriority.NORMAL
    created_at: datetime = None
    timeout_seconds: int = 120
    retry_count: int = 0
    max_retries: int = 1
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['priority'] = self.priority.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SandboxJob':
        """Create from dictionary."""
        data = data.copy()
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['priority'] = JobPriority(data['priority'])
        return cls(**data)


@dataclass
class JobResult:
    """Represents the result of a sandbox job."""
    job_id: str
    status: JobStatus
    result_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    worker_id: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    artifacts_urls: List[str] = None
    
    def __post_init__(self):
        if self.artifacts_urls is None:
            self.artifacts_urls = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['status'] = self.status.value
        if self.started_at:
            data['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            data['completed_at'] = self.completed_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'JobResult':
        """Create from dictionary."""
        data = data.copy()
        data['status'] = JobStatus(data['status'])
        if data.get('started_at'):
            data['started_at'] = datetime.fromisoformat(data['started_at'])
        if data.get('completed_at'):
            data['completed_at'] = datetime.fromisoformat(data['completed_at'])
        return cls(**data)


class SandboxJobQueue:
    """Redis-based job queue for sandbox workers."""
    
    # Redis keys
    JOBS_QUEUE = "sandbox:jobs"
    JOBS_PRIORITY_QUEUE = "sandbox:priority_jobs"
    JOBS_IN_PROGRESS = "sandbox:in_progress"
    JOBS_RESULTS = "sandbox:results"
    JOBS_METADATA = "sandbox:metadata"
    WORKERS_HEARTBEAT = "sandbox:workers"
    QUEUE_STATS = "sandbox:stats"
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        """Initialize job queue."""
        self.redis_url = redis_url
        self.redis_client: Optional[redis.Redis] = None
        self.job_callbacks: Dict[str, Callable] = {}
        self._connect()
    
    def _connect(self):
        """Connect to Redis."""
        try:
            self.redis_client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=5.0,
                socket_connect_timeout=5.0,
                retry_on_timeout=True
            )
            # Test connection
            self.redis_client.ping()
            logger.info("Connected to Redis job queue", url=self.redis_url)
        except RedisError as e:
            logger.error("Failed to connect to Redis", error=str(e))
            raise
    
    async def enqueue_job(self, job: SandboxJob) -> bool:
        """
        Enqueue a sandbox job for processing.
        
        Args:
            job: SandboxJob to enqueue
            
        Returns:
            bool: True if successfully enqueued
        """
        try:
            # Store job metadata
            job_data = job.to_dict()
            self.redis_client.hset(self.JOBS_METADATA, job.job_id, json.dumps(job_data))
            
            # Add to appropriate queue based on priority
            queue_key = self.JOBS_PRIORITY_QUEUE if job.priority.value >= JobPriority.HIGH.value else self.JOBS_QUEUE
            
            job_payload = {
                "job_id": job.job_id,
                "url": job.target_url,
                "priority": job.priority.value,
                "timeout": job.timeout_seconds,
                "enqueued_at": datetime.utcnow().isoformat()
            }
            
            self.redis_client.lpush(queue_key, json.dumps(job_payload))
            
            # Update stats
            self.redis_client.hincrby(self.QUEUE_STATS, "jobs_enqueued", 1)
            self.redis_client.hincrby(self.QUEUE_STATS, f"priority_{job.priority.name.lower()}", 1)
            
            logger.info("Job enqueued", job_id=job.job_id, url=job.target_url, priority=job.priority.name)
            return True
            
        except Exception as e:
            logger.error("Failed to enqueue job", job_id=job.job_id, error=str(e))
            return False
    
    async def get_next_job(self, worker_id: str, timeout: int = 30) -> Optional[SandboxJob]:
        """
        Get the next job from the queue for processing.
        
        Args:
            worker_id: ID of the worker requesting the job
            timeout: Maximum time to wait for a job (seconds)
            
        Returns:
            Optional[SandboxJob]: Next job to process, or None if timeout
        """
        try:
            # Update worker heartbeat
            self.redis_client.hset(
                self.WORKERS_HEARTBEAT,
                worker_id,
                json.dumps({
                    "last_seen": datetime.utcnow().isoformat(),
                    "status": "waiting"
                })
            )
            
            # Try priority queue first, then regular queue
            job_data = self.redis_client.brpop(
                [self.JOBS_PRIORITY_QUEUE, self.JOBS_QUEUE],
                timeout=timeout
            )
            
            if not job_data:
                return None
            
            queue_name, job_json = job_data
            job_payload = json.loads(job_json)
            job_id = job_payload["job_id"]
            
            # Get full job metadata
            job_metadata_json = self.redis_client.hget(self.JOBS_METADATA, job_id)
            if not job_metadata_json:
                logger.error("Job metadata not found", job_id=job_id)
                return None
            
            job = SandboxJob.from_dict(json.loads(job_metadata_json))
            
            # Move job to in-progress
            in_progress_data = {
                "job_id": job_id,
                "worker_id": worker_id,
                "started_at": datetime.utcnow().isoformat(),
                "timeout_at": (datetime.utcnow() + timedelta(seconds=job.timeout_seconds)).isoformat()
            }
            
            self.redis_client.hset(self.JOBS_IN_PROGRESS, job_id, json.dumps(in_progress_data))
            
            # Update worker status
            self.redis_client.hset(
                self.WORKERS_HEARTBEAT,
                worker_id,
                json.dumps({
                    "last_seen": datetime.utcnow().isoformat(),
                    "status": "processing",
                    "current_job": job_id
                })
            )
            
            # Update stats
            self.redis_client.hincrby(self.QUEUE_STATS, "jobs_started", 1)
            
            logger.info("Job assigned to worker", job_id=job_id, worker_id=worker_id)
            return job
            
        except Exception as e:
            logger.error("Failed to get next job", worker_id=worker_id, error=str(e))
            return None
    
    async def complete_job(self, job_id: str, result: JobResult) -> bool:
        """
        Mark a job as completed and store the result.
        
        Args:
            job_id: ID of the completed job
            result: Job execution result
            
        Returns:
            bool: True if successfully completed
        """
        try:
            # Store result
            self.redis_client.hset(self.JOBS_RESULTS, job_id, json.dumps(result.to_dict()))
            
            # Remove from in-progress
            self.redis_client.hdel(self.JOBS_IN_PROGRESS, job_id)
            
            # Update worker heartbeat
            if result.worker_id:
                self.redis_client.hset(
                    self.WORKERS_HEARTBEAT,
                    result.worker_id,
                    json.dumps({
                        "last_seen": datetime.utcnow().isoformat(),
                        "status": "idle"
                    })
                )
            
            # Update stats
            if result.status == JobStatus.COMPLETED:
                self.redis_client.hincrby(self.QUEUE_STATS, "jobs_completed", 1)
            else:
                self.redis_client.hincrby(self.QUEUE_STATS, "jobs_failed", 1)
            
            # Trigger callbacks
            if job_id in self.job_callbacks:
                callback = self.job_callbacks.pop(job_id)
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(result)
                    else:
                        callback(result)
                except Exception as e:
                    logger.error("Job callback failed", job_id=job_id, error=str(e))
            
            logger.info("Job completed", job_id=job_id, status=result.status.name, duration_ms=result.duration_ms)
            return True
            
        except Exception as e:
            logger.error("Failed to complete job", job_id=job_id, error=str(e))
            return False
    
    async def get_job_result(self, job_id: str) -> Optional[JobResult]:
        """
        Get the result of a completed job.
        
        Args:
            job_id: ID of the job
            
        Returns:
            Optional[JobResult]: Job result if available
        """
        try:
            result_json = self.redis_client.hget(self.JOBS_RESULTS, job_id)
            if result_json:
                return JobResult.from_dict(json.loads(result_json))
            return None
        except Exception as e:
            logger.error("Failed to get job result", job_id=job_id, error=str(e))
            return None
    
    async def register_job_callback(self, job_id: str, callback: Callable):
        """Register a callback to be called when a job completes."""
        self.job_callbacks[job_id] = callback
    
    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        try:
            stats = self.redis_client.hgetall(self.QUEUE_STATS)
            
            # Add current queue lengths
            stats.update({
                "queue_length": self.redis_client.llen(self.JOBS_QUEUE),
                "priority_queue_length": self.redis_client.llen(self.JOBS_PRIORITY_QUEUE),
                "in_progress_count": self.redis_client.hlen(self.JOBS_IN_PROGRESS),
                "active_workers": self._get_active_workers_count()
            })
            
            return stats
        except Exception as e:
            logger.error("Failed to get queue stats", error=str(e))
            return {}
    
    def _get_active_workers_count(self) -> int:
        """Get count of active workers."""
        try:
            workers = self.redis_client.hgetall(self.WORKERS_HEARTBEAT)
            cutoff_time = datetime.utcnow() - timedelta(minutes=2)
            
            active_count = 0
            for worker_id, data_json in workers.items():
                try:
                    data = json.loads(data_json)
                    last_seen = datetime.fromisoformat(data["last_seen"])
                    if last_seen > cutoff_time:
                        active_count += 1
                except:
                    continue
            
            return active_count
        except:
            return 0
    
    async def cleanup_expired_jobs(self):
        """Clean up expired jobs and inactive workers."""
        try:
            current_time = datetime.utcnow()
            
            # Check for timed-out jobs
            in_progress_jobs = self.redis_client.hgetall(self.JOBS_IN_PROGRESS)
            for job_id, job_data_json in in_progress_jobs.items():
                try:
                    job_data = json.loads(job_data_json)
                    timeout_at = datetime.fromisoformat(job_data["timeout_at"])
                    
                    if current_time > timeout_at:
                        # Job timed out
                        result = JobResult(
                            job_id=job_id,
                            status=JobStatus.TIMEOUT,
                            error_message="Job execution timed out",
                            worker_id=job_data.get("worker_id"),
                            started_at=datetime.fromisoformat(job_data["started_at"]),
                            completed_at=current_time
                        )
                        
                        await self.complete_job(job_id, result)
                        logger.warning("Job timed out", job_id=job_id)
                        
                except Exception as e:
                    logger.error("Failed to process timeout check", job_id=job_id, error=str(e))
            
            # Clean up inactive workers
            workers = self.redis_client.hgetall(self.WORKERS_HEARTBEAT)
            cutoff_time = current_time - timedelta(minutes=5)
            
            for worker_id, data_json in workers.items():
                try:
                    data = json.loads(data_json)
                    last_seen = datetime.fromisoformat(data["last_seen"])
                    
                    if last_seen < cutoff_time:
                        self.redis_client.hdel(self.WORKERS_HEARTBEAT, worker_id)
                        logger.info("Removed inactive worker", worker_id=worker_id)
                        
                except Exception as e:
                    logger.error("Failed to process worker cleanup", worker_id=worker_id, error=str(e))
                    
        except Exception as e:
            logger.error("Cleanup failed", error=str(e))


class SandboxJobManager:
    """High-level manager for sandbox jobs."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        """Initialize job manager."""
        self.queue = SandboxJobQueue(redis_url)
        self.cleanup_task: Optional[asyncio.Task] = None
    
    async def start(self):
        """Start the job manager."""
        # Start cleanup task
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Sandbox job manager started")
    
    async def stop(self):
        """Stop the job manager."""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("Sandbox job manager stopped")
    
    async def submit_analysis(self, url: str, priority: JobPriority = JobPriority.NORMAL) -> str:
        """
        Submit a URL for sandbox analysis.
        
        Args:
            url: URL to analyze
            priority: Job priority
            
        Returns:
            str: Job ID
        """
        job_id = str(uuid.uuid4())
        job = SandboxJob(
            job_id=job_id,
            target_url=url,
            priority=priority
        )
        
        success = await self.queue.enqueue_job(job)
        if not success:
            raise RuntimeError(f"Failed to enqueue job for URL: {url}")
        
        return job_id
    
    async def get_analysis_result(self, job_id: str) -> Optional[JobResult]:
        """Get analysis result by job ID."""
        return await self.queue.get_job_result(job_id)
    
    async def wait_for_result(self, job_id: str, timeout: int = 300) -> Optional[JobResult]:
        """Wait for a job to complete and return the result."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            result = await self.get_analysis_result(job_id)
            if result and result.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.TIMEOUT]:
                return result
            
            await asyncio.sleep(1)
        
        return None
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get job queue statistics."""
        return await self.queue.get_queue_stats()
    
    async def _cleanup_loop(self):
        """Background task for cleaning up expired jobs."""
        while True:
            try:
                await self.queue.cleanup_expired_jobs()
                await asyncio.sleep(60)  # Run every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Cleanup loop error", error=str(e))
                await asyncio.sleep(10)


# Global job manager instance
_job_manager: Optional[SandboxJobManager] = None


async def get_job_manager() -> SandboxJobManager:
    """Get or create the global job manager."""
    global _job_manager
    
    if _job_manager is None:
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        _job_manager = SandboxJobManager(redis_url)
        await _job_manager.start()
    
    return _job_manager
