"""
Job queue management system with Redis backend.
Handles job queuing, priority management, dead letter queues, and retry logic.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

from app.core.redis_client import get_queue_manager, get_redis_client, QueueManager
from app.models.jobs import JobStatus, JobPriority, WorkerType, EmailScanJob

logger = logging.getLogger(__name__)

class QueueNames:
    """Standard queue names for different job types"""
    EMAIL_SCAN = "email_scan"
    SANDBOX_ANALYSIS = "sandbox_analysis"
    API_ANALYSIS = "api_analysis"
    THREAT_SCORING = "threat_scoring"
    AGGREGATION = "aggregation"
    RETRY = "retry"
    DEAD_LETTER = "dead_letter"
    HIGH_PRIORITY = "high_priority"

@dataclass
class JobMessage:
    """Standard job message format for queue communication"""
    job_id: str
    job_type: str
    payload: Dict[str, Any]
    created_at: float
    priority: int = JobPriority.NORMAL
    retry_count: int = 0
    max_retries: int = 3
    timeout_seconds: int = 300
    worker_type: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'JobMessage':
        """Create JobMessage from dictionary"""
        return cls(**data)
    
    @property
    def age_seconds(self) -> float:
        """Get age of job message in seconds"""
        return time.time() - self.created_at
    
    @property
    def is_expired(self) -> bool:
        """Check if job has exceeded timeout"""
        return self.age_seconds > self.timeout_seconds

class JobQueueManager:
    """
    Enhanced job queue manager with priority queues, dead letter queues,
    and retry mechanisms.
    """
    
    def __init__(self, redis_queue_manager: QueueManager = None):
        self.queue_manager = redis_queue_manager or get_queue_manager()
        self.redis_client = get_redis_client()
        
        # Queue configuration
        self.default_ttl = 24 * 60 * 60  # 24 hours
        self.retry_delay_base = 60  # Base retry delay in seconds
        self.max_retry_delay = 3600  # Max retry delay (1 hour)
        
        # Monitoring
        self._queue_stats = {}
        self._last_stats_update = 0
    
    def enqueue_job(self, queue_name: str, job_message: JobMessage) -> bool:
        """
        Enqueue a job with priority handling.
        
        Args:
            queue_name: Target queue name
            job_message: Job message to enqueue
            
        Returns:
            True if successfully enqueued
        """
        try:
            # Serialize job message
            job_data = job_message.to_dict()
            
            # Add timestamp if not present
            if 'created_at' not in job_data:
                job_data['created_at'] = time.time()
            
            # Use priority as score (lower = higher priority)
            priority_score = job_message.priority
            
            # Add to priority queue first if high priority
            if job_message.priority <= JobPriority.HIGH:
                self.queue_manager.enqueue(QueueNames.HIGH_PRIORITY, job_data, priority_score)
            
            # Always add to the specific queue
            success = self.queue_manager.enqueue(queue_name, job_data, priority_score)
            
            if success:
                logger.info(f"Enqueued job {job_message.job_id} to {queue_name} with priority {job_message.priority}")
                self._update_queue_stats(queue_name, 'enqueued')
            
            return success
            
        except Exception as e:
            logger.error(f"Error enqueuing job {job_message.job_id}: {e}")
            return False
    
    async def async_enqueue_job(self, queue_name: str, job_message: JobMessage) -> bool:
        """Async version of enqueue_job"""
        try:
            job_data = job_message.to_dict()
            
            if 'created_at' not in job_data:
                job_data['created_at'] = time.time()
            
            priority_score = job_message.priority
            
            # Add to priority queue for high priority jobs
            if job_message.priority <= JobPriority.HIGH:
                await self.queue_manager.async_enqueue(QueueNames.HIGH_PRIORITY, job_data, priority_score)
            
            success = await self.queue_manager.async_enqueue(queue_name, job_data, priority_score)
            
            if success:
                logger.info(f"Async enqueued job {job_message.job_id} to {queue_name}")
                self._update_queue_stats(queue_name, 'enqueued')
            
            return success
            
        except Exception as e:
            logger.error(f"Error async enqueuing job {job_message.job_id}: {e}")
            return False
    
    def dequeue_job(self, queue_names: Union[str, List[str]], timeout: int = 5) -> Optional[JobMessage]:
        """
        Dequeue a job from one or more queues.
        
        Args:
            queue_names: Queue name(s) to check (in priority order)
            timeout: Blocking timeout in seconds
            
        Returns:
            JobMessage if available, None otherwise
        """
        try:
            if isinstance(queue_names, str):
                queue_names = [queue_names]
            
            # Always check high priority queue first
            all_queues = [QueueNames.HIGH_PRIORITY] + queue_names
            
            for queue_name in all_queues:
                # Try non-blocking first
                job_data = self.queue_manager.dequeue(queue_name, timeout=0)
                
                if job_data:
                    job_message = JobMessage.from_dict(job_data)
                    
                    # Check if job has expired
                    if job_message.is_expired:
                        logger.warning(f"Job {job_message.job_id} expired, moving to dead letter queue")
                        self._move_to_dead_letter(job_message, "Job expired")
                        continue
                    
                    logger.info(f"Dequeued job {job_message.job_id} from {queue_name}")
                    self._update_queue_stats(queue_name, 'dequeued')
                    return job_message
            
            # If no immediate jobs, do blocking wait on primary queue
            if queue_names:
                job_data = self.queue_manager.dequeue(queue_names[0], timeout=timeout)
                if job_data:
                    job_message = JobMessage.from_dict(job_data)
                    if not job_message.is_expired:
                        self._update_queue_stats(queue_names[0], 'dequeued')
                        return job_message
                    else:
                        self._move_to_dead_letter(job_message, "Job expired")
            
            return None
            
        except Exception as e:
            logger.error(f"Error dequeuing job: {e}")
            return None
    
    async def async_dequeue_job(self, queue_names: Union[str, List[str]], timeout: int = 5) -> Optional[JobMessage]:
        """Async version of dequeue_job"""
        try:
            if isinstance(queue_names, str):
                queue_names = [queue_names]
            
            all_queues = [QueueNames.HIGH_PRIORITY] + queue_names
            
            for queue_name in all_queues:
                job_data = await self.queue_manager.async_dequeue(queue_name, timeout=0)
                
                if job_data:
                    job_message = JobMessage.from_dict(job_data)
                    
                    if job_message.is_expired:
                        logger.warning(f"Job {job_message.job_id} expired")
                        await self._async_move_to_dead_letter(job_message, "Job expired")
                        continue
                    
                    logger.info(f"Async dequeued job {job_message.job_id} from {queue_name}")
                    self._update_queue_stats(queue_name, 'dequeued')
                    return job_message
            
            # Blocking wait on primary queue
            if queue_names:
                job_data = await self.queue_manager.async_dequeue(queue_names[0], timeout=timeout)
                if job_data:
                    job_message = JobMessage.from_dict(job_data)
                    if not job_message.is_expired:
                        self._update_queue_stats(queue_names[0], 'dequeued')
                        return job_message
                    else:
                        await self._async_move_to_dead_letter(job_message, "Job expired")
            
            return None
            
        except Exception as e:
            logger.error(f"Error async dequeuing job: {e}")
            return None
    
    def retry_job(self, job_message: JobMessage, error_message: str = None) -> bool:
        """
        Retry a failed job with exponential backoff.
        
        Args:
            job_message: Failed job message
            error_message: Error description
            
        Returns:
            True if job scheduled for retry, False if max retries exceeded
        """
        try:
            job_message.retry_count += 1
            
            if job_message.retry_count > job_message.max_retries:
                logger.warning(f"Job {job_message.job_id} exceeded max retries, moving to dead letter queue")
                self._move_to_dead_letter(job_message, f"Max retries exceeded: {error_message}")
                return False
            
            # Calculate exponential backoff delay
            delay_seconds = min(
                self.retry_delay_base * (2 ** (job_message.retry_count - 1)),
                self.max_retry_delay
            )
            
            # Add jitter to prevent thundering herd
            import random
            jitter = random.uniform(0.1, 0.3) * delay_seconds
            total_delay = delay_seconds + jitter
            
            # Schedule for retry
            retry_data = job_message.to_dict()
            retry_data['retry_scheduled_at'] = time.time() + total_delay
            retry_data['retry_reason'] = error_message
            
            # Use timestamp as priority for delayed execution
            priority_score = time.time() + total_delay
            
            success = self.queue_manager.enqueue(QueueNames.RETRY, retry_data, priority_score)
            
            if success:
                logger.info(f"Scheduled job {job_message.job_id} for retry #{job_message.retry_count} "
                          f"in {total_delay:.1f} seconds")
                self._update_queue_stats(QueueNames.RETRY, 'scheduled')
            
            return success
            
        except Exception as e:
            logger.error(f"Error scheduling job retry: {e}")
            return False
    
    async def async_retry_job(self, job_message: JobMessage, error_message: str = None) -> bool:
        """Async version of retry_job"""
        try:
            job_message.retry_count += 1
            
            if job_message.retry_count > job_message.max_retries:
                await self._async_move_to_dead_letter(job_message, f"Max retries exceeded: {error_message}")
                return False
            
            delay_seconds = min(
                self.retry_delay_base * (2 ** (job_message.retry_count - 1)),
                self.max_retry_delay
            )
            
            import random
            jitter = random.uniform(0.1, 0.3) * delay_seconds
            total_delay = delay_seconds + jitter
            
            retry_data = job_message.to_dict()
            retry_data['retry_scheduled_at'] = time.time() + total_delay
            retry_data['retry_reason'] = error_message
            
            priority_score = time.time() + total_delay
            
            success = await self.queue_manager.async_enqueue(QueueNames.RETRY, retry_data, priority_score)
            
            if success:
                logger.info(f"Async scheduled job {job_message.job_id} for retry #{job_message.retry_count}")
                self._update_queue_stats(QueueNames.RETRY, 'scheduled')
            
            return success
            
        except Exception as e:
            logger.error(f"Error async scheduling job retry: {e}")
            return False
    
    def process_retry_queue(self) -> List[JobMessage]:
        """
        Process the retry queue and requeue jobs that are ready.
        
        Returns:
            List of jobs that were requeued
        """
        requeued_jobs = []
        current_time = time.time()
        
        try:
            # Check for jobs ready to retry
            retry_queue_length = self.queue_manager.queue_length(QueueNames.RETRY)
            
            for _ in range(retry_queue_length):
                job_data = self.queue_manager.dequeue(QueueNames.RETRY, timeout=0)
                if not job_data:
                    break
                
                retry_time = job_data.get('retry_scheduled_at', 0)
                
                if current_time >= retry_time:
                    # Time to retry
                    job_message = JobMessage.from_dict(job_data)
                    
                    # Determine target queue based on job type
                    target_queue = self._get_target_queue(job_message.job_type)
                    
                    if self.enqueue_job(target_queue, job_message):
                        requeued_jobs.append(job_message)
                        logger.info(f"Requeued job {job_message.job_id} for retry #{job_message.retry_count}")
                    else:
                        # Failed to requeue, put back in retry queue
                        self.queue_manager.enqueue(QueueNames.RETRY, job_data, retry_time)
                else:
                    # Not ready yet, put back
                    self.queue_manager.enqueue(QueueNames.RETRY, job_data, retry_time)
            
        except Exception as e:
            logger.error(f"Error processing retry queue: {e}")
        
        return requeued_jobs
    
    def _move_to_dead_letter(self, job_message: JobMessage, reason: str) -> None:
        """Move job to dead letter queue"""
        try:
            dead_letter_data = job_message.to_dict()
            dead_letter_data['dead_letter_reason'] = reason
            dead_letter_data['dead_letter_timestamp'] = time.time()
            
            self.queue_manager.enqueue(QueueNames.DEAD_LETTER, dead_letter_data, time.time())
            self._update_queue_stats(QueueNames.DEAD_LETTER, 'moved')
            
            logger.warning(f"Moved job {job_message.job_id} to dead letter queue: {reason}")
            
        except Exception as e:
            logger.error(f"Error moving job to dead letter queue: {e}")
    
    async def _async_move_to_dead_letter(self, job_message: JobMessage, reason: str) -> None:
        """Async version of _move_to_dead_letter"""
        try:
            dead_letter_data = job_message.to_dict()
            dead_letter_data['dead_letter_reason'] = reason
            dead_letter_data['dead_letter_timestamp'] = time.time()
            
            await self.queue_manager.async_enqueue(QueueNames.DEAD_LETTER, dead_letter_data, time.time())
            self._update_queue_stats(QueueNames.DEAD_LETTER, 'moved')
            
        except Exception as e:
            logger.error(f"Error async moving job to dead letter queue: {e}")
    
    def _get_target_queue(self, job_type: str) -> str:
        """Get target queue name for job type"""
        queue_mapping = {
            'email_scan': QueueNames.EMAIL_SCAN,
            'sandbox_analysis': QueueNames.SANDBOX_ANALYSIS,
            'api_analysis': QueueNames.API_ANALYSIS,
            'threat_scoring': QueueNames.THREAT_SCORING,
            'aggregation': QueueNames.AGGREGATION
        }
        return queue_mapping.get(job_type, QueueNames.EMAIL_SCAN)
    
    def _update_queue_stats(self, queue_name: str, operation: str) -> None:
        """Update queue statistics"""
        current_time = time.time()
        
        if queue_name not in self._queue_stats:
            self._queue_stats[queue_name] = {
                'enqueued': 0,
                'dequeued': 0,
                'scheduled': 0,
                'moved': 0,
                'last_activity': current_time
            }
        
        self._queue_stats[queue_name][operation] += 1
        self._queue_stats[queue_name]['last_activity'] = current_time
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics and health metrics"""
        stats = {
            'queues': {},
            'total_pending': 0,
            'retry_queue_size': 0,
            'dead_letter_size': 0,
            'last_updated': time.time()
        }
        
        # Get queue lengths
        standard_queues = [
            QueueNames.EMAIL_SCAN,
            QueueNames.SANDBOX_ANALYSIS,
            QueueNames.API_ANALYSIS,
            QueueNames.THREAT_SCORING,
            QueueNames.AGGREGATION,
            QueueNames.HIGH_PRIORITY
        ]
        
        for queue_name in standard_queues:
            length = self.queue_manager.queue_length(queue_name)
            stats['queues'][queue_name] = {
                'length': length,
                'stats': self._queue_stats.get(queue_name, {})
            }
            stats['total_pending'] += length
        
        stats['retry_queue_size'] = self.queue_manager.queue_length(QueueNames.RETRY)
        stats['dead_letter_size'] = self.queue_manager.queue_length(QueueNames.DEAD_LETTER)
        
        return stats
    
    def clear_queue(self, queue_name: str) -> bool:
        """Clear all jobs from a queue (use with caution)"""
        try:
            success = self.queue_manager.clear_queue(queue_name)
            if success:
                logger.warning(f"Cleared queue {queue_name}")
            return success
        except Exception as e:
            logger.error(f"Error clearing queue {queue_name}: {e}")
            return False

# Helper functions for common queue operations
def create_email_scan_job_message(email_id: str, user_id: str, request_id: str = None,
                                priority: JobPriority = JobPriority.NORMAL,
                                timeout_seconds: int = 300) -> JobMessage:
    """Create a standardized email scan job message"""
    return JobMessage(
        job_id=str(uuid.uuid4()),
        job_type="email_scan",
        payload={
            "email_id": email_id,
            "user_id": user_id,
            "request_id": request_id or str(uuid.uuid4())
        },
        created_at=time.time(),
        priority=priority,
        timeout_seconds=timeout_seconds,
        worker_type=WorkerType.ORCHESTRATOR
    )

def create_sandbox_job_message(url: str, job_id: str = None,
                             priority: JobPriority = JobPriority.NORMAL) -> JobMessage:
    """Create a sandbox analysis job message"""
    return JobMessage(
        job_id=job_id or str(uuid.uuid4()),
        job_type="sandbox_analysis",
        payload={"url": url},
        created_at=time.time(),
        priority=priority,
        worker_type=WorkerType.SANDBOX
    )

def create_api_analysis_job_message(resource: str, resource_type: str, 
                                  apis: List[str], job_id: str = None,
                                  priority: JobPriority = JobPriority.NORMAL) -> JobMessage:
    """Create an API analysis job message"""
    return JobMessage(
        job_id=job_id or str(uuid.uuid4()),
        job_type="api_analysis",
        payload={
            "resource": resource,
            "resource_type": resource_type,
            "apis": apis
        },
        created_at=time.time(),
        priority=priority,
        worker_type=WorkerType.ANALYZER
    )

# Global queue manager instance
job_queue_manager = JobQueueManager()

def get_job_queue_manager() -> JobQueueManager:
    """Get global job queue manager instance"""
    return job_queue_manager
