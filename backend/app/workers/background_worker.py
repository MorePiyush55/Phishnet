"""
Background worker system for email scanning
Implements async task queue with Celery-like functionality using Redis
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

from app.db.mongodb import MongoDBManager
from app.models.mongodb_models import User, EmailAnalysis, AuditLog
from app.core.redis_client import get_redis_client
from app.services.gmail_operations import GmailOperationsService
from app.config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class TaskPriority(Enum):
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"

class TaskStatus(Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"

@dataclass
class ScanTask:
    """Email scan task definition."""
    user_id: int
    message_ids: List[str]
    priority: TaskPriority
    created_at: datetime
    attempts: int = 0
    max_attempts: int = 3
    status: TaskStatus = TaskStatus.QUEUED
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class BackgroundWorker:
    """Background worker for processing email scan tasks."""
    
    def __init__(self, worker_id: str = None):
        self.worker_id = worker_id or f"worker_{int(time.time())}"
        self.redis_client = get_redis_client()
        self.gmail_service = GmailOperationsService()
        self.running = False
        
        # Database setup for worker
        engine = create_engine(get_database_url())
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        
        # Queue configuration
        self.queues = {
            TaskPriority.HIGH: "scan_queue_high",
            TaskPriority.NORMAL: "scan_queue_normal", 
            TaskPriority.LOW: "scan_queue_low"
        }
        
        # Worker configuration
        self.batch_size = getattr(settings, 'WORKER_BATCH_SIZE', 5)
        self.poll_interval = getattr(settings, 'WORKER_POLL_INTERVAL', 5)  # seconds
        self.max_processing_time = getattr(settings, 'WORKER_MAX_PROCESSING_TIME', 300)  # 5 minutes

    async def start(self):
        """Start the background worker."""
        
        self.running = True
        logger.info(f"Starting background worker {self.worker_id}")
        
        # Register worker
        await self._register_worker()
        
        try:
            while self.running:
                await self._process_tasks()
                await asyncio.sleep(self.poll_interval)
        except KeyboardInterrupt:
            logger.info(f"Worker {self.worker_id} interrupted")
        finally:
            await self._cleanup_worker()

    async def stop(self):
        """Stop the background worker."""
        self.running = False
        logger.info(f"Stopping worker {self.worker_id}")

    async def _process_tasks(self):
        """Process tasks from queues by priority."""
        
        # Process queues in priority order
        for priority in [TaskPriority.HIGH, TaskPriority.NORMAL, TaskPriority.LOW]:
            queue_name = self.queues[priority]
            
            # Get tasks from queue
            tasks = await self._get_tasks_from_queue(queue_name)
            
            if tasks:
                logger.info(f"Worker {self.worker_id} processing {len(tasks)} {priority.value} priority tasks")
                
                for task_data in tasks:
                    if not self.running:
                        break
                    
                    try:
                        task = self._deserialize_task(task_data)
                        await self._process_single_task(task)
                    except Exception as e:
                        logger.error(f"Failed to process task: {e}")

    async def _get_tasks_from_queue(self, queue_name: str) -> List[str]:
        """Get tasks from Redis queue."""
        
        tasks = []
        for _ in range(self.batch_size):
            task_data = await self.redis_client.rpop(queue_name)
            if not task_data:
                break
            tasks.append(task_data)
        
        return tasks

    async def _process_single_task(self, task: ScanTask):
        """Process a single email scan task."""
        
        db = self.SessionLocal()
        start_time = datetime.utcnow()
        
        try:
            # Update task status
            task.status = TaskStatus.PROCESSING
            task.attempts += 1
            
            # Store processing status
            await self._update_task_status(task)
            
            # Process each message
            scan_results = []
            for message_id in task.message_ids:
                try:
                    result = await self._scan_single_message(db, task.user_id, message_id)
                    scan_results.append(result)
                except Exception as e:
                    logger.error(f"Failed to scan message {message_id}: {e}")
                    scan_results.append({
                        "message_id": message_id,
                        "status": "error",
                        "error": str(e)
                    })
            
            # Update task completion
            task.status = TaskStatus.COMPLETED
            task.metadata = {
                "scan_results": scan_results,
                "processing_time_ms": int((datetime.utcnow() - start_time).total_seconds() * 1000),
                "worker_id": self.worker_id
            }
            
            await self._update_task_status(task)
            
            # Audit log
            await self._log_audit_event(
                db=db,
                user_id=task.user_id,
                action="background_scan_completed",
                success=True,
                metadata={
                    "message_count": len(task.message_ids),
                    "results_summary": self._summarize_scan_results(scan_results),
                    "worker_id": self.worker_id
                }
            )
            
            logger.info(f"Completed scan task for user {task.user_id}: {len(scan_results)} messages")
            
        except Exception as e:
            # Handle task failure
            task.status = TaskStatus.FAILED
            task.error_message = str(e)
            
            # Retry logic
            if task.attempts < task.max_attempts:
                task.status = TaskStatus.RETRYING
                # Re-queue with exponential backoff
                delay = min(300, 2 ** task.attempts * 10)  # Max 5 minutes
                await self._requeue_task_with_delay(task, delay)
            
            await self._update_task_status(task)
            
            # Audit log failure
            await self._log_audit_event(
                db=db,
                user_id=task.user_id,
                action="background_scan_failed",
                success=False,
                error_message=str(e),
                metadata={
                    "attempts": task.attempts,
                    "max_attempts": task.max_attempts,
                    "worker_id": self.worker_id
                }
            )
            
            logger.error(f"Failed to process scan task for user {task.user_id}: {e}")
            
        finally:
            db.close()

    async def _scan_single_message(
        self,
        db: Session,
        user_id: int,
        message_id: str
    ) -> Dict[str, Any]:
        """Scan a single email message for phishing threats."""
        
        start_time = datetime.utcnow()
        
        try:
            # Fetch email content
            email_data = await self.gmail_service.fetch_email_content(
                db=db,
                user_id=user_id,
                message_id=message_id,
                format="raw"
            )
            
            # Extract email metadata
            parsed_content = email_data.get("parsed_content", {})
            subject = parsed_content.get("subject", "")
            sender = parsed_content.get("from", "")
            body = parsed_content.get("body", "")
            
            # TODO: Integrate with actual phishing detection orchestrator
            # For now, implement a simple scoring system
            verdict, score, details = await self._mock_phishing_analysis(
                subject=subject,
                sender=sender,
                body=body,
                raw_content=email_data.get("raw_content", "")
            )
            
            # Store scan result
            scan_result = ScanResult(
                user_id=user_id,
                msg_id=message_id,
                thread_id=email_data.get("thread_id"),
                verdict=verdict,
                score=score,
                details=details,
                sender=sender,
                subject=subject,
                received_at=datetime.utcnow(),  # TODO: Parse actual receive date
                scan_duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000),
                model_version="mock_v1.0"  # TODO: Use actual model version
            )
            
            db.add(scan_result)
            db.commit()
            
            # Auto-quarantine if phishing detected
            if verdict in ["phishing", "malicious"] and score > 0.8:
                quarantined = await self.gmail_service.quarantine_email(
                    db=db,
                    user_id=user_id,
                    message_id=message_id
                )
                details["auto_quarantined"] = quarantined
            
            return {
                "message_id": message_id,
                "status": "completed",
                "verdict": verdict,
                "score": score,
                "quarantined": details.get("auto_quarantined", False)
            }
            
        except Exception as e:
            logger.error(f"Failed to scan message {message_id} for user {user_id}: {e}")
            return {
                "message_id": message_id,
                "status": "error",
                "error": str(e)
            }

    async def _mock_phishing_analysis(
        self,
        subject: str,
        sender: str,
        body: str,
        raw_content: str
    ) -> tuple[str, float, Dict[str, Any]]:
        """
        Mock phishing analysis - replace with actual orchestrator integration.
        
        Returns: (verdict, score, details)
        """
        
        # Simple keyword-based detection for demo
        phishing_keywords = [
            "urgent", "verify account", "suspended", "click here",
            "limited time", "act now", "confirm identity", "security alert"
        ]
        
        suspicious_domains = [
            "suspicious-bank.com", "phishing-site.org", "fake-paypal.net"
        ]
        
        score = 0.0
        details = {
            "keywords_found": [],
            "suspicious_sender": False,
            "url_analysis": {},
            "attachment_analysis": {},
            "header_analysis": {}
        }
        
        # Keyword analysis
        content_text = f"{subject} {body}".lower()
        for keyword in phishing_keywords:
            if keyword in content_text:
                details["keywords_found"].append(keyword)
                score += 0.1
        
        # Sender analysis
        sender_lower = sender.lower()
        for domain in suspicious_domains:
            if domain in sender_lower:
                details["suspicious_sender"] = True
                score += 0.3
                break
        
        # URL analysis (simplified)
        if "http" in body.lower():
            details["url_analysis"]["urls_found"] = True
            score += 0.2
        
        # Determine verdict based on score
        if score >= 0.8:
            verdict = "phishing"
        elif score >= 0.5:
            verdict = "suspicious"
        elif score >= 0.2:
            verdict = "questionable"
        else:
            verdict = "safe"
        
        return verdict, min(score, 1.0), details

    def _summarize_scan_results(self, scan_results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Summarize scan results for audit logging."""
        
        summary = {
            "total": len(scan_results),
            "safe": 0,
            "suspicious": 0,
            "phishing": 0,
            "malicious": 0,
            "errors": 0,
            "quarantined": 0
        }
        
        for result in scan_results:
            if result.get("status") == "error":
                summary["errors"] += 1
            else:
                verdict = result.get("verdict", "safe")
                summary[verdict] = summary.get(verdict, 0) + 1
                
                if result.get("quarantined"):
                    summary["quarantined"] += 1
        
        return summary

    def _deserialize_task(self, task_data: str) -> ScanTask:
        """Deserialize task from JSON string."""
        
        data = json.loads(task_data)
        return ScanTask(
            user_id=data["user_id"],
            message_ids=data["message_ids"],
            priority=TaskPriority(data.get("priority", "normal")),
            created_at=datetime.fromisoformat(data["created_at"]),
            attempts=data.get("attempts", 0),
            max_attempts=data.get("max_attempts", 3),
            status=TaskStatus(data.get("status", "queued")),
            error_message=data.get("error_message"),
            metadata=data.get("metadata")
        )

    async def _update_task_status(self, task: ScanTask):
        """Update task status in Redis."""
        
        task_data = {
            "user_id": task.user_id,
            "message_ids": task.message_ids,
            "priority": task.priority.value,
            "created_at": task.created_at.isoformat(),
            "attempts": task.attempts,
            "max_attempts": task.max_attempts,
            "status": task.status.value,
            "error_message": task.error_message,
            "metadata": task.metadata
        }
        
        # Store task status with TTL
        job_id = f"scan_{task.user_id}_{int(task.created_at.timestamp())}"
        await self.redis_client.setex(
            f"scan_job:{job_id}",
            3600,  # 1 hour TTL
            json.dumps(task_data, default=str)
        )

    async def _requeue_task_with_delay(self, task: ScanTask, delay_seconds: int):
        """Re-queue failed task with delay."""
        
        # Store task for delayed processing
        delayed_task_data = {
            "user_id": task.user_id,
            "message_ids": task.message_ids,
            "priority": task.priority.value,
            "created_at": task.created_at.isoformat(),
            "attempts": task.attempts,
            "max_attempts": task.max_attempts,
            "status": task.status.value,
            "error_message": task.error_message,
            "metadata": task.metadata,
            "retry_at": (datetime.utcnow() + timedelta(seconds=delay_seconds)).isoformat()
        }
        
        await self.redis_client.zadd(
            "delayed_tasks",
            {json.dumps(delayed_task_data, default=str): time.time() + delay_seconds}
        )

    async def _register_worker(self):
        """Register worker in Redis."""
        
        worker_data = {
            "worker_id": self.worker_id,
            "started_at": datetime.utcnow().isoformat(),
            "status": "running",
            "processed_tasks": 0
        }
        
        await self.redis_client.hset(
            "workers",
            self.worker_id,
            json.dumps(worker_data, default=str)
        )

    async def _cleanup_worker(self):
        """Clean up worker registration."""
        
        await self.redis_client.hdel("workers", self.worker_id)
        logger.info(f"Worker {self.worker_id} cleaned up")

    async def _log_audit_event(
        self,
        db: Session,
        user_id: int,
        action: str,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Log audit event."""
        
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            actor="worker",
            success=success,
            metadata=metadata,
            error_message=error_message
        )
        
        db.add(audit_log)
        db.commit()


class WorkerManager:
    """Manager for background workers."""
    
    def __init__(self):
        self.workers: List[BackgroundWorker] = []
        self.redis_client = get_redis_client()

    async def start_workers(self, num_workers: int = 2):
        """Start multiple background workers."""
        
        logger.info(f"Starting {num_workers} background workers")
        
        for i in range(num_workers):
            worker = BackgroundWorker(f"worker_{i}")
            self.workers.append(worker)
            
            # Start worker in background
            asyncio.create_task(worker.start())

    async def stop_all_workers(self):
        """Stop all workers."""
        
        logger.info("Stopping all workers")
        
        for worker in self.workers:
            await worker.stop()

    async def get_worker_status(self) -> Dict[str, Any]:
        """Get status of all workers."""
        
        workers_data = await self.redis_client.hgetall("workers")
        
        status = {
            "total_workers": len(workers_data),
            "workers": {}
        }
        
        for worker_id, worker_data_str in workers_data.items():
            worker_data = json.loads(worker_data_str)
            status["workers"][worker_id] = worker_data
        
        return status

    async def get_queue_status(self) -> Dict[str, Any]:
        """Get status of task queues."""
        
        queue_status = {}
        
        for priority, queue_name in {
            "high": "scan_queue_high",
            "normal": "scan_queue_normal",
            "low": "scan_queue_low"
        }.items():
            queue_length = await self.redis_client.llen(queue_name)
            queue_status[priority] = {
                "queue_name": queue_name,
                "pending_tasks": queue_length
            }
        
        # Get delayed tasks
        delayed_count = await self.redis_client.zcard("delayed_tasks")
        queue_status["delayed"] = {
            "pending_tasks": delayed_count
        }
        
        return queue_status


# Global worker manager
worker_manager = WorkerManager()


# CLI script for running workers
if __name__ == "__main__":
    import sys
    
    async def main():
        if len(sys.argv) > 1 and sys.argv[1] == "start":
            num_workers = int(sys.argv[2]) if len(sys.argv) > 2 else 2
            await worker_manager.start_workers(num_workers)
            
            try:
                # Keep running
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                await worker_manager.stop_all_workers()
        else:
            print("Usage: python background_worker.py start [num_workers]")
    
    asyncio.run(main())
