"""Email processing worker for handling Gmail message analysis."""

import json
import asyncio
import uuid
import signal
import os
from datetime import datetime
from typing import Dict, Any, Optional
import traceback

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db
from app.core.redis_client import redis_client
from app.models.email_scan import EmailScanRequest, ScanStatus, AuditLog
from app.services.gmail_secure import gmail_service
from app.orchestrator.threat_orchestrator import ThreatOrchestrator
from app.core.metrics import worker_metrics
from app.workers.health import get_health_checker, run_worker_health_server

logger = get_logger(__name__)


class EmailProcessor:
    """Worker for processing Gmail email scan requests."""
    
    def __init__(self, worker_id: Optional[str] = None):
        """Initialize email processor."""
        self.worker_id = worker_id or f"email_worker_{uuid.uuid4().hex[:8]}"
        self.threat_orchestrator = ThreatOrchestrator()
        self.running = False
        self.processed_count = 0
        self.error_count = 0
        
        # Health monitoring integration
        self.health_checker = get_health_checker("email_processing")
        self.health_server_task = None
        self.current_job_id = None
    
    async def start(self):
        """Start the email processing worker."""
        self.running = True
        logger.info(f"Starting email processor {self.worker_id}")
        
        # Start health server
        health_port = int(os.getenv("HEALTH_PORT", "8001"))
        self.health_server_task = asyncio.create_task(
            run_worker_health_server("email_processing", health_port)
        )
        
        # Setup signal handlers for graceful shutdown
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            asyncio.create_task(self.graceful_shutdown())
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            while self.running and not self.health_checker.should_stop():
                await self._process_batch()
                await asyncio.sleep(1)  # Brief pause between batches
        except KeyboardInterrupt:
            logger.info(f"Email processor {self.worker_id} interrupted")
            await self.graceful_shutdown()
        except Exception as e:
            logger.error(f"Email processor {self.worker_id} crashed: {e}")
            logger.error(traceback.format_exc())
        finally:
            await self._cleanup()
    
    async def graceful_shutdown(self):
        """Perform graceful shutdown of the worker."""
        logger.info(f"Starting graceful shutdown for {self.worker_id}")
        
        # Stop accepting new jobs
        self.health_checker.set_stopping()
        
        # Wait for current job to complete
        if self.current_job_id:
            logger.info(f"Waiting for current job {self.current_job_id} to complete...")
            timeout = 30  # 30 second timeout
            start_time = asyncio.get_event_loop().time()
            
            while self.current_job_id and (asyncio.get_event_loop().time() - start_time) < timeout:
                await asyncio.sleep(1)
            
            if self.current_job_id:
                logger.warning(f"Job {self.current_job_id} did not complete within timeout")
        
        # Stop worker
        self.running = False
        
        # Cancel health server
        if self.health_server_task:
            self.health_server_task.cancel()
        
        logger.info(f"Graceful shutdown completed for {self.worker_id}")
    
    async def stop(self):
        """Stop the email processing worker."""
        self.running = False
        logger.info(f"Stopping email processor {self.worker_id}")
    
    async def _process_batch(self):
        """Process a batch of email jobs from the queue."""
        try:
            # Get jobs from Redis queue (blocking pop with timeout)
            job_data = await redis_client.brpop("email_processing_queue", timeout=5)
            
            if not job_data:
                return  # No jobs available
            
            queue_name, job_json = job_data
            job = json.loads(job_json.decode())
            
            await self._process_email_job(job)
            
        except Exception as e:
            logger.error(f"Batch processing error in {self.worker_id}: {e}")
            self.error_count += 1
    
    async def _process_email_job(self, job: Dict[str, Any]):
        """Process individual email scan job."""
        scan_request_id = job.get("scan_request_id")
        user_id = job.get("user_id")
        gmail_message_id = job.get("gmail_message_id")
        
        if not all([scan_request_id, user_id, gmail_message_id]):
            logger.error(f"Invalid job data: {job}")
            return
        
        # Mark current job for health tracking
        self.current_job_id = scan_request_id
        
        start_time = datetime.utcnow()
        logger.info(f"Processing email job {scan_request_id} for user {user_id}")
        
        try:
            # Update scan request status
            async with get_db() as db:
                scan_request = db.query(EmailScanRequest).filter(
                    EmailScanRequest.id == scan_request_id
                ).first()
                
                if not scan_request:
                    logger.error(f"Scan request {scan_request_id} not found")
                    self.current_job_id = None
                    return
                
                if scan_request.status != ScanStatus.PENDING:
                    logger.info(f"Scan request {scan_request_id} already processed (status: {scan_request.status})")
                    self.current_job_id = None
                    return
                
                # Mark as processing
                scan_request.status = ScanStatus.PROCESSING
                scan_request.started_at = start_time
                scan_request.worker_id = self.worker_id
                db.commit()
            
            # Fetch email content from Gmail
            email_content = await gmail_service.fetch_email_content(user_id, gmail_message_id)
            
            if not email_content:
                await self._handle_processing_error(
                    scan_request_id,
                    "Failed to fetch email content from Gmail"
                )
                return
            
            # Queue for threat analysis
            await self._queue_for_threat_analysis(scan_request_id, email_content)
            
            # Update metrics and health tracking
            worker_metrics.emails_processed.inc()
            self.processed_count += 1
            self.health_checker.mark_job_processed()
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"Email job {scan_request_id} queued for analysis in {duration:.2f}s")
            
        except Exception as e:
            error_msg = f"Email processing failed: {str(e)}"
            logger.error(f"Error processing {scan_request_id}: {error_msg}")
            logger.error(traceback.format_exc())
            
            await self._handle_processing_error(scan_request_id, error_msg)
            self.error_count += 1
            worker_metrics.processing_errors.inc()
        
        finally:
            # Clear current job tracking
            self.current_job_id = None
    
    async def _queue_for_threat_analysis(
        self, 
        scan_request_id: str, 
        email_content: Dict[str, Any]
    ):
        """Queue email for threat analysis."""
        try:
            # Create analysis job
            analysis_job = {
                "scan_request_id": scan_request_id,
                "email_content": email_content,
                "analysis_id": f"analysis_{uuid.uuid4().hex}",
                "queued_at": datetime.utcnow().isoformat(),
                "priority": 5  # Default priority
            }
            
            # Add to threat analysis queue
            await redis_client.lpush("threat_analysis_queue", json.dumps(analysis_job))
            
            logger.info(f"Queued scan {scan_request_id} for threat analysis")
            
        except Exception as e:
            logger.error(f"Failed to queue threat analysis for {scan_request_id}: {e}")
            raise
    
    async def _handle_processing_error(self, scan_request_id: str, error_message: str):
        """Handle processing error and update scan request."""
        try:
            async with get_db() as db:
                scan_request = db.query(EmailScanRequest).filter(
                    EmailScanRequest.id == scan_request_id
                ).first()
                
                if scan_request:
                    scan_request.status = ScanStatus.FAILED
                    scan_request.completed_at = datetime.utcnow()
                    scan_request.error_message = error_message
                    scan_request.retry_count += 1
                    
                    # Check if we should retry
                    if scan_request.retry_count < 3:
                        # Requeue with exponential backoff
                        retry_delay = 2 ** scan_request.retry_count  # 2, 4, 8 seconds
                        
                        retry_job = {
                            "scan_request_id": str(scan_request.id),
                            "user_id": scan_request.user_id,
                            "gmail_message_id": scan_request.gmail_message_id,
                            "retry": True,
                            "retry_count": scan_request.retry_count,
                            "delay": retry_delay
                        }
                        
                        # Add to delayed queue (you'd need to implement this)
                        await redis_client.zadd(
                            "email_retry_queue",
                            {json.dumps(retry_job): datetime.utcnow().timestamp() + retry_delay}
                        )
                        
                        scan_request.status = ScanStatus.PENDING
                        logger.info(f"Scheduled retry {scan_request.retry_count} for {scan_request_id} in {retry_delay}s")
                    
                    # Log audit event
                    audit = AuditLog(
                        user_id=scan_request.user_id,
                        scan_request_id=scan_request.id,
                        action="email_processing_failed",
                        resource_type="email",
                        resource_id=scan_request.gmail_message_id,
                        success=False,
                        error_message=error_message,
                        details={
                            "worker_id": self.worker_id,
                            "retry_count": scan_request.retry_count,
                            "will_retry": scan_request.retry_count < 3
                        }
                    )
                    db.add(audit)
                    
                    db.commit()
                    
        except Exception as e:
            logger.error(f"Failed to handle processing error for {scan_request_id}: {e}")
    
    async def _cleanup(self):
        """Cleanup worker resources."""
        logger.info(f"Email processor {self.worker_id} cleanup - processed: {self.processed_count}, errors: {self.error_count}")
        
        # Update any in-progress jobs to failed state
        try:
            async with get_db() as db:
                in_progress_scans = db.query(EmailScanRequest).filter(
                    EmailScanRequest.worker_id == self.worker_id,
                    EmailScanRequest.status == ScanStatus.PROCESSING
                ).all()
                
                for scan in in_progress_scans:
                    scan.status = ScanStatus.FAILED
                    scan.completed_at = datetime.utcnow()
                    scan.error_message = "Worker shutdown during processing"
                
                if in_progress_scans:
                    db.commit()
                    logger.info(f"Marked {len(in_progress_scans)} in-progress scans as failed")
                    
        except Exception as e:
            logger.error(f"Cleanup error for {self.worker_id}: {e}")


async def process_retry_queue():
    """Process retry queue for failed emails."""
    while True:
        try:
            # Get jobs that are ready for retry
            current_time = datetime.utcnow().timestamp()
            ready_jobs = await redis_client.zrangebyscore(
                "email_retry_queue",
                "-inf",
                current_time,
                withscores=True,
                start=0,
                num=10
            )
            
            for job_data, score in ready_jobs:
                try:
                    job = json.loads(job_data.decode())
                    
                    # Remove from retry queue
                    await redis_client.zrem("email_retry_queue", job_data)
                    
                    # Add back to main processing queue
                    await redis_client.lpush("email_processing_queue", job_data)
                    
                    logger.info(f"Retried job {job.get('scan_request_id')}")
                    
                except Exception as e:
                    logger.error(f"Failed to process retry job: {e}")
            
            # Sleep before next check
            await asyncio.sleep(5)
            
        except Exception as e:
            logger.error(f"Retry queue processing error: {e}")
            await asyncio.sleep(10)


async def main():
    """Main worker entry point."""
    # Create worker instances based on concurrency setting
    concurrency = int(settings.WORKER_CONCURRENCY or 4)
    
    # Create workers
    workers = []
    for i in range(concurrency):
        worker = EmailProcessor(f"email_worker_{i+1}")
        workers.append(worker)
    
    # Start retry queue processor
    retry_processor = asyncio.create_task(process_retry_queue())
    
    try:
        # Start all workers
        worker_tasks = [asyncio.create_task(worker.start()) for worker in workers]
        
        logger.info(f"Started {len(workers)} email processing workers")
        
        # Wait for all workers
        await asyncio.gather(*worker_tasks)
        
    except KeyboardInterrupt:
        logger.info("Shutting down email processors...")
        
        # Stop all workers
        for worker in workers:
            await worker.stop()
        
        # Cancel retry processor
        retry_processor.cancel()
        
        logger.info("Email processors shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
