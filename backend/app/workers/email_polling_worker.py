"""
Background Email Polling Worker
================================
Continuously polls the IMAP inbox for new forwarded emails
and processes them through the on-demand analysis pipeline.

Features:
- Configurable polling interval (default: 30 seconds)
- Graceful shutdown handling
- Error recovery and retry logic
- Rate limiting to prevent overload
- Metrics tracking
"""

import asyncio
import signal
import time
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

from app.config.logging import get_logger
from app.config.settings import get_settings
from app.services.ondemand_orchestrator import get_ondemand_orchestrator, AnalysisJob

logger = get_logger(__name__)
settings = get_settings()


class WorkerState(str, Enum):
    """Worker lifecycle states"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class WorkerMetrics:
    """Tracks worker performance metrics"""
    started_at: Optional[datetime] = None
    last_poll_at: Optional[datetime] = None
    total_polls: int = 0
    total_emails_processed: int = 0
    total_errors: int = 0
    consecutive_errors: int = 0
    
    # Verdict breakdown
    phishing_count: int = 0
    suspicious_count: int = 0
    safe_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "last_poll_at": self.last_poll_at.isoformat() if self.last_poll_at else None,
            "total_polls": self.total_polls,
            "total_emails_processed": self.total_emails_processed,
            "total_errors": self.total_errors,
            "consecutive_errors": self.consecutive_errors,
            "verdicts": {
                "phishing": self.phishing_count,
                "suspicious": self.suspicious_count,
                "safe": self.safe_count
            }
        }


class EmailPollingWorker:
    """
    Background worker that polls IMAP inbox and processes emails.
    
    Usage:
        worker = EmailPollingWorker()
        await worker.start()  # Runs until stopped
        
        # Or run a single poll cycle:
        await worker.poll_once()
    """
    
    # Configuration
    DEFAULT_POLL_INTERVAL = 30  # seconds
    MIN_POLL_INTERVAL = 10  # seconds
    MAX_POLL_INTERVAL = 300  # seconds
    
    # Error handling
    MAX_CONSECUTIVE_ERRORS = 5
    ERROR_BACKOFF_MULTIPLIER = 2
    MAX_ERROR_BACKOFF = 300  # 5 minutes max backoff
    
    def __init__(
        self,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
        auto_start: bool = False
    ):
        """
        Initialize the email polling worker.
        
        Args:
            poll_interval: Seconds between poll cycles
            auto_start: Whether to start polling immediately
        """
        self.poll_interval = max(
            self.MIN_POLL_INTERVAL,
            min(poll_interval, self.MAX_POLL_INTERVAL)
        )
        
        self._state = WorkerState.STOPPED
        self._stop_event = asyncio.Event()
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # Not paused by default
        
        self.metrics = WorkerMetrics()
        self._current_backoff = 0
        
        # Get orchestrator
        self._orchestrator = get_ondemand_orchestrator()
        
        logger.info(f"EmailPollingWorker initialized with {self.poll_interval}s interval")
    
    @property
    def state(self) -> WorkerState:
        """Current worker state"""
        return self._state
    
    @property
    def is_running(self) -> bool:
        """Check if worker is actively running"""
        return self._state == WorkerState.RUNNING
    
    async def start(self) -> None:
        """
        Start the background polling loop.
        
        This runs indefinitely until stop() is called.
        """
        if self._state == WorkerState.RUNNING:
            logger.warning("Worker is already running")
            return
        
        self._state = WorkerState.STARTING
        self._stop_event.clear()
        self.metrics.started_at = datetime.utcnow()
        
        logger.info("Starting email polling worker...")
        self._state = WorkerState.RUNNING
        
        try:
            while not self._stop_event.is_set():
                # Wait if paused
                await self._pause_event.wait()
                
                # Check for stop signal
                if self._stop_event.is_set():
                    break
                
                # Execute poll cycle
                try:
                    await self._poll_cycle()
                    self._reset_backoff()
                    
                except Exception as e:
                    await self._handle_error(e)
                
                # Wait for next cycle (interruptible)
                wait_time = self.poll_interval + self._current_backoff
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=wait_time
                    )
                except asyncio.TimeoutError:
                    pass  # Normal timeout, continue polling
                    
        except asyncio.CancelledError:
            logger.info("Worker cancelled")
        finally:
            self._state = WorkerState.STOPPED
            logger.info("Email polling worker stopped")
    
    async def stop(self, timeout: float = 10.0) -> None:
        """
        Stop the polling worker gracefully.
        
        Args:
            timeout: Maximum seconds to wait for graceful shutdown
        """
        if self._state == WorkerState.STOPPED:
            return
        
        logger.info("Stopping email polling worker...")
        self._state = WorkerState.STOPPING
        self._stop_event.set()
        self._pause_event.set()  # Unpause if paused
        
        # Wait for current operation to complete
        await asyncio.sleep(0.1)
    
    def pause(self) -> None:
        """Pause polling (current operation will complete)"""
        if self._state == WorkerState.RUNNING:
            self._pause_event.clear()
            self._state = WorkerState.PAUSED
            logger.info("Email polling worker paused")
    
    def resume(self) -> None:
        """Resume polling after pause"""
        if self._state == WorkerState.PAUSED:
            self._pause_event.set()
            self._state = WorkerState.RUNNING
            logger.info("Email polling worker resumed")
    
    async def poll_once(self) -> List[AnalysisJob]:
        """
        Execute a single poll cycle.
        
        Useful for manual triggering or testing.
        
        Returns:
            List of completed analysis jobs
        """
        return await self._poll_cycle()
    
    async def _poll_cycle(self) -> List[AnalysisJob]:
        """
        Execute one complete polling cycle.
        
        1. Check IMAP for pending emails
        2. Process each through the orchestrator
        3. Update metrics
        """
        self.metrics.total_polls += 1
        self.metrics.last_poll_at = datetime.utcnow()
        
        # Use INFO level so we can see polling activity in Render logs
        logger.info(f"📬 Poll cycle #{self.metrics.total_polls} starting...")
        
        try:
            # Process all pending emails
            completed_jobs = await self._orchestrator.process_all_pending()
            
            # Update metrics
            for job in completed_jobs:
                self.metrics.total_emails_processed += 1
                
                if job.detection_result:
                    verdict = job.detection_result.final_verdict
                    if verdict == "PHISHING":
                        self.metrics.phishing_count += 1
                    elif verdict == "SUSPICIOUS":
                        self.metrics.suspicious_count += 1
                    else:
                        self.metrics.safe_count += 1
            
            if completed_jobs:
                logger.info(
                    f"✅ Poll cycle #{self.metrics.total_polls} complete: "
                    f"{len(completed_jobs)} emails processed"
                )
            else:
                logger.info(f"📭 Poll cycle #{self.metrics.total_polls}: No new emails to process")
            
            return completed_jobs
            
        except Exception as e:
            logger.error(f"Poll cycle error: {e}", exc_info=True)
            # DON'T raise - just log and continue polling
            return []
    
    async def _handle_error(self, error: Exception) -> None:
        """Handle polling errors with exponential backoff"""
        self.metrics.total_errors += 1
        self.metrics.consecutive_errors += 1
        
        logger.error(
            f"Poll error (consecutive: {self.metrics.consecutive_errors}): {error}"
        )
        
        # Calculate backoff
        if self.metrics.consecutive_errors >= self.MAX_CONSECUTIVE_ERRORS:
            self._current_backoff = min(
                self._current_backoff * self.ERROR_BACKOFF_MULTIPLIER or self.poll_interval,
                self.MAX_ERROR_BACKOFF
            )
            logger.warning(
                f"Multiple consecutive errors. Backing off {self._current_backoff}s"
            )
            
            # Enter error state if too many failures
            if self.metrics.consecutive_errors >= self.MAX_CONSECUTIVE_ERRORS * 2:
                self._state = WorkerState.ERROR
                logger.error("Too many errors. Worker entering error state.")
    
    def _reset_backoff(self) -> None:
        """Reset error backoff after successful poll"""
        if self.metrics.consecutive_errors > 0:
            logger.info("Poll successful, resetting error counters")
        self.metrics.consecutive_errors = 0
        self._current_backoff = 0
        
        if self._state == WorkerState.ERROR:
            self._state = WorkerState.RUNNING
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive worker status"""
        return {
            "state": self._state.value,
            "poll_interval": self.poll_interval,
            "current_backoff": self._current_backoff,
            "metrics": self.metrics.to_dict()
        }


# Singleton instance
_worker_instance: Optional[EmailPollingWorker] = None


def get_email_polling_worker() -> EmailPollingWorker:
    """Get or create singleton worker instance"""
    global _worker_instance
    if _worker_instance is None:
        poll_interval = getattr(settings, 'EMAIL_POLL_INTERVAL', 30)
        _worker_instance = EmailPollingWorker(poll_interval=poll_interval)
    return _worker_instance


async def start_background_polling():
    """
    Start background polling as an async task.
    
    Call this from your application startup.
    """
    worker = get_email_polling_worker()
    
    # Create background task
    task = asyncio.create_task(worker.start())
    
    # Setup signal handlers for graceful shutdown
    def shutdown_handler(sig):
        logger.info(f"Received signal {sig}, stopping worker...")
        asyncio.create_task(worker.stop())
    
    try:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda s=sig: shutdown_handler(s))
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                pass
    except Exception:
        pass
    
    return task


# Convenience exports
email_polling_service = get_email_polling_worker()
