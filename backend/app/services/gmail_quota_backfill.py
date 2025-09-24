"""Advanced Gmail API quota management and backfill scanning system."""

import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid
import json

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_session
from app.models.user import User
from app.models.email_scan import EmailScanRequest, ScanStatus
from app.services.enhanced_gmail_service import enhanced_gmail_service

logger = get_logger(__name__)


class QuotaType(str, Enum):
    """Gmail API quota types."""
    MESSAGES_LIST = "messages_list"
    MESSAGES_GET = "messages_get"
    HISTORY_LIST = "history_list"
    USERS_WATCH = "users_watch"


@dataclass
class QuotaTracker:
    """Track API quota usage per quota type."""
    quota_type: QuotaType
    requests_per_100_seconds: int = 0
    requests_per_day: int = 0
    last_reset_100s: datetime = field(default_factory=datetime.utcnow)
    last_reset_daily: datetime = field(default_factory=datetime.utcnow)
    
    # Gmail API limits (conservative estimates)
    max_requests_per_100s: int = 250  # Conservative limit
    max_requests_per_day: int = 1000000  # Daily limit
    
    def can_make_request(self) -> bool:
        """Check if we can make another API request."""
        now = datetime.utcnow()
        
        # Reset 100-second counter if needed
        if (now - self.last_reset_100s).total_seconds() >= 100:
            self.requests_per_100_seconds = 0
            self.last_reset_100s = now
        
        # Reset daily counter if needed
        if (now - self.last_reset_daily).total_seconds() >= 86400:
            self.requests_per_day = 0
            self.last_reset_daily = now
        
        return (self.requests_per_100_seconds < self.max_requests_per_100s and 
                self.requests_per_day < self.max_requests_per_day)
    
    def record_request(self):
        """Record an API request."""
        self.requests_per_100_seconds += 1
        self.requests_per_day += 1
    
    def get_wait_time(self) -> float:
        """Get recommended wait time before next request."""
        now = datetime.utcnow()
        
        # If we're at 100-second limit, wait until reset
        if self.requests_per_100_seconds >= self.max_requests_per_100s:
            time_since_reset = (now - self.last_reset_100s).total_seconds()
            return max(0, 100 - time_since_reset)
        
        # If we're approaching limits, add delay
        usage_ratio = self.requests_per_100_seconds / self.max_requests_per_100s
        if usage_ratio > 0.8:
            return 0.5  # Half second delay when approaching limit
        elif usage_ratio > 0.6:
            return 0.2  # Small delay when moderately busy
        
        return 0.1  # Minimum delay for quota safety


@dataclass
class BackfillJob:
    """Backfill job configuration and state."""
    job_id: str
    user_id: int
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    total_estimated: Optional[int] = None
    processed: int = 0
    failed: int = 0
    status: str = "pending"  # pending, running, paused, completed, failed
    current_query: Optional[str] = None
    page_token: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class GmailQuotaManager:
    """Advanced Gmail API quota management with intelligent throttling."""
    
    def __init__(self):
        self.quota_trackers: Dict[QuotaType, QuotaTracker] = {
            quota_type: QuotaTracker(quota_type) for quota_type in QuotaType
        }
        self.global_lock = asyncio.Lock()
        self.backfill_jobs: Dict[str, BackfillJob] = {}
        
    async def acquire_quota(self, quota_type: QuotaType) -> bool:
        """Acquire quota for an API request with intelligent waiting."""
        async with self.global_lock:
            tracker = self.quota_trackers[quota_type]
            
            # Check if we can make request immediately
            if tracker.can_make_request():
                tracker.record_request()
                return True
            
            # Calculate wait time
            wait_time = tracker.get_wait_time()
            
            if wait_time > 60:  # If we need to wait more than a minute, fail
                logger.warning(f"Quota exhausted for {quota_type}, need to wait {wait_time}s")
                return False
            
            # Wait and try again
            logger.info(f"Quota throttling: waiting {wait_time}s for {quota_type}")
            await asyncio.sleep(wait_time)
            
            # Try again after waiting
            if tracker.can_make_request():
                tracker.record_request()
                return True
            
            return False
    
    async def make_gmail_api_call(self, quota_type: QuotaType, api_call_func, *args, **kwargs):
        """Make Gmail API call with quota management and retry logic."""
        max_retries = 3
        
        for attempt in range(max_retries):
            # Acquire quota
            if not await self.acquire_quota(quota_type):
                raise Exception(f"Unable to acquire quota for {quota_type}")
            
            try:
                # Make the API call
                result = api_call_func(*args, **kwargs)
                return result
                
            except HttpError as e:
                if e.resp.status == 429:  # Rate limited
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.warning(f"Rate limited on attempt {attempt + 1}, waiting {wait_time}s")
                    await asyncio.sleep(wait_time)
                    continue
                elif e.resp.status in [403, 400]:  # Quota exceeded or bad request
                    logger.error(f"Gmail API error {e.resp.status}: {e}")
                    raise
                else:
                    raise
            except Exception as e:
                logger.error(f"Unexpected error in Gmail API call: {e}")
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(1)
        
        raise Exception(f"Failed to complete Gmail API call after {max_retries} attempts")
    
    def get_quota_status(self) -> Dict[str, Any]:
        """Get current quota usage status."""
        status = {}
        for quota_type, tracker in self.quota_trackers.items():
            status[quota_type.value] = {
                "requests_per_100s": tracker.requests_per_100_seconds,
                "requests_per_day": tracker.requests_per_day,
                "usage_100s_percent": (tracker.requests_per_100_seconds / tracker.max_requests_per_100s) * 100,
                "usage_daily_percent": (tracker.requests_per_day / tracker.max_requests_per_day) * 100,
                "can_make_request": tracker.can_make_request(),
                "recommended_wait": tracker.get_wait_time()
            }
        return status


class GmailBackfillService:
    """Service for backfilling large Gmail inboxes with historical data."""
    
    def __init__(self, quota_manager: GmailQuotaManager):
        self.quota_manager = quota_manager
        self.active_jobs: Dict[str, asyncio.Task] = {}
    
    async def start_backfill_job(self, user_id: int, 
                                start_date: Optional[datetime] = None,
                                end_date: Optional[datetime] = None,
                                chunk_size_days: int = 30) -> str:
        """Start a backfill job for historical email scanning."""
        try:
            job_id = str(uuid.uuid4())
            
            # Default to last 2 years if no start date specified
            if start_date is None:
                start_date = datetime.utcnow() - timedelta(days=730)
            if end_date is None:
                end_date = datetime.utcnow()
            
            # Create job
            job = BackfillJob(
                job_id=job_id,
                user_id=user_id,
                start_date=start_date,
                end_date=end_date,
                status="pending"
            )
            
            self.quota_manager.backfill_jobs[job_id] = job
            
            # Start processing in background
            task = asyncio.create_task(self._process_backfill_job(job, chunk_size_days))
            self.active_jobs[job_id] = task
            
            logger.info(f"Started backfill job {job_id} for user {user_id}")
            return job_id
            
        except Exception as e:
            logger.error(f"Failed to start backfill job for user {user_id}: {e}")
            raise
    
    async def _process_backfill_job(self, job: BackfillJob, chunk_size_days: int):
        """Process a backfill job in time-based chunks."""
        try:
            job.status = "running"
            job.started_at = datetime.utcnow()
            
            # Get user credentials
            async with get_session() as db:
                user = await db.get(User, job.user_id)
                if not user or not user.gmail_credentials:
                    raise Exception("No Gmail credentials found")
                
                credentials = enhanced_gmail_service._decrypt_credentials(user.gmail_credentials)
                await enhanced_gmail_service._refresh_credentials_if_needed(job.user_id, credentials)
                
                service = build('gmail', 'v1', credentials=credentials)
            
            # Process in date chunks to manage memory and quota
            current_date = job.start_date
            
            while current_date < job.end_date:
                chunk_end = min(current_date + timedelta(days=chunk_size_days), job.end_date)
                
                # Create date query
                date_query = f'after:{current_date.strftime("%Y/%m/%d")} before:{chunk_end.strftime("%Y/%m/%d")}'
                job.current_query = f'in:inbox {date_query}'
                
                logger.info(f"Processing backfill chunk for job {job.job_id}: {date_query}")
                
                # Process this date chunk
                await self._process_date_chunk(job, service, job.current_query)
                
                # Check if job was paused/cancelled
                if job.status not in ["running"]:
                    break
                
                current_date = chunk_end
                
                # Small delay between chunks
                await asyncio.sleep(1)
            
            # Mark job complete if still running
            if job.status == "running":
                job.status = "completed"
                job.completed_at = datetime.utcnow()
                
                logger.info(f"Backfill job {job.job_id} completed: {job.processed} processed, {job.failed} failed")
            
        except Exception as e:
            logger.error(f"Backfill job {job.job_id} failed: {e}")
            job.status = "failed"
            job.error_message = str(e)
            job.completed_at = datetime.utcnow()
        finally:
            # Clean up active job tracking
            if job.job_id in self.active_jobs:
                del self.active_jobs[job.job_id]
    
    async def _process_date_chunk(self, job: BackfillJob, service, query: str):
        """Process a specific date chunk with pagination."""
        page_token = job.page_token
        
        while True:
            try:
                # Build request parameters
                list_params = {
                    'userId': 'me',
                    'maxResults': 100,
                    'q': query
                }
                
                if page_token:
                    list_params['pageToken'] = page_token
                
                # Make API call with quota management
                result = await self.quota_manager.make_gmail_api_call(
                    QuotaType.MESSAGES_LIST,
                    service.users().messages().list,
                    **list_params
                )
                
                messages = result.get('messages', [])
                
                if not messages:
                    break
                
                # Process batch of messages
                await self._process_message_batch(job, service, messages)
                
                # Update pagination
                page_token = result.get('nextPageToken')
                job.page_token = page_token
                
                if not page_token:
                    break
                
                # Check if job was paused
                if job.status != "running":
                    break
                
            except Exception as e:
                logger.error(f"Error processing date chunk in job {job.job_id}: {e}")
                job.failed += 1
                break
        
        # Clear page token when chunk is complete
        job.page_token = None
    
    async def _process_message_batch(self, job: BackfillJob, service, messages: List[Dict]):
        """Process a batch of messages from backfill."""
        for message_data in messages:
            try:
                message_id = message_data['id']
                
                # Check if already processed
                if await enhanced_gmail_service._is_message_already_processed(job.user_id, message_id):
                    job.processed += 1
                    continue
                
                # Get message metadata
                message_result = await self.quota_manager.make_gmail_api_call(
                    QuotaType.MESSAGES_GET,
                    service.users().messages().get,
                    userId='me',
                    id=message_id,
                    format='metadata',
                    metadataHeaders=['From', 'To', 'Subject', 'Date', 'Message-ID']
                )
                
                # Extract and store metadata
                metadata = enhanced_gmail_service._extract_message_metadata(message_result)
                
                # Create scan request
                async with get_session() as db:
                    scan_request = EmailScanRequest(
                        user_id=job.user_id,
                        gmail_message_id=message_id,
                        gmail_thread_id=metadata['thread_id'],
                        sender_domain=metadata['sender_domain'],
                        subject_hash=metadata['subject_hash'],
                        content_hash=metadata['content_hash'],
                        received_at=metadata['received_at'],
                        size_bytes=metadata['size_bytes'],
                        scan_request_id=str(uuid.uuid4()),
                        status=ScanStatus.PENDING,
                        priority=3  # Lower priority for backfill
                    )
                    
                    db.add(scan_request)
                    await db.commit()
                
                job.processed += 1
                
                # Small delay for quota management
                await asyncio.sleep(0.05)
                
            except Exception as e:
                logger.error(f"Failed to process message {message_data.get('id')} in backfill job {job.job_id}: {e}")
                job.failed += 1
    
    async def pause_backfill_job(self, job_id: str) -> bool:
        """Pause a running backfill job."""
        if job_id in self.quota_manager.backfill_jobs:
            job = self.quota_manager.backfill_jobs[job_id]
            if job.status == "running":
                job.status = "paused"
                logger.info(f"Paused backfill job {job_id}")
                return True
        return False
    
    async def resume_backfill_job(self, job_id: str) -> bool:
        """Resume a paused backfill job."""
        if job_id in self.quota_manager.backfill_jobs:
            job = self.quota_manager.backfill_jobs[job_id]
            if job.status == "paused":
                job.status = "running"
                
                # Restart processing task if not already running
                if job_id not in self.active_jobs:
                    task = asyncio.create_task(self._process_backfill_job(job, 30))
                    self.active_jobs[job_id] = task
                
                logger.info(f"Resumed backfill job {job_id}")
                return True
        return False
    
    async def cancel_backfill_job(self, job_id: str) -> bool:
        """Cancel a backfill job."""
        if job_id in self.quota_manager.backfill_jobs:
            job = self.quota_manager.backfill_jobs[job_id]
            job.status = "cancelled"
            job.completed_at = datetime.utcnow()
            
            # Cancel active task
            if job_id in self.active_jobs:
                self.active_jobs[job_id].cancel()
                del self.active_jobs[job_id]
            
            logger.info(f"Cancelled backfill job {job_id}")
            return True
        return False
    
    def get_backfill_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a backfill job."""
        if job_id in self.quota_manager.backfill_jobs:
            job = self.quota_manager.backfill_jobs[job_id]
            
            # Calculate progress
            progress_percent = 0
            if job.total_estimated and job.total_estimated > 0:
                progress_percent = (job.processed / job.total_estimated) * 100
            elif job.start_date and job.end_date:
                # Estimate based on time progress
                total_time = (job.end_date - job.start_date).total_seconds()
                if job.started_at:
                    elapsed_time = (datetime.utcnow() - job.started_at).total_seconds()
                    progress_percent = min(100, (elapsed_time / total_time) * 100)
            
            return {
                "job_id": job.job_id,
                "user_id": job.user_id,
                "status": job.status,
                "processed": job.processed,
                "failed": job.failed,
                "progress_percent": progress_percent,
                "start_date": job.start_date.isoformat() if job.start_date else None,
                "end_date": job.end_date.isoformat() if job.end_date else None,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
                "current_query": job.current_query,
                "error_message": job.error_message
            }
        return None
    
    def get_all_backfill_jobs(self, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get all backfill jobs, optionally filtered by user."""
        jobs = []
        for job in self.quota_manager.backfill_jobs.values():
            if user_id is None or job.user_id == user_id:
                job_status = self.get_backfill_status(job.job_id)
                if job_status:
                    jobs.append(job_status)
        return jobs


# Global instances
gmail_quota_manager = GmailQuotaManager()
gmail_backfill_service = GmailBackfillService(gmail_quota_manager)