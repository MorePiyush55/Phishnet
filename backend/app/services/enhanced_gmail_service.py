"""Enhanced Gmail ingestion service with full inbox scanning capabilities."""

import base64
import json
import hashlib
import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple, AsyncGenerator
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db, get_session
from app.models.user import User
from app.models.email_scan import EmailScanRequest, ScanStatus
from app.orchestrator.utils import email_orchestrator

logger = get_logger(__name__)


class SyncStatus(str, Enum):
    """Gmail sync status enumeration."""
    NOT_STARTED = "not_started"
    INITIAL_SYNC = "initial_sync"
    INCREMENTAL = "incremental"
    PAUSED = "paused"
    FAILED = "failed"
    COMPLETED = "completed"


@dataclass
class SyncProgress:
    """Sync progress tracking."""
    user_id: int
    status: SyncStatus
    total_messages: Optional[int] = None
    processed_messages: int = 0
    failed_messages: int = 0
    start_time: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    current_batch: int = 0
    total_batches: Optional[int] = None
    last_error: Optional[str] = None
    page_token: Optional[str] = None
    history_id: Optional[str] = None


@dataclass
class BatchConfig:
    """Batch processing configuration."""
    batch_size: int = 100
    max_concurrent_batches: int = 3
    retry_attempts: int = 3
    retry_delay: float = 1.0
    quota_delay: float = 0.1  # Delay between API calls for quota management


class EnhancedGmailService:
    """Enhanced Gmail service with full inbox scanning and real-time monitoring."""
    
    def __init__(self):
        """Initialize enhanced Gmail service."""
        self.scopes = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/gmail.labels'
        ]
        self.sync_progress: Dict[int, SyncProgress] = {}
        self.active_syncs: Dict[int, bool] = {}  # Track active sync processes
        
    async def get_auth_url(self, user_id: int) -> str:
        """Get Gmail OAuth authorization URL."""
        try:
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": settings.GMAIL_CLIENT_ID,
                        "client_secret": settings.GMAIL_CLIENT_SECRET,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [settings.GMAIL_REDIRECT_URI]
                    }
                },
                scopes=self.scopes
            )
            flow.redirect_uri = settings.GMAIL_REDIRECT_URI
            
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                state=str(user_id),
                prompt='consent'
            )
            
            return auth_url
            
        except Exception as e:
            logger.error(f"Failed to generate OAuth URL: {e}")
            raise

    async def handle_oauth_callback(self, code: str, state: str) -> Dict[str, Any]:
        """Handle OAuth callback and initialize Gmail integration."""
        try:
            user_id = int(state)
            
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": settings.GMAIL_CLIENT_ID,
                        "client_secret": settings.GMAIL_CLIENT_SECRET,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [settings.GMAIL_REDIRECT_URI]
                    }
                },
                scopes=self.scopes
            )
            flow.redirect_uri = settings.GMAIL_REDIRECT_URI
            
            # Exchange code for token
            flow.fetch_token(code=code)
            credentials = flow.credentials
            
            # Store credentials and initialize
            async with get_session() as db:
                user = await db.get(User, user_id)
                if user:
                    # Encrypt and store credentials
                    user.gmail_credentials = self._encrypt_credentials(credentials.to_json())
                    user.email_monitoring_enabled = True
                    user.gmail_sync_status = SyncStatus.NOT_STARTED.value
                    await db.commit()
                    
                    # Set up Gmail watch for real-time notifications
                    await self.setup_gmail_watch(user_id, credentials)
                    
                    logger.info(f"Gmail integration successful for user {user_id}")
                    return {
                        "status": "success", 
                        "message": "Gmail connected successfully. Ready for initial sync."
                    }
                else:
                    return {"status": "error", "message": "User not found"}
                
        except Exception as e:
            logger.error(f"Gmail OAuth callback failed: {e}")
            return {"status": "error", "message": "Failed to connect Gmail"}

    async def setup_gmail_watch(self, user_id: int, credentials: Credentials):
        """Set up Gmail push notifications via Pub/Sub."""
        try:
            service = build('gmail', 'v1', credentials=credentials)
            
            # Set up watch request for inbox
            watch_request = {
                'labelIds': ['INBOX'],
                'topicName': f'projects/{settings.GOOGLE_CLOUD_PROJECT}/topics/gmail-notifications'
            }
            
            response = service.users().watch(userId='me', body=watch_request).execute()
            
            # Store watch details
            async with get_session() as db:
                user = await db.get(User, user_id)
                if user:
                    user.gmail_watch_expiration = datetime.fromtimestamp(
                        int(response['expiration']) / 1000
                    )
                    user.gmail_history_id = response.get('historyId')
                    await db.commit()
            
            logger.info(f"Gmail watch setup successful for user {user_id}, expires: {response['expiration']}")
            return response
            
        except HttpError as e:
            logger.error(f"Failed to setup Gmail watch: {e}")
            raise

    async def start_initial_sync(self, user_id: int, confirm_large_mailbox: bool = False) -> Dict[str, Any]:
        """Start initial full inbox sync with user confirmation for large mailboxes."""
        try:
            # Check if sync is already running
            if user_id in self.active_syncs and self.active_syncs[user_id]:
                return {
                    "status": "error",
                    "message": "Sync already in progress for this user"
                }

            # Get user credentials
            async with get_session() as db:
                user = await db.get(User, user_id)
                if not user or not user.gmail_credentials:
                    return {"status": "error", "message": "No Gmail credentials found"}
                
                credentials = self._decrypt_credentials(user.gmail_credentials)
                await self._refresh_credentials_if_needed(user_id, credentials)
                
                service = build('gmail', 'v1', credentials=credentials)
                
                # Get mailbox size estimate
                profile = service.users().getProfile(userId='me').execute()
                total_messages = profile.get('messagesTotal', 0)
                
                logger.info(f"Mailbox size for user {user_id}: {total_messages} messages")
                
                # Warn about large mailboxes
                if total_messages > 1000 and not confirm_large_mailbox:
                    return {
                        "status": "confirmation_required",
                        "message": f"Large mailbox detected ({total_messages:,} messages). This may take significant time and API quota.",
                        "total_messages": total_messages,
                        "estimated_time_minutes": max(1, total_messages // 100),  # Rough estimate
                        "estimated_api_calls": total_messages * 2  # List + get for each message
                    }
                
                # Initialize sync progress
                progress = SyncProgress(
                    user_id=user_id,
                    status=SyncStatus.INITIAL_SYNC,
                    total_messages=total_messages,
                    start_time=datetime.utcnow()
                )
                self.sync_progress[user_id] = progress
                self.active_syncs[user_id] = True
                
                # Update user status
                user.gmail_sync_status = SyncStatus.INITIAL_SYNC.value
                user.gmail_last_sync_start = datetime.utcnow()
                await db.commit()
                
                # Start sync in background
                asyncio.create_task(self._perform_initial_sync(user_id, service, progress))
                
                return {
                    "status": "success",
                    "message": "Initial sync started",
                    "sync_id": str(user_id),
                    "total_messages": total_messages
                }
                
        except Exception as e:
            logger.error(f"Failed to start initial sync for user {user_id}: {e}")
            self.active_syncs[user_id] = False
            return {"status": "error", "message": f"Failed to start sync: {str(e)}"}

    async def _perform_initial_sync(self, user_id: int, service, progress: SyncProgress):
        """Perform the actual initial sync with pagination and batching."""
        try:
            config = BatchConfig()
            page_token = None
            batch_count = 0
            
            logger.info(f"Starting initial sync for user {user_id}")
            
            while True:
                try:
                    # Get batch of message IDs
                    results = service.users().messages().list(
                        userId='me',
                        maxResults=config.batch_size,
                        pageToken=page_token,
                        q='in:inbox'
                    ).execute()
                    
                    messages = results.get('messages', [])
                    if not messages:
                        break
                    
                    batch_count += 1
                    progress.current_batch = batch_count
                    progress.page_token = page_token
                    
                    # Process batch
                    await self._process_message_batch(user_id, service, messages, config)
                    
                    progress.processed_messages += len(messages)
                    
                    # Update progress
                    if progress.total_messages:
                        progress.estimated_completion = self._calculate_eta(progress)
                    
                    # Check for next page
                    page_token = results.get('nextPageToken')
                    if not page_token:
                        break
                    
                    # Quota management delay
                    await asyncio.sleep(config.quota_delay)
                    
                    # Check if sync was paused/cancelled
                    if not self.active_syncs.get(user_id, False):
                        progress.status = SyncStatus.PAUSED
                        break
                    
                except HttpError as e:
                    if e.resp.status == 429:  # Rate limit
                        await self._handle_rate_limit(config)
                        continue
                    else:
                        raise
                        
            # Mark sync complete
            if self.active_syncs.get(user_id, False):
                progress.status = SyncStatus.COMPLETED
                await self._update_sync_completion(user_id)
                
            logger.info(f"Initial sync completed for user {user_id}: {progress.processed_messages} messages")
            
        except Exception as e:
            logger.error(f"Initial sync failed for user {user_id}: {e}")
            progress.status = SyncStatus.FAILED
            progress.last_error = str(e)
            
        finally:
            self.active_syncs[user_id] = False

    async def _process_message_batch(self, user_id: int, service, messages: List[Dict], config: BatchConfig):
        """Process a batch of messages with concurrency control."""
        semaphore = asyncio.Semaphore(config.max_concurrent_batches)
        
        async def process_single_message(message_data: Dict):
            async with semaphore:
                message_id = message_data['id']
                
                # Check if already processed
                if await self._is_message_already_processed(user_id, message_id):
                    return
                
                # Process with retry logic
                for attempt in range(config.retry_attempts):
                    try:
                        await self._ingest_single_message(user_id, service, message_id)
                        break
                    except Exception as e:
                        if attempt == config.retry_attempts - 1:
                            logger.error(f"Failed to process message {message_id} after {config.retry_attempts} attempts: {e}")
                            self.sync_progress[user_id].failed_messages += 1
                        else:
                            await asyncio.sleep(config.retry_delay * (2 ** attempt))
        
        # Process all messages in batch concurrently
        tasks = [process_single_message(msg) for msg in messages]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _ingest_single_message(self, user_id: int, service, message_id: str):
        """Ingest a single message with enhanced metadata extraction."""
        try:
            # Get full message
            message = service.users().messages().get(
                userId='me',
                id=message_id,
                format='metadata',
                metadataHeaders=['From', 'To', 'Subject', 'Date', 'Message-ID']
            ).execute()
            
            # Extract metadata only (privacy-first approach)
            metadata = self._extract_message_metadata(message)
            
            # Create scan request
            async with get_session() as db:
                # Check for duplicates using Gmail message ID
                existing = await db.execute(
                    f"SELECT id FROM email_scan_requests WHERE gmail_message_id = '{message_id}' AND user_id = {user_id}"
                )
                if existing.first():
                    return  # Already processed
                
                scan_request = EmailScanRequest(
                    user_id=user_id,
                    gmail_message_id=message_id,
                    gmail_thread_id=metadata['thread_id'],
                    sender_domain=metadata['sender_domain'],
                    subject_hash=metadata['subject_hash'],
                    content_hash=metadata['content_hash'],
                    received_at=metadata['received_at'],
                    size_bytes=metadata['size_bytes'],
                    scan_request_id=str(uuid.uuid4()),
                    status=ScanStatus.PENDING
                )
                
                db.add(scan_request)
                await db.commit()
                await db.refresh(scan_request)
                
                # Queue for analysis
                await email_orchestrator.process_email(scan_request.id)
                
        except Exception as e:
            logger.error(f"Failed to ingest message {message_id}: {e}")
            raise

    def _extract_message_metadata(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Extract privacy-safe metadata from Gmail message."""
        payload = message.get('payload', {})
        headers = {h['name'].lower(): h['value'] for h in payload.get('headers', [])}
        
        # Extract sender domain only (not full email)
        sender = headers.get('from', '')
        sender_domain = sender.split('@')[-1] if '@' in sender else ''
        
        # Hash subject for deduplication without storing content
        subject = headers.get('subject', '')
        subject_hash = hashlib.sha256(subject.encode('utf-8')).hexdigest()[:16] if subject else None
        
        # Create content hash from available metadata
        content_for_hash = f"{sender_domain}{subject}{headers.get('message-id', '')}"
        content_hash = hashlib.sha256(content_for_hash.encode('utf-8')).hexdigest()
        
        # Parse date
        date_str = headers.get('date', '')
        received_at = self._parse_email_date(date_str)
        
        return {
            'thread_id': message.get('threadId', ''),
            'sender_domain': sender_domain,
            'subject_hash': subject_hash,
            'content_hash': content_hash,
            'received_at': received_at,
            'size_bytes': message.get('sizeEstimate', 0)
        }

    async def _is_message_already_processed(self, user_id: int, message_id: str) -> bool:
        """Check if message has already been processed."""
        try:
            async with get_session() as db:
                result = await db.execute(
                    f"SELECT 1 FROM email_scan_requests WHERE gmail_message_id = '{message_id}' AND user_id = {user_id} LIMIT 1"
                )
                return result.first() is not None
        except Exception:
            return False

    def _calculate_eta(self, progress: SyncProgress) -> datetime:
        """Calculate estimated completion time."""
        if not progress.start_time or not progress.total_messages or progress.processed_messages == 0:
            return datetime.utcnow() + timedelta(hours=1)  # Default estimate
        
        elapsed = datetime.utcnow() - progress.start_time
        rate = progress.processed_messages / elapsed.total_seconds()
        remaining = progress.total_messages - progress.processed_messages
        
        if rate > 0:
            remaining_seconds = remaining / rate
            return datetime.utcnow() + timedelta(seconds=remaining_seconds)
        
        return datetime.utcnow() + timedelta(hours=1)

    async def _handle_rate_limit(self, config: BatchConfig):
        """Handle Gmail API rate limiting with exponential backoff."""
        wait_time = min(60, config.retry_delay * 2)
        logger.warning(f"Rate limited, waiting {wait_time} seconds")
        await asyncio.sleep(wait_time)
        config.retry_delay = wait_time

    async def _update_sync_completion(self, user_id: int):
        """Update database when sync completes."""
        try:
            async with get_session() as db:
                user = await db.get(User, user_id)
                if user:
                    user.gmail_sync_status = SyncStatus.COMPLETED.value
                    user.gmail_last_sync_complete = datetime.utcnow()
                    await db.commit()
        except Exception as e:
            logger.error(f"Failed to update sync completion for user {user_id}: {e}")

    async def pause_sync(self, user_id: int) -> Dict[str, Any]:
        """Pause ongoing sync for a user."""
        if user_id in self.active_syncs:
            self.active_syncs[user_id] = False
            if user_id in self.sync_progress:
                self.sync_progress[user_id].status = SyncStatus.PAUSED
            
            async with get_session() as db:
                user = await db.get(User, user_id)
                if user:
                    user.gmail_sync_status = SyncStatus.PAUSED.value
                    await db.commit()
            
            return {"status": "success", "message": "Sync paused"}
        else:
            return {"status": "error", "message": "No active sync found"}

    async def resume_sync(self, user_id: int) -> Dict[str, Any]:
        """Resume paused sync for a user."""
        if user_id in self.sync_progress and self.sync_progress[user_id].status == SyncStatus.PAUSED:
            progress = self.sync_progress[user_id]
            progress.status = SyncStatus.INITIAL_SYNC
            self.active_syncs[user_id] = True
            
            # Get credentials and resume
            async with get_session() as db:
                user = await db.get(User, user_id)
                if user and user.gmail_credentials:
                    credentials = self._decrypt_credentials(user.gmail_credentials)
                    service = build('gmail', 'v1', credentials=credentials)
                    
                    # Resume from where we left off
                    asyncio.create_task(self._perform_initial_sync(user_id, service, progress))
                    
                    return {"status": "success", "message": "Sync resumed"}
            
        return {"status": "error", "message": "No paused sync found"}

    def get_sync_progress(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get current sync progress for a user."""
        if user_id in self.sync_progress:
            progress = self.sync_progress[user_id]
            return {
                "status": progress.status.value,
                "total_messages": progress.total_messages,
                "processed_messages": progress.processed_messages,
                "failed_messages": progress.failed_messages,
                "progress_percentage": (
                    (progress.processed_messages / progress.total_messages * 100) 
                    if progress.total_messages else 0
                ),
                "start_time": progress.start_time.isoformat() if progress.start_time else None,
                "estimated_completion": progress.estimated_completion.isoformat() if progress.estimated_completion else None,
                "current_batch": progress.current_batch,
                "last_error": progress.last_error
            }
        return None

    async def _refresh_credentials_if_needed(self, user_id: int, credentials: Credentials):
        """Refresh credentials if expired."""
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            
            # Update stored credentials
            async with get_session() as db:
                user = await db.get(User, user_id)
                if user:
                    user.gmail_credentials = self._encrypt_credentials(credentials.to_json())
                    await db.commit()

    def _parse_email_date(self, date_str: str) -> datetime:
        """Parse email date string to datetime."""
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str)
        except Exception:
            return datetime.utcnow()

    def _encrypt_credentials(self, credentials_json: str) -> str:
        """Encrypt credentials for secure storage."""
        # TODO: Implement proper encryption in production
        return credentials_json

    def _decrypt_credentials(self, encrypted_credentials: str) -> Credentials:
        """Decrypt stored credentials."""
        credentials_data = json.loads(encrypted_credentials)
        return Credentials.from_authorized_user_info(credentials_data)


# Global enhanced Gmail service instance
enhanced_gmail_service = EnhancedGmailService()