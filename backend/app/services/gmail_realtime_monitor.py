"""Gmail real-time monitoring with Pub/Sub push notifications."""

import base64
import json
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

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


class GmailRealtimeMonitor:
    """Gmail real-time monitoring service using Pub/Sub push notifications."""
    
    def __init__(self):
        self.processing_locks: Dict[int, asyncio.Lock] = {}
    
    async def process_gmail_webhook(self, pub_sub_message: Dict[str, Any]) -> Dict[str, Any]:
        """Process Gmail webhook notification from Pub/Sub."""
        try:
            logger.info(f"Processing Gmail webhook: {pub_sub_message}")
            
            # Decode Pub/Sub message
            if 'data' not in pub_sub_message:
                logger.warning("No data in Pub/Sub message")
                return {"status": "error", "message": "No data in message"}
            
            data = base64.b64decode(pub_sub_message['data']).decode('utf-8')
            message_data = json.loads(data)
            
            email_address = message_data.get('emailAddress')
            history_id = message_data.get('historyId')
            
            if not email_address or not history_id:
                logger.warning(f"Missing email address or history ID: {message_data}")
                return {"status": "error", "message": "Missing required fields"}
            
            # Find user by email
            async with get_session() as db:
                # Note: This assumes users have their Gmail address as their primary email
                # In production, you might need a separate table to map Gmail addresses to users
                user = await db.execute(
                    f"SELECT * FROM users WHERE email = '{email_address}' OR gmail_address = '{email_address}' LIMIT 1"
                )
                user_record = user.first()
                
                if not user_record or not user_record.gmail_credentials:
                    logger.warning(f"No user found or no credentials for {email_address}")
                    return {"status": "error", "message": "User not found or no credentials"}
                
                user_id = user_record.id
                
                # Get processing lock for this user to prevent concurrent processing
                if user_id not in self.processing_locks:
                    self.processing_locks[user_id] = asyncio.Lock()
                
                async with self.processing_locks[user_id]:
                    # Get user's Gmail credentials
                    credentials = enhanced_gmail_service._decrypt_credentials(user_record.gmail_credentials)
                    await enhanced_gmail_service._refresh_credentials_if_needed(user_id, credentials)
                    
                    # Fetch new messages since last history ID
                    result = await self.fetch_gmail_history(user_id, credentials, history_id)
                    
                    return {
                        "status": "success",
                        "messages_processed": result.get("messages_processed", 0),
                        "user_id": user_id
                    }
                
        except Exception as e:
            logger.error(f"Failed to process Gmail webhook: {e}")
            return {"status": "error", "message": str(e)}
    
    async def fetch_gmail_history(self, user_id: int, credentials: Credentials, start_history_id: str) -> Dict[str, Any]:
        """Fetch Gmail history and process new messages incrementally."""
        try:
            service = build('gmail', 'v1', credentials=credentials)
            
            # Get stored last history ID
            async with get_session() as db:
                user = await db.get(User, user_id)
                last_history_id = user.gmail_history_id if user else None
            
            # Use the stored history ID if available, otherwise use the provided one
            if last_history_id:
                start_history_id = last_history_id
            
            logger.info(f"Fetching Gmail history for user {user_id} from history ID {start_history_id}")
            
            # Get history with pagination
            messages_processed = 0
            next_page_token = None
            
            while True:
                try:
                    # Get history
                    history_params = {
                        'userId': 'me',
                        'startHistoryId': start_history_id,
                        'labelId': 'INBOX',
                        'maxResults': 100
                    }
                    
                    if next_page_token:
                        history_params['pageToken'] = next_page_token
                    
                    history_response = service.users().history().list(**history_params).execute()
                    
                    history = history_response.get('history', [])
                    
                    if not history:
                        logger.info(f"No new history found for user {user_id}")
                        break
                    
                    # Process history records
                    for history_record in history:
                        messages_added = history_record.get('messagesAdded', [])
                        
                        for message_added in messages_added:
                            message = message_added.get('message', {})
                            message_id = message.get('id')
                            
                            if message_id:
                                # Check label filters (only process inbox messages)
                                message_labels = message.get('labelIds', [])
                                if 'INBOX' in message_labels:
                                    await self._process_new_message(user_id, service, message_id)
                                    messages_processed += 1
                    
                    # Check for next page
                    next_page_token = history_response.get('nextPageToken')
                    if not next_page_token:
                        break
                    
                    # Small delay for quota management
                    await asyncio.sleep(0.1)
                    
                except HttpError as e:
                    if e.resp.status == 404:
                        # History ID too old, need to do a fresh sync
                        logger.warning(f"History ID too old for user {user_id}, triggering fresh sync")
                        await self._trigger_fresh_sync(user_id, service)
                        break
                    elif e.resp.status == 429:
                        # Rate limited
                        logger.warning(f"Rate limited during history fetch for user {user_id}")
                        await asyncio.sleep(10)
                        continue
                    else:
                        raise
            
            # Update last processed history ID
            await self._update_last_history_id(user_id, start_history_id)
            
            logger.info(f"Processed {messages_processed} new messages for user {user_id}")
            
            return {
                "messages_processed": messages_processed,
                "last_history_id": start_history_id
            }
            
        except Exception as e:
            logger.error(f"Failed to fetch Gmail history for user {user_id}: {e}")
            raise
    
    async def _process_new_message(self, user_id: int, service, message_id: str):
        """Process a single new message from real-time notifications."""
        try:
            # Check if we already processed this message
            if await enhanced_gmail_service._is_message_already_processed(user_id, message_id):
                logger.debug(f"Message {message_id} already processed for user {user_id}")
                return
            
            # Ingest the message
            await enhanced_gmail_service._ingest_single_message(user_id, service, message_id)
            
            logger.info(f"Real-time processed message {message_id} for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to process new message {message_id} for user {user_id}: {e}")
    
    async def _trigger_fresh_sync(self, user_id: int, service):
        """Trigger fresh sync when history ID is too old."""
        try:
            logger.info(f"Triggering fresh incremental sync for user {user_id}")
            
            # Get recent messages (last 24 hours worth)
            one_day_ago = datetime.utcnow() - timedelta(days=1)
            query = f'in:inbox after:{one_day_ago.strftime("%Y/%m/%d")}'
            
            results = service.users().messages().list(
                userId='me',
                maxResults=500,
                q=query
            ).execute()
            
            messages = results.get('messages', [])
            
            for message in messages:
                await self._process_new_message(user_id, service, message['id'])
            
            logger.info(f"Fresh sync completed for user {user_id}: {len(messages)} messages")
            
        except Exception as e:
            logger.error(f"Failed to trigger fresh sync for user {user_id}: {e}")
    
    async def _update_last_history_id(self, user_id: int, history_id: str):
        """Update the last processed history ID for a user."""
        try:
            async with get_session() as db:
                user = await db.get(User, user_id)
                if user:
                    user.gmail_history_id = history_id
                    user.gmail_last_webhook_processed = datetime.utcnow()
                    await db.commit()
        except Exception as e:
            logger.error(f"Failed to update history ID for user {user_id}: {e}")
    
    async def setup_all_gmail_watches(self):
        """Set up Gmail watches for all users with Gmail integration."""
        try:
            async with get_session() as db:
                # Get all users with Gmail credentials
                result = await db.execute(
                    "SELECT id, gmail_credentials, gmail_watch_expiration FROM users "
                    "WHERE gmail_credentials IS NOT NULL AND email_monitoring_enabled = true"
                )
                users = result.fetchall()
                
                setup_count = 0
                for user_record in users:
                    user_id = user_record.id
                    
                    # Check if watch needs renewal (expires within 24 hours)
                    if user_record.gmail_watch_expiration:
                        if user_record.gmail_watch_expiration > datetime.utcnow() + timedelta(hours=24):
                            continue  # Watch is still valid
                    
                    try:
                        credentials = enhanced_gmail_service._decrypt_credentials(user_record.gmail_credentials)
                        await enhanced_gmail_service._refresh_credentials_if_needed(user_id, credentials)
                        await enhanced_gmail_service.setup_gmail_watch(user_id, credentials)
                        setup_count += 1
                        
                        # Small delay to avoid rate limits
                        await asyncio.sleep(0.5)
                        
                    except Exception as e:
                        logger.error(f"Failed to setup Gmail watch for user {user_id}: {e}")
                
                logger.info(f"Set up Gmail watches for {setup_count} users")
                return setup_count
                
        except Exception as e:
            logger.error(f"Failed to setup Gmail watches: {e}")
            return 0
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for Gmail monitoring service."""
        try:
            async with get_session() as db:
                # Count active Gmail integrations
                result = await db.execute(
                    "SELECT COUNT(*) as count FROM users "
                    "WHERE gmail_credentials IS NOT NULL AND email_monitoring_enabled = true"
                )
                active_integrations = result.scalar()
                
                # Count recent webhook processing
                one_hour_ago = datetime.utcnow() - timedelta(hours=1)
                result = await db.execute(
                    f"SELECT COUNT(*) as count FROM users "
                    f"WHERE gmail_last_webhook_processed > '{one_hour_ago}'"
                )
                recent_webhooks = result.scalar()
                
                # Count watch expirations needing renewal
                tomorrow = datetime.utcnow() + timedelta(days=1)
                result = await db.execute(
                    f"SELECT COUNT(*) as count FROM users "
                    f"WHERE gmail_watch_expiration < '{tomorrow}' AND gmail_credentials IS NOT NULL"
                )
                expiring_watches = result.scalar()
                
                return {
                    "status": "healthy",
                    "active_gmail_integrations": active_integrations,
                    "recent_webhook_processing": recent_webhooks,
                    "expiring_watches": expiring_watches,
                    "processing_locks_active": len(self.processing_locks)
                }
                
        except Exception as e:
            logger.error(f"Gmail monitoring health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e)
            }


# Global real-time monitor instance
gmail_realtime_monitor = GmailRealtimeMonitor()