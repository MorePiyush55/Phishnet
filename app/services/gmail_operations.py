"""
Gmail operations service for backend with orchestrator integration
Handles Gmail API operations, watch setup, and background scanning
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import base64
import email
from email.mime.text import MIMEText

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.user import User, OAuthCredential, ScanResult, AuditLog
from app.services.backend_oauth import BackendOAuthService
from app.core.redis_client import get_redis_client
from app.config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class GmailOperationsService:
    """Gmail operations service for backend Gmail integration."""
    
    def __init__(self):
        self.oauth_service = BackendOAuthService()
        self.redis_client = get_redis_client()
        
        # Gmail API configuration
        self.gmail_scopes = [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.labels"
        ]

    async def setup_gmail_watch(
        self,
        db: Session,
        user_id: int,
        topic_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Set up Gmail watch for push notifications.
        
        Implements users.watch API call per specifications.
        """
        
        # Get valid access token
        access_token = await self.oauth_service.get_valid_access_token(db, user_id)
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No valid Gmail credentials found"
            )
        
        # Use configured Pub/Sub topic
        if not topic_name:
            topic_name = getattr(settings, 'PUBSUB_TOPIC', None)
            if not topic_name:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Pub/Sub topic not configured"
                )
        
        try:
            # Build Gmail service
            credentials = Credentials(token=access_token)
            service = build('gmail', 'v1', credentials=credentials)
            
            # Set up watch request
            watch_request = {
                'labelIds': ['INBOX'],  # Monitor inbox only
                'topicName': topic_name
            }
            
            result = service.users().watch(userId='me', body=watch_request).execute()
            
            # Update user with watch information
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.gmail_watch_history_id = result.get('historyId')
                user.gmail_watch_expiration = datetime.fromtimestamp(
                    int(result.get('expiration', 0)) / 1000
                )
                user.gmail_realtime_enabled = True
                db.commit()
            
            # Audit log
            await self._log_audit_event(
                db=db,
                user_id=user_id,
                action="gmail_watch_setup",
                success=True,
                metadata={
                    "history_id": result.get('historyId'),
                    "expiration": result.get('expiration'),
                    "topic": topic_name
                }
            )
            
            logger.info(f"Gmail watch set up for user {user_id}: {result}")
            return result
            
        except HttpError as e:
            error_details = json.loads(e.content.decode()) if e.content else {}
            error_message = error_details.get('error', {}).get('message', str(e))
            
            await self._log_audit_event(
                db=db,
                user_id=user_id,
                action="gmail_watch_setup",
                success=False,
                error_message=error_message
            )
            
            logger.error(f"Failed to set up Gmail watch for user {user_id}: {error_message}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to set up Gmail watch: {error_message}"
            )

    async def stop_gmail_watch(
        self,
        db: Session,
        user_id: int
    ) -> bool:
        """
        Stop Gmail watch for a user.
        """
        
        access_token = await self.oauth_service.get_valid_access_token(db, user_id)
        if not access_token:
            return False
        
        try:
            credentials = Credentials(token=access_token)
            service = build('gmail', 'v1', credentials=credentials)
            service.users().stop(userId='me').execute()
            
            # Clear watch information
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.gmail_watch_history_id = None
                user.gmail_watch_expiration = None
                user.gmail_realtime_enabled = False
                db.commit()
            
            await self._log_audit_event(
                db=db,
                user_id=user_id,
                action="gmail_watch_stop",
                success=True
            )
            
            logger.info(f"Gmail watch stopped for user {user_id}")
            return True
            
        except HttpError as e:
            error_details = json.loads(e.content.decode()) if e.content else {}
            error_message = error_details.get('error', {}).get('message', str(e))
            
            await self._log_audit_event(
                db=db,
                user_id=user_id,
                action="gmail_watch_stop",
                success=False,
                error_message=error_message
            )
            
            logger.error(f"Failed to stop Gmail watch for user {user_id}: {error_message}")
            return False

    async def fetch_email_content(
        self,
        db: Session,
        user_id: int,
        message_id: str,
        format: str = "raw"
    ) -> Dict[str, Any]:
        """
        Fetch email content using messages.get API.
        
        Implements raw MIME fetching per specifications.
        """
        
        access_token = await self.oauth_service.get_valid_access_token(db, user_id)
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No valid Gmail credentials found"
            )
        
        try:
            credentials = Credentials(token=access_token)
            service = build('gmail', 'v1', credentials=credentials)
            
            # Get message with specified format
            message = service.users().messages().get(
                userId='me',
                id=message_id,
                format=format
            ).execute()
            
            # Parse content based on format
            if format == "raw":
                # Decode raw MIME content
                raw_data = base64.urlsafe_b64decode(message['raw']).decode('utf-8')
                parsed_email = email.message_from_string(raw_data)
                
                return {
                    "message_id": message_id,
                    "thread_id": message.get('threadId'),
                    "label_ids": message.get('labelIds', []),
                    "snippet": message.get('snippet', ''),
                    "raw_content": raw_data,
                    "parsed_content": {
                        "subject": parsed_email.get('Subject', ''),
                        "from": parsed_email.get('From', ''),
                        "to": parsed_email.get('To', ''),
                        "date": parsed_email.get('Date', ''),
                        "body": self._extract_email_body(parsed_email)
                    }
                }
            else:
                # Return metadata format
                headers = {}
                if 'payload' in message and 'headers' in message['payload']:
                    for header in message['payload']['headers']:
                        headers[header['name'].lower()] = header['value']
                
                return {
                    "message_id": message_id,
                    "thread_id": message.get('threadId'),
                    "label_ids": message.get('labelIds', []),
                    "snippet": message.get('snippet', ''),
                    "headers": headers,
                    "internal_date": message.get('internalDate')
                }
                
        except HttpError as e:
            error_details = json.loads(e.content.decode()) if e.content else {}
            error_message = error_details.get('error', {}).get('message', str(e))
            
            logger.error(f"Failed to fetch email {message_id} for user {user_id}: {error_message}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to fetch email: {error_message}"
            )

    async def get_message_history(
        self,
        db: Session,
        user_id: int,
        start_history_id: Optional[str] = None,
        max_results: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get Gmail message history for processing new messages.
        """
        
        access_token = await self.oauth_service.get_valid_access_token(db, user_id)
        if not access_token:
            return []
        
        try:
            credentials = Credentials(token=access_token)
            service = build('gmail', 'v1', credentials=credentials)
            
            # Get user's last known history ID
            user = db.query(User).filter(User.id == user_id).first()
            if not start_history_id and user:
                start_history_id = user.gmail_watch_history_id
            
            if not start_history_id:
                # If no history ID, get recent messages
                return await self._get_recent_messages(service, max_results)
            
            # Get history since last known ID
            history_response = service.users().history().list(
                userId='me',
                startHistoryId=start_history_id,
                historyTypes=['messageAdded'],
                maxResults=max_results
            ).execute()
            
            new_messages = []
            for history_item in history_response.get('history', []):
                for message_added in history_item.get('messagesAdded', []):
                    message_id = message_added['message']['id']
                    label_ids = message_added['message'].get('labelIds', [])
                    
                    # Only process inbox messages
                    if 'INBOX' in label_ids:
                        new_messages.append({
                            "message_id": message_id,
                            "label_ids": label_ids,
                            "history_id": history_item.get('id')
                        })
            
            return new_messages
            
        except HttpError as e:
            logger.error(f"Failed to get message history for user {user_id}: {e}")
            return []

    async def quarantine_email(
        self,
        db: Session,
        user_id: int,
        message_id: str,
        quarantine_label: str = "PHISHING_QUARANTINE"
    ) -> bool:
        """
        Quarantine suspicious email by applying labels.
        
        Implements Gmail.modify for quarantining emails.
        """
        
        access_token = await self.oauth_service.get_valid_access_token(db, user_id)
        if not access_token:
            return False
        
        try:
            credentials = Credentials(token=access_token)
            service = build('gmail', 'v1', credentials=credentials)
            
            # Create quarantine label if it doesn't exist
            await self._ensure_quarantine_label_exists(service, quarantine_label)
            
            # Apply quarantine label and remove from inbox
            modify_request = {
                'addLabelIds': [quarantine_label],
                'removeLabelIds': ['INBOX']
            }
            
            service.users().messages().modify(
                userId='me',
                id=message_id,
                body=modify_request
            ).execute()
            
            # Audit log
            await self._log_audit_event(
                db=db,
                user_id=user_id,
                action="email_quarantined",
                success=True,
                metadata={
                    "message_id": message_id,
                    "quarantine_label": quarantine_label
                }
            )
            
            logger.info(f"Email {message_id} quarantined for user {user_id}")
            return True
            
        except HttpError as e:
            error_message = str(e)
            
            await self._log_audit_event(
                db=db,
                user_id=user_id,
                action="email_quarantine",
                success=False,
                error_message=error_message,
                metadata={"message_id": message_id}
            )
            
            logger.error(f"Failed to quarantine email {message_id} for user {user_id}: {error_message}")
            return False

    async def trigger_background_scan(
        self,
        db: Session,
        user_id: int,
        message_ids: List[str],
        priority: str = "normal"
    ) -> Dict[str, Any]:
        """
        Trigger background scanning for emails.
        
        Queues emails for processing by background workers.
        """
        
        try:
            # Create scan job data
            scan_job = {
                "user_id": user_id,
                "message_ids": message_ids,
                "priority": priority,
                "created_at": datetime.utcnow().isoformat(),
                "status": "queued"
            }
            
            # Queue job in Redis for background processing
            job_id = f"scan_{user_id}_{datetime.utcnow().timestamp()}"
            
            await self.redis_client.lpush(
                f"scan_queue_{priority}",
                json.dumps(scan_job)
            )
            
            # Store job tracking
            await self.redis_client.setex(
                f"scan_job:{job_id}",
                3600,  # 1 hour TTL
                json.dumps(scan_job)
            )
            
            # Audit log
            await self._log_audit_event(
                db=db,
                user_id=user_id,
                action="background_scan_triggered",
                success=True,
                metadata={
                    "job_id": job_id,
                    "message_count": len(message_ids),
                    "priority": priority
                }
            )
            
            logger.info(f"Background scan triggered for user {user_id}: {len(message_ids)} messages")
            
            return {
                "job_id": job_id,
                "message_count": len(message_ids),
                "status": "queued",
                "estimated_completion": "5-10 minutes"
            }
            
        except Exception as e:
            logger.error(f"Failed to trigger background scan for user {user_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to trigger background scan"
            )

    # Private helper methods
    
    def _extract_email_body(self, parsed_email) -> str:
        """Extract email body from parsed email message."""
        
        body = ""
        
        if parsed_email.is_multipart():
            for part in parsed_email.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        body += str(part.get_payload())
                elif content_type == "text/html" and "attachment" not in content_disposition and not body:
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        body = str(part.get_payload())
        else:
            try:
                body = parsed_email.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body = str(parsed_email.get_payload())
        
        return body.strip()

    async def _get_recent_messages(self, service, max_results: int) -> List[Dict[str, Any]]:
        """Get recent messages when no history ID is available."""
        
        try:
            # List recent messages
            messages_result = service.users().messages().list(
                userId='me',
                q='in:inbox',
                maxResults=max_results
            ).execute()
            
            messages = []
            for msg in messages_result.get('messages', []):
                messages.append({
                    "message_id": msg['id'],
                    "thread_id": msg.get('threadId'),
                    "label_ids": ['INBOX']  # Assume inbox since queried
                })
            
            return messages
            
        except HttpError as e:
            logger.error(f"Failed to get recent messages: {e}")
            return []

    async def _ensure_quarantine_label_exists(self, service, label_name: str):
        """Ensure quarantine label exists, create if not."""
        
        try:
            # List existing labels
            labels_result = service.users().labels().list(userId='me').execute()
            labels = labels_result.get('labels', [])
            
            # Check if quarantine label exists
            for label in labels:
                if label['name'] == label_name:
                    return label['id']
            
            # Create quarantine label
            label_object = {
                'name': label_name,
                'labelListVisibility': 'labelShow',
                'messageListVisibility': 'show'
            }
            
            created_label = service.users().labels().create(
                userId='me',
                body=label_object
            ).execute()
            
            logger.info(f"Created quarantine label: {label_name}")
            return created_label['id']
            
        except HttpError as e:
            logger.error(f"Failed to ensure quarantine label exists: {e}")
            return label_name  # Return name as fallback

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
            actor="system",
            success=success,
            metadata=metadata,
            error_message=error_message
        )
        
        db.add(audit_log)
        db.commit()


# Dependency injection
def get_gmail_operations_service() -> GmailOperationsService:
    """Dependency to get Gmail operations service."""
    return GmailOperationsService()
