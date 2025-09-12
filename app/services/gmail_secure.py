"""Production-ready Gmail service with OAuth, encryption, and Pub/Sub."""

import base64
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import asyncio
import email
from email.mime.text import MIMEText
import logging

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.cloud import pubsub_v1
from cryptography.fernet import Fernet
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db
from app.models.user import User
from app.models.email_scan import EmailScanRequest, ScanStatus, AuditLog, UserConsent
from app.core.redis_client import redis_client

logger = get_logger(__name__)


class SecureGmailService:
    """Production-ready Gmail service with comprehensive security."""
    
    def __init__(self):
        """Initialize Gmail service with encryption and Pub/Sub."""
        self.scopes = [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/gmail.modify"
        ]
        self.encryption_key = self._get_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Initialize Pub/Sub client
        if settings.ENVIRONMENT == "production":
            self.publisher_client = pubsub_v1.PublisherClient()
            self.subscriber_client = pubsub_v1.SubscriberClient()
        else:
            # Use emulator for development
            import os
            os.environ["PUBSUB_EMULATOR_HOST"] = settings.PUBSUB_EMULATOR_HOST or "localhost:8085"
            self.publisher_client = pubsub_v1.PublisherClient()
            self.subscriber_client = pubsub_v1.SubscriberClient()
    
    def _get_encryption_key(self) -> bytes:
        """Get encryption key from settings (must be 32 bytes)."""
        key = settings.ENCRYPTION_KEY.encode()
        if len(key) != 32:
            # Generate a proper key from the provided key
            return hashlib.sha256(key).digest()
        return key
    
    def _encrypt_credentials(self, credentials_json: str) -> str:
        """Encrypt OAuth credentials for secure storage."""
        try:
            encrypted = self.cipher_suite.encrypt(credentials_json.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Failed to encrypt credentials: {e}")
            raise
    
    def _decrypt_credentials(self, encrypted_credentials: str) -> Credentials:
        """Decrypt stored OAuth credentials."""
        try:
            encrypted_data = base64.b64decode(encrypted_credentials.encode())
            decrypted = self.cipher_suite.decrypt(encrypted_data)
            credentials_data = json.loads(decrypted.decode())
            return Credentials.from_authorized_user_info(credentials_data)
        except Exception as e:
            logger.error(f"Failed to decrypt credentials: {e}")
            raise
    
    async def generate_oauth_url(self, user_id: int, redirect_uri: str) -> Tuple[str, str]:
        """Generate OAuth URL with CSRF protection."""
        try:
            # Create flow
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": settings.GMAIL_CLIENT_ID,
                        "client_secret": settings.GMAIL_CLIENT_SECRET,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [redirect_uri]
                    }
                },
                scopes=self.scopes
            )
            flow.redirect_uri = redirect_uri
            
            # Generate state with user ID and timestamp for security
            state_data = {
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat(),
                "csrf_token": hashlib.sha256(f"{user_id}-{datetime.utcnow()}".encode()).hexdigest()[:16]
            }
            state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()
            
            # Generate authorization URL
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                state=state,
                prompt='consent'  # Force consent screen for clarity
            )
            
            # Store CSRF token in Redis for validation
            await redis_client.setex(
                f"oauth_csrf:{user_id}", 
                300,  # 5 minutes
                state_data["csrf_token"]
            )
            
            logger.info(f"Generated OAuth URL for user {user_id}")
            return auth_url, state_data["csrf_token"]
            
        except Exception as e:
            logger.error(f"Failed to generate OAuth URL: {e}")
            raise
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def handle_oauth_callback(
        self, 
        code: str, 
        state: str, 
        user_id: int,
        ip_address: str = None,
        user_agent: str = None
    ) -> Dict[str, Any]:
        """Handle OAuth callback with security validation."""
        try:
            # Decode and validate state
            try:
                state_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
                stated_user_id = state_data["user_id"]
                csrf_token = state_data["csrf_token"]
                timestamp_str = state_data["timestamp"]
            except Exception as e:
                logger.error(f"Invalid state parameter: {e}")
                raise ValueError("Invalid state parameter")
            
            # Validate user ID matches
            if stated_user_id != user_id:
                logger.error(f"User ID mismatch: {stated_user_id} != {user_id}")
                raise ValueError("Invalid state parameter")
            
            # Validate CSRF token
            stored_csrf = await redis_client.get(f"oauth_csrf:{user_id}")
            if not stored_csrf or stored_csrf.decode() != csrf_token:
                logger.error(f"CSRF token validation failed for user {user_id}")
                raise ValueError("Invalid CSRF token")
            
            # Clean up CSRF token
            await redis_client.delete(f"oauth_csrf:{user_id}")
            
            # Validate timestamp (not older than 10 minutes)
            state_time = datetime.fromisoformat(timestamp_str)
            if datetime.utcnow() - state_time > timedelta(minutes=10):
                logger.error(f"State expired for user {user_id}")
                raise ValueError("State expired")
            
            # Exchange code for tokens
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
            
            # Get tokens
            flow.fetch_token(code=code)
            credentials = flow.credentials
            
            # Validate token by making a test API call
            await self._validate_token(credentials)
            
            # Get user info from Gmail API
            service = build('gmail', 'v1', credentials=credentials)
            profile = service.users().getProfile(userId='me').execute()
            gmail_address = profile.get('emailAddress')
            
            # Store credentials and update user
            async with get_db() as db:
                user = db.query(User).filter(User.id == user_id).first()
                if not user:
                    raise ValueError("User not found")
                
                # Encrypt and store credentials
                encrypted_creds = self._encrypt_credentials(credentials.to_json())
                user.gmail_credentials = encrypted_creds
                user.email_monitoring_enabled = True
                user.last_email_scan = datetime.utcnow()
                
                # Store consent record
                consent = UserConsent(
                    user_id=user_id,
                    consent_type="gmail_scanning",
                    granted=True,
                    scopes=self.scopes,
                    purposes=["email_threat_analysis", "phishing_detection"],
                    consent_version="1.0",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    retention_period_days=365  # 1 year default
                )
                db.add(consent)
                
                # Log audit event
                audit = AuditLog(
                    user_id=user_id,
                    action="oauth_grant",
                    resource_type="gmail_credentials",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={
                        "gmail_address": gmail_address,
                        "scopes": self.scopes,
                        "consent_granted": True
                    },
                    legal_basis="consent",
                    data_processed=["email_metadata", "oauth_tokens"]
                )
                db.add(audit)
                
                db.commit()
            
            # Set up Gmail watch for real-time notifications
            await self._setup_gmail_watch(user_id, credentials)
            
            logger.info(f"OAuth flow completed successfully for user {user_id}")
            return {
                "success": True,
                "gmail_address": gmail_address,
                "scopes": self.scopes,
                "watch_enabled": True
            }
            
        except Exception as e:
            logger.error(f"OAuth callback failed for user {user_id}: {e}")
            
            # Log failed attempt
            async with get_db() as db:
                audit = AuditLog(
                    user_id=user_id,
                    action="oauth_grant",
                    resource_type="gmail_credentials",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    error_message=str(e),
                    details={"error": str(e)}
                )
                db.add(audit)
                db.commit()
            
            raise
    
    async def _validate_token(self, credentials: Credentials) -> bool:
        """Validate OAuth token by making a test API call."""
        try:
            service = build('gmail', 'v1', credentials=credentials)
            profile = service.users().getProfile(userId='me').execute()
            return bool(profile.get('emailAddress'))
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return False
    
    async def _setup_gmail_watch(self, user_id: int, credentials: Credentials) -> bool:
        """Set up Gmail push notifications via Pub/Sub."""
        try:
            service = build('gmail', 'v1', credentials=credentials)
            
            # Create Pub/Sub topic if it doesn't exist
            topic_name = f"projects/{settings.GOOGLE_CLOUD_PROJECT_ID}/topics/gmail-notifications"
            
            try:
                self.publisher_client.create_topic(request={"name": topic_name})
                logger.info(f"Created Pub/Sub topic: {topic_name}")
            except Exception as e:
                if "already exists" not in str(e).lower():
                    logger.error(f"Failed to create Pub/Sub topic: {e}")
            
            # Set up Gmail watch
            watch_request = {
                'labelIds': ['INBOX'],
                'topicName': topic_name
            }
            
            watch_response = service.users().watch(userId='me', body=watch_request).execute()
            
            # Store watch info in Redis for tracking
            watch_data = {
                "user_id": user_id,
                "history_id": watch_response.get('historyId'),
                "expiration": watch_response.get('expiration')
            }
            await redis_client.setex(
                f"gmail_watch:{user_id}",
                86400 * 7,  # 7 days
                json.dumps(watch_data)
            )
            
            logger.info(f"Gmail watch set up for user {user_id}, history_id: {watch_response.get('historyId')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set up Gmail watch for user {user_id}: {e}")
            return False
    
    async def process_pubsub_notification(self, message_data: Dict[str, Any]) -> bool:
        """Process Gmail Pub/Sub notification."""
        try:
            # Decode message
            if 'data' in message_data:
                decoded_data = base64.b64decode(message_data['data']).decode('utf-8')
                notification = json.loads(decoded_data)
            else:
                notification = message_data
            
            email_address = notification.get('emailAddress')
            history_id = notification.get('historyId')
            
            if not email_address or not history_id:
                logger.error(f"Invalid notification data: {notification}")
                return False
            
            # Find user by Gmail address
            async with get_db() as db:
                user = db.query(User).filter(User.email == email_address).first()
                if not user or not user.gmail_credentials:
                    logger.warning(f"No user found or no credentials for {email_address}")
                    return False
                
                # Get stored watch data
                watch_data_raw = await redis_client.get(f"gmail_watch:{user.id}")
                if not watch_data_raw:
                    logger.warning(f"No watch data found for user {user.id}")
                    return False
                
                watch_data = json.loads(watch_data_raw.decode())
                last_history_id = watch_data.get('history_id')
                
                # Decrypt credentials
                credentials = self._decrypt_credentials(user.gmail_credentials)
                
                # Process new messages
                await self._fetch_and_queue_new_messages(
                    user.id, 
                    credentials, 
                    last_history_id, 
                    history_id
                )
                
                # Update watch data
                watch_data['history_id'] = history_id
                await redis_client.setex(
                    f"gmail_watch:{user.id}",
                    86400 * 7,  # 7 days
                    json.dumps(watch_data)
                )
                
                return True
                
        except Exception as e:
            logger.error(f"Failed to process Pub/Sub notification: {e}")
            return False
    
    async def _fetch_and_queue_new_messages(
        self,
        user_id: int,
        credentials: Credentials,
        start_history_id: str,
        end_history_id: str
    ) -> int:
        """Fetch new messages and queue them for processing."""
        try:
            # Refresh token if needed
            if credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
                
                # Update stored credentials
                async with get_db() as db:
                    user = db.query(User).filter(User.id == user_id).first()
                    if user:
                        user.gmail_credentials = self._encrypt_credentials(credentials.to_json())
                        db.commit()
            
            service = build('gmail', 'v1', credentials=credentials)
            
            # Get history
            history_response = service.users().history().list(
                userId='me',
                startHistoryId=start_history_id,
                historyTypes=['messageAdded']
            ).execute()
            
            history = history_response.get('history', [])
            messages_queued = 0
            
            for history_record in history:
                messages_added = history_record.get('messagesAdded', [])
                
                for message_added in messages_added:
                    message_id = message_added['message']['id']
                    
                    # Check if already processed
                    async with get_db() as db:
                        existing = db.query(EmailScanRequest).filter(
                            EmailScanRequest.gmail_message_id == message_id,
                            EmailScanRequest.user_id == user_id
                        ).first()
                        
                        if not existing:
                            # Queue message for processing
                            await self._queue_email_for_processing(user_id, message_id, credentials)
                            messages_queued += 1
            
            logger.info(f"Queued {messages_queued} new messages for user {user_id}")
            return messages_queued
            
        except Exception as e:
            logger.error(f"Failed to fetch new messages for user {user_id}: {e}")
            return 0
    
    async def _queue_email_for_processing(
        self,
        user_id: int,
        message_id: str,
        credentials: Credentials
    ) -> bool:
        """Queue individual email for processing."""
        try:
            # Get minimal message data for metadata
            service = build('gmail', 'v1', credentials=credentials)
            message = service.users().messages().get(
                userId='me',
                id=message_id,
                format='metadata',
                metadataHeaders=['From', 'To', 'Subject', 'Date']
            ).execute()
            
            # Extract metadata (no PII content)
            headers = {h['name']: h['value'] for h in message.get('payload', {}).get('headers', [])}
            
            sender_email = headers.get('From', '')
            sender_domain = sender_email.split('@')[-1] if '@' in sender_email else None
            subject = headers.get('Subject', '')
            date_str = headers.get('Date', '')
            
            # Create content hash for deduplication
            content_hash = hashlib.sha256(f"{message_id}:{subject}:{sender_email}".encode()).hexdigest()
            
            # Parse date
            try:
                from email.utils import parsedate_to_datetime
                received_at = parsedate_to_datetime(date_str) if date_str else datetime.utcnow()
            except:
                received_at = datetime.utcnow()
            
            # Create scan request
            scan_request_id = f"scan_{user_id}_{message_id}_{int(datetime.utcnow().timestamp())}"
            
            async with get_db() as db:
                scan_request = EmailScanRequest(
                    user_id=user_id,
                    gmail_message_id=message_id,
                    gmail_thread_id=message.get('threadId'),
                    sender_domain=sender_domain,
                    subject_hash=hashlib.sha256(subject.encode()).hexdigest() if subject else None,
                    content_hash=content_hash,
                    received_at=received_at,
                    size_bytes=message.get('sizeEstimate'),
                    scan_request_id=scan_request_id,
                    status=ScanStatus.PENDING,
                    priority=5  # Default priority
                )
                db.add(scan_request)
                db.commit()
                db.refresh(scan_request)
                
                # Queue for processing in Redis
                job_data = {
                    "scan_request_id": str(scan_request.id),
                    "user_id": user_id,
                    "gmail_message_id": message_id,
                    "priority": scan_request.priority
                }
                
                # Add to high-priority queue
                await redis_client.lpush("email_processing_queue", json.dumps(job_data))
                
                logger.info(f"Queued email {message_id} for user {user_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to queue email {message_id} for user {user_id}: {e}")
            return False
    
    async def fetch_email_content(self, user_id: int, message_id: str) -> Optional[Dict[str, Any]]:
        """Fetch full email content for analysis."""
        try:
            async with get_db() as db:
                user = db.query(User).filter(User.id == user_id).first()
                if not user or not user.gmail_credentials:
                    raise ValueError("User not found or no Gmail credentials")
                
                credentials = self._decrypt_credentials(user.gmail_credentials)
                
                # Refresh token if needed
                if credentials.expired and credentials.refresh_token:
                    credentials.refresh(Request())
                    user.gmail_credentials = self._encrypt_credentials(credentials.to_json())
                    db.commit()
                
                service = build('gmail', 'v1', credentials=credentials)
                
                # Get full message
                message = service.users().messages().get(
                    userId='me',
                    id=message_id,
                    format='full'
                ).execute()
                
                # Parse email content
                email_data = self._parse_gmail_message(message)
                
                return email_data
                
        except Exception as e:
            logger.error(f"Failed to fetch email content for {message_id}: {e}")
            return None
    
    def _parse_gmail_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Gmail message into structured data."""
        payload = message.get('payload', {})
        headers = {h['name']: h['value'] for h in payload.get('headers', [])}
        
        # Extract text and HTML content
        text_content = ""
        html_content = ""
        attachments = []
        links = []
        
        def extract_content(part):
            nonlocal text_content, html_content, attachments, links
            
            mime_type = part.get('mimeType', '')
            
            if mime_type == 'text/plain':
                data = part.get('body', {}).get('data', '')
                if data:
                    decoded = base64.urlsafe_b64decode(data.encode()).decode('utf-8', errors='ignore')
                    text_content += decoded
                    
            elif mime_type == 'text/html':
                data = part.get('body', {}).get('data', '')
                if data:
                    decoded = base64.urlsafe_b64decode(data.encode()).decode('utf-8', errors='ignore')
                    html_content += decoded
                    
            elif 'attachment' in part.get('body', {}):
                attachments.append({
                    'filename': part.get('filename', 'unknown'),
                    'mime_type': mime_type,
                    'size': part.get('body', {}).get('size', 0)
                })
            
            # Recursively process parts
            for subpart in part.get('parts', []):
                extract_content(subpart)
        
        extract_content(payload)
        
        # Extract links from HTML content
        if html_content:
            import re
            link_pattern = r'href=[\'"]?(https?://[^\'">\s]+)'
            links = re.findall(link_pattern, html_content, re.IGNORECASE)
        
        return {
            'message_id': message['id'],
            'thread_id': message.get('threadId'),
            'label_ids': message.get('labelIds', []),
            'headers': headers,
            'text_content': text_content,
            'html_content': html_content,
            'attachments': attachments,
            'links': list(set(links)),  # Remove duplicates
            'size_estimate': message.get('sizeEstimate', 0)
        }
    
    async def apply_label(
        self, 
        user_id: int, 
        message_id: str, 
        label: str,
        action_type: str = "quarantine"
    ) -> bool:
        """Apply Gmail label (for quarantine/approval)."""
        try:
            async with get_db() as db:
                user = db.query(User).filter(User.id == user_id).first()
                if not user or not user.gmail_credentials:
                    return False
                
                credentials = self._decrypt_credentials(user.gmail_credentials)
                
                # Refresh token if needed
                if credentials.expired and credentials.refresh_token:
                    credentials.refresh(Request())
                    user.gmail_credentials = self._encrypt_credentials(credentials.to_json())
                    db.commit()
                
                service = build('gmail', 'v1', credentials=credentials)
                
                # Apply label
                body = {
                    'addLabelIds': [label],
                }
                
                service.users().messages().modify(
                    userId='me',
                    id=message_id,
                    body=body
                ).execute()
                
                logger.info(f"Applied label '{label}' to message {message_id} for user {user_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to apply label to message {message_id}: {e}")
            return False
    
    async def revoke_access(self, user_id: int, ip_address: str = None) -> bool:
        """Revoke Gmail access and clean up data."""
        try:
            async with get_db() as db:
                user = db.query(User).filter(User.id == user_id).first()
                if not user:
                    return False
                
                # Revoke OAuth token if possible
                if user.gmail_credentials:
                    try:
                        credentials = self._decrypt_credentials(user.gmail_credentials)
                        if credentials.refresh_token:
                            # Revoke token at Google
                            async with httpx.AsyncClient() as client:
                                await client.post(
                                    "https://oauth2.googleapis.com/revoke",
                                    params={"token": credentials.refresh_token}
                                )
                    except Exception as e:
                        logger.error(f"Failed to revoke token at Google: {e}")
                
                # Clear user data
                user.gmail_credentials = None
                user.email_monitoring_enabled = False
                user.gmail_watch_expiration = None
                
                # Update consent records
                consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id,
                    UserConsent.consent_type == "gmail_scanning"
                ).first()
                if consent:
                    consent.granted = False
                    consent.revoked_at = datetime.utcnow()
                
                # Log audit event
                audit = AuditLog(
                    user_id=user_id,
                    action="oauth_revoke",
                    resource_type="gmail_credentials",
                    ip_address=ip_address,
                    details={"revoked_by": "user"},
                    legal_basis="consent_withdrawal"
                )
                db.add(audit)
                
                db.commit()
                
                # Clean up Redis data
                await redis_client.delete(f"gmail_watch:{user_id}")
                
                logger.info(f"Revoked Gmail access for user {user_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to revoke access for user {user_id}: {e}")
            return False


# Global service instance
gmail_service = SecureGmailService()
