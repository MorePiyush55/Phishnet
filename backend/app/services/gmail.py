"""Gmail API integration for email ingestion and monitoring."""

import base64
import json
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
from email.mime.text import MIMEText

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db
from app.models.user import User
from app.models.email import Email, EmailStatus
from app.orchestrator.utils import email_orchestrator

logger = get_logger(__name__)


class GmailService:
    """Gmail API service for email ingestion."""
    
    def __init__(self):
        """Initialize Gmail service."""
        self.scopes = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/gmail.labels'
        ]
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
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
                prompt='consent'  # Force consent to get refresh token
            )
            
            return auth_url
            
        except Exception as e:
            logger.error(f"Failed to generate OAuth URL: {e}")
            raise
    
    async def handle_oauth_callback(self, code: str, state: str) -> Dict[str, Any]:
        """Handle OAuth callback and store credentials."""
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
            
            # Store credentials securely
            with next(get_db()) as db:
                user = db.query(User).filter(User.id == user_id).first()
                if user:
                    # Encrypt and store credentials
                    user.gmail_credentials = self._encrypt_credentials(credentials.to_json())
                    user.email_monitoring_enabled = True
                    db.commit()
                    
                    # Set up Gmail watch for real-time notifications
                    await self.setup_gmail_watch(user_id, credentials)
                    
                    logger.info(f"Gmail integration successful for user {user_id}")
                    return {"status": "success", "message": "Gmail connected successfully"}
                else:
                    return {"status": "error", "message": "User not found"}
                
        except Exception as e:
            logger.error(f"Gmail OAuth callback failed: {e}")
            return {"status": "error", "message": "Failed to connect Gmail"}
    
    async def setup_gmail_watch(self, user_id: int, credentials: Credentials):
        """Set up Gmail push notifications for real-time monitoring."""
        try:
            service = build('gmail', 'v1', credentials=credentials)
            
            # Set up watch request for inbox
            watch_request = {
                'labelIds': ['INBOX'],
                'topicName': f'projects/{settings.GOOGLE_CLOUD_PROJECT}/topics/gmail-notifications'
            }
            
            response = service.users().watch(userId='me', body=watch_request).execute()
            
            # Store watch details
            with next(get_db()) as db:
                user = db.query(User).filter(User.id == user_id).first()
                if user:
                    user.gmail_watch_expiration = datetime.fromtimestamp(
                        int(response['expiration']) / 1000
                    )
                    db.commit()
            
            logger.info(f"Gmail watch setup successful for user {user_id}")
            return response
            
        except HttpError as e:
            logger.error(f"Failed to setup Gmail watch: {e}")
            raise
    
    async def process_gmail_webhook(self, pub_sub_message: Dict[str, Any]):
        """Process Gmail webhook notification from Pub/Sub."""
        try:
            # Decode Pub/Sub message
            data = base64.b64decode(pub_sub_message['data']).decode('utf-8')
            message_data = json.loads(data)
            
            email_address = message_data.get('emailAddress')
            history_id = message_data.get('historyId')
            
            # Find user by email
            with next(get_db()) as db:
                user = db.query(User).filter(User.email == email_address).first()
                if not user or not user.gmail_credentials:
                    logger.warning(f"No user found or no credentials for {email_address}")
                    return
                
                # Get user's Gmail credentials
                credentials = self._decrypt_credentials(user.gmail_credentials)
                
                # Fetch new messages since last history ID
                await self.fetch_gmail_history(user.id, credentials, history_id)
                
        except Exception as e:
            logger.error(f"Failed to process Gmail webhook: {e}")
    
    async def fetch_gmail_history(self, user_id: int, credentials: Credentials, start_history_id: str):
        """Fetch Gmail history and process new messages."""
        try:
            if credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
                # Update stored credentials
                with next(get_db()) as db:
                    user = db.query(User).filter(User.id == user_id).first()
                    if user:
                        user.gmail_credentials = self._encrypt_credentials(credentials.to_json())
                        db.commit()
            
            service = build('gmail', 'v1', credentials=credentials)
            
            # Get history
            history_response = service.users().history().list(
                userId='me',
                startHistoryId=start_history_id,
                labelId='INBOX'
            ).execute()
            
            history = history_response.get('history', [])
            
            for history_record in history:
                messages_added = history_record.get('messagesAdded', [])
                
                for message_added in messages_added:
                    message_id = message_added['message']['id']
                    
                    # Check if we already processed this message
                    with next(get_db()) as db:
                        existing_email = db.query(Email).filter(
                            Email.gmail_msg_id == message_id,
                            Email.user_id == user_id
                        ).first()
                        
                        if not existing_email:
                            await self.ingest_email(user_id, service, message_id)
            
        except HttpError as e:
            logger.error(f"Failed to fetch Gmail history: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in fetch_gmail_history: {e}")
    
    async def ingest_email(self, user_id: int, service, message_id: str):
        """Ingest a single email message."""
        try:
            # Get full message
            message = service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            # Extract email data
            email_data = self._extract_email_data(message)
            
            # Check for duplicates using content hash
            with next(get_db()) as db:
                existing_email = db.query(Email).filter(
                    Email.content_hash == email_data['content_hash']
                ).first()
                
                if existing_email:
                    logger.debug(f"Email already exists: {message_id}")
                    return
                
                # Create email record
                email_record = Email(
                    user_id=user_id,
                    gmail_msg_id=message_id,
                    thread_id=email_data['thread_id'],
                    sender=email_data['sender'],
                    recipients=json.dumps(email_data['recipients']),
                    subject=email_data['subject'],
                    received_at=email_data['received_at'],
                    raw_headers=json.dumps(email_data['headers']),
                    raw_html=email_data['html_content'],
                    raw_text=email_data['text_content'],
                    content_hash=email_data['content_hash'],
                    size_bytes=email_data['size_bytes'],
                    status=EmailStatus.PENDING
                )
                
                db.add(email_record)
                db.commit()
                db.refresh(email_record)
                
                # Send to orchestrator for processing
                await email_orchestrator.process_email(email_record.id)
                
                logger.info(f"Ingested email {message_id} for user {user_id}")
                
        except Exception as e:
            logger.error(f"Failed to ingest email {message_id}: {e}")
    
    def _extract_email_data(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Extract email data from Gmail API response."""
        payload = message['payload']
        headers = {h['name'].lower(): h['value'] for h in payload.get('headers', [])}
        
        # Extract metadata
        subject = headers.get('subject', '')
        sender = headers.get('from', '')
        recipients = [headers.get('to', '')]
        if headers.get('cc'):
            recipients.append(headers.get('cc'))
        if headers.get('bcc'):
            recipients.append(headers.get('bcc'))
        
        # Parse date
        date_str = headers.get('date', '')
        received_at = self._parse_email_date(date_str)
        
        # Extract content
        html_content = ""
        text_content = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                content_type = part.get('mimeType', '')
                body_data = part.get('body', {}).get('data', '')
                
                if body_data:
                    decoded_content = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                    
                    if content_type == 'text/html':
                        html_content += decoded_content
                    elif content_type == 'text/plain':
                        text_content += decoded_content
        else:
            # Single part message
            content_type = payload.get('mimeType', '')
            body_data = payload.get('body', {}).get('data', '')
            
            if body_data:
                decoded_content = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                
                if content_type == 'text/html':
                    html_content = decoded_content
                elif content_type == 'text/plain':
                    text_content = decoded_content
        
        # Create content hash
        content_for_hash = f"{subject}{sender}{text_content or html_content}"
        content_hash = hashlib.sha256(content_for_hash.encode('utf-8')).hexdigest()
        
        # Calculate size
        size_bytes = message.get('sizeEstimate', 0)
        
        return {
            'thread_id': message.get('threadId', ''),
            'subject': subject,
            'sender': sender,
            'recipients': recipients,
            'received_at': received_at,
            'headers': dict(headers),
            'html_content': html_content,
            'text_content': text_content,
            'content_hash': content_hash,
            'size_bytes': size_bytes
        }
    
    def _parse_email_date(self, date_str: str) -> datetime:
        """Parse email date string to datetime."""
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str)
        except Exception:
            return datetime.utcnow()
    
    def _encrypt_credentials(self, credentials_json: str) -> str:
        """Encrypt credentials for secure storage."""
        # In production, use proper encryption (Fernet, etc.)
        # For now, we'll store as-is but this should be encrypted
        return credentials_json
    
    def _decrypt_credentials(self, encrypted_credentials: str) -> Credentials:
        """Decrypt stored credentials."""
        # In production, decrypt the credentials
        credentials_data = json.loads(encrypted_credentials)
        return Credentials.from_authorized_user_info(credentials_data)
    
    async def scan_recent_emails(self, user_id: int, max_results: int = 10) -> List[Dict[str, Any]]:
        """Scan recent emails for a user."""
        try:
            with next(get_db()) as db:
                user = db.query(User).filter(User.id == user_id).first()
                if not user or not user.gmail_credentials:
                    raise ValueError("No Gmail credentials found")
                
                credentials = self._decrypt_credentials(user.gmail_credentials)
                
                if credentials.expired and credentials.refresh_token:
                    credentials.refresh(Request())
                    user.gmail_credentials = self._encrypt_credentials(credentials.to_json())
                    db.commit()
                
                service = build('gmail', 'v1', credentials=credentials)
                
                # Get recent messages
                results = service.users().messages().list(
                    userId='me',
                    maxResults=max_results,
                    q='in:inbox'
                ).execute()
                
                messages = results.get('messages', [])
                scan_results = []
                
                for message in messages:
                    try:
                        await self.ingest_email(user_id, service, message['id'])
                        scan_results.append({
                            'message_id': message['id'],
                            'status': 'processed'
                        })
                    except Exception as e:
                        logger.error(f"Failed to process message {message['id']}: {e}")
                        scan_results.append({
                            'message_id': message['id'],
                            'status': 'error',
                            'error': str(e)
                        })
                
                user.last_email_scan = datetime.utcnow()
                db.commit()
                
                logger.info(f"Scanned {len(messages)} emails for user {user_id}")
                return scan_results
                
        except Exception as e:
            logger.error(f"Failed to scan emails: {e}")
            raise


# Global Gmail service instance
gmail_service = GmailService()
