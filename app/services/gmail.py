"""Gmail API service for email actions."""

import json
from typing import List, Dict, Any, Optional
import base64
from datetime import datetime, timezone

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from app.config.logging import get_logger

logger = get_logger(__name__)


class GmailService:
    """Service for Gmail API operations."""
    
    def __init__(self):
        self.service = None
        self.credentials = None
        
        # Gmail API scopes
        self.scopes = [
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/gmail.labels'
        ]
        
    async def initialize(self, credentials_data: Dict[str, Any] = None):
        """Initialize Gmail service with user credentials."""
        try:
            if credentials_data:
                self.credentials = Credentials.from_authorized_user_info(
                    credentials_data, self.scopes
                )
            
            if not self.credentials or not self.credentials.valid:
                if self.credentials and self.credentials.expired and self.credentials.refresh_token:
                    self.credentials.refresh(Request())
                else:
                    # Would need OAuth flow for new users
                    logger.warning("Gmail credentials not available - using mock mode")
                    return False
            
            self.service = build('gmail', 'v1', credentials=self.credentials)
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Gmail service: {str(e)}")
            return False
    
    async def get_or_create_label(self, label_name: str) -> Optional[str]:
        """Get or create a Gmail label."""
        try:
            # List existing labels
            results = self.service.users().labels().list(userId='me').execute()
            labels = results.get('labels', [])
            
            # Check if label exists
            for label in labels:
                if label['name'] == label_name:
                    return label['id']
            
            # Create new label
            label_object = {
                'name': label_name,
                'labelListVisibility': 'labelShow',
                'messageListVisibility': 'show',
                'type': 'user'
            }
            
            created_label = self.service.users().labels().create(
                userId='me', body=label_object
            ).execute()
            
            logger.info(f"Created Gmail label: {label_name}")
            return created_label['id']
            
        except HttpError as e:
            logger.error(f"Failed to get/create label {label_name}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error with label {label_name}: {str(e)}")
            return None
    
    async def apply_label(self, message_id: str, label_name: str) -> Dict[str, Any]:
        """Apply a label to a Gmail message."""
        try:
            # Get or create label
            label_id = await self.get_or_create_label(label_name)
            if not label_id:
                return {'success': False, 'error': 'Failed to get/create label'}
            
            # Apply label to message
            modify_request = {
                'addLabelIds': [label_id]
            }
            
            result = self.service.users().messages().modify(
                userId='me',
                id=message_id,
                body=modify_request
            ).execute()
            
            return {
                'success': True,
                'message_id': message_id,
                'label_id': label_id,
                'label_name': label_name,
                'result': result
            }
            
        except HttpError as e:
            logger.error(f"Failed to apply label {label_name} to message {message_id}: {str(e)}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error applying label: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    async def remove_label(self, message_id: str, label_name: str) -> Dict[str, Any]:
        """Remove a label from a Gmail message."""
        try:
            # Get label ID
            label_id = await self.get_or_create_label(label_name)
            if not label_id:
                return {'success': False, 'error': 'Label not found'}
            
            # Remove label from message
            modify_request = {
                'removeLabelIds': [label_id]
            }
            
            result = self.service.users().messages().modify(
                userId='me',
                id=message_id,
                body=modify_request
            ).execute()
            
            return {
                'success': True,
                'message_id': message_id,
                'label_id': label_id,
                'label_name': label_name,
                'result': result
            }
            
        except HttpError as e:
            logger.error(f"Failed to remove label {label_name} from message {message_id}: {str(e)}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error removing label: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    async def get_message(self, message_id: str) -> Dict[str, Any]:
        """Get a Gmail message by ID."""
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            return {
                'success': True,
                'message': message
            }
            
        except HttpError as e:
            logger.error(f"Failed to get message {message_id}: {str(e)}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error getting message: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    async def search_messages(self, query: str, max_results: int = 100) -> List[Dict[str, Any]]:
        """Search Gmail messages."""
        try:
            results = self.service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            
            # Get full message details
            detailed_messages = []
            for message in messages[:10]:  # Limit to avoid rate limits
                msg_result = await self.get_message(message['id'])
                if msg_result['success']:
                    detailed_messages.append(msg_result['message'])
            
            return detailed_messages
            
        except HttpError as e:
            logger.error(f"Failed to search messages: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error searching messages: {str(e)}")
            return []
    
    async def quarantine_message(self, message_id: str, reason: str = "Phishing detected") -> Dict[str, Any]:
        """Quarantine a message by applying quarantine label."""
        result = await self.apply_label(message_id, "PhishNet/Quarantine")
        
        if result['success']:
            # Optionally move to a specific folder
            # Add INBOX removal if needed
            pass
        
        result['action'] = 'quarantine'
        result['reason'] = reason
        
        return result
    
    async def unquarantine_message(self, message_id: str) -> Dict[str, Any]:
        """Unquarantine a message by removing quarantine label."""
        result = await self.remove_label(message_id, "PhishNet/Quarantine")
        
        result['action'] = 'unquarantine'
        
        return result
    
    async def create_filter(self, criteria: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Gmail filter."""
        try:
            filter_object = {
                'criteria': criteria,
                'action': action
            }
            
            created_filter = self.service.users().settings().filters().create(
                userId='me',
                body=filter_object
            ).execute()
            
            return {
                'success': True,
                'filter': created_filter
            }
            
        except HttpError as e:
            logger.error(f"Failed to create filter: {str(e)}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error creating filter: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def extract_email_data(self, gmail_message: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant email data from Gmail message."""
        try:
            headers = {}
            payload = gmail_message.get('payload', {})
            
            # Extract headers
            for header in payload.get('headers', []):
                headers[header['name'].lower()] = header['value']
            
            # Extract body
            body_text = ""
            body_html = ""
            
            if payload.get('body', {}).get('data'):
                # Simple text email
                body_text = base64.urlsafe_b64decode(
                    payload['body']['data']
                ).decode('utf-8', errors='ignore')
            
            elif payload.get('parts'):
                # Multipart email
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain' and part.get('body', {}).get('data'):
                        body_text = base64.urlsafe_b64decode(
                            part['body']['data']
                        ).decode('utf-8', errors='ignore')
                    elif part['mimeType'] == 'text/html' and part.get('body', {}).get('data'):
                        body_html = base64.urlsafe_b64decode(
                            part['body']['data']
                        ).decode('utf-8', errors='ignore')
            
            return {
                'message_id': gmail_message['id'],
                'thread_id': gmail_message['threadId'],
                'subject': headers.get('subject', ''),
                'sender': headers.get('from', ''),
                'recipient': headers.get('to', ''),
                'date': headers.get('date', ''),
                'body_text': body_text,
                'body_html': body_html,
                'headers': headers,
                'label_ids': gmail_message.get('labelIds', [])
            }
            
        except Exception as e:
            logger.error(f"Failed to extract email data: {str(e)}")
            return {}


class MockGmailService(GmailService):
    """Mock Gmail service for testing/demo purposes."""
    
    def __init__(self):
        super().__init__()
        self.mock_labels = {}
        self.mock_messages = {}
        
    async def initialize(self, credentials_data: Dict[str, Any] = None):
        """Mock initialization always succeeds."""
        logger.info("Using mock Gmail service")
        return True
    
    async def get_or_create_label(self, label_name: str) -> str:
        """Mock label creation."""
        if label_name not in self.mock_labels:
            label_id = f"label_{len(self.mock_labels) + 1}"
            self.mock_labels[label_name] = label_id
            logger.info(f"Mock created label: {label_name} -> {label_id}")
        
        return self.mock_labels[label_name]
    
    async def apply_label(self, message_id: str, label_name: str) -> Dict[str, Any]:
        """Mock label application."""
        label_id = await self.get_or_create_label(label_name)
        
        if message_id not in self.mock_messages:
            self.mock_messages[message_id] = {'labels': []}
        
        if label_id not in self.mock_messages[message_id]['labels']:
            self.mock_messages[message_id]['labels'].append(label_id)
        
        logger.info(f"Mock applied label {label_name} to message {message_id}")
        
        return {
            'success': True,
            'message_id': message_id,
            'label_id': label_id,
            'label_name': label_name,
            'mock': True
        }
    
    async def remove_label(self, message_id: str, label_name: str) -> Dict[str, Any]:
        """Mock label removal."""
        label_id = await self.get_or_create_label(label_name)
        
        if message_id in self.mock_messages:
            labels = self.mock_messages[message_id].get('labels', [])
            if label_id in labels:
                labels.remove(label_id)
        
        logger.info(f"Mock removed label {label_name} from message {message_id}")
        
        return {
            'success': True,
            'message_id': message_id,
            'label_id': label_id,
            'label_name': label_name,
            'mock': True
        }
