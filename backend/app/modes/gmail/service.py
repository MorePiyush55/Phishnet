"""
Gmail API Service - Mode 2 (On-Demand Check)
=============================================
Handles Gmail API integration for on-demand email analysis.

This service implements the EmailFetcher interface for Gmail API-based retrieval.
Users explicitly click to check specific emails - privacy-first design.

Key Features:
- Fetch single email by Message ID
- Minimal scope (gmail.readonly only)
- Short-lived tokens (no refresh by default)
- No storage without explicit consent

Privacy Principles:
- Only fetch emails explicitly requested by user
- No background scanning or indexing
- Tokens expire after 1 hour
- Analysis results not stored unless user consents
"""

import asyncio
import base64
import email
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from app.modes.base import (
    EmailFetcher,
    FetchedEmail,
    EmailMetadata,
    ModeType,
)
from app.config.settings import get_settings
from app.config.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)


class GmailAPIService(EmailFetcher):
    """
    Gmail API-based email fetching for Mode 2 (On-Demand).
    
    This service uses the Gmail API to fetch specific messages
    that users want to check, with minimal scope and no storage.
    
    Configuration:
    - GMAIL_CLIENT_ID: OAuth client ID
    - GMAIL_CLIENT_SECRET: OAuth client secret
    """
    
    GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
    REQUIRED_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
    TOKEN_LIFETIME = 3600  # 1 hour
    
    def __init__(self):
        """Initialize Gmail API service."""
        self.client_id = getattr(settings, 'GMAIL_CLIENT_ID', None)
        self.client_secret = getattr(settings, 'GMAIL_CLIENT_SECRET', None)
        self.scopes = [self.REQUIRED_SCOPE]
        
        if not self.client_id or not self.client_secret:
            logger.warning("Gmail OAuth credentials not configured")
    
    @property
    def mode(self) -> ModeType:
        """Return the mode type this fetcher supports."""
        return ModeType.GMAIL_ONDEMAND
    
    @property
    def is_configured(self) -> bool:
        """Check if Gmail API is properly configured."""
        return bool(self.client_id and self.client_secret)
    
    async def fetch_email(self, identifier: str, **kwargs) -> Optional[FetchedEmail]:
        """
        Fetch email content by Gmail Message ID.
        
        Args:
            identifier: Gmail Message ID
            **kwargs: Required options:
                - access_token: str - Valid Gmail access token
                
        Returns:
            FetchedEmail with content and metadata, or None if not found
        """
        access_token = kwargs.get('access_token')
        if not access_token:
            logger.error("Access token required for Gmail API fetch")
            return None
        
        try:
            # Fetch raw message
            raw_message = await self._fetch_message_raw(access_token, identifier)
            if not raw_message:
                return None
            
            # Parse the email
            parsed = self._parse_email_message(raw_message)
            
            # Get raw bytes for analysis
            raw_bytes = raw_message.as_bytes()
            
            # Build EmailMetadata
            metadata = EmailMetadata(
                message_id=identifier,
                subject=parsed['subject'],
                sender=parsed['from'],
                recipients=parsed['to'] + parsed.get('cc', []),
                date=parsed.get('date'),
                size_bytes=len(raw_bytes),
                has_attachments=len(parsed['attachments']) > 0,
                attachment_count=len(parsed['attachments']),
            )
            
            # Build FetchedEmail
            return FetchedEmail(
                identifier=identifier,
                metadata=metadata,
                raw_email=raw_bytes,
                body_text=parsed['body_text'],
                body_html=parsed['body_html'],
                headers=parsed['headers'],
                attachments=parsed['attachments'],
                is_forwarded=False,  # Gmail mode doesn't handle forwarded emails
                original_email=None,
                forwarded_by=None,
            )
            
        except Exception as e:
            logger.error(f"Failed to fetch Gmail message {identifier}: {str(e)}")
            return None
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def _fetch_message_raw(
        self,
        access_token: str,
        message_id: str
    ) -> Optional[email.message.Message]:
        """
        Fetch single message from Gmail in raw format.
        
        Args:
            access_token: Valid Gmail access token
            message_id: Gmail message ID
            
        Returns:
            Parsed email.message.Message object or None
        """
        url = f"{self.GMAIL_API_BASE}/users/me/messages/{message_id}?format=raw"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url, headers=headers, timeout=30.0)
                
                if response.status_code == 404:
                    logger.warning(f"Message {message_id} not found")
                    return None
                
                if response.status_code == 401:
                    logger.error("Gmail access token expired or invalid")
                    raise ValueError("Access token expired or invalid")
                
                if response.status_code != 200:
                    logger.error(f"Gmail API error: {response.status_code} - {response.text}")
                    return None
                
                data = response.json()
                raw_message = data.get("raw")
                
                if not raw_message:
                    logger.error("No raw message data in response")
                    return None
                
                # Decode base64url
                raw_bytes = base64.urlsafe_b64decode(raw_message)
                
                # Parse MIME message
                message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
                
                logger.info(f"Successfully fetched Gmail message {message_id}")
                return message
                
            except httpx.RequestError as e:
                logger.error(f"Gmail API request failed: {e}")
                raise
    
    async def list_pending(self, limit: int = 50, **kwargs) -> List[Dict[str, Any]]:
        """
        Not applicable for on-demand mode.
        
        On-demand mode is user-driven - users explicitly select which
        emails to check. There is no concept of "pending" emails.
        
        Raises:
            NotImplementedError: Always (this is by design)
        """
        raise NotImplementedError(
            "On-demand mode does not support listing pending emails. "
            "Users must explicitly select which emails to analyze."
        )
    
    async def mark_processed(self, identifier: str, **kwargs) -> bool:
        """
        Mark email as processed.
        
        For Gmail on-demand mode, this is a no-op since we don't
        maintain server-side state for analyzed emails.
        
        Args:
            identifier: Gmail Message ID
            **kwargs: Ignored
            
        Returns:
            True (always succeeds as no-op)
        """
        logger.debug(f"Gmail on-demand: mark_processed is no-op for {identifier}")
        return True
    
    async def test_connection(self) -> bool:
        """
        Test Gmail API configuration.
        
        Note: This only checks if credentials are configured.
        Actual API connectivity requires a valid access token.
        
        Returns:
            True if OAuth credentials are configured
        """
        return self.is_configured
    
    async def fetch_message_metadata(
        self,
        access_token: str,
        message_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch message metadata only (no body content).
        
        Useful for checking if a message exists before fetching full content.
        
        Args:
            access_token: Valid Gmail access token
            message_id: Gmail message ID
            
        Returns:
            Dict with metadata or None if not found
        """
        url = f"{self.GMAIL_API_BASE}/users/me/messages/{message_id}?format=metadata"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url, headers=headers, timeout=15.0)
                
                if response.status_code != 200:
                    return None
                
                data = response.json()
                
                # Extract headers
                headers_list = data.get("payload", {}).get("headers", [])
                headers_dict = {h["name"]: h["value"] for h in headers_list}
                
                return {
                    "id": data.get("id"),
                    "thread_id": data.get("threadId"),
                    "label_ids": data.get("labelIds", []),
                    "snippet": data.get("snippet", ""),
                    "subject": headers_dict.get("Subject", ""),
                    "from": headers_dict.get("From", ""),
                    "to": headers_dict.get("To", ""),
                    "date": headers_dict.get("Date", ""),
                }
                
            except Exception as e:
                logger.error(f"Failed to fetch message metadata: {e}")
                return None
    
    def _parse_email_message(self, msg: email.message.Message) -> Dict[str, Any]:
        """
        Parse email message and extract all relevant data.
        
        Args:
            msg: email.message.Message object
            
        Returns:
            Dict with subject, from, to, body, attachments, headers
        """
        try:
            # Extract basic fields
            subject = msg.get('Subject', '')
            from_addr = parseaddr(msg.get('From', ''))[1]
            to_addrs = getaddresses([msg.get('To', '')])
            cc_addrs = getaddresses([msg.get('Cc', '')])
            
            # Parse date
            date_str = msg.get('Date', '')
            date = None
            if date_str:
                try:
                    from email.utils import parsedate_to_datetime
                    date = parsedate_to_datetime(date_str)
                except:
                    pass
            
            # Extract body
            body_text = ""
            body_html = ""
            attachments = []
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))
                    
                    # Skip attachments for body extraction
                    if "attachment" in content_disposition:
                        filename = part.get_filename() or "unnamed"
                        payload = part.get_payload(decode=True)
                        if payload:
                            attachments.append({
                                'filename': filename,
                                'content_type': content_type,
                                'size': len(payload),
                                'sha256': hashlib.sha256(payload).hexdigest()
                            })
                        continue
                    
                    if content_type == "text/plain" and not body_text:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text = payload.decode("utf-8", errors="ignore")
                    
                    elif content_type == "text/html" and not body_html:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_html = payload.decode("utf-8", errors="ignore")
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_text = payload.decode("utf-8", errors="ignore")
            
            # Extract important headers
            headers = {}
            important_headers = [
                'From', 'To', 'Cc', 'Reply-To', 'Return-Path',
                'Received', 'X-Originating-IP', 'X-Sender-IP',
                'Authentication-Results', 'Received-SPF',
                'DKIM-Signature', 'Message-ID', 'Date'
            ]
            
            for hdr in important_headers:
                value = msg.get(hdr)
                if value:
                    headers[hdr] = value
            
            return {
                'subject': subject,
                'from': from_addr,
                'to': [addr[1] for addr in to_addrs if addr[1]],
                'cc': [addr[1] for addr in cc_addrs if addr[1]],
                'date': date,
                'body_text': body_text,
                'body_html': body_html,
                'attachments': attachments,
                'headers': headers,
            }
            
        except Exception as e:
            logger.error(f"Failed to parse email: {str(e)}")
            return {
                'subject': '',
                'from': '',
                'to': [],
                'cc': [],
                'date': None,
                'body_text': '',
                'body_html': '',
                'attachments': [],
                'headers': {},
            }


# Singleton instance factory
_instance: Optional[GmailAPIService] = None

def get_gmail_service() -> GmailAPIService:
    """Get singleton Gmail API service instance."""
    global _instance
    if _instance is None:
        _instance = GmailAPIService()
    return _instance
