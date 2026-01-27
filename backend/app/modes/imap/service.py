"""
IMAP Email Service - Mode 1 (Bulk Forward)
==========================================
Handles IMAP connection and email fetching for forwarded email analysis.

This service implements the EmailFetcher interface for IMAP-based email retrieval.
Users forward suspicious emails to a central inbox, which this service monitors.

Key Features:
- Fetch emails by UID
- List pending/recent emails
- Extract .eml attachments (forwarded emails)
- Mark emails as processed
"""

import asyncio
import email
from email import policy, header
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from imap_tools import MailBox, AND

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


class IMAPEmailService(EmailFetcher):
    """
    IMAP-based email fetching for Mode 1 (Bulk Forward).
    
    This service connects to an IMAP inbox where users forward
    suspicious emails for automatic analysis.
    
    Configuration is read from settings:
    - IMAP_HOST: Server hostname (default: imap.gmail.com)
    - IMAP_USER: Username/email
    - IMAP_PASSWORD: Password or app password
    - IMAP_FOLDER: Folder to monitor (default: INBOX)
    """
    
    def __init__(
        self,
        host: str = None,
        user: str = None,
        password: str = None,
        folder: str = None
    ):
        """
        Initialize IMAP service.
        
        Args:
            host: IMAP server hostname (overrides settings)
            user: IMAP username (overrides settings)
            password: IMAP password (overrides settings)
            folder: IMAP folder to monitor (overrides settings)
        """
        self.host = host or getattr(settings, 'IMAP_HOST', 'imap.gmail.com')
        self.user = user or getattr(settings, 'IMAP_USER', '')
        self.password = password or getattr(settings, 'IMAP_PASSWORD', '')
        self.folder = folder or getattr(settings, 'IMAP_FOLDER', 'INBOX')
        
        if not self.user or not self.password:
            logger.warning("IMAP credentials not configured")
    
    @property
    def mode(self) -> ModeType:
        """Return the mode type this fetcher supports."""
        return ModeType.IMAP_BULK
    
    @property
    def is_configured(self) -> bool:
        """Check if IMAP is properly configured."""
        return bool(self.user and self.password)
    
    async def fetch_email(self, identifier: str, **kwargs) -> Optional[FetchedEmail]:
        """
        Fetch email content by IMAP UID.
        
        Process:
        1. Fetch email from IMAP by UID
        2. Extract .eml attachment if present (forwarded email)
        3. Parse email content, headers, attachments
        4. Return structured FetchedEmail
        
        Args:
            identifier: IMAP UID of the email
            **kwargs: Additional options (mark_read: bool)
            
        Returns:
            FetchedEmail with content and metadata, or None if not found
        """
        if not self.is_configured:
            logger.error("IMAP not configured")
            return None
        
        mark_read = kwargs.get('mark_read', True)
        
        try:
            # Run synchronous IMAP operations in thread pool
            return await asyncio.to_thread(
                self._fetch_email_sync, identifier, mark_read
            )
        except Exception as e:
            logger.error(f"Failed to fetch email {identifier}: {str(e)}")
            return None
    
    def _fetch_email_sync(self, uid: str, mark_read: bool = True) -> Optional[FetchedEmail]:
        """Synchronous email fetch implementation."""
        try:
            with MailBox(self.host).login(self.user, self.password, self.folder) as mailbox:
                for msg in mailbox.fetch(AND(uid=uid)):
                    # Get who forwarded this email
                    forwarded_by = msg.from_
                    
                    # Try to extract .eml attachment (ThePhish-style forwarding)
                    internal_email = None
                    raw_email = None
                    is_forwarded = False
                    
                    # Check attachments for .eml file
                    for att in msg.attachments:
                        is_eml = (
                            att.content_type in ['message/rfc822', 'application/rfc822'] or
                            att.filename.lower().endswith('.eml') or
                            (att.content_type == 'application/octet-stream' and 
                             att.filename.lower().endswith('.eml'))
                        )
                        
                        if is_eml:
                            try:
                                payload = att.payload
                                if not payload:
                                    logger.warning(f"Empty payload for EML attachment in message {uid}")
                                    continue
                                
                                internal_email = BytesParser(policy=policy.default).parsebytes(payload)
                                raw_email = payload
                                is_forwarded = True
                                logger.info(f"Extracted .eml attachment from forwarded email {uid}")
                                break
                            except Exception as e:
                                logger.warning(f"Failed to parse EML attachment: {str(e)}")
                    
                    # If no EML attachment, use the email itself
                    if not internal_email:
                        logger.info(f"No .eml attachment found, analyzing email directly")
                        raw_email = msg.obj.as_bytes()
                        internal_email = msg.obj
                    
                    # Parse the email for analysis
                    parsed = self._parse_email_message(internal_email)
                    
                    # Build EmailMetadata
                    metadata = EmailMetadata(
                        message_id=parsed['message_id'],
                        subject=parsed['subject'],
                        sender=parsed['from'],
                        recipients=parsed['to'] + parsed.get('cc', []),
                        date=msg.date if msg.date else None,
                        size_bytes=len(raw_email) if raw_email else 0,
                        has_attachments=len(parsed['attachments']) > 0,
                        attachment_count=len(parsed['attachments']),
                    )
                    
                    # Build FetchedEmail
                    fetched = FetchedEmail(
                        identifier=uid,
                        metadata=metadata,
                        raw_email=raw_email,
                        body_text=parsed['body_text'],
                        body_html=parsed['body_html'],
                        headers=parsed['headers'],
                        attachments=parsed['attachments'],
                        is_forwarded=is_forwarded,
                        original_email=raw_email if is_forwarded else None,
                        forwarded_by=forwarded_by if is_forwarded else None,
                    )
                    
                    # Mark as read if requested
                    if mark_read:
                        mailbox.flag(uid, ['\\Seen'], True)
                        logger.debug(f"Marked email {uid} as read")
                    
                    return fetched
                
                logger.warning(f"Email with UID {uid} not found")
                return None
                
        except Exception as e:
            logger.error(f"Failed to fetch email {uid}: {str(e)}")
            return None
    
    async def list_pending(self, limit: int = 50, **kwargs) -> List[Dict[str, Any]]:
        """
        List pending emails for analysis.
        
        By default returns recent emails (both read and unread) for robust
        polling that handles accidentally opened emails.
        
        Args:
            limit: Maximum number of emails to return
            **kwargs: Additional options
                - unread_only: bool - Only return unread emails
                
        Returns:
            List of email metadata dicts
        """
        if not self.is_configured:
            logger.error("IMAP not configured")
            return []
        
        unread_only = kwargs.get('unread_only', False)
        
        try:
            return await asyncio.to_thread(
                self._list_pending_sync, limit, unread_only
            )
        except Exception as e:
            logger.error(f"Failed to list pending emails: {str(e)}")
            return []
    
    def _list_pending_sync(self, limit: int, unread_only: bool) -> List[Dict[str, Any]]:
        """Synchronous list pending implementation."""
        try:
            with MailBox(self.host).login(self.user, self.password, self.folder) as mailbox:
                emails = []
                
                if unread_only:
                    # Fetch only unread emails
                    for msg in mailbox.fetch(AND(seen=False)):
                        if len(emails) >= limit:
                            break
                        emails.append(self._msg_to_dict(msg))
                else:
                    # Fetch recent emails (reverse order for newest first)
                    for msg in mailbox.fetch(limit=limit, reverse=True):
                        emails.append(self._msg_to_dict(msg))
                
                logger.info(f"Found {len(emails)} {'unread' if unread_only else 'recent'} emails")
                return emails
                
        except Exception as e:
            logger.error(f"Failed to list emails: {str(e)}")
            return []
    
    def _msg_to_dict(self, msg) -> Dict[str, Any]:
        """Convert imap_tools message to dict."""
        return {
            'uid': msg.uid,
            'from': msg.from_,
            'subject': msg.subject,
            'date': msg.date.isoformat() if msg.date else None,
            'message_id': msg.headers.get('message-id', [''])[0],
            'size': msg.size,
            'flags': list(msg.flags),
            'is_read': '\\Seen' in msg.flags,
        }
    
    async def mark_processed(self, identifier: str, **kwargs) -> bool:
        """
        Mark email as processed by setting the \\Seen flag.
        
        Args:
            identifier: IMAP UID
            **kwargs: Additional options (move_to_folder: str)
            
        Returns:
            True if successful
        """
        if not self.is_configured:
            return False
        
        try:
            return await asyncio.to_thread(
                self._mark_processed_sync, identifier, kwargs.get('move_to_folder')
            )
        except Exception as e:
            logger.error(f"Failed to mark email {identifier} as processed: {str(e)}")
            return False
    
    def _mark_processed_sync(self, uid: str, move_to_folder: str = None) -> bool:
        """Synchronous mark processed implementation."""
        try:
            with MailBox(self.host).login(self.user, self.password, self.folder) as mailbox:
                mailbox.flag(uid, ['\\Seen'], True)
                
                if move_to_folder:
                    mailbox.move(uid, move_to_folder)
                    logger.info(f"Moved email {uid} to {move_to_folder}")
                
                return True
        except Exception as e:
            logger.error(f"Failed to mark email {uid}: {str(e)}")
            return False
    
    async def test_connection(self) -> bool:
        """
        Test IMAP connection.
        
        Returns:
            True if connection is healthy
        """
        if not self.is_configured:
            logger.error("IMAP credentials not configured")
            return False
        
        try:
            return await asyncio.to_thread(self._test_connection_sync)
        except Exception as e:
            logger.error(f"IMAP connection test failed: {str(e)}")
            return False
    
    def _test_connection_sync(self) -> bool:
        """Synchronous connection test."""
        try:
            with MailBox(self.host).login(self.user, self.password):
                logger.info("IMAP connection test successful")
                return True
        except Exception as e:
            logger.error(f"IMAP connection failed: {str(e)}")
            return False
    
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
            subject = self._decode_header(msg.get('Subject', ''))
            from_addr = parseaddr(msg.get('From', ''))[1]
            to_addrs = getaddresses([msg.get('To', '')])
            cc_addrs = getaddresses([msg.get('Cc', '')])
            message_id = msg.get('Message-ID', '') or ''
            
            # Extract body
            body_text = ""
            body_html = ""
            attachments = []
            
            # Walk through email parts
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = part.get_content_disposition()
                    
                    if content_disposition == 'attachment':
                        # Process attachment
                        filename = part.get_filename() or 'unnamed'
                        payload = part.get_payload(decode=True)
                        
                        if payload:
                            attachments.append({
                                'filename': filename,
                                'content_type': content_type,
                                'size': len(payload),
                                'sha256': hashlib.sha256(payload).hexdigest()
                            })
                    
                    elif content_type == 'text/plain' and not body_text:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body_text = payload.decode('utf-8', errors='ignore')
                        except:
                            body_text = str(part.get_payload())
                    
                    elif content_type == 'text/html' and not body_html:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body_html = payload.decode('utf-8', errors='ignore')
                        except:
                            body_html = str(part.get_payload())
            else:
                # Single part email
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body_text = payload.decode('utf-8', errors='ignore')
                except:
                    body_text = str(msg.get_payload())
            
            # Extract important headers for analysis
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
            
            # Extract organization domain from sender
            org_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else 'unknown'
            
            return {
                'message_id': message_id,
                'subject': subject,
                'from': from_addr,
                'to': [addr[1] for addr in to_addrs if addr[1]],
                'cc': [addr[1] for addr in cc_addrs if addr[1]],
                'body_text': body_text,
                'body_html': body_html,
                'attachments': attachments,
                'headers': headers,
                'org_domain': org_domain,
            }
            
        except Exception as e:
            logger.error(f"Failed to parse email message: {str(e)}")
            return {
                'message_id': '',
                'subject': 'Parse Error',
                'from': '',
                'to': [],
                'cc': [],
                'body_text': '',
                'body_html': '',
                'attachments': [],
                'headers': {},
                'org_domain': 'unknown',
            }
    
    def _decode_header(self, header_value: str) -> str:
        """Decode email header value."""
        if not header_value:
            return ''
        
        try:
            decoded_parts = header.decode_header(header_value)
            decoded_str = []
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_str.append(part.decode(encoding, errors='ignore'))
                    else:
                        decoded_str.append(part.decode('utf-8', errors='ignore'))
                else:
                    decoded_str.append(str(part))
            
            return ''.join(decoded_str)
        except Exception as e:
            logger.warning(f"Failed to decode header: {str(e)}")
            return str(header_value)


# Backward compatibility alias
QuickIMAPService = IMAPEmailService


# Singleton instance factory
_instance: Optional[IMAPEmailService] = None

def get_imap_service() -> IMAPEmailService:
    """Get singleton IMAP service instance."""
    global _instance
    if _instance is None:
        _instance = IMAPEmailService()
    return _instance
