"""
Quick IMAP Email Service - ThePhish-style Implementation
Simple IMAP-based email forwarding for PhishNet
"""

from imap_tools import MailBox, AND
from typing import List, Dict, Any, Optional
import email
from email import policy
from email.parser import BytesParser
import hashlib
from datetime import datetime

from app.config.settings import get_settings
from app.config.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)


class QuickIMAPService:
    """
    Simple IMAP service for handling forwarded suspicious emails.
    Based on ThePhish workflow - users forward emails as attachments.
    """
    
    def __init__(self):
        # IMAP configuration from settings
        self.host = getattr(settings, 'IMAP_HOST', 'imap.gmail.com')
        self.user = getattr(settings, 'IMAP_USER', '')
        self.password = getattr(settings, 'IMAP_PASSWORD', '')
        self.folder = getattr(settings, 'IMAP_FOLDER', 'INBOX')
        
        if not self.user or not self.password:
            logger.warning("IMAP credentials not configured")
    
    def get_pending_emails(self) -> List[Dict[str, Any]]:
        """
        Get list of unread forwarded emails waiting for analysis.
        
        Returns:
            List of email metadata dicts with uid, from, subject, date
        """
        if not self.user or not self.password:
            logger.error("IMAP not configured")
            return []
        
        try:
            with MailBox(self.host).login(self.user, self.password, self.folder) as mailbox:
                pending_emails = []
                
                # Fetch all unread emails
                for msg in mailbox.fetch(AND(seen=False)):
                    pending_emails.append({
                        'uid': msg.uid,
                        'from': msg.from_,
                        'subject': msg.subject,
                        'date': msg.date.isoformat() if msg.date else None,
                        'message_id': msg.headers.get('message-id', [''])[0],
                        'size': msg.size
                    })
                
                logger.info(f"Found {len(pending_emails)} pending forwarded emails")
                return pending_emails
                
        except Exception as e:
            logger.error(f"Failed to fetch pending emails: {str(e)}")
            return []

    def get_recent_emails(self, limit: int = 15) -> List[Dict[str, Any]]:
        """
        Get list of recent emails (both READ and UNREAD).
        Used for robust polling that handles accidentally opened emails.
        
        Args:
            limit: Number of recent emails to fetch
        
        Returns:
            List of email metadata
        """
        if not self.user or not self.password:
            logger.error("IMAP not configured")
            return []
        
        try:
            with MailBox(self.host).login(self.user, self.password, self.folder) as mailbox:
                recent_emails = []
                
                # Fetch recent emails (reverse order to get newest first)
                for msg in mailbox.fetch(limit=limit, reverse=True):
                    recent_emails.append({
                        'uid': msg.uid,
                        'from': msg.from_,
                        'subject': msg.subject,
                        'date': msg.date.isoformat() if msg.date else None,
                        'message_id': msg.headers.get('message-id', [''])[0],
                        'size': msg.size,
                        'flags': list(msg.flags)  # \\Seen, etc.
                    })
                
                logger.info(f"Found {len(recent_emails)} recent emails (limit={limit})")
                return recent_emails
                
        except Exception as e:
            logger.error(f"Failed to fetch recent emails: {str(e)}")
            return []
    
    def fetch_email_for_analysis(self, uid: str) -> Optional[Dict[str, Any]]:
        """
        Fetch email by UID and extract data for analysis.
        
        Process:
        1. Fetch email from IMAP
        2. Extract .eml attachment if present (forwarded email)
        3. Parse email content, headers, attachments
        4. Return structured data for phishing analysis
        
        Args:
            uid: Email UID from IMAP
            
        Returns:
            Dict with parsed email data or None if failed
        """
        if not self.user or not self.password:
            logger.error("IMAP not configured")
            return None
        
        try:
            with MailBox(self.host).login(self.user, self.password, self.folder) as mailbox:
                # Fetch specific email by UID
                for msg in mailbox.fetch(AND(uid=uid)):
                    
                    # Get who forwarded this email
                    forwarded_by = msg.from_
                    
                    # Try to extract .eml attachment (ThePhish-style forwarding)
                    internal_email = None
                    raw_email = None
                    
                    # Check attachments for .eml file
                    for att in msg.attachments:
                        # Check if attachment is EML file (message/rfc822 or .eml extension)
                        is_eml = (
                            att.content_type in ['message/rfc822', 'application/rfc822'] or
                            att.filename.lower().endswith('.eml') or
                            (att.content_type == 'application/octet-stream' and att.filename.lower().endswith('.eml'))
                        )
                        
                        if is_eml:
                            # Parse attached email
                            try:
                                # Some clients send nested messages in different encodings
                                payload = att.payload
                                if not payload:
                                    logger.warning(f"Empty payload for EML attachment in message {uid}")
                                    continue
                                    
                                internal_email = BytesParser(policy=policy.default).parsebytes(payload)
                                raw_email = payload
                                logger.info(f"Extracted .eml attachment from forwarded email {uid}")
                                break
                            except Exception as e:
                                logger.warning(f"Failed to parse EML attachment: {str(e)}")
                    
                    # If no EML attachment, use the email itself
                    if not internal_email:
                        logger.info(f"No .eml attachment found, analyzing forwarded email directly")
                        raw_email = msg.obj.as_bytes()
                        internal_email = msg.obj
                    
                    # Parse the email for analysis
                    parsed_data = self._parse_email_message(internal_email)
                    
                    # Add metadata
                    parsed_data['forwarded_by'] = forwarded_by
                    parsed_data['mail_uid'] = uid
                    parsed_data['raw_email'] = raw_email
                    parsed_data['received_date'] = msg.date
                    
                    # Mark as read (analyzed)
                    mailbox.flag(uid, ['\\Seen'], True)
                    logger.info(f"Marked email {uid} as analyzed")
                    
                    return parsed_data
                
                logger.warning(f"Email with UID {uid} not found")
                return None
                
        except Exception as e:
            logger.error(f"Failed to fetch email {uid}: {str(e)}")
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
            subject = self._decode_header(msg.get('Subject', ''))
            from_addr = email.utils.parseaddr(msg.get('From', ''))[1]
            to_addrs = email.utils.getaddresses([msg.get('To', '')])
            cc_addrs = email.utils.getaddresses([msg.get('Cc', '')])
            
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
                            body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except:
                            body_text = str(part.get_payload())
                    
                    elif content_type == 'text/html' and not body_html:
                        try:
                            body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except:
                            body_html = str(part.get_payload())
            else:
                # Single part email
                try:
                    body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    body_text = str(msg.get_payload())
            
            # Extract important headers for analysis
            headers = {}
            important_headers = [
                'From', 'To', 'Cc', 'Reply-To', 'Return-Path',
                'Received', 'X-Originating-IP', 'X-Sender-IP',
                'Authentication-Results', 'Received-SPF',
                'Message-ID', 'Date'
            ]
            
            for header in important_headers:
                value = msg.get(header)
                if value:
                    headers[header] = value
            
            # Extract organization from sender (domain-based)
            org_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else 'unknown'
            
            return {
                'subject': subject,
                'from': from_addr,
                'to': [addr[1] for addr in to_addrs if addr[1]],
                'cc': [addr[1] for addr in cc_addrs if addr[1]],
                'body_text': body_text,
                'body_html': body_html,
                'attachments': attachments,
                'headers': headers,
                'org_domain': org_domain
            }
            
        except Exception as e:
            logger.error(f"Failed to parse email message: {str(e)}")
            return {
                'subject': 'Parse Error',
                'from': '',
                'to': [],
                'cc': [],
                'body_text': '',
                'body_html': '',
                'attachments': [],
                'headers': {}
            }
    
    def _decode_header(self, header_value: str) -> str:
        """Decode email header value."""
        if not header_value:
            return ''
        
        try:
            decoded_parts = email.header.decode_header(header_value)
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
    
    def test_connection(self) -> bool:
        """
        Test IMAP connection.
        
        Returns:
            True if connection successful, False otherwise
        """
        if not self.user or not self.password:
            logger.error("IMAP credentials not configured")
            return False
        
        try:
            with MailBox(self.host).login(self.user, self.password):
                logger.info("IMAP connection test successful")
                return True
        except Exception as e:
            logger.error(f"IMAP connection test failed: {str(e)}")
            return False
