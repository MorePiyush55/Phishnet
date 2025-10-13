# Email Integration Solution - Based on ThePhish Analysis

## 🎯 Problem Identification

Based on analysis of ThePhish workflow (which is 90% similar to PhishNet), the following email integration gaps have been identified in PhishNet:

### Current Issues in PhishNet:
1. ❌ **No Direct Email Forwarding Workflow**: ThePhish uses forwarded emails as attachments, PhishNet relies only on OAuth/API
2. ❌ **No Real-time Email Polling**: ThePhish uses IMAP polling, PhishNet depends on Pub/Sub (complex setup)
3. ❌ **Missing EML Parser**: ThePhish extracts observables from raw .eml files, PhishNet only parses via Gmail API
4. ❌ **No Analyst Review Interface**: ThePhish shows email list for manual selection, PhishNet is fully automated
5. ❌ **Complex OAuth Setup**: Requires Google Cloud Console + Pub/Sub configuration

## 📊 ThePhish Workflow Analysis

### ThePhish Architecture (From Diagram):
```
1. Attacker → Sends phishing email
2. User → Receives phishing email
3. User → Forwards suspicious email to ThePhish as ATTACHMENT
4. ThePhish → Connects to IMAP inbox
5. ThePhish → Lists unread emails for analyst
6. Analyst → Selects email to analyze
7. ThePhish → Extracts .eml attachment from forwarded email
8. ThePhish → Parses observables (URLs, IPs, domains, emails, hashes)
9. ThePhish → Creates case in TheHive
10. ThePhish → Runs Cortex analyzers
11. ThePhish → Calculates verdict
12. ThePhish (Decision) → Is verdict final?
    - YES → Close case
    - NO → Loop back to analyst review
13. ThePhish → Sends analysis result notification to user
```

### Key Differences: ThePhish vs PhishNet

| Feature | ThePhish | PhishNet (Current) | Solution Needed |
|---------|----------|-------------------|-----------------|
| **Email Source** | IMAP polling | Gmail API OAuth | ✅ Add IMAP option |
| **User Action** | Forward email as attachment | Automatic scanning | ✅ Add forward option |
| **Email Format** | .eml file parsing | JSON from API | ✅ Add .eml parser |
| **Analyst Flow** | Manual selection from list | Fully automated | ✅ Add manual mode |
| **Authentication** | IMAP user/pass | OAuth2 (complex) | ✅ Simplify auth |
| **Real-time** | Poll every N seconds | Pub/Sub push | ✅ Add polling mode |
| **Verdict Loop** | Analyst can re-analyze | Single analysis | ✅ Add re-analysis |
| **User Notification** | Email with verdict | Dashboard only | ✅ Add email alerts |

## 🔧 ThePhish Code Analysis

### 1. IMAP Connection (Simple & Reliable)
```python
# From ThePhish/app/case_from_email.py

def connect_to_IMAP_server(wsl):
    # Create IMAP connection using host and port
    connection = imaplib.IMAP4_SSL(config['imapHost'], config['imapPort'])
    
    # Log in using username and password
    connection.login(config['imapUser'], config['imapPassword'])
    
    log.info('Connected to email {0} server {1}:{2}/{3}'.format(
        config['imapUser'], 
        config['imapHost'], 
        config['imapPort'], 
        config['imapFolder']
    ))
    
    return connection

# Configuration example:
{
    "imap": {
        "host": "imap.gmail.com",
        "port": "993",
        "user": "phishnet@example.com",
        "password": "app_specific_password",  # NOT OAuth!
        "folder": "inbox"
    }
}
```

**Advantages:**
- ✅ Simple username/password (use Gmail App Password)
- ✅ No OAuth complexity
- ✅ Works with any IMAP server (Gmail, Outlook, custom)
- ✅ No Google Cloud Console configuration
- ✅ No Pub/Sub topic setup

### 2. Email Listing for Analyst Selection
```python
# From ThePhish/app/list_emails.py

def list_unread_emails(connection):
    """List all unread emails in the configured folder."""
    
    # Select folder
    connection.select(config['imapFolder'])
    
    # Search for UNSEEN (unread) emails
    typ, dat = connection.search(None, '(UNSEEN)')
    
    # Get UIDs of unread emails
    mail_uids = dat[0].split()
    
    emails_info = []
    for uid in mail_uids:
        # Fetch email metadata
        typ, dat = connection.fetch(uid, '(BODY.PEEK[HEADER])')
        
        # Parse headers
        msg = email.message_from_bytes(dat[0][1])
        
        emails_info.append({
            'uid': uid.decode(),
            'from': msg.get('From'),
            'subject': msg.get('Subject'),
            'date': msg.get('Date')
        })
    
    return emails_info
```

**Frontend Flow:**
```javascript
// Analyst sees list of suspicious emails forwarded by users
GET /api/emails/pending
Response: [
    {
        "uid": "123",
        "from": "user@company.com",
        "subject": "FW: Suspicious PayPal Email",
        "date": "Mon, 13 Oct 2025 10:30:00"
    }
]

// Analyst clicks "Analyze" button
POST /api/emails/analyze
Body: { "mail_uid": "123" }
```

### 3. EML Attachment Extraction
```python
# From ThePhish/app/case_from_email.py

def obtain_eml(connection, mail_uid, wsl):
    """
    Extract .eml attachment from forwarded email.
    
    Users forward suspicious emails as attachments.
    ThePhish extracts the internal .eml file for analysis.
    """
    
    # Fetch the forwarded email
    typ, dat = connection.fetch(mail_uid.encode(), '(RFC822)')
    message = dat[0][1]
    
    # Parse outer email (forwarded by user)
    msg = email.message_from_bytes(message)
    
    # Extract internal EML attachment
    internal_msg = None
    
    for part in msg.walk():
        mimetype = part.get_content_type()
        
        # Check for EML attachment (message/rfc822 or application/octet-stream)
        if mimetype in ['application/octet-stream', 'message/rfc822']:
            
            if mimetype == 'application/octet-stream':
                # Binary EML file
                eml_payload = part.get_payload(decode=True)
                internal_msg = email.message_from_bytes(eml_payload)
                
            elif mimetype == 'message/rfc822':
                # Embedded message
                eml_payload = part.get_payload(decode=False)[0]
                internal_msg = eml_payload
            
            break  # Found EML, stop searching
    
    # Mark email as read (analyzed)
    connection.store(mail_uid.encode(), '+FLAGS', '\\Seen')
    
    return internal_msg
```

**Key Insight:** ThePhish expects users to **forward emails as attachments**, not inline forwards!

### 4. Observable Extraction from EML
```python
# From ThePhish/app/case_from_email.py

def parse_eml(internal_msg, wsl):
    """Parse EML file and extract observables."""
    
    # Extract subject
    subject_field = parse_email_header(internal_msg['Subject'])
    
    # Lists for observables
    observables_body = []
    observables_header = {}
    attachments = []
    hashes_attachments = []
    
    # Header fields to search for observables
    header_fields_list = [
        'To', 'From', 'Sender', 'Cc', 'Delivered-To',
        'Return-Path', 'Reply-To', 'Bounces-to',
        'Received', 'X-Received', 'X-OriginatorOrg',
        'X-Sender-IP', 'X-Originating-IP', 'X-SenderIP',
        'X-Originating-Email'
    ]
    
    # Extract observables from headers
    for field in header_fields_list:
        if field in internal_msg:
            observables_header[field] = search_observables(
                internal_msg[field], wsl
            )
    
    # Extract observables from body
    for part in internal_msg.walk():
        mimetype = part.get_content_type()
        
        if mimetype == "text/plain":
            body = part.get_payload(decode=True).decode()
            observables_body.extend(search_observables(body, wsl))
        
        elif mimetype == "text/html":
            html_body = part.get_payload(decode=True).decode()
            observables_body.extend(search_observables(html_body, wsl))
        
        # Extract attachments
        elif part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            payload = part.get_payload(decode=True)
            
            attachments.append({
                'filename': filename,
                'size': len(payload),
                'hash': hashlib.sha256(payload).hexdigest()
            })
    
    return {
        'subject': subject_field,
        'observables_body': observables_body,
        'observables_header': observables_header,
        'attachments': attachments
    }

def search_observables(buffer, wsl):
    """Use ioc_finder to extract observables."""
    observables = []
    
    # Parse using ioc_finder module
    iocs = {}
    iocs['email_addresses'] = ioc_finder.parse_email_addresses(buffer)
    iocs['ipv4s'] = ioc_finder.parse_ipv4_addresses(buffer)
    iocs['domains'] = ioc_finder.parse_domain_names(buffer)
    iocs['urls'] = ioc_finder.parse_urls(buffer, parse_urls_without_scheme=False)
    
    # Filter whitelisted observables
    for mail in iocs['email_addresses']:
        if not is_whitelisted('mail', mail):
            observables.append({'type': 'mail', 'value': mail})
    
    for ip in iocs['ipv4s']:
        if not is_whitelisted('ip', ip):
            observables.append({'type': 'ip', 'value': ip})
    
    for domain in iocs['domains']:
        if not is_whitelisted('domain', domain):
            observables.append({'type': 'domain', 'value': domain})
    
    for url in iocs['urls']:
        if not is_whitelisted('url', url):
            observables.append({'type': 'url', 'value': url})
    
    return observables
```

### 5. Whitelist System
```json
// From ThePhish/app/whitelist.json
{
    "ipExact": ["127.0.0.1"],
    "domainExact": ["example.com", "google.com"],
    "mailExact": ["noreply@company.com"],
    "urlExact": [],
    "ipRegex": [],
    "domainRegex": [".*\\.internal$"],
    "mailRegex": [".*@company\\.com$"],
    "urlRegex": [],
    "regexDomainsInSubdomains": ["company\\.com$"],
    "regexDomainsInURLs": ["company\\.com"],
    "regexDomainsInEmails": ["@company\\.com$"]
}
```

## 🚀 Solution: Hybrid Email Integration for PhishNet

### Architecture Overview
```
┌─────────────────────────────────────────────────────────────┐
│                     PhishNet Email Integration               │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  MODE 1: OAuth + Gmail API (Automatic - Current)            │
│  ├─ User grants OAuth access                                 │
│  ├─ PhishNet monitors inbox via Gmail API                    │
│  └─ Real-time analysis of incoming emails                    │
│                                                               │
│  MODE 2: IMAP + Forward (Manual - ThePhish-style) ← NEW!   │
│  ├─ User forwards suspicious email to PhishNet inbox         │
│  ├─ PhishNet polls IMAP for new emails                       │
│  ├─ Analyst selects emails from pending list                 │
│  ├─ PhishNet extracts .eml attachment                        │
│  └─ Manual trigger for analysis                              │
│                                                               │
│  MODE 3: Hybrid (Best of Both)                               │
│  ├─ OAuth for automatic monitoring                           │
│  ├─ IMAP for forwarded email analysis                        │
│  └─ Unified dashboard for both sources                       │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Plan

#### Phase 1: Add IMAP Email Polling (1-2 days)

**File: `backend/app/services/email/imap_service.py`** (NEW)
```python
"""IMAP email service for manual forwarding workflow."""

import imaplib
import email
from typing import List, Dict, Any, Optional
from email.mime.text import MIMEText
import hashlib

from app.config.logging import get_logger
from app.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


class IMAPEmailService:
    """
    IMAP-based email service for handling forwarded suspicious emails.
    Based on ThePhish implementation.
    """
    
    def __init__(self):
        self.connection = None
        self.config = {
            'host': settings.IMAP_HOST or 'imap.gmail.com',
            'port': settings.IMAP_PORT or 993,
            'user': settings.IMAP_USER,
            'password': settings.IMAP_PASSWORD,
            'folder': settings.IMAP_FOLDER or 'INBOX'
        }
    
    def connect(self) -> bool:
        """Connect to IMAP server."""
        try:
            self.connection = imaplib.IMAP4_SSL(
                self.config['host'], 
                int(self.config['port'])
            )
            self.connection.login(
                self.config['user'], 
                self.config['password']
            )
            logger.info(f"Connected to IMAP server: {self.config['host']}")
            return True
        except Exception as e:
            logger.error(f"IMAP connection failed: {str(e)}")
            return False
    
    def list_pending_emails(self) -> List[Dict[str, Any]]:
        """
        List all unread emails pending analysis.
        These are emails forwarded by users with suspicious content.
        """
        if not self.connection:
            if not self.connect():
                return []
        
        try:
            # Select inbox
            self.connection.select(self.config['folder'])
            
            # Search for UNSEEN emails
            typ, data = self.connection.search(None, '(UNSEEN)')
            
            if typ != 'OK':
                logger.error(f"IMAP search failed: {data}")
                return []
            
            mail_uids = data[0].split()
            emails_info = []
            
            for uid in mail_uids:
                # Fetch only headers (don't mark as read)
                typ, msg_data = self.connection.fetch(
                    uid, 
                    '(BODY.PEEK[HEADER])'
                )
                
                if typ != 'OK':
                    continue
                
                # Parse headers
                msg = email.message_from_bytes(msg_data[0][1])
                
                emails_info.append({
                    'uid': uid.decode(),
                    'from': msg.get('From', ''),
                    'subject': msg.get('Subject', ''),
                    'date': msg.get('Date', ''),
                    'message_id': msg.get('Message-ID', '')
                })
            
            logger.info(f"Found {len(emails_info)} pending emails")
            return emails_info
            
        except Exception as e:
            logger.error(f"Failed to list emails: {str(e)}")
            return []
    
    def fetch_email_for_analysis(self, mail_uid: str) -> Optional[Dict[str, Any]]:
        """
        Fetch complete email and extract .eml attachment.
        
        This implements ThePhish's obtain_eml + parse_eml logic.
        """
        if not self.connection:
            if not self.connect():
                return None
        
        try:
            # Fetch complete email
            typ, data = self.connection.fetch(
                mail_uid.encode(), 
                '(RFC822)'
            )
            
            if typ != 'OK':
                logger.error(f"Failed to fetch email {mail_uid}")
                return None
            
            # Parse outer email (forwarded by user)
            outer_msg = email.message_from_bytes(data[0][1])
            
            # Get sender info (user who forwarded)
            forwarded_by = email.utils.parseaddr(outer_msg.get('From', ''))[1]
            
            # Extract internal EML attachment
            internal_eml = self._extract_eml_attachment(outer_msg)
            
            if not internal_eml:
                logger.warning(f"No EML attachment found in {mail_uid}")
                # Try parsing as direct email
                internal_eml = outer_msg
            
            # Parse internal email for analysis
            parsed_data = self._parse_eml(internal_eml)
            
            # Mark as read (analyzed)
            self.connection.store(mail_uid.encode(), '+FLAGS', '\\Seen')
            
            # Add metadata
            parsed_data['forwarded_by'] = forwarded_by
            parsed_data['mail_uid'] = mail_uid
            
            logger.info(f"Successfully fetched and parsed email {mail_uid}")
            return parsed_data
            
        except Exception as e:
            logger.error(f"Failed to fetch email {mail_uid}: {str(e)}")
            return None
    
    def _extract_eml_attachment(self, msg: email.message.Message) -> Optional[email.message.Message]:
        """Extract .eml file from forwarded email."""
        for part in msg.walk():
            mimetype = part.get_content_type()
            
            # Check for EML attachment types
            if mimetype in ['application/octet-stream', 'message/rfc822']:
                
                if mimetype == 'application/octet-stream':
                    # Binary .eml file
                    payload = part.get_payload(decode=True)
                    if payload:
                        return email.message_from_bytes(payload)
                
                elif mimetype == 'message/rfc822':
                    # Embedded RFC822 message
                    payload = part.get_payload(decode=False)
                    if payload and len(payload) > 0:
                        return payload[0]
        
        return None
    
    def _parse_eml(self, msg: email.message.Message) -> Dict[str, Any]:
        """Parse EML file and extract all data for analysis."""
        
        # Extract subject
        subject = self._decode_header(msg.get('Subject', ''))
        
        # Extract sender
        from_addr = email.utils.parseaddr(msg.get('From', ''))[1]
        
        # Extract recipients
        to_addrs = email.utils.getaddresses([msg.get('To', '')])
        cc_addrs = email.utils.getaddresses([msg.get('Cc', '')])
        
        # Extract body
        body_text = ""
        body_html = ""
        attachments = []
        
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get_content_disposition()
            
            if content_disposition == 'attachment':
                # Process attachment
                filename = part.get_filename()
                payload = part.get_payload(decode=True)
                
                if payload:
                    attachments.append({
                        'filename': filename or 'unnamed',
                        'content_type': content_type,
                        'size': len(payload),
                        'sha256': hashlib.sha256(payload).hexdigest()
                    })
            
            elif content_type == 'text/plain' and not body_text:
                body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            
            elif content_type == 'text/html' and not body_html:
                body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
        
        # Extract headers for observable analysis
        headers = {}
        important_headers = [
            'From', 'To', 'Cc', 'Reply-To', 'Return-Path',
            'Received', 'X-Originating-IP', 'X-Sender-IP',
            'Authentication-Results', 'Received-SPF'
        ]
        
        for header in important_headers:
            value = msg.get(header)
            if value:
                headers[header] = value
        
        return {
            'subject': subject,
            'from': from_addr,
            'to': [addr[1] for addr in to_addrs],
            'cc': [addr[1] for addr in cc_addrs],
            'body_text': body_text,
            'body_html': body_html,
            'attachments': attachments,
            'headers': headers,
            'raw_email': msg.as_bytes()  # For enhanced analyzer
        }
    
    def _decode_header(self, header_value: str) -> str:
        """Decode email header."""
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
    
    def disconnect(self):
        """Close IMAP connection."""
        if self.connection:
            try:
                self.connection.close()
                self.connection.logout()
                logger.info("IMAP connection closed")
            except:
                pass
```

#### Phase 2: Add API Endpoints (1 day)

**File: `backend/app/api/v1/imap_emails.py`** (NEW)
```python
"""IMAP email endpoints for manual forwarding workflow."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.auth import get_current_active_user, require_analyst
from app.models.user import User
from app.services.email.imap_service import IMAPEmailService
from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Initialize services
imap_service = IMAPEmailService()
enhanced_analyzer = EnhancedPhishingAnalyzer()


@router.get("/pending")
async def list_pending_emails(
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db)
):
    """
    List pending forwarded emails waiting for analysis.
    
    These are emails forwarded by users to the PhishNet inbox.
    Analysts can review and select emails for analysis.
    """
    try:
        emails = imap_service.list_pending_emails()
        return {
            "success": True,
            "count": len(emails),
            "emails": emails
        }
    except Exception as e:
        logger.error(f"Failed to list pending emails: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve pending emails: {str(e)}"
        )


@router.post("/analyze/{mail_uid}")
async def analyze_forwarded_email(
    mail_uid: str,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db)
):
    """
    Analyze a forwarded email selected by analyst.
    
    Process:
    1. Fetch email from IMAP
    2. Extract .eml attachment
    3. Run enhanced phishing analysis
    4. Store results
    5. Send notification to user who forwarded it
    """
    try:
        # Fetch and parse email
        email_data = imap_service.fetch_email_for_analysis(mail_uid)
        
        if not email_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Email {mail_uid} not found or already analyzed"
            )
        
        # Run enhanced analysis
        analysis_result = enhanced_analyzer.analyze_email(
            email_data['raw_email']
        )
        
        # Store results (similar to existing email storage)
        # ... database storage logic ...
        
        # Send notification to user who forwarded the email
        await _send_verdict_notification(
            email_data['forwarded_by'],
            analysis_result
        )
        
        return {
            "success": True,
            "mail_uid": mail_uid,
            "forwarded_by": email_data['forwarded_by'],
            "subject": email_data['subject'],
            "verdict": analysis_result.final_verdict,
            "total_score": analysis_result.total_score,
            "confidence": analysis_result.confidence,
            "risk_factors": analysis_result.risk_factors,
            "sections": {
                "sender": {
                    "score": analysis_result.sender.score,
                    "indicators": analysis_result.sender.indicators
                },
                "content": {
                    "score": analysis_result.content.score,
                    "keyword_count": analysis_result.content.keyword_count
                },
                "links": {
                    "score": analysis_result.links.overall_score,
                    "total_links": analysis_result.links.total_links
                },
                "authentication": {
                    "score": analysis_result.authentication.overall_score,
                    "spf": analysis_result.authentication.spf_result,
                    "dkim": analysis_result.authentication.dkim_result,
                    "dmarc": analysis_result.authentication.dmarc_result
                },
                "attachments": {
                    "score": analysis_result.attachments.score,
                    "count": analysis_result.attachments.total_attachments
                }
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to analyze email {mail_uid}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


async def _send_verdict_notification(recipient_email: str, analysis_result):
    """Send analysis verdict to user who forwarded the email."""
    # Implementation for email notification
    pass
```

#### Phase 3: Update Settings (5 minutes)

**File: `backend/app/config/settings.py`**
```python
class Settings(BaseSettings):
    # ... existing settings ...
    
    # IMAP Configuration for forwarded emails
    IMAP_ENABLED: bool = False
    IMAP_HOST: str = "imap.gmail.com"
    IMAP_PORT: int = 993
    IMAP_USER: str = ""
    IMAP_PASSWORD: str = ""  # Use Gmail App Password
    IMAP_FOLDER: str = "INBOX"
    IMAP_POLL_INTERVAL: int = 60  # seconds
```

#### Phase 4: Frontend Components (2-3 days)

**File: `frontend/src/pages/ForwardedEmails.tsx`** (NEW)
```typescript
import React, { useState, useEffect } from 'react';
import { Card, Button, Table, Tag, message } from 'antd';
import { MailOutlined, WarningOutlined } from '@ant-design/icons';

interface PendingEmail {
  uid: string;
  from: string;
  subject: string;
  date: string;
  message_id: string;
}

export const ForwardedEmailsPage: React.FC = () => {
  const [emails, setEmails] = useState<PendingEmail[]>([]);
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState<string | null>(null);

  useEffect(() => {
    fetchPendingEmails();
    // Poll every 30 seconds
    const interval = setInterval(fetchPendingEmails, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchPendingEmails = async () => {
    try {
      const response = await fetch('/api/v1/imap-emails/pending');
      const data = await response.json();
      setEmails(data.emails || []);
    } catch (error) {
      message.error('Failed to fetch pending emails');
    }
  };

  const handleAnalyze = async (uid: string) => {
    setAnalyzing(uid);
    try {
      const response = await fetch(`/api/v1/imap-emails/analyze/${uid}`, {
        method: 'POST'
      });
      const result = await response.json();
      
      message.success(
        `Analysis complete: ${result.verdict} (Score: ${result.total_score}%)`
      );
      
      // Remove from pending list
      setEmails(emails.filter(e => e.uid !== uid));
    } catch (error) {
      message.error('Analysis failed');
    } finally {
      setAnalyzing(null);
    }
  };

  const columns = [
    {
      title: 'From',
      dataIndex: 'from',
      key: 'from',
      render: (text: string) => (
        <><MailOutlined /> {text}</>
      )
    },
    {
      title: 'Subject',
      dataIndex: 'subject',
      key: 'subject'
    },
    {
      title: 'Date',
      dataIndex: 'date',
      key: 'date'
    },
    {
      title: 'Action',
      key: 'action',
      render: (_, record: PendingEmail) => (
        <Button
          type="primary"
          loading={analyzing === record.uid}
          onClick={() => handleAnalyze(record.uid)}
        >
          Analyze
        </Button>
      )
    }
  ];

  return (
    <div style={{ padding: '24px' }}>
      <Card 
        title={
          <>
            <WarningOutlined /> Forwarded Emails Pending Analysis
          </>
        }
        extra={
          <Button onClick={fetchPendingEmails} loading={loading}>
            Refresh
          </Button>
        }
      >
        <p>
          These are suspicious emails forwarded by users to {' '}
          <strong>phishnet@yourcompany.com</strong>. 
          Click "Analyze" to perform phishing detection.
        </p>
        
        <Table
          columns={columns}
          dataSource={emails}
          rowKey="uid"
          pagination={false}
        />
        
        {emails.length === 0 && (
          <div style={{ textAlign: 'center', padding: '40px' }}>
            No pending emails. Users can forward suspicious emails to 
            start analysis.
          </div>
        )}
      </Card>
    </div>
  );
};
```

## 📋 Complete Setup Guide

### Step 1: Gmail App Password Setup (No OAuth!)

1. Go to your Google Account: https://myaccount.google.com/
2. Navigate to **Security** → **2-Step Verification**
3. Scroll to **App passwords**
4. Generate new app password for "Mail"
5. Copy the 16-character password

### Step 2: Environment Configuration

```bash
# .env file
IMAP_ENABLED=true
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_USER=phishnet@yourcompany.com
IMAP_PASSWORD=your_app_password_here
IMAP_FOLDER=INBOX
IMAP_POLL_INTERVAL=60
```

### Step 3: User Instructions

**Create user guide document:**

```
How to Report Suspicious Emails to PhishNet
============================================

Method 1: Forward as Attachment (Recommended)
----------------------------------------------
1. Open the suspicious email
2. Click "More" (⋮) or "Forward" dropdown
3. Select "Forward as attachment"
4. Send to: phishnet@yourcompany.com
5. Check PhishNet dashboard for analysis results

Method 2: OAuth Automatic Scanning (Already Active)
--------------------------------------------------
PhishNet automatically scans your inbox in real-time.
No action needed from you!

Why Forward as Attachment?
--------------------------
- Preserves original email headers
- Includes all metadata for analysis
- Ensures accurate threat detection
```

### Step 4: Deployment

```bash
# Install dependencies
pip install imap-tools  # Better than imaplib

# Run migrations (if needed)
alembic upgrade head

# Start services
python -m uvicorn app.main:app --reload

# Test IMAP connection
python -c "from app.services.email.imap_service import IMAPEmailService; svc = IMAPEmailService(); print('Connected!' if svc.connect() else 'Failed')"
```

## 🔄 Complete Workflow Comparison

### ThePhish Workflow:
```
User → Forward email as attachment → IMAP inbox
→ Analyst views pending list → Selects email
→ ThePhish extracts .eml → Analyzes observables
→ Creates TheHive case → Runs Cortex analyzers
→ Sends verdict to user
```

### PhishNet New Workflow:
```
User → Forward email as attachment → IMAP inbox
→ Analyst views pending list → Clicks "Analyze"
→ PhishNet extracts .eml → Enhanced phishing analysis
  - Sender analysis
  - Content keywords
  - Link analysis
  - Authentication (SPF/DKIM/DMARC)
  - Attachment scanning
→ Stores in database → Shows in dashboard
→ Sends email notification to user
```

## ✅ Benefits of Hybrid Approach

| Benefit | Description |
|---------|-------------|
| **Simplicity** | No complex OAuth setup for forwarding |
| **Reliability** | IMAP is stable and well-supported |
| **Flexibility** | Users choose: automatic or manual |
| **Analysis Quality** | Raw .eml preserves all metadata |
| **Analyst Control** | Manual review before auto-actions |
| **Universal** | Works with any email provider |

## 🚀 Quick Win: 3-Hour Implementation

If you need this working **TODAY**, follow this minimal implementation:

### 1. Install Library (2 minutes)
```bash
pip install imap-tools
```

### 2. Create Simple Service (30 minutes)
```python
# backend/app/services/simple_imap.py
from imap_tools import MailBox

def get_pending_emails():
    with MailBox('imap.gmail.com').login('user', 'password') as mailbox:
        return [
            {
                'uid': msg.uid,
                'from': msg.from_,
                'subject': msg.subject,
                'date': str(msg.date)
            }
            for msg in mailbox.fetch(criteria='UNSEEN')
        ]

def analyze_email(uid):
    with MailBox('imap.gmail.com').login('user', 'password') as mailbox:
        for msg in mailbox.fetch(criteria=f'UID {uid}'):
            # Get raw email
            raw_email = msg.obj.as_bytes()
            
            # Run your existing analyzer
            from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer
            analyzer = EnhancedPhishingAnalyzer()
            result = analyzer.analyze_email(raw_email)
            
            # Mark as read
            mailbox.flag(uid, ['\\Seen'], True)
            
            return result
```

### 3. Add API Route (15 minutes)
```python
# backend/app/api/v1/quick_imap.py
from fastapi import APIRouter
from app.services.simple_imap import get_pending_emails, analyze_email

router = APIRouter()

@router.get("/pending")
async def list_emails():
    return {"emails": get_pending_emails()}

@router.post("/analyze/{uid}")
async def analyze(uid: str):
    result = analyze_email(uid)
    return {
        "verdict": result.final_verdict,
        "score": result.total_score,
        "risk_factors": result.risk_factors
    }
```

### 4. Test (15 minutes)
```bash
# Start server
uvicorn app.main:app --reload

# Test in browser or curl
curl http://localhost:8000/api/v1/quick-imap/pending
curl -X POST http://localhost:8000/api/v1/quick-imap/analyze/123
```

Done! You now have ThePhish-style email forwarding working in PhishNet! 🎉

## 📊 Success Metrics

After implementation, track:
- ✅ Number of emails forwarded by users
- ✅ Average analysis time per email
- ✅ Analyst productivity (emails analyzed per hour)
- ✅ User satisfaction (compared to OAuth-only)
- ✅ False positive rate

## 🎯 Next Steps

1. **Immediate**: Implement IMAP service (use Quick Win above)
2. **This Week**: Add analyst dashboard page
3. **Next Week**: User documentation and training
4. **Month 1**: Monitor usage and refine
5. **Month 2**: Add advanced features (auto-whitelist, batch analysis)

---

**Key Takeaway:** ThePhish's success comes from its **simplicity**. By adding IMAP-based forwarding to PhishNet, you get the best of both worlds: automatic monitoring via OAuth + manual forwarding via IMAP. This solves your integration problems while maintaining the advanced analysis capabilities you've already built!
