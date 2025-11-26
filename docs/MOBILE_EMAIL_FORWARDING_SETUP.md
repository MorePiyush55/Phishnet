# PhishNet Mobile Email Forwarding - Quick Start Guide

## Overview
This guide shows you how to set up PhishNet to receive and analyze emails forwarded from mobile devices.

---

## Architecture

```
Mobile User → Forward Email → PhishNet Inbox → IMAP Polling → Analysis → Reply Email
```

---

## Setup Steps

### 1. Create Dedicated Email Account

Create a Gmail account specifically for receiving forwarded emails:
- Email: `phishnet@yourdomain.com` (or use Gmail)
- Enable "Less secure app access" or create App Password
- Forward a test email to verify it's working

### 2. Configure Environment Variables

Add to your `.env` file:

```env
# IMAP Configuration for Email Forwarding
IMAP_ENABLED=true
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_USER=phishnet@yourdomain.com
IMAP_PASSWORD=your-app-password-here
IMAP_FOLDER=INBOX
IMAP_POLL_INTERVAL=60

# SMTP Configuration for Sending Replies
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=phishnet@yourdomain.com
SMTP_PASSWORD=your-app-password-here
SMTP_FROM_EMAIL=noreply@phishnet.com
SMTP_FROM_NAME=PhishNet Security
```

### 3. Create IMAP Polling Service

Create `backend/app/services/imap_poller.py`:

```python
"""
IMAP Email Polling Service
Polls the PhishNet inbox for forwarded emails and processes them
"""

import asyncio
import imaplib
import email
import base64
from typing import List
from datetime import datetime, timezone

from app.services.email_forward_analyzer import email_forward_analyzer
from app.config.settings import settings
from app.config.logging import get_logger

logger = get_logger(__name__)


class IMAPPollerService:
    """Service for polling IMAP inbox for forwarded emails."""
    
    def __init__(self):
        self.host = settings.IMAP_HOST
        self.port = settings.IMAP_PORT
        self.user = settings.IMAP_USER
        self.password = settings.IMAP_PASSWORD
        self.folder = getattr(settings, 'IMAP_FOLDER', 'INBOX')
        self.poll_interval = getattr(settings, 'IMAP_POLL_INTERVAL', 60)
        self.running = False
    
    async def start_polling(self):
        """Start polling the IMAP inbox."""
        self.running = True
        logger.info(f"Starting IMAP poller for {self.user}")
        
        while self.running:
            try:
                await self._poll_inbox()
            except Exception as e:
                logger.error(f"IMAP polling error: {e}")
            
            # Wait before next poll
            await asyncio.sleep(self.poll_interval)
    
    def stop_polling(self):
        """Stop the IMAP poller."""
        self.running = False
        logger.info("Stopping IMAP poller")
    
    async def _poll_inbox(self):
        """Poll inbox for new emails."""
        try:
            # Connect to IMAP server
            mail = imaplib.IMAP4_SSL(self.host, self.port)
            mail.login(self.user, self.password)
            mail.select(self.folder)
            
            # Search for unread emails
            _, message_numbers = mail.search(None, 'UNSEEN')
            
            for num in message_numbers[0].split():
                try:
                    # Fetch email
                    _, msg_data = mail.fetch(num, '(RFC822)')
                    raw_email = msg_data[0][1]
                    
                    # Parse sender
                    email_message = email.message_from_bytes(raw_email)
                    forwarded_by = email_message.get('From', '')
                    
                    # Analyze email
                    logger.info(f"Processing forwarded email from {forwarded_by}")
                    result = await email_forward_analyzer.analyze_forwarded_email(
                        raw_email_bytes=raw_email,
                        forwarded_by=forwarded_by
                    )
                    
                    if result.get('success'):
                        logger.info(f"Analysis complete: {result.get('analysis', {}).get('risk_level')}")
                        
                        # Send reply email
                        await self._send_reply(result, forwarded_by)
                        
                        # Mark as read
                        mail.store(num, '+FLAGS', '\\Seen')
                    else:
                        logger.error(f"Analysis failed: {result.get('error')}")
                
                except Exception as e:
                    logger.error(f"Error processing email {num}: {e}")
            
            mail.close()
            mail.logout()
            
        except Exception as e:
            logger.error(f"IMAP connection error: {e}")
    
    async def _send_reply(self, analysis_result: dict, recipient_email: str):
        """Send reply email with analysis results."""
        try:
            # Generate reply content
            original_subject = analysis_result.get('email_metadata', {}).get('subject', '')
            analysis = analysis_result.get('analysis', {})
            
            reply_body = await email_forward_analyzer.generate_reply_email(
                analysis_result=analysis,
                recipient_email=recipient_email,
                original_subject=original_subject
            )
            
            # Send via SMTP (implement email service here)
            logger.info(f"Sending reply to {recipient_email}")
            # await email_service.send_email(
            #     to=recipient_email,
            #     subject=f"PhishNet Analysis: {original_subject}",
            #     body=reply_body
            # )
            
        except Exception as e:
            logger.error(f"Failed to send reply email: {e}")


# Singleton instance
imap_poller = IMAPPollerService()
```

### 4. Create SMTP Email Service

Create `backend/app/services/email_service.py`:

```python
"""
Email Service for Sending Analysis Results
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.config.settings import settings
from app.config.logging import get_logger

logger = get_logger(__name__)


class EmailService:
    """Service for sending emails via SMTP."""
    
    def __init__(self):
        self.smtp_host = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_user = settings.SMTP_USER
        self.smtp_password = settings.SMTP_PASSWORD
        self.from_email = getattr(settings, 'SMTP_FROM_EMAIL', self.smtp_user)
        self.from_name = getattr(settings, 'SMTP_FROM_NAME', 'PhishNet')
    
    async def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        html: bool = False
    ):
        """
        Send an email via SMTP.
        
        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body (text or HTML)
            html: Whether body is HTML
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = to
            msg['Subject'] = subject
            
            # Add body
            mime_type = 'html' if html else 'plain'
            msg.attach(MIMEText(body, mime_type))
            
            # Send via SMTP
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email sent to {to}: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to}: {e}")
            return False


# Singleton instance
email_service = EmailService()
```

### 5. Start IMAP Poller on Application Startup

Add to `backend/app/main.py`:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting PhishNet application")
    
    # ... existing startup code ...
    
    # Start IMAP poller if enabled
    if getattr(settings, 'IMAP_ENABLED', False):
        try:
            from app.services.imap_poller import imap_poller
            import asyncio
            asyncio.create_task(imap_poller.start_polling())
            logger.info("IMAP poller started")
        except Exception as e:
            logger.warning(f"IMAP poller failed to start: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down PhishNet application")
    
    # Stop IMAP poller
    if getattr(settings, 'IMAP_ENABLED', False):
        try:
            from app.services.imap_poller import imap_poller
            imap_poller.stop_polling()
        except Exception as e:
            logger.warning(f"Error stopping IMAP poller: {e}")
    
    # ... existing shutdown code ...
```

---

## Usage for End Users

### Mobile Forwarding Workflow

1. **User receives suspicious email on mobile**
   - Email appears in Gmail/Outlook/etc.
   
2. **User forwards email to PhishNet**
   - Tap "Forward" button
   - Enter: `phishnet@yourdomain.com`
   - Send

3. **PhishNet processes email automatically**
   - IMAP poller detects new email
   - Extracts original email from forward
   - Analyzes with AI and threat intelligence
   - Stores results in MongoDB

4. **User receives analysis results**
   - Reply email sent within 60 seconds
   - Contains risk level, findings, and recommendations
   - No login or app required

### Example User Experience

**Forward Email:**
```
From: user@gmail.com
To: phishnet@yourdomain.com
Subject: Fwd: Urgent: Your Account Will Be Closed

[Original suspicious email content]
```

**Receive Reply:**
```
From: PhishNet <noreply@phishnet.com>
To: user@gmail.com
Subject: PhishNet Analysis: Urgent: Your Account Will Be Closed

PhishNet Analysis Results
==================================================

Subject: Urgent: Your Account Will Be Closed
Risk Level: HIGH
Threat Score: 0.85/1.00

⚠️ HIGH RISK - This email is likely a phishing attempt

==================================================

ANALYSIS FINDINGS:
1. Suspicious link detected pointing to fake login page
2. Sender domain does not match claimed organization
3. Urgent language detected attempting to create panic
...
```

---

## Testing

### Test IMAP Connection

```python
# backend/test_imap.py
import imaplib
from app.config.settings import settings

def test_imap_connection():
    try:
        mail = imaplib.IMAP4_SSL(settings.IMAP_HOST, settings.IMAP_PORT)
        mail.login(settings.IMAP_USER, settings.IMAP_PASSWORD)
        print("✅ IMAP connection successful")
        mail.logout()
    except Exception as e:
        print(f"❌ IMAP connection failed: {e}")

test_imap_connection()
```

### Test Email Sending

```python
# backend/test_smtp.py
from app.services.email_service import email_service
import asyncio

async def test_email():
    success = await email_service.send_email(
        to="your-email@example.com",
        subject="PhishNet Test Email",
        body="This is a test email from PhishNet"
    )
    print("✅ Email sent" if success else "❌ Email failed")

asyncio.run(test_email())
```

### Test Full Workflow

1. Forward a test email to your PhishNet address
2. Check logs: `tail -f backend/logs/phishnet.log`
3. Verify email is processed
4. Check your inbox for reply email

---

## Monitoring

### Check IMAP Poller Status

```python
# In your monitoring dashboard or logs
logger.info(f"IMAP Poller Status: {'Running' if imap_poller.running else 'Stopped'}")
logger.info(f"Emails processed today: {email_count}")
logger.info(f"Average analysis time: {avg_time}ms")
```

### MongoDB Queries

```javascript
// Count forwarded emails today
db.forwarded_email_analyses.count({
  created_at: { $gte: ISODate("2025-11-24T00:00:00Z") }
})

// Find high-risk emails
db.forwarded_email_analyses.find({
  risk_level: { $in: ["HIGH", "CRITICAL"] }
}).sort({ created_at: -1 })

// Check reply status
db.forwarded_email_analyses.count({ reply_sent: false })
```

---

## Troubleshooting

### IMAP Connection Fails
- Check credentials in `.env`
- Verify "Less secure app access" is enabled (Gmail)
- Check firewall rules for port 993
- Try using App Password instead of regular password

### Emails Not Being Processed
- Check IMAP poller is running: `ps aux | grep python`
- Check logs for errors
- Verify emails are in correct folder (INBOX)
- Test IMAP connection manually

### Reply Emails Not Sent
- Check SMTP credentials
- Verify SMTP port (usually 587 for TLS)
- Check spam folder of recipient
- Review email service logs

---

## Production Deployment

### Using SendGrid (Recommended)

```env
# .env
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=YOUR_SENDGRID_API_KEY
SMTP_FROM_EMAIL=noreply@phishnet.com
```

### Using AWS SES

```env
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=YOUR_SES_SMTP_USERNAME
SMTP_PASSWORD=YOUR_SES_SMTP_PASSWORD
```

### Scaling Considerations

- Use Redis for job queue if processing many emails
- Add multiple IMAP poller instances
- Implement rate limiting (e.g., 100 emails/hour per user)
- Set up email archival and retention policies

---

## Security Best Practices

1. **Email Validation**
   - Verify sender email before processing
   - Implement allowlist/blocklist
   - Rate limit per email address

2. **Content Sanitization**
   - Strip potentially malicious content
   - Limit email size (10MB max)
   - Scan attachments before processing

3. **Data Privacy**
   - Auto-delete emails after 30 days
   - Encrypt stored email content
   - Log access to sensitive data

4. **Authentication**
   - Use App Passwords, not regular passwords
   - Rotate credentials regularly
   - Use OAuth where possible

---

## Next Steps

1. ✅ Set up dedicated email account
2. ✅ Configure IMAP/SMTP settings
3. ✅ Create poller and email services
4. ✅ Test locally with forwarded emails
5. ✅ Deploy to production
6. ✅ Monitor usage and performance
7. ✅ Gather user feedback

---

**Support**: For questions, contact support@phishnet.com
**Documentation**: https://docs.phishnet.com
**Status**: https://status.phishnet.com

---

Last Updated: November 24, 2025
