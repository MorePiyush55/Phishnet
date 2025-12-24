import smtplib
import base64
import httpx
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config.settings import settings
from app.config.logging import get_logger
import ssl
from starlette.concurrency import run_in_threadpool

logger = get_logger(__name__)


# ============================================================================
# Resend Email Sender - Works Immediately (Recommended)
# ============================================================================

RESEND_API_URL = "https://api.resend.com/emails"


async def send_email_via_resend(to_email: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Send email using Resend API over HTTPS.
    Free tier: 100 emails/day, works immediately.
    
    Requires RESEND_API_KEY environment variable.
    """
    api_key = os.getenv('RESEND_API_KEY') or getattr(settings, 'RESEND_API_KEY', None)
    
    if not api_key:
        return False
    
    # Resend requires verified domain or use onboarding@resend.dev for testing
    sender_email = os.getenv('RESEND_FROM_EMAIL', 'PhishNet <onboarding@resend.dev>')
    
    payload = {
        "from": sender_email,
        "to": [to_email],
        "subject": subject,
    }
    
    if html:
        payload["html"] = body
    else:
        payload["text"] = body
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(RESEND_API_URL, json=payload, headers=headers)
            
            if response.status_code in [200, 201]:
                logger.info(f"✅ Resend: Email sent successfully to {to_email}")
                return True
            else:
                logger.error(f"❌ Resend API error: {response.status_code} - {response.text}")
                return False
                
    except Exception as e:
        logger.error(f"❌ Resend error: {str(e)}")
        return False


# ============================================================================
# Brevo (Sendinblue) Email Sender - Requires Account Activation
# ============================================================================

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


async def send_email_via_brevo(to_email: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Send email using Brevo (Sendinblue) API over HTTPS.
    Free tier: 300 emails/day.
    
    Requires BREVO_API_KEY environment variable.
    Note: New accounts need activation (24-48 hours).
    """
    api_key = os.getenv('BREVO_API_KEY') or getattr(settings, 'BREVO_API_KEY', None)
    
    if not api_key:
        return False
    
    sender_email = getattr(settings, 'IMAP_USER', 'phishnet.ai@gmail.com')
    sender_name = "PhishNet Analysis"
    
    payload = {
        "sender": {
            "name": sender_name,
            "email": sender_email
        },
        "to": [
            {
                "email": to_email
            }
        ],
        "subject": subject,
    }
    
    if html:
        payload["htmlContent"] = body
    else:
        payload["textContent"] = body
    
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": api_key
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(BREVO_API_URL, json=payload, headers=headers)
            
            if response.status_code in [200, 201]:
                logger.info(f"✅ Brevo: Email sent successfully to {to_email}")
                return True
            else:
                logger.error(f"❌ Brevo API error: {response.status_code} - {response.text}")
                return False
                
    except httpx.TimeoutException:
        logger.error(f"❌ Brevo timeout sending to {to_email}")
        return False
    except Exception as e:
        logger.error(f"❌ Brevo error: {str(e)}")
        return False


async def send_email_smtp_with_fallback(to_email: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Try email providers in order: Resend -> Brevo -> SMTP
    """
    # Try Resend first (works immediately)
    resend_key = os.getenv('RESEND_API_KEY') or getattr(settings, 'RESEND_API_KEY', None)
    if resend_key:
        result = await send_email_via_resend(to_email, subject, body, html)
        if result:
            return True
    
    # Try Brevo second
    brevo_key = os.getenv('BREVO_API_KEY') or getattr(settings, 'BREVO_API_KEY', None)
    if brevo_key:
        result = await send_email_via_brevo(to_email, subject, body, html)
        if result:
            return True
    
    # Fallback to SMTP (will fail on Render free tier)
    try:
        result = await run_in_threadpool(send_email_sync, to_email, subject, body, html)
        return result
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        logger.warning(
            f"📧 EMAIL DELIVERY FAILED - Configure RESEND_API_KEY (recommended) or BREVO_API_KEY"
        )
        return False


def send_email_sync(to_email: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Send an email using SMTP (Synchronous - blocking).
    Note: SMTP is blocked on Render free tier. Use Brevo instead.
    """
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    
    sender_email = getattr(settings, 'IMAP_USER', None)
    password = getattr(settings, 'IMAP_PASSWORD', None)

    if not sender_email or not password:
        logger.warning(f"SMTP credentials missing.")
        return False

    msg = MIMEMultipart()
    msg['From'] = f"PhishNet Analysis <{sender_email}>"
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'html' if html else 'plain'))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            server.set_debuglevel(0)
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(sender_email, password)
            server.send_message(msg)
            
        logger.info(f"✅ SMTP: Email sent successfully to {to_email}")
        return True
        
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP Authentication failed.")
        return False
    except OSError as e:
        if e.errno == 101:
            logger.error(f"🚫 SMTP BLOCKED (Render). Configure BREVO_API_KEY instead.")
        else:
            logger.error(f"SMTP Network Error: {e}")
        return False
    except Exception as e:
        logger.error(f"SMTP Error: {str(e)}")
        return False


async def send_email(to_email: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Async wrapper for sending email.
    Priority: Resend -> Brevo -> SMTP
    """
    # Try Resend first (works immediately, recommended)
    resend_key = os.getenv('RESEND_API_KEY') or getattr(settings, 'RESEND_API_KEY', None)
    if resend_key:
        result = await send_email_via_resend(to_email, subject, body, html)
        if result:
            return True
    
    # Try Brevo second
    brevo_key = os.getenv('BREVO_API_KEY') or getattr(settings, 'BREVO_API_KEY', None)
    if brevo_key:
        result = await send_email_via_brevo(to_email, subject, body, html)
        if result:
            return True
    
    # Fallback to SMTP (blocked on Render)
    return await run_in_threadpool(send_email_sync, to_email, subject, body, html)
