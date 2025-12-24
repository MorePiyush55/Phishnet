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
# Brevo (Sendinblue) Email Sender - Works on Render Free Tier
# ============================================================================

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


async def send_email_via_brevo(to_email: str, subject: str, body: str, html: bool = True) -> bool:
    """
    Send email using Brevo (Sendinblue) HTTPS API.
    Works on Render free tier - 300 emails/day free.
    
    Requires: BREVO_API_KEY environment variable
    """
    api_key = getattr(settings, 'BREVO_API_KEY', None) or os.getenv('BREVO_API_KEY')
    
    if not api_key:
        logger.warning("BREVO_API_KEY not configured, falling back to SMTP")
        return await send_email(to_email, subject, body, html)
    
    sender_email = getattr(settings, 'IMAP_USER', None) or os.getenv('IMAP_USER', 'phishnet.ai@gmail.com')
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
            
            if response.status_code in (200, 201):
                logger.info(f"✅ Brevo: Email sent successfully to {to_email}")
                return True
            else:
                logger.error(f"Brevo API error {response.status_code}: {response.text}")
                return False
                
    except httpx.TimeoutException:
        logger.error(f"Brevo API timeout sending to {to_email}")
        return False
    except Exception as e:
        logger.error(f"Brevo API error: {e}")
        return False


# ============================================================================
# Main Email Sending Function (Uses Brevo if available, fallback to SMTP)
# ============================================================================

async def send_email_smart(to_email: str, subject: str, body: str, html: bool = True) -> bool:
    """
    Smart email sender - tries Brevo first (works on Render), falls back to SMTP.
    """
    # Try Brevo first (works on Render)
    brevo_key = getattr(settings, 'BREVO_API_KEY', None) or os.getenv('BREVO_API_KEY')
    
    if brevo_key:
        logger.info(f"📧 Sending email via Brevo to {to_email}")
        return await send_email_via_brevo(to_email, subject, body, html)
    
    # Fallback to SMTP (may not work on Render free tier)
    logger.info(f"📧 Sending email via SMTP to {to_email}")
    return await send_email(to_email, subject, body, html)


# ============================================================================
# SMTP Email Sender (Fallback - blocked on Render free tier)
# ============================================================================

def send_email_sync(to_email: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Send an email using SMTP (Synchronous - blocking).
    Note: SMTP is blocked on Render free tier.
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
            logger.error(f"🚫 SMTP BLOCKED by Render. Configure BREVO_API_KEY for email delivery.")
        else:
            logger.error(f"SMTP Network Error: {e}")
        return False
    except Exception as e:
        logger.error(f"SMTP Error: {str(e)}")
        return False


async def send_email(to_email: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Async wrapper for SMTP email sending.
    """
    return await run_in_threadpool(send_email_sync, to_email, subject, body, html)
