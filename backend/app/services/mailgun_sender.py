"""
Mailgun Email Service
Sends emails via Mailgun HTTP API (works on Render where SMTP is blocked)
"""
import requests
from typing import Optional
from app.config.settings import get_settings
from app.config.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)


def send_email_via_mailgun(
    to_email: str,
    subject: str,
    body: str,
    html: bool = False
) -> bool:
    """
    Send email using Mailgun HTTP API.
    
    Args:
        to_email: Recipient email
        subject: Email subject
        body: Email body
        html: Whether body is HTML
        
    Returns:
        True if sent successfully, False otherwise
    """
    # Get Mailgun credentials from settings
    api_key = getattr(settings, 'MAILGUN_API_KEY', None)
    domain = getattr(settings, 'MAILGUN_DOMAIN', 'sandboxXXX.mailgun.org')  # Default sandbox
    from_email = getattr(settings, 'MAILGUN_FROM_EMAIL', f'PhishNet <mailgun@{domain}>')
    
    if not api_key:
        logger.error("MAILGUN_API_KEY not configured")
        return False
    
    # Mailgun API endpoint
    url = f"https://api.mailgun.net/v3/{domain}/messages"
    
    # Prepare request
    auth = ("api", api_key)
    data = {
        "from": from_email,
        "to": to_email,
        "subject": subject,
    }
    
    if html:
        data["html"] = body
    else:
        data["text"] = body
    
    try:
        response = requests.post(url, auth=auth, data=data, timeout=10)
        
        if response.status_code == 200:
            logger.info(f"✅ Mailgun: Email sent successfully to {to_email}")
            return True
        else:
            logger.error(f"❌ Mailgun error {response.status_code}: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        logger.error(f"❌ Mailgun request timed out for {to_email}")
        return False
    except Exception as e:
        logger.error(f"❌ Mailgun error sending to {to_email}: {e}")
        return False


async def send_email_async(
    to_email: str,
    subject: str,
    body: str,
    html: bool = False
) -> bool:
    """
    Async wrapper for Mailgun email sending.
    """
    import asyncio
    return await asyncio.to_thread(send_email_via_mailgun, to_email, subject, body, html)
