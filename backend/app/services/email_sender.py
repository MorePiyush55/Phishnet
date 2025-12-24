import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config.settings import settings
from app.config.logging import get_logger
import ssl
from starlette.concurrency import run_in_threadpool

logger = get_logger(__name__)

def send_email_sync(to_email: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Send an email using Mailgun HTTP API (SMTP blocked on Render).
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        body: Email body content
        html: Whether body is HTML (default False)
        
    Returns:
        bool: True if sent successfully, False otherwise
    """
    try:
        # Use Mailgun instead of SMTP (Render blocks SMTP)
        from app.services.mailgun_sender import send_email_via_mailgun
        return send_email_via_mailgun(to_email, subject, body, html)
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        return False

async def send_email(to_email: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Async wrapper for sending email using threadpool.
    """
    return await run_in_threadpool(send_email_sync, to_email, subject, body, html)
