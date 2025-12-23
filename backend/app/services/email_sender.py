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
    Send an email using SMTP (Synchronous - blocking).
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        body: Email body content
        html: Whether body is HTML (default False)
        
    Returns:
        bool: True if sent successfully, False otherwise
    """
    # Use settings but fallback to os.getenv if needed (redundant if settings loads correctly)
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    
    # Credentials should come from settings (loaded from env)
    sender_email = getattr(settings, 'IMAP_USER', None)
    password = getattr(settings, 'IMAP_PASSWORD', None)

    if not sender_email or not password:
        logger.warning(f"SMTP credentials missing. User: {sender_email}, Pass: {'*' * 5 if password else 'None'}")
        return False

    msg = MIMEMultipart()
    msg['From'] = f"PhishNet Analysis <{sender_email}>"
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'html' if html else 'plain'))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.set_debuglevel(0)  # Set to 1 for debug output
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(sender_email, password)
            server.send_message(msg)
            
        logger.info(f"SMTP: Email sent successfully to {to_email}")
        return True
        
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP Authentication failed. Check username/app password.")
        return False
    except Exception as e:
        logger.error(f"SMTP Error sending to {to_email}: {str(e)}")
        return False

async def send_email(to_email: str, subject: str, body: str, html: bool = False) -> bool:
    """
    Async wrapper for sending email using threadpool.
    """
    return await run_in_threadpool(send_email_sync, to_email, subject, body, html)
