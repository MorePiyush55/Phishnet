"""
Mailbox Fixtures
================
Pre-captured email fixtures for testing.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any


def create_email_fixture(
    uid: str,
    message_id: str,
    subject: str,
    from_addr: str,
    body: str,
    is_phishing: bool = False,
    has_attachment: bool = False,
    urls: List[str] = None
) -> Dict[str, Any]:
    """
    Create email fixture.
    
    Args:
        uid: Email UID
        message_id: Message-ID header
        subject: Email subject
        from_addr: Sender address
        body: Email body
        is_phishing: Whether email is phishing
        has_attachment: Whether email has attachments
        urls: List of URLs in email
        
    Returns:
        Email fixture dictionary
    """
    email_content = f"""From: {from_addr}
Subject: {subject}
Message-ID: {message_id}
Date: {datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')}
Content-Type: text/plain; charset=utf-8

{body}
"""
    
    return {
        'uid': uid,
        'message_id': message_id,
        'subject': subject,
        'from': from_addr,
        'date': datetime.now(timezone.utc),
        'raw': email_content.encode('utf-8'),
        'is_phishing': is_phishing,
        'has_attachment': has_attachment,
        'urls': urls or []
    }


# ============================================================================
# Pre-defined Fixtures
# ============================================================================

SAFE_EMAIL_FIXTURE = create_email_fixture(
    uid='1001',
    message_id='<safe-email-001@example.com>',
    subject='Weekly Team Meeting',
    from_addr='manager@company.com',
    body='''Hi team,

Our weekly meeting is scheduled for Friday at 2 PM.

Agenda:
- Project updates
- Q1 planning
- Team announcements

See you there!
''',
    is_phishing=False
)


PHISHING_EMAIL_FIXTURE = create_email_fixture(
    uid='1002',
    message_id='<phishing-001@malicious.com>',
    subject='URGENT: Verify Your Account',
    from_addr='security@paypa1.com',  # Typo-squatting
    body='''Dear Customer,

Your account has been compromised. Click here to verify immediately:
http://paypa1-verify.malicious.com/login

Failure to verify within 24 hours will result in account suspension.

PayPal Security Team
''',
    is_phishing=True,
    urls=['http://paypa1-verify.malicious.com/login']
)


DUPLICATE_EMAIL_FIXTURE = create_email_fixture(
    uid='1003',
    message_id='<safe-email-001@example.com>',  # Same Message-ID as SAFE_EMAIL
    subject='Weekly Team Meeting',
    from_addr='manager@company.com',
    body='Same email, different UID',
    is_phishing=False
)


SIMILAR_EMAIL_FIXTURE = create_email_fixture(
    uid='1004',
    message_id='<similar-email-001@example.com>',  # Different Message-ID
    subject='Weekly Team Meeting',
    from_addr='manager@company.com',
    body='''Hi team,

Our weekly meeting is scheduled for Friday at 2 PM.

Agenda:
- Project updates
- Q1 planning
- Team announcements

See you there!
''',  # Same content as SAFE_EMAIL
    is_phishing=False
)


ATTACHMENT_EMAIL_FIXTURE = create_email_fixture(
    uid='1005',
    message_id='<attachment-001@example.com>',
    subject='Invoice #12345',
    from_addr='billing@vendor.com',
    body='Please find attached invoice for your review.',
    is_phishing=False,
    has_attachment=True
)


MALICIOUS_ATTACHMENT_FIXTURE = create_email_fixture(
    uid='1006',
    message_id='<malicious-attachment-001@evil.com>',
    subject='Your Package Delivery',
    from_addr='delivery@fedex-tracking.evil.com',
    body='Your package is ready. See attached tracking details.',
    is_phishing=True,
    has_attachment=True
)


URL_TRACKING_FIXTURE = create_email_fixture(
    uid='1007',
    message_id='<tracking-url-001@newsletter.com>',
    subject='Newsletter: January Edition',
    from_addr='news@company.com',
    body='''Check out our latest articles:
    
https://company.com/article?utm_source=email&utm_campaign=jan2026&utm_medium=newsletter
''',
    is_phishing=False,
    urls=[
        'https://company.com/article?utm_source=email&utm_campaign=jan2026&utm_medium=newsletter'
    ]
)


# ============================================================================
# Fixture Collections
# ============================================================================

def get_default_mailbox_fixture() -> List[Dict[str, Any]]:
    """Get default mailbox fixture for testing."""
    return [
        SAFE_EMAIL_FIXTURE,
        PHISHING_EMAIL_FIXTURE,
        ATTACHMENT_EMAIL_FIXTURE
    ]


def get_dedup_test_fixture() -> List[Dict[str, Any]]:
    """Get fixture for deduplication testing."""
    return [
        SAFE_EMAIL_FIXTURE,
        DUPLICATE_EMAIL_FIXTURE,
        SIMILAR_EMAIL_FIXTURE
    ]


def get_phishing_test_fixture() -> List[Dict[str, Any]]:
    """Get fixture for phishing detection testing."""
    return [
        SAFE_EMAIL_FIXTURE,
        PHISHING_EMAIL_FIXTURE,
        MALICIOUS_ATTACHMENT_FIXTURE
    ]


def get_url_analysis_fixture() -> List[Dict[str, Any]]:
    """Get fixture for URL analysis testing."""
    return [
        PHISHING_EMAIL_FIXTURE,
        URL_TRACKING_FIXTURE
    ]
