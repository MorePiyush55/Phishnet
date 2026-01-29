"""Test fixtures package."""

from tests.fixtures.fake_imap_client import FakeIMAPClient
from tests.fixtures.mailbox_fixtures import (
    get_default_mailbox_fixture,
    get_dedup_test_fixture,
    get_phishing_test_fixture,
    get_url_analysis_fixture,
    SAFE_EMAIL_FIXTURE,
    PHISHING_EMAIL_FIXTURE,
    DUPLICATE_EMAIL_FIXTURE,
    SIMILAR_EMAIL_FIXTURE
)

__all__ = [
    'FakeIMAPClient',
    'get_default_mailbox_fixture',
    'get_dedup_test_fixture',
    'get_phishing_test_fixture',
    'get_url_analysis_fixture',
    'SAFE_EMAIL_FIXTURE',
    'PHISHING_EMAIL_FIXTURE',
    'DUPLICATE_EMAIL_FIXTURE',
    'SIMILAR_EMAIL_FIXTURE'
]
