"""
Pytest configuration and fixtures for inbox system tests.
"""

import pytest
import asyncio
from typing import AsyncGenerator, Generator
from httpx import AsyncClient
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from datetime import datetime, timezone

from app.main import app
from app.models.inbox_models import InboxEmail, EmailLabel
from app.core.config import settings


# ==================== Pytest Configuration ====================

@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ==================== Database Fixtures ====================

@pytest.fixture(scope="function")
async def test_db():
    """Create a test database and clean it up after tests."""
    # Use test database
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client["phishnet_test"]
    
    # Initialize Beanie with test database
    await init_beanie(
        database=db,
        document_models=[InboxEmail, EmailLabel]
    )
    
    yield db
    
    # Cleanup: Drop all collections
    await db.drop_collection("inbox_emails")
    await db.drop_collection("email_labels")
    client.close()


# ==================== HTTP Client Fixtures ====================

@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """Create async HTTP client for testing."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


# ==================== Authentication Fixtures ====================

@pytest.fixture
def test_user():
    """Test user data."""
    return {
        "user_id": "test_user_123",
        "email": "test@example.com",
        "name": "Test User"
    }


@pytest.fixture
def auth_headers(test_user):
    """Authentication headers for test requests."""
    # Mock JWT token (in real tests, generate actual token)
    token = "test_token_123"
    return {
        "Authorization": f"Bearer {token}"
    }


# ==================== Sample Data Fixtures ====================

@pytest.fixture
async def sample_emails(test_db, test_user):
    """Create sample emails for testing."""
    emails = []
    
    for i in range(20):
        email = InboxEmail(
            user_id=test_user["user_id"],
            message_id=f"msg_{i}",
            thread_id=f"thread_{i // 3}",  # Group every 3 emails
            sender={
                "name": f"Sender {i}",
                "email": f"sender{i}@example.com"
            },
            recipients={
                "to": [{"email": test_user["email"]}],
                "cc": [],
                "bcc": []
            },
            subject=f"Test Email {i}",
            snippet=f"This is test email number {i}",
            body_text=f"Full body of test email {i}",
            body_html=f"<p>Full body of test email {i}</p>",
            is_read=i % 2 == 0,  # Even emails are read
            is_starred=i % 5 == 0,  # Every 5th email is starred
            has_attachment=i % 3 == 0,  # Every 3rd email has attachment
            attachments=[],
            labels=[],
            folder="inbox",
            received_at=datetime.now(timezone.utc),
            threat_score=0.1 * (i % 10),
            risk_level="SAFE" if i % 10 < 7 else "SUSPICIOUS",
            threat_indicators=[]
        )
        
        await email.insert()
        emails.append(email)
    
    return emails


@pytest.fixture
async def sample_labels(test_db, test_user):
    """Create sample labels for testing."""
    labels = []
    
    # Top-level labels
    work_label = EmailLabel(
        user_id=test_user["user_id"],
        label_id="label_work",
        name="Work",
        color="#FF5722",
        email_count=5
    )
    await work_label.insert()
    labels.append(work_label)
    
    personal_label = EmailLabel(
        user_id=test_user["user_id"],
        label_id="label_personal",
        name="Personal",
        color="#2196F3",
        email_count=3
    )
    await personal_label.insert()
    labels.append(personal_label)
    
    # Nested label
    urgent_label = EmailLabel(
        user_id=test_user["user_id"],
        label_id="label_urgent",
        name="Urgent",
        color="#F44336",
        parent_label_id="label_work",
        email_count=2
    )
    await urgent_label.insert()
    labels.append(urgent_label)
    
    return labels


# ==================== Helper Functions ====================

@pytest.fixture
def create_email_data(test_user):
    """Factory function to create email data."""
    def _create(
        message_id: str = "test_msg",
        subject: str = "Test Subject",
        is_read: bool = False,
        is_starred: bool = False,
        folder: str = "inbox",
        **kwargs
    ):
        return {
            "user_id": test_user["user_id"],
            "message_id": message_id,
            "thread_id": kwargs.get("thread_id", "test_thread"),
            "sender": {
                "name": "Test Sender",
                "email": "sender@example.com"
            },
            "recipients": {
                "to": [{"email": test_user["email"]}],
                "cc": [],
                "bcc": []
            },
            "subject": subject,
            "snippet": "Test snippet",
            "body_text": "Test body",
            "is_read": is_read,
            "is_starred": is_starred,
            "has_attachment": False,
            "attachments": [],
            "labels": [],
            "folder": folder,
            "received_at": datetime.now(timezone.utc),
            "threat_score": 0.0,
            "risk_level": "SAFE",
            "threat_indicators": [],
            **kwargs
        }
    
    return _create


# ==================== Cleanup ====================

@pytest.fixture(autouse=True)
async def cleanup_after_test(test_db):
    """Cleanup after each test."""
    yield
    # Additional cleanup if needed
    pass
