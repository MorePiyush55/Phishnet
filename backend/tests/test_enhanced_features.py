"""Tests for enhanced PhishNet features."""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta

from app.models.user import User, UserRole
from app.models.email import Email, EmailStatus
from app.models.refresh_token import RefreshToken
from app.core.security import create_access_token, verify_token, hash_token
from app.services.sanitizer import content_sanitizer
from app.orchestrator.utils import email_orchestrator


class TestAuthentication:
    """Test enhanced authentication and RBAC."""
    
    def test_user_roles(self):
        """Test user role enumeration."""
        assert UserRole.ADMIN == "admin"
        assert UserRole.ANALYST == "analyst"
        assert UserRole.VIEWER == "viewer"
    
    def test_access_token_creation(self):
        """Test access token creation with roles."""
        user_data = {
            "sub": "testuser",
            "user_id": 1,
            "role": UserRole.ANALYST.value
        }
        
        token = create_access_token(user_data)
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens are fairly long
    
    def test_token_verification(self):
        """Test token verification."""
        user_data = {
            "sub": "testuser",
            "user_id": 1,
            "role": UserRole.ANALYST.value
        }
        
        token = create_access_token(user_data)
        token_data = verify_token(token, "access")
        
        assert token_data is not None
        assert token_data.username == "testuser"
        assert token_data.user_id == 1
        assert token_data.role == UserRole.ANALYST.value
    
    def test_refresh_token_model(self):
        """Test refresh token model."""
        token = RefreshToken(
            user_id=1,
            token_hash="test_hash",
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        
        assert token.is_valid
        assert not token.is_expired
        
        # Test revocation
        token.revoke()
        assert not token.is_valid
        assert token.revoked
        assert token.revoked_at is not None


class TestEmailModels:
    """Test enhanced email models."""
    
    def test_email_status_enum(self):
        """Test email status enumeration."""
        assert EmailStatus.PENDING == "pending"
        assert EmailStatus.QUARANTINED == "quarantined"
        assert EmailStatus.SAFE == "safe"
    
    def test_email_model_fields(self):
        """Test email model has required fields."""
        email = Email(
            user_id=1,
            gmail_msg_id="test_msg_123",
            sender="test@example.com",
            recipients='["user@domain.com"]',
            subject="Test Email",
            received_at=datetime.utcnow(),
            content_hash="abc123",
            size_bytes=1024,
            status=EmailStatus.PENDING
        )
        
        assert email.gmail_msg_id == "test_msg_123"
        assert email.status == EmailStatus.PENDING
        assert email.size_bytes == 1024


class TestContentSanitization:
    """Test content sanitization."""
    
    def test_html_sanitization(self):
        """Test HTML content sanitization."""
        dangerous_html = """
        <script>alert('xss')</script>
        <p onclick="malicious()">Safe content</p>
        <a href="javascript:void(0)">Bad link</a>
        <img src="http://example.com/image.jpg" alt="Safe image">
        """
        
        sanitized = content_sanitizer.sanitize_html(dangerous_html)
        
        # Should remove script tags
        assert "<script>" not in sanitized
        assert "alert('xss')" not in sanitized
        
        # Should remove event handlers
        assert "onclick" not in sanitized
        
        # Should remove javascript: URLs
        assert "javascript:" not in sanitized
        
        # Should keep safe content
        assert "Safe content" in sanitized
        assert "Safe image" in sanitized
    
    def test_url_extraction(self):
        """Test URL extraction from content."""
        content = """
        Check out this link: https://example.com/page
        And this one: http://test.com
        <a href="https://link.com">Click here</a>
        <img src="https://img.com/pic.jpg" alt="pic">
        """
        
        urls = content_sanitizer.extract_urls(content)
        
        assert len(urls) >= 4
        extracted_urls = [url['url'] for url in urls]
        assert "https://example.com/page" in extracted_urls
        assert "https://link.com" in extracted_urls
        assert "https://img.com/pic.jpg" in extracted_urls
    
    def test_safe_url_validation(self):
        """Test URL safety validation."""
        # Safe URLs
        assert content_sanitizer.is_safe_url("https://example.com")
        assert content_sanitizer.is_safe_url("http://test.com")
        assert content_sanitizer.is_safe_url("mailto:user@example.com")
        
        # Dangerous URLs
        assert not content_sanitizer.is_safe_url("javascript:alert('xss')")
        assert not content_sanitizer.is_safe_url("data:text/html,<script>alert('xss')</script>")
        assert not content_sanitizer.is_safe_url("vbscript:msgbox('xss')")
    
    def test_csp_generation(self):
        """Test Content Security Policy generation."""
        csp = content_sanitizer.get_content_security_policy()
        
        assert "default-src 'self'" in csp
        assert "script-src" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp


class TestEmailOrchestrator:
    """Test email processing orchestrator."""
    
    @pytest.mark.asyncio
    async def test_orchestrator_initialization(self):
        """Test orchestrator can be initialized."""
        orchestrator = email_orchestrator
        assert orchestrator is not None
        assert not orchestrator.is_running
    
    @pytest.mark.asyncio
    async def test_email_processing_queue(self):
        """Test email processing queue."""
        orchestrator = email_orchestrator
        
        # Add email to queue
        await orchestrator.process_email(123)
        
        # Check queue is not empty
        assert not orchestrator.processing_queue.empty()


class TestGmailIntegration:
    """Test Gmail integration features."""
    
    @patch('app.services.gmail.Flow')
    @pytest.mark.asyncio
    async def test_gmail_auth_url_generation(self, mock_flow):
        """Test Gmail OAuth URL generation."""
        from app.services.gmail import gmail_service
        
        # Mock the OAuth flow
        mock_flow.from_client_config.return_value.authorization_url.return_value = (
            "https://accounts.google.com/oauth2/auth?client_id=test", 
            "state"
        )
        
        auth_url = await gmail_service.get_auth_url(user_id=1)
        assert "accounts.google.com" in auth_url
        assert "oauth2/auth" in auth_url
    
    def test_email_data_extraction(self):
        """Test email data extraction from Gmail API response."""
        from app.services.gmail import gmail_service
        
        mock_message = {
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Test Subject"},
                    {"name": "From", "value": "test@example.com"},
                    {"name": "To", "value": "user@example.com"},
                    {"name": "Date", "value": "Mon, 1 Jan 2024 12:00:00 +0000"}
                ],
                "body": {
                    "data": "VGVzdCBlbWFpbCBjb250ZW50"  # Base64 for "Test email content"
                }
            },
            "threadId": "thread_123",
            "sizeEstimate": 1024
        }
        
        email_data = gmail_service._extract_email_data(mock_message)
        
        assert email_data["subject"] == "Test Subject"
        assert email_data["sender"] == "test@example.com"
        assert "Test email content" in email_data["text_content"]
        assert email_data["thread_id"] == "thread_123"
        assert email_data["size_bytes"] == 1024


def test_password_security():
    """Test password hashing security."""
    from app.core.security import get_password_hash, verify_password
    
    password = "test_password_123"
    hashed = get_password_hash(password)
    
    # Hash should be different from original
    assert hashed != password
    
    # Should verify correctly
    assert verify_password(password, hashed)
    
    # Should not verify incorrect password
    assert not verify_password("wrong_password", hashed)


def test_token_hashing():
    """Test token hashing for storage."""
    from app.core.security import hash_token
    
    token = "test_token_123"
    hashed = hash_token(token)
    
    assert len(hashed) == 64  # SHA256 hex digest length
    assert hashed != token
    
    # Same token should produce same hash
    assert hash_token(token) == hashed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
