"""Unit tests for email sanitization and processing."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone
import json

from app.services.email_processor import EmailProcessor, EmailSanitizer
from app.models.email import Email
from app.schemas.email import EmailCreate


class TestEmailSanitizer:
    """Test email sanitization functionality."""
    
    def test_sanitize_html_basic(self):
        """Test basic HTML sanitization."""
        sanitizer = EmailSanitizer()
        
        dirty_html = """
        <div>
            <script>alert('xss')</script>
            <p>Hello <strong>World</strong>!</p>
            <img src="evil.jpg" onerror="alert('xss')">
            <a href="javascript:alert('xss')">Click me</a>
        </div>
        """
        
        clean_html = sanitizer.sanitize_html(dirty_html)
        
        # Should remove scripts and dangerous attributes
        assert "<script>" not in clean_html
        assert "javascript:" not in clean_html
        assert "onerror=" not in clean_html
        
        # Should keep safe tags
        assert "<p>" in clean_html
        assert "<strong>" in clean_html
        assert "Hello" in clean_html
        assert "World" in clean_html
    
    def test_sanitize_html_preserve_structure(self):
        """Test that HTML structure is preserved during sanitization."""
        sanitizer = EmailSanitizer()
        
        html = """
        <div class="content">
            <h1>Title</h1>
            <p>Paragraph with <em>emphasis</em> and <strong>strong</strong> text.</p>
            <ul>
                <li>Item 1</li>
                <li>Item 2</li>
            </ul>
        </div>
        """
        
        clean_html = sanitizer.sanitize_html(html)
        
        # Structure should be preserved
        assert "<div" in clean_html
        assert "<h1>" in clean_html
        assert "<p>" in clean_html
        assert "<ul>" in clean_html
        assert "<li>" in clean_html
        assert "<em>" in clean_html
        assert "<strong>" in clean_html
    
    def test_extract_urls(self):
        """Test URL extraction from email content."""
        sanitizer = EmailSanitizer()
        
        content = """
        Visit our website at https://example.com
        Or check out http://test.org/path?param=value
        Also available at ftp://files.example.com/download
        Email us at contact@example.com
        """
        
        urls = sanitizer.extract_urls(content)
        
        assert "https://example.com" in urls
        assert "http://test.org/path?param=value" in urls
        assert "ftp://files.example.com/download" in urls
        assert "contact@example.com" not in urls  # Email addresses should be excluded
    
    def test_extract_urls_from_html(self):
        """Test URL extraction from HTML content."""
        sanitizer = EmailSanitizer()
        
        html = """
        <div>
            <a href="https://example.com">Link 1</a>
            <a href="http://test.org">Link 2</a>
            <img src="https://images.example.com/pic.jpg">
            <form action="https://forms.example.com/submit">
        </div>
        """
        
        urls = sanitizer.extract_urls(html)
        
        assert "https://example.com" in urls
        assert "http://test.org" in urls
        assert "https://images.example.com/pic.jpg" in urls
        assert "https://forms.example.com/submit" in urls
    
    def test_extract_attachments_info(self):
        """Test attachment information extraction."""
        sanitizer = EmailSanitizer()
        
        headers = {
            "Content-Type": "multipart/mixed; boundary=boundary123"
        }
        
        body = """
        --boundary123
        Content-Type: text/plain
        
        Email body content
        
        --boundary123
        Content-Type: application/pdf
        Content-Disposition: attachment; filename="document.pdf"
        Content-Transfer-Encoding: base64
        
        [base64 content]
        
        --boundary123
        Content-Type: image/jpeg
        Content-Disposition: attachment; filename="image.jpg"
        
        [binary content]
        
        --boundary123--
        """
        
        attachments = sanitizer.extract_attachments_info(headers, body)
        
        assert len(attachments) == 2
        assert any(att["filename"] == "document.pdf" for att in attachments)
        assert any(att["filename"] == "image.jpg" for att in attachments)
        assert any(att["content_type"] == "application/pdf" for att in attachments)
        assert any(att["content_type"] == "image/jpeg" for att in attachments)


class TestEmailProcessor:
    """Test email processing functionality."""
    
    @pytest.fixture
    def email_processor(self):
        """Create EmailProcessor instance for testing."""
        return EmailProcessor()
    
    @pytest.fixture
    def sample_email_data(self):
        """Sample email data for testing."""
        return EmailCreate(
            message_id="test-123@example.com",
            subject="Test Email Subject",
            sender="sender@example.com",
            recipient="recipient@example.com",
            body="This is a test email with https://example.com link",
            headers={
                "Date": "Mon, 1 Jan 2024 12:00:00 +0000",
                "Content-Type": "text/html; charset=utf-8"
            },
            raw_email="Raw email content here"
        )
    
    @patch('app.services.email_processor.EmailProcessor._extract_metadata')
    def test_process_email_basic(self, mock_extract_metadata, email_processor, sample_email_data):
        """Test basic email processing."""
        # Mock metadata extraction
        mock_extract_metadata.return_value = {
            "urls": ["https://example.com"],
            "domains": ["example.com"],
            "ips": [],
            "attachments": []
        }
        
        processed = email_processor.process_email(sample_email_data)
        
        assert processed.subject == "Test Email Subject"
        assert processed.sender == "sender@example.com"
        assert processed.recipient == "recipient@example.com"
        assert "https://example.com" in processed.body
        
        # Metadata should be extracted
        mock_extract_metadata.assert_called_once()
    
    def test_extract_metadata(self, email_processor):
        """Test metadata extraction from email."""
        content = """
        <html>
            <body>
                <p>Visit https://example.com for more info</p>
                <p>Also check http://test.org</p>
                <img src="https://images.example.com/logo.png">
            </body>
        </html>
        """
        
        headers = {"Content-Type": "text/html"}
        
        metadata = email_processor._extract_metadata(content, headers)
        
        assert "urls" in metadata
        assert "domains" in metadata
        assert len(metadata["urls"]) >= 2
        assert "example.com" in metadata["domains"]
        assert "test.org" in metadata["domains"]
    
    def test_validate_email_headers(self, email_processor):
        """Test email header validation."""
        valid_headers = {
            "Date": "Mon, 1 Jan 2024 12:00:00 +0000",
            "From": "sender@example.com",
            "To": "recipient@example.com",
            "Subject": "Test Subject"
        }
        
        invalid_headers = {
            "Date": "Invalid Date Format",
            "From": "invalid-email",
            "To": "",
            "Subject": ""
        }
        
        # Valid headers should pass
        is_valid, errors = email_processor._validate_headers(valid_headers)
        assert is_valid
        assert len(errors) == 0
        
        # Invalid headers should fail
        is_valid, errors = email_processor._validate_headers(invalid_headers)
        assert not is_valid
        assert len(errors) > 0
    
    @patch('app.services.email_processor.sanitize_html')
    def test_sanitize_email_content(self, mock_sanitize, email_processor):
        """Test email content sanitization."""
        mock_sanitize.return_value = "Clean content"
        
        dirty_content = "<script>alert('xss')</script><p>Hello</p>"
        clean_content = email_processor._sanitize_content(dirty_content)
        
        mock_sanitize.assert_called_once_with(dirty_content)
        assert clean_content == "Clean content"
    
    def test_extract_domains_from_urls(self, email_processor):
        """Test domain extraction from URLs."""
        urls = [
            "https://example.com/path",
            "http://test.org:8080/page",
            "ftp://files.example.com/download",
            "https://subdomain.example.com"
        ]
        
        domains = email_processor._extract_domains(urls)
        
        assert "example.com" in domains
        assert "test.org" in domains
        assert "files.example.com" in domains
        assert "subdomain.example.com" in domains
    
    def test_detect_suspicious_patterns(self, email_processor):
        """Test detection of suspicious patterns in email content."""
        suspicious_content = """
        URGENT: Your account will be suspended!
        Click here immediately: https://fake-bank.com/login
        Verify your password now or lose access forever!
        """
        
        patterns = email_processor._detect_suspicious_patterns(suspicious_content)
        
        assert len(patterns) > 0
        assert any("urgent" in pattern.lower() for pattern in patterns)
        assert any("click here" in pattern.lower() for pattern in patterns)
    
    @pytest.mark.asyncio
    async def test_process_email_async(self, email_processor, sample_email_data):
        """Test asynchronous email processing."""
        with patch.object(email_processor, 'process_email') as mock_process:
            mock_process.return_value = sample_email_data
            
            result = await email_processor.process_email_async(sample_email_data)
            
            mock_process.assert_called_once_with(sample_email_data)
            assert result == sample_email_data


class TestEmailValidation:
    """Test email validation functionality."""
    
    def test_valid_email_format(self):
        """Test valid email format validation."""
        from app.services.email_processor import validate_email_format
        
        valid_emails = [
            "user@example.com",
            "test.email+tag@domain.co.uk",
            "user123@test-domain.org"
        ]
        
        for email in valid_emails:
            assert validate_email_format(email), f"Email {email} should be valid"
    
    def test_invalid_email_format(self):
        """Test invalid email format validation."""
        from app.services.email_processor import validate_email_format
        
        invalid_emails = [
            "invalid-email",
            "@domain.com",
            "user@",
            "user@domain",
            "user..double.dot@domain.com"
        ]
        
        for email in invalid_emails:
            assert not validate_email_format(email), f"Email {email} should be invalid"
    
    def test_email_domain_extraction(self):
        """Test domain extraction from email addresses."""
        from app.services.email_processor import extract_email_domain
        
        test_cases = [
            ("user@example.com", "example.com"),
            ("test@subdomain.example.org", "subdomain.example.org"),
            ("admin@test-domain.co.uk", "test-domain.co.uk")
        ]
        
        for email, expected_domain in test_cases:
            domain = extract_email_domain(email)
            assert domain == expected_domain


# Helper functions for email processing
def validate_email_format(email: str) -> bool:
    """Validate email format using regex."""
    import re
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def extract_email_domain(email: str) -> str:
    """Extract domain from email address."""
    if '@' in email:
        return email.split('@')[1]
    return ""


# Test fixtures and utilities
@pytest.fixture
def sample_phishing_email():
    """Sample phishing email for testing."""
    return {
        "subject": "URGENT: Verify Your Account Now!",
        "sender": "security@paypaI.com",  # Note the typo squatting
        "body": """
        Dear Customer,
        
        Your PayPal account has been temporarily limited due to suspicious activity.
        
        Click here to verify your account immediately:
        https://paypal-verification.suspicious-domain.com/login
        
        If you don't verify within 24 hours, your account will be permanently suspended.
        
        Best regards,
        PayPal Security Team
        """,
        "headers": {
            "From": "security@paypaI.com",
            "Reply-To": "noreply@suspicious-domain.com",
            "Return-Path": "bounce@evil-domain.com"
        }
    }


@pytest.fixture
def sample_legitimate_email():
    """Sample legitimate email for testing."""
    return {
        "subject": "Your Monthly Statement is Ready",
        "sender": "statements@bank.com",
        "body": """
        Dear Customer,
        
        Your monthly statement for January 2024 is now available.
        
        You can view it by logging into your account at:
        https://bank.com/login
        
        Thank you for banking with us.
        
        Customer Service Team
        """,
        "headers": {
            "From": "statements@bank.com",
            "Reply-To": "support@bank.com",
            "Return-Path": "bounce@bank.com"
        }
    }
