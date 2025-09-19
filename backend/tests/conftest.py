"""
Comprehensive Test Configuration and Runner
Pytest configuration with all test suites and coverage reporting
"""

import pytest
import asyncio
import sys
import os
from typing import Dict, Any, Generator, AsyncGenerator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import Mock, AsyncMock
import redis

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

# Test Configuration
pytest_plugins = [
    "pytest_asyncio",
    "pytest_cov"
]

# Test environment setup
test_env_vars = {
    'TESTING': 'true',
    'ENVIRONMENT': 'development',  # Use valid enum value
    'DATABASE_URL': 'sqlite:///./test.db',
    'REDIS_URL': 'redis://localhost:6379/1',
    'SECRET_KEY': 'test-secret-key-with-32-plus-characters-for-testing-only',  # Must be 32+ chars
    'DEBUG': 'true',
    'ENCRYPTION_KEY': 'test_encryption_key_32_characters_long',
    'VIRUSTOTAL_API_KEY': 'test_vt_api_key',
    'GEMINI_API_KEY': 'test_gemini_api_key',
    'GMAIL_CLIENT_ID': 'test_gmail_client_id',
    'GMAIL_CLIENT_SECRET': 'test_gmail_client_secret',
    'SANDBOX_NETWORK_RANGE': '10.0.100.0/24',
    'AUDIT_LOG_RETENTION_DAYS': '2555',  # 7 years for compliance
    'PII_REDACTION_ENABLED': 'true',
    'SANDBOX_IP_ENFORCEMENT': 'true',
    'CORS_ORIGINS': '["http://localhost:3000"]',  # Fix JSON parsing issue
    'JWT_SECRET_KEY': 'test-jwt-secret-key-for-testing-only-32-characters',
    'JWT_ALGORITHM': 'HS256',
    'ENABLE_EXTERNAL_APIS': 'false',
    'SANDBOX_ENABLED': 'false',
    'LOG_LEVEL': 'ERROR'
}

for key, value in test_env_vars.items():
    os.environ[key] = value


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_db():
    """Create test database."""
    from app.core.database import Base, engine
    from app.models import user, email, detection, scoring, link_analysis
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    yield engine
    
    # Cleanup
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(test_db):
    """Create database session for testing."""
    from app.core.database import SessionLocal
    
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# Mock fixtures for external dependencies
@pytest.fixture
def mock_redis():
    """Mock Redis connection"""
    mock_redis = Mock()
    mock_redis.get.return_value = None
    mock_redis.set.return_value = True
    mock_redis.delete.return_value = True
    mock_redis.exists.return_value = False
    mock_redis.ping.return_value = True
    return mock_redis


@pytest.fixture
def mock_database():
    """Mock database connection"""
    mock_db = Mock()
    mock_db.execute.return_value = Mock()
    mock_db.commit.return_value = None
    return mock_db


@pytest.fixture
def mock_gmail_client():
    """Mock Gmail client"""
    mock_gmail = Mock()
    mock_gmail.list_messages.return_value = []
    mock_gmail.get_message.return_value = {}
    mock_gmail.apply_label.return_value = True
    return mock_gmail


@pytest.fixture
def mock_virustotal_client():
    """Mock VirusTotal client"""
    mock_vt = Mock()
    mock_vt.scan_url.return_value = {
        'scan_id': 'test_scan_123',
        'positives': 0,
        'total': 70,
        'permalink': 'https://virustotal.com/test'
    }
    return mock_vt


@pytest.fixture
def mock_gemini_client():
    """Mock Gemini client"""
    mock_gemini = Mock()
    mock_gemini.analyze_content.return_value = {
        'threat_probability': 0.1,
        'confidence': 0.95,
        'reasoning': 'Test analysis',
        'risk_factors': []
    }
    return mock_gemini


@pytest.fixture
def mock_playwright():
    """Mock Playwright browser."""
    mock_browser = Mock()
    mock_context = Mock()
    mock_page = Mock()
    
    # Setup async methods
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    mock_context.new_page = AsyncMock(return_value=mock_page)
    mock_page.goto = AsyncMock()
    mock_page.wait_for_load_state = AsyncMock()
    mock_page.close = AsyncMock()
    mock_context.close = AsyncMock()
    mock_browser.close = AsyncMock()
    
    return mock_browser, mock_context, mock_page


@pytest.fixture
def mock_ai_service():
    """Mock AI analysis service."""
    mock_service = Mock()
    mock_service.analyze_email = AsyncMock(return_value={
        "classification": "legitimate",
        "confidence": 0.85,
        "reasoning": "No suspicious patterns detected"
    })
    return mock_service


@pytest.fixture
def mock_threat_intel():
    """Mock threat intelligence service."""
    mock_service = Mock()
    mock_service.check_domain = AsyncMock(return_value={
        "malicious": False,
        "reputation_score": 0.1,
        "categories": []
    })
    mock_service.check_ip = AsyncMock(return_value={
        "malicious": False,
        "abuse_confidence": 0,
        "country": "US"
    })
    return mock_service


@pytest.fixture
def sample_legitimate_email():
    """Sample legitimate email for testing."""
    return {
        "subject": "Monthly Newsletter",
        "sender": "newsletter@company.com",
        "recipient": "user@example.com",
        "body": "Here's your monthly update from our company.",
        "headers": {
            "From": "newsletter@company.com",
            "To": "user@example.com",
            "Date": "Mon, 1 Jan 2024 12:00:00 +0000"
        }
    }


@pytest.fixture
def sample_phishing_email():
    """Sample phishing email for testing."""
    return {
        "subject": "URGENT: Account Verification Required",
        "sender": "security@fake-bank.com",
        "recipient": "victim@company.com",
        "body": """
        Your account has been suspended due to suspicious activity.
        Click here to verify immediately: https://fake-bank-verify.com/login
        Failure to verify within 24 hours will result in account closure.
        """,
        "headers": {
            "From": "security@fake-bank.com",
            "Reply-To": "noreply@evil-domain.com",
            "Date": "Mon, 1 Jan 2024 12:00:00 +0000"
        }
    }


@pytest.fixture
def sample_spam_email():
    """Sample spam email for testing."""
    return {
        "subject": "Congratulations! You've Won $1,000,000!",
        "sender": "winner@lottery-scam.com",
        "recipient": "victim@company.com",
        "body": """
        You have been selected as our grand prize winner!
        To claim your prize, send your personal information to:
        claim@lottery-scam.com
        """,
        "headers": {
            "From": "winner@lottery-scam.com",
            "Date": "Mon, 1 Jan 2024 12:00:00 +0000"
        }
    }


@pytest.fixture
def temp_file():
    """Create temporary file for testing."""
    fd, path = tempfile.mkstemp()
    try:
        yield path
    finally:
        os.close(fd)
        os.unlink(path)


@pytest.fixture
def temp_dir():
    """Create temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture(autouse=False)  # Disabled - causing issues
def mock_external_services(monkeypatch):
    """Mock external services to avoid real API calls during testing."""
    
    # Mock Gemini AI - disabled due to import issues
    # mock_genai = Mock()
    # mock_model = Mock()
    # mock_response = Mock()
    # mock_response.text = "This email appears to be legitimate."
    # mock_model.generate_content = Mock(return_value=mock_response)
    # mock_genai.GenerativeModel = Mock(return_value=mock_model)
    # mock_genai.configure = Mock()
    # monkeypatch.setattr("google.generativeai", mock_genai)
    
    # Mock HTTP requests
    mock_httpx = AsyncMock()
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json = Mock(return_value={"data": {}})
    mock_httpx.get = AsyncMock(return_value=mock_response)
    mock_httpx.post = AsyncMock(return_value=mock_response)
    
    monkeypatch.setattr("httpx.AsyncClient", lambda: mock_httpx)


@pytest.fixture
def mock_email_processor():
    """Mock email processor for testing."""
    from app.services.email_processor import EmailProcessor
    
    processor = Mock(spec=EmailProcessor)
    processor.process_email = Mock()
    processor.sanitize_content = Mock(return_value="Sanitized content")
    processor.extract_urls = Mock(return_value=["https://example.com"])
    processor.extract_metadata = Mock(return_value={
        "urls": ["https://example.com"],
        "domains": ["example.com"],
        "attachments": []
    })
    
    return processor


@pytest.fixture
def mock_scoring_engine():
    """Mock scoring engine for testing."""
    from app.services.scoring import ScoringEngine
    from app.models.scoring import EmailScore
    
    engine = Mock(spec=ScoringEngine)
    engine.calculate_overall_score = Mock(return_value=EmailScore(
        email_id="test-123",
        risk_score=0.3,
        confidence=0.8,
        processing_time=1.5
    ))
    
    return engine


# Test utilities
class TestEmailFactory:
    """Factory for creating test emails."""
    
    @staticmethod
    def create_legitimate_email(**kwargs):
        """Create legitimate email with optional overrides."""
        default = {
            "subject": "Test Email",
            "sender": "test@legitimate.com",
            "recipient": "user@company.com",
            "body": "This is a test email.",
            "headers": {"From": "test@legitimate.com"}
        }
        default.update(kwargs)
        return default
    
    @staticmethod
    def create_phishing_email(**kwargs):
        """Create phishing email with optional overrides."""
        default = {
            "subject": "URGENT: Verify Account",
            "sender": "security@fake-site.com",
            "recipient": "victim@company.com",
            "body": "Click here: https://fake-site.com/verify",
            "headers": {"From": "security@fake-site.com"}
        }
        default.update(kwargs)
        return default
    
    @staticmethod
    def create_email_with_attachments(**kwargs):
        """Create email with attachments."""
        default = {
            "subject": "Document Attached",
            "sender": "sender@company.com",
            "recipient": "recipient@company.com",
            "body": "Please find attached document.",
            "headers": {"From": "sender@company.com"},
            "attachments": [
                {
                    "filename": "document.pdf",
                    "content_type": "application/pdf",
                    "size": 1024
                }
            ]
        }
        default.update(kwargs)
        return default


class MockAnalysisResult:
    """Mock analysis result for testing."""
    
    def __init__(self, risk_score=0.5, confidence=0.8, threats=None):
        self.risk_score = risk_score
        self.confidence = confidence
        self.threats = threats or []
        self.processing_time = 1.0
        self.details = {
            "ai_analysis": {"classification": "suspicious"},
            "link_analysis": {"suspicious_urls": []},
            "threat_intel": {"malicious_domains": []}
        }


# Environment setup for testing
@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    """Setup test environment variables"""
    for key, value in test_env_vars.items():
        monkeypatch.setenv(key, value)


# Pytest markers for test organization
def pytest_configure(config):
    """Configure pytest markers"""
    config.addinivalue_line(
        "markers", "unit: Unit tests for individual components"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests with external systems"
    )
    config.addinivalue_line(
        "markers", "e2e: End-to-end tests"
    )
    config.addinivalue_line(
        "markers", "privacy: Privacy and PII protection tests"
    )
    config.addinivalue_line(
        "markers", "security: Security and sandbox tests"
    )
    config.addinivalue_line(
        "markers", "load: Load and performance tests"
    )
    config.addinivalue_line(
        "markers", "acceptance: Acceptance criteria tests"
    )
    config.addinivalue_line(
        "markers", "slow: Tests that take longer than 30 seconds"
    )
    config.addinivalue_line(
        "markers", "external: mark test as requiring external services"
    )
    config.addinivalue_line(
        "markers", "contract: mark test as contract test"
    )
    config.addinivalue_line(
        "markers", "worker: mark test as worker test"
    )


# Test collection and reporting hooks
def pytest_collection_modifyitems(config, items):
    """Modify test items during collection"""
    for item in items:
        # Add markers based on test file names
        if "test_privacy" in item.nodeid:
            item.add_marker(pytest.mark.privacy)
        if "test_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        if "test_load" in item.nodeid:
            item.add_marker(pytest.mark.load)
        if "test_acceptance" in item.nodeid:
            item.add_marker(pytest.mark.acceptance)
        
        # Add markers based on test file location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "contract" in str(item.fspath):
            item.add_marker(pytest.mark.contract)
        elif "worker" in str(item.fspath):
            item.add_marker(pytest.mark.worker)
        
        # Mark slow tests
        if any(keyword in item.nodeid.lower() for keyword in ['load', 'sustained', 'benchmark']):
            item.add_marker(pytest.mark.slow)
        
        # Mark tests that use external services
        if hasattr(item, 'fixturenames'):
            if any(fixture in item.fixturenames for fixture in ['mock_playwright', 'mock_ai_service']):
                item.add_marker(pytest.mark.external)


def pytest_runtest_setup(item):
    """Setup for each test run"""
    # Skip integration tests if external services not available
    if "integration" in item.keywords:
        # Add any integration test setup/skip logic here
        pass


def pytest_sessionstart(session):
    """Called after the Session object has been created"""
    print("\n" + "="*80)
    print("PhishNet Privacy-Hardened System - Comprehensive Test Suite")
    print("="*80)
    print("Running tests with the following coverage:")
    print("• Unit Tests: Core component functionality")
    print("• Integration Tests: System integration with mocked external services")
    print("• Privacy Tests: PII protection and data sanitization")  
    print("• Security Tests: Sandbox IP control and encryption")
    print("• Load Tests: Performance under concurrent load")
    print("• Acceptance Tests: Known test datasets and criteria")
    print("="*80)


def pytest_sessionfinish(session, exitstatus):
    """Called after whole test run finished"""
    print("\n" + "="*80)
    print("Test Suite Execution Complete")
    print("="*80)
    
    # Calculate test statistics
    passed = len([i for i in session.items if hasattr(i, 'passed') and i.passed])
    failed = len([i for i in session.items if hasattr(i, 'failed') and i.failed])
    skipped = len([i for i in session.items if hasattr(i, 'skipped') and i.skipped])
    total = len(session.items)
    
    if hasattr(session, 'testscollected'):
        total = session.testscollected
    
    print(f"Total Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Skipped: {skipped}")
    
    if total > 0:
        success_rate = (passed / total) * 100
        print(f"Success Rate: {success_rate:.1f}%")
    
    if exitstatus == 0:
        print("✅ All tests passed! Privacy-hardened system ready for deployment.")
    else:
        print("❌ Some tests failed. Review failures before deployment.")
    
    print("="*80)


# Custom test result reporting
class TestReporter:
    """Custom test result reporter for privacy compliance"""
    
    def __init__(self):
        self.privacy_tests_passed = 0
        self.security_tests_passed = 0
        self.acceptance_tests_passed = 0
        self.total_privacy_tests = 0
        self.total_security_tests = 0
        self.total_acceptance_tests = 0
    
    def record_test_result(self, test_name: str, passed: bool, markers: list):
        """Record test result for compliance reporting"""
        if 'privacy' in markers:
            self.total_privacy_tests += 1
            if passed:
                self.privacy_tests_passed += 1
        
        if 'security' in markers:
            self.total_security_tests += 1
            if passed:
                self.security_tests_passed += 1
        
        if 'acceptance' in markers:
            self.total_acceptance_tests += 1
            if passed:
                self.acceptance_tests_passed += 1
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance test report"""
        return {
            'privacy_compliance': {
                'passed': self.privacy_tests_passed,
                'total': self.total_privacy_tests,
                'compliance_rate': self.privacy_tests_passed / max(self.total_privacy_tests, 1)
            },
            'security_compliance': {
                'passed': self.security_tests_passed,
                'total': self.total_security_tests,
                'compliance_rate': self.security_tests_passed / max(self.total_security_tests, 1)
            },
            'acceptance_criteria': {
                'passed': self.acceptance_tests_passed,
                'total': self.total_acceptance_tests,
                'compliance_rate': self.acceptance_tests_passed / max(self.total_acceptance_tests, 1)
            }
        }


# Global test reporter instance
test_reporter = TestReporter()


@pytest.fixture
def compliance_reporter():
    """Fixture to access compliance reporter"""
    return test_reporter


# Pytest command line options
def pytest_addoption(parser):
    """Add custom command line options"""
    parser.addoption(
        "--privacy-only",
        action="store_true",
        default=False,
        help="Run only privacy and PII protection tests"
    )
    parser.addoption(
        "--security-only", 
        action="store_true",
        default=False,
        help="Run only security and sandbox tests"
    )
    parser.addoption(
        "--acceptance-only",
        action="store_true",
        default=False,
        help="Run only acceptance criteria tests"
    )
    parser.addoption(
        "--skip-slow",
        action="store_true",
        default=False,
        help="Skip slow running tests"
    )


def pytest_runtest_teardown(item):
    """Called after test execution"""
    # Record results in compliance reporter
    markers = [mark.name for mark in item.iter_markers()]
    passed = getattr(item, 'passed', True)
    test_reporter.record_test_result(item.name, passed, markers)


# Test data cleanup
@pytest.fixture(autouse=True)
def cleanup_test_data():
    """Cleanup test data after each test"""
    yield
    # Cleanup any test artifacts
    # Remove test files, clear caches, etc.
    pass


# Performance monitoring
@pytest.fixture
def performance_monitor():
    """Monitor test performance"""
    import time
    start_time = time.time()
    yield
    end_time = time.time()
    execution_time = end_time - start_time
    
    # Log slow tests
    if execution_time > 5.0:
        print(f"\n⚠️  Slow test detected: {execution_time:.2f}s")


# Performance testing utilities
@pytest.fixture
def performance_timer():
    """Timer for performance testing."""
    import time
    
    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
        
        def start(self):
            self.start_time = time.time()
        
        def stop(self):
            self.end_time = time.time()
        
        @property
        def duration(self):  # Changed from elapsed to duration
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None
    
    return Timer()


@pytest.fixture
def sample_url():
    """Sample URL for testing."""
    return "https://example.com"


# Database testing utilities
@pytest.fixture
def clean_db(db_session):
    """Clean database before each test."""
    # Clear all tables
    from app.models.email import Email
    from app.models.detection import Detection
    from app.models.scoring import EmailScore, EmailAction
    from app.models.user import User
    
    db_session.query(EmailAction).delete()
    db_session.query(EmailScore).delete()
    db_session.query(Detection).delete()
    db_session.query(Email).delete()
    db_session.query(User).delete()
    db_session.commit()
    
    yield db_session
    
    # Cleanup after test
    db_session.rollback()
