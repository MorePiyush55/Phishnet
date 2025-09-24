"""
Security Testing Suite

Comprehensive security testing for threat detection and protection features:
- Authentication security testing
- Authorization testing  
- Input validation testing
- SQL injection protection
- XSS prevention testing
- CSRF protection testing
- Rate limiting testing
- Security headers testing
- Encryption testing
- Threat detection accuracy testing
"""

import pytest
import asyncio
import json
import hashlib
import hmac
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
from unittest.mock import AsyncMock, MagicMock, patch

from backend.app.auth import AuthService, JWTManager, RateLimiter
from backend.app.security import SecurityService, ThreatDetector, InputValidator
from backend.app.ml import ThreatClassifier
from backend.app.observability import get_logger

logger = get_logger(__name__)

@pytest.fixture
async def auth_service():
    """Create auth service for testing."""
    return AuthService(
        jwt_manager=JWTManager(secret_key="test_secret_key_123"),
        db_manager=AsyncMock(),
        rate_limiter=RateLimiter()
    )

@pytest.fixture
async def security_service():
    """Create security service for testing."""
    return SecurityService(
        threat_detector=ThreatDetector(),
        input_validator=InputValidator()
    )

@pytest.fixture
async def threat_classifier():
    """Create threat classifier for testing."""
    return ThreatClassifier(model_path="test_model.pkl")

class TestAuthentication:
    """Test authentication security."""
    
    @pytest.mark.asyncio
    async def test_password_strength_validation(self, auth_service):
        """Test password strength requirements."""
        weak_passwords = [
            "123456",
            "password",
            "abc123",
            "qwerty",
            "admin",
            "pass",
            "12345678"
        ]
        
        for password in weak_passwords:
            is_valid = await auth_service.validate_password_strength(password)
            assert not is_valid, f"Weak password '{password}' should be rejected"
        
        strong_passwords = [
            "MyStr0ng!Pass",
            "C0mpl3x@P@ssw0rd",
            "S3cur3#P@ssw0rd!2024",
            "Tr0ub@d0ur&B@tter!es"
        ]
        
        for password in strong_passwords:
            is_valid = await auth_service.validate_password_strength(password)
            assert is_valid, f"Strong password '{password}' should be accepted"
    
    @pytest.mark.asyncio
    async def test_password_hashing(self, auth_service):
        """Test secure password hashing."""
        password = "test_password_123"
        
        # Hash password
        password_hash = await auth_service.hash_password(password)
        
        # Verify hash properties
        assert password_hash != password, "Password should be hashed"
        assert len(password_hash) > 50, "Hash should be sufficiently long"
        assert "$" in password_hash, "Should use proper hashing algorithm"
        
        # Verify password verification
        is_valid = await auth_service.verify_password(password, password_hash)
        assert is_valid, "Should verify correct password"
        
        # Verify wrong password rejection
        is_valid = await auth_service.verify_password("wrong_password", password_hash)
        assert not is_valid, "Should reject wrong password"
    
    @pytest.mark.asyncio
    async def test_jwt_token_security(self, auth_service):
        """Test JWT token security."""
        user_id = "test_user_123"
        
        # Generate token
        token = await auth_service.generate_token(user_id)
        
        assert token is not None
        assert len(token) > 100, "Token should be sufficiently long"
        
        # Verify token
        payload = await auth_service.verify_token(token)
        assert payload["user_id"] == user_id
        
        # Test token expiration
        expired_token = await auth_service.generate_token(
            user_id, 
            expires_in=timedelta(seconds=-1)  # Already expired
        )
        
        with pytest.raises(Exception):
            await auth_service.verify_token(expired_token)
    
    @pytest.mark.asyncio
    async def test_account_lockout(self, auth_service):
        """Test account lockout after failed attempts."""
        user_id = "test_user_lockout"
        
        # Simulate multiple failed login attempts
        for _ in range(5):
            await auth_service.record_failed_login(user_id)
        
        # Check if account is locked
        is_locked = await auth_service.is_account_locked(user_id)
        assert is_locked, "Account should be locked after failed attempts"
        
        # Verify login is prevented
        can_login = await auth_service.can_attempt_login(user_id)
        assert not can_login, "Login should be prevented for locked account"
    
    @pytest.mark.asyncio
    async def test_session_management(self, auth_service):
        """Test secure session management."""
        user_id = "test_user_session"
        
        # Create session
        session_id = await auth_service.create_session(user_id)
        assert session_id is not None
        
        # Verify session
        session_user = await auth_service.get_session_user(session_id)
        assert session_user == user_id
        
        # Invalidate session
        await auth_service.invalidate_session(session_id)
        
        # Verify session no longer valid
        session_user = await auth_service.get_session_user(session_id)
        assert session_user is None

class TestAuthorization:
    """Test authorization and access control."""
    
    @pytest.mark.asyncio
    async def test_role_based_access(self, auth_service):
        """Test role-based access control."""
        # Test different user roles
        test_cases = [
            {
                "user_id": "admin_user",
                "role": "admin",
                "permissions": ["read", "write", "delete", "admin"]
            },
            {
                "user_id": "regular_user", 
                "role": "user",
                "permissions": ["read", "write"]
            },
            {
                "user_id": "readonly_user",
                "role": "readonly",
                "permissions": ["read"]
            }
        ]
        
        for case in test_cases:
            # Set user role
            await auth_service.set_user_role(case["user_id"], case["role"])
            
            # Test permissions
            for permission in ["read", "write", "delete", "admin"]:
                has_permission = await auth_service.check_permission(
                    case["user_id"], 
                    permission
                )
                
                if permission in case["permissions"]:
                    assert has_permission, f"User {case['role']} should have {permission} permission"
                else:
                    assert not has_permission, f"User {case['role']} should not have {permission} permission"
    
    @pytest.mark.asyncio
    async def test_resource_based_access(self, auth_service):
        """Test resource-based access control."""
        user_id = "test_user_resource"
        resource_id = "email_scan_123"
        
        # Grant access to specific resource
        await auth_service.grant_resource_access(user_id, resource_id, "read")
        
        # Verify access granted
        has_access = await auth_service.check_resource_access(user_id, resource_id, "read")
        assert has_access, "Should have read access to granted resource"
        
        # Verify no write access
        has_write = await auth_service.check_resource_access(user_id, resource_id, "write")
        assert not has_write, "Should not have write access without grant"
        
        # Test access to different resource
        other_resource = "email_scan_456"
        has_other_access = await auth_service.check_resource_access(user_id, other_resource, "read")
        assert not has_other_access, "Should not have access to other resources"

class TestInputValidation:
    """Test input validation and sanitization."""
    
    def test_email_validation(self):
        """Test email address validation."""
        valid_emails = [
            "user@example.com",
            "test.user@company.org",
            "user+tag@domain.co.uk",
            "123@456.com"
        ]
        
        invalid_emails = [
            "invalid-email",
            "@domain.com", 
            "user@",
            "user space@domain.com",
            "<script>alert('xss')</script>@evil.com",
            "user@domain..com"
        ]
        
        validator = InputValidator()
        
        for email in valid_emails:
            assert validator.validate_email(email), f"Valid email {email} should pass validation"
        
        for email in invalid_emails:
            assert not validator.validate_email(email), f"Invalid email {email} should fail validation"
    
    def test_url_validation(self):
        """Test URL validation."""
        valid_urls = [
            "https://example.com",
            "http://test.org/path",
            "https://subdomain.example.com/path?param=value",
            "https://example.com:8080/secure"
        ]
        
        invalid_urls = [
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            "file:///etc/passwd",
            "ftp://malicious.com",
            "not-a-url",
            "http://<script>alert('xss')</script>"
        ]
        
        validator = InputValidator()
        
        for url in valid_urls:
            assert validator.validate_url(url), f"Valid URL {url} should pass validation"
        
        for url in invalid_urls:
            assert not validator.validate_url(url), f"Invalid URL {url} should fail validation"
    
    def test_html_sanitization(self):
        """Test HTML sanitization."""
        dangerous_inputs = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "<iframe src=javascript:alert('xss')></iframe>",
            "<svg onload=alert('xss')>",
            "<body onload=alert('xss')>",
            "javascript:alert('xss')",
            "<a href='javascript:alert(\"xss\")'>click me</a>"
        ]
        
        validator = InputValidator()
        
        for dangerous_input in dangerous_inputs:
            sanitized = validator.sanitize_html(dangerous_input)
            
            # Check that dangerous elements are removed/escaped
            assert "<script>" not in sanitized.lower()
            assert "javascript:" not in sanitized.lower()
            assert "onerror=" not in sanitized.lower()
            assert "onload=" not in sanitized.lower()
            assert "alert(" not in sanitized
    
    def test_sql_injection_prevention(self):
        """Test SQL injection prevention."""
        sql_injection_attempts = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1; DELETE FROM emails; --",
            "' UNION SELECT * FROM passwords --",
            "1' OR 1=1 /*"
        ]
        
        validator = InputValidator()
        
        for injection_attempt in sql_injection_attempts:
            is_safe = validator.check_sql_injection(injection_attempt)
            assert not is_safe, f"SQL injection attempt should be detected: {injection_attempt}"

class TestRateLimiting:
    """Test rate limiting protection."""
    
    @pytest.mark.asyncio
    async def test_api_rate_limiting(self, auth_service):
        """Test API endpoint rate limiting."""
        client_ip = "192.168.1.100"
        endpoint = "/api/scan"
        
        # Configure rate limit (5 requests per minute)
        rate_limiter = RateLimiter(max_requests=5, time_window=60)
        
        # Make requests within limit
        for i in range(5):
            allowed = await rate_limiter.check_rate_limit(client_ip, endpoint)
            assert allowed, f"Request {i+1} should be allowed"
        
        # Next request should be blocked
        blocked = await rate_limiter.check_rate_limit(client_ip, endpoint)
        assert not blocked, "Request should be blocked after hitting rate limit"
    
    @pytest.mark.asyncio
    async def test_login_rate_limiting(self, auth_service):
        """Test login attempt rate limiting."""
        client_ip = "192.168.1.101"
        
        # Configure login rate limit (3 attempts per 5 minutes)
        login_limiter = RateLimiter(max_requests=3, time_window=300)
        
        # Make login attempts
        for i in range(3):
            allowed = await login_limiter.check_rate_limit(client_ip, "login")
            assert allowed, f"Login attempt {i+1} should be allowed"
        
        # Next attempt should be blocked
        blocked = await login_limiter.check_rate_limit(client_ip, "login")
        assert not blocked, "Login attempt should be blocked"
    
    @pytest.mark.asyncio 
    async def test_distributed_rate_limiting(self, auth_service):
        """Test rate limiting across multiple instances."""
        # Simulate distributed environment
        rate_limiter = RateLimiter(
            max_requests=10,
            time_window=60,
            distributed=True,
            redis_client=AsyncMock()
        )
        
        client_ip = "192.168.1.102"
        endpoint = "/api/analyze"
        
        # Simulate requests from different instances
        for instance in range(3):
            for request in range(4):  # Total: 12 requests (exceeds limit of 10)
                allowed = await rate_limiter.check_rate_limit(
                    client_ip, 
                    endpoint,
                    instance_id=f"instance_{instance}"
                )
                
                total_requests = (instance * 4) + request + 1
                if total_requests <= 10:
                    assert allowed, f"Request {total_requests} should be allowed"
                else:
                    assert not allowed, f"Request {total_requests} should be blocked"

class TestThreatDetection:
    """Test threat detection accuracy."""
    
    @pytest.mark.asyncio
    async def test_phishing_detection(self, threat_classifier):
        """Test phishing email detection."""
        # Test phishing emails
        phishing_samples = [
            {
                "subject": "URGENT: Verify your account NOW!",
                "body": "Click here to verify your PayPal account: http://phishing-site.com",
                "sender": "security@paypal-fake.com"
            },
            {
                "subject": "Your account has been suspended",
                "body": "Login immediately to restore access: http://evil-site.com/login",
                "sender": "noreply@bank-fake.org"
            },
            {
                "subject": "Prize notification - You've won $1,000,000!",
                "body": "Claim your prize by providing personal information",
                "sender": "lottery@scam-site.com"
            }
        ]
        
        for sample in phishing_samples:
            prediction = await threat_classifier.predict(sample)
            
            assert prediction["is_phishing"], f"Should detect phishing: {sample['subject']}"
            assert prediction["confidence"] > 0.8, f"Should have high confidence: {prediction['confidence']}"
    
    @pytest.mark.asyncio
    async def test_legitimate_email_detection(self, threat_classifier):
        """Test legitimate email detection."""
        # Test legitimate emails
        legitimate_samples = [
            {
                "subject": "Weekly team meeting reminder",
                "body": "Don't forget our team meeting tomorrow at 2 PM in conference room A",
                "sender": "manager@company.com"
            },
            {
                "subject": "Project update", 
                "body": "Here's the latest status on the development project...",
                "sender": "developer@team.org"
            },
            {
                "subject": "Invoice for services",
                "body": "Please find attached the invoice for consulting services provided",
                "sender": "billing@legitimate-company.com"
            }
        ]
        
        for sample in legitimate_samples:
            prediction = await threat_classifier.predict(sample)
            
            assert not prediction["is_phishing"], f"Should not detect phishing: {sample['subject']}"
            assert prediction["confidence"] > 0.7, f"Should have good confidence: {prediction['confidence']}"
    
    @pytest.mark.asyncio
    async def test_malware_link_detection(self, security_service):
        """Test malware link detection."""
        malicious_urls = [
            "http://malware-download.com/virus.exe",
            "https://phishing-site.evil/steal-credentials.html", 
            "http://suspicious-domain.tk/malware.zip",
            "https://bit.ly/suspicious-redirect",  # Suspicious shortener
            "http://127.0.0.1:8080/exploit.php"   # Local network exploit
        ]
        
        for url in malicious_urls:
            threat_result = await security_service.analyze_url(url)
            
            assert threat_result["is_malicious"], f"Should detect malicious URL: {url}"
            assert threat_result["risk_score"] > 0.7, f"Should have high risk score: {threat_result['risk_score']}"
    
    @pytest.mark.asyncio
    async def test_attachment_scanning(self, security_service):
        """Test email attachment scanning."""
        # Test malicious attachments
        malicious_attachments = [
            {
                "filename": "invoice.pdf.exe",
                "content_type": "application/octet-stream",
                "size": 1024000,  # 1MB
                "hash": "malicious_file_hash_123"
            },
            {
                "filename": "document.docm",  # Macro-enabled document
                "content_type": "application/vnd.ms-word.document.macroEnabled.12",
                "size": 512000,
                "hash": "suspicious_macro_hash_456"
            }
        ]
        
        for attachment in malicious_attachments:
            scan_result = await security_service.scan_attachment(attachment)
            
            assert scan_result["is_malicious"], f"Should detect malicious attachment: {attachment['filename']}"
            assert scan_result["risk_level"] in ["HIGH", "CRITICAL"]

class TestSecurityHeaders:
    """Test security headers implementation."""
    
    @pytest.mark.asyncio
    async def test_security_headers_present(self, security_service):
        """Test that required security headers are present."""
        # Simulate HTTP response headers
        response_headers = await security_service.get_security_headers()
        
        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "Referrer-Policy"
        ]
        
        for header in required_headers:
            assert header in response_headers, f"Security header {header} should be present"
        
        # Verify specific header values
        assert response_headers["X-Content-Type-Options"] == "nosniff"
        assert response_headers["X-Frame-Options"] == "DENY"
        assert "max-age=" in response_headers["Strict-Transport-Security"]
    
    @pytest.mark.asyncio
    async def test_csp_policy(self, security_service):
        """Test Content Security Policy configuration."""
        csp_header = await security_service.get_csp_header()
        
        # Verify CSP directives
        assert "default-src 'self'" in csp_header
        assert "script-src 'self'" in csp_header
        assert "object-src 'none'" in csp_header
        assert "base-uri 'self'" in csp_header
        
        # Should not allow unsafe inline or eval
        assert "'unsafe-inline'" not in csp_header or "script-src" not in csp_header
        assert "'unsafe-eval'" not in csp_header

class TestEncryption:
    """Test encryption implementation."""
    
    @pytest.mark.asyncio
    async def test_data_encryption(self, security_service):
        """Test data encryption/decryption."""
        sensitive_data = "This is sensitive user information"
        
        # Encrypt data
        encrypted_data = await security_service.encrypt_data(sensitive_data)
        
        assert encrypted_data != sensitive_data, "Data should be encrypted"
        assert len(encrypted_data) > len(sensitive_data), "Encrypted data should be longer"
        
        # Decrypt data
        decrypted_data = await security_service.decrypt_data(encrypted_data)
        
        assert decrypted_data == sensitive_data, "Decrypted data should match original"
    
    @pytest.mark.asyncio
    async def test_password_encryption(self, auth_service):
        """Test password encryption in transit and at rest."""
        password = "user_password_123"
        
        # Simulate password transmission encryption
        transmitted_password = await auth_service.encrypt_for_transmission(password)
        assert transmitted_password != password, "Password should be encrypted for transmission"
        
        # Simulate password storage encryption
        stored_password_hash = await auth_service.hash_password(password)
        assert stored_password_hash != password, "Password should be hashed for storage"
        assert len(stored_password_hash) > 50, "Hash should be sufficiently long"
    
    @pytest.mark.asyncio
    async def test_token_encryption(self, auth_service):
        """Test authentication token encryption."""
        user_id = "test_user_encryption"
        
        # Generate encrypted token
        token = await auth_service.generate_encrypted_token(user_id)
        
        assert token is not None
        assert user_id not in token, "User ID should not be visible in token"
        
        # Verify token decryption
        decrypted_payload = await auth_service.decrypt_token(token)
        assert decrypted_payload["user_id"] == user_id

class TestSecurityMonitoring:
    """Test security monitoring and alerting."""
    
    @pytest.mark.asyncio
    async def test_suspicious_activity_detection(self, security_service):
        """Test detection of suspicious activities."""
        user_id = "test_user_suspicious"
        
        # Simulate suspicious activities
        suspicious_activities = [
            {"type": "multiple_failed_logins", "count": 10, "timeframe": 300},
            {"type": "unusual_access_pattern", "locations": ["US", "RU", "CN"], "timeframe": 3600},
            {"type": "privilege_escalation_attempt", "from_role": "user", "to_role": "admin"},
            {"type": "data_exfiltration_pattern", "volume": "1GB", "timeframe": 600}
        ]
        
        for activity in suspicious_activities:
            is_suspicious = await security_service.detect_suspicious_activity(user_id, activity)
            assert is_suspicious, f"Should detect suspicious activity: {activity['type']}"
    
    @pytest.mark.asyncio
    async def test_security_alert_generation(self, security_service):
        """Test security alert generation."""
        # Simulate security incident
        incident = {
            "type": "brute_force_attack",
            "source_ip": "192.168.1.100",
            "target_user": "admin",
            "attempts": 50,
            "timeframe": 600
        }
        
        alert = await security_service.generate_security_alert(incident)
        
        assert alert is not None
        assert alert["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert alert["type"] == "brute_force_attack"
        assert "source_ip" in alert
        assert "mitigation_steps" in alert
    
    @pytest.mark.asyncio
    async def test_security_metrics_collection(self, security_service):
        """Test security metrics collection."""
        # Collect security metrics
        metrics = await security_service.collect_security_metrics()
        
        expected_metrics = [
            "failed_login_attempts",
            "successful_logins", 
            "blocked_ips",
            "detected_threats",
            "security_alerts",
            "rate_limit_violations"
        ]
        
        for metric in expected_metrics:
            assert metric in metrics, f"Security metric {metric} should be collected"
            assert isinstance(metrics[metric], (int, float)), f"Metric {metric} should be numeric"

# Performance tests for security operations
class TestSecurityPerformance:
    """Test performance of security operations."""
    
    @pytest.mark.asyncio
    async def test_threat_detection_performance(self, threat_classifier):
        """Test threat detection performance."""
        # Prepare test email
        test_email = {
            "subject": "Test email for performance",
            "body": "This is a test email for performance testing",
            "sender": "test@example.com"
        }
        
        start_time = asyncio.get_event_loop().time()
        
        # Perform multiple predictions
        for _ in range(100):
            await threat_classifier.predict(test_email)
        
        end_time = asyncio.get_event_loop().time()
        duration = end_time - start_time
        
        # Should complete 100 predictions in under 5 seconds
        assert duration < 5.0, f"Threat detection too slow: {duration:.3f}s for 100 predictions"
    
    @pytest.mark.asyncio
    async def test_encryption_performance(self, security_service):
        """Test encryption/decryption performance."""
        # Test with various data sizes
        data_sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
        
        for size in data_sizes:
            test_data = "A" * size
            
            start_time = asyncio.get_event_loop().time()
            
            # Encrypt and decrypt
            encrypted = await security_service.encrypt_data(test_data)
            decrypted = await security_service.decrypt_data(encrypted)
            
            end_time = asyncio.get_event_loop().time()
            duration = end_time - start_time
            
            # Should complete in reasonable time
            max_time = size / 10240  # 100ms per 10KB
            assert duration < max_time, f"Encryption too slow for {size} bytes: {duration:.3f}s"
            assert decrypted == test_data, "Decryption should produce original data"

# Integration tests
class TestSecurityIntegration:
    """Test security component integration."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_security_flow(self, auth_service, security_service, threat_classifier):
        """Test complete security flow."""
        # Step 1: Authenticate user
        user_id = "test_user_security_e2e"
        password = "SecureP@ssw0rd!123"
        
        # Register user
        await auth_service.register_user(user_id, password)
        
        # Authenticate
        token = await auth_service.authenticate(user_id, password)
        assert token is not None
        
        # Step 2: Validate authorization
        has_permission = await auth_service.check_permission(user_id, "email_scan")
        assert has_permission, "User should have email scan permission"
        
        # Step 3: Process email with security checks
        test_email = {
            "subject": "Suspicious email test",
            "body": "Click here: http://suspicious-site.com",
            "sender": "suspicious@evil.com"
        }
        
        # Validate input
        is_valid_email = InputValidator().validate_email(test_email["sender"])
        assert not is_valid_email, "Should detect suspicious sender"
        
        # Analyze threats
        threat_result = await threat_classifier.predict(test_email)
        url_analysis = await security_service.analyze_url("http://suspicious-site.com")
        
        # Step 4: Log security events
        await security_service.log_security_event(
            event_type="threat_analysis",
            user_id=user_id,
            details={
                "email_threat": threat_result,
                "url_analysis": url_analysis
            }
        )
        
        # Verify complete security flow
        security_log = await security_service.get_security_log(user_id)
        assert len(security_log) > 0, "Security events should be logged"

if __name__ == "__main__":
    # Run security tests
    pytest.main([__file__, "-v", "--tb=short"])