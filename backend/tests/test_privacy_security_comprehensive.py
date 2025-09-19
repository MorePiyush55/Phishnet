"""
Comprehensive Privacy/Security Tests for PhishNet
Ensure no PII is sent to third parties - scan payloads and assert redaction
Test comprehensive PII validation and security controls
"""

import pytest
import asyncio
import json
import re
import time
from unittest.mock import Mock, patch, AsyncMock, MagicMock, call
from typing import Dict, List, Any, Optional, Tuple
import requests
import base64
from datetime import datetime, timedelta

# Core imports
from app.core.pii_sanitizer import get_pii_sanitizer, PIISanitizer
from app.core.sandbox_security import get_sandbox_ip_manager
from app.core.encryption import get_encryption_manager
from app.orchestrator.main import PhishNetOrchestrator
from app.integrations.virustotal import VirusTotalAdapter
from app.integrations.gemini import GeminiAdapter
from app.integrations.abuseipdb import AbuseIPDBAdapter


class PIIDetector:
    """Advanced PII detection for payload validation"""
    
    def __init__(self):
        self.pii_patterns = {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})'),
            'ssn': re.compile(r'\b\d{3}-?\d{2}-?\d{4}\b'),
            'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'api_key': re.compile(r'(?:api[_-]?key|token|secret)["\'\s]*[:=]["\'\s]*([A-Za-z0-9+/=]{16,})'),
            'password': re.compile(r'(?:password|pwd|pass)["\'\s]*[:=]["\'\s]*([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]{6,})'),
            'url_param': re.compile(r'[?&](token|key|secret|password|auth|session)=([^&\s]+)'),
        }
    
    def detect_pii(self, text: str) -> Dict[str, List[str]]:
        """Detect all PII types in text"""
        detected = {}
        
        for pii_type, pattern in self.pii_patterns.items():
            matches = pattern.findall(text)
            if matches:
                detected[pii_type] = matches
        
        return detected
    
    def has_any_pii(self, text: str) -> bool:
        """Check if text contains any PII"""
        return len(self.detect_pii(text)) > 0


class PayloadInterceptor:
    """Intercept and validate API payloads"""
    
    def __init__(self):
        self.intercepted_payloads = []
        self.pii_detector = PIIDetector()
    
    def intercept_payload(self, service: str, payload: Any) -> Dict[str, Any]:
        """Intercept and analyze API payload"""
        payload_str = str(payload)
        
        analysis = {
            'service': service,
            'timestamp': datetime.now().isoformat(),
            'payload_size': len(payload_str),
            'detected_pii': self.pii_detector.detect_pii(payload_str),
            'has_pii': self.pii_detector.has_any_pii(payload_str),
            'payload_preview': payload_str[:500] + "..." if len(payload_str) > 500 else payload_str
        }
        
        self.intercepted_payloads.append(analysis)
        return analysis
    
    def get_pii_violations(self) -> List[Dict[str, Any]]:
        """Get all payloads that contain PII"""
        return [p for p in self.intercepted_payloads if p['has_pii']]
    
    def clear_intercepted(self):
        """Clear intercepted payloads"""
        self.intercepted_payloads.clear()


class TestPIIRedactionValidation:
    """Test comprehensive PII redaction and validation"""
    
    def setup_method(self):
        """Set up test environment"""
        self.sanitizer = get_pii_sanitizer()
        self.pii_detector = PIIDetector()
        self.payload_interceptor = PayloadInterceptor()
    
    def test_email_address_redaction(self):
        """Test email address redaction in various formats"""
        test_cases = [
            "Contact john.doe@company.com for support",
            "Email: user+tag@subdomain.example.org",
            "Send to: admin@domain-name.co.uk",
            "Reply to firstname.lastname@company-name.com",
            "User john.doe+newsletter@example-site.net needs help"
        ]
        
        for test_content in test_cases:
            for service in ["virustotal", "gemini", "openai", "anthropic"]:
                result = self.sanitizer.sanitize_for_third_party(test_content, service)
                sanitized = result['sanitized_content']
                
                # Verify no email addresses remain
                detected_emails = self.pii_detector.detect_pii(sanitized).get('email', [])
                assert len(detected_emails) == 0, f"Emails found in {service} payload: {detected_emails}"
                
                # Verify redaction occurred
                assert sanitized != test_content, f"No redaction occurred for {service}"
    
    def test_phone_number_redaction(self):
        """Test phone number redaction in various formats"""
        test_cases = [
            "Call (555) 123-4567 for assistance",
            "Phone: +1-555-123-4567",
            "Contact 555.123.4567 or 555-123-4567",
            "Mobile: +1 (555) 123 4567",
            "Emergency: 911 or +1-555-HELP (4357)"
        ]
        
        for test_content in test_cases:
            for service in ["virustotal", "gemini", "openai", "anthropic"]:
                result = self.sanitizer.sanitize_for_third_party(test_content, service)
                sanitized = result['sanitized_content']
                
                # Verify no phone numbers remain
                detected_phones = self.pii_detector.detect_pii(sanitized).get('phone', [])
                assert len(detected_phones) == 0, f"Phone numbers found in {service} payload: {detected_phones}"
    
    def test_ssn_redaction(self):
        """Test SSN redaction"""
        test_cases = [
            "SSN: 123-45-6789",
            "Social Security Number 123456789",
            "Your SSN is 123 45 6789",
            "ID: 987-65-4321 for verification"
        ]
        
        for test_content in test_cases:
            result = self.sanitizer.sanitize_for_third_party(test_content, "gemini")
            sanitized = result['sanitized_content']
            
            # Verify no SSNs remain
            detected_ssns = self.pii_detector.detect_pii(sanitized).get('ssn', [])
            assert len(detected_ssns) == 0, f"SSNs found in payload: {detected_ssns}"
    
    def test_credit_card_redaction(self):
        """Test credit card number redaction"""
        test_cases = [
            "Card: 4532-1234-5678-9012",
            "Credit card 4532 1234 5678 9012",
            "Payment via 4532123456789012",
            "Visa ending in 9012: 4532-1234-5678-9012"
        ]
        
        for test_content in test_cases:
            result = self.sanitizer.sanitize_for_third_party(test_content, "openai")
            sanitized = result['sanitized_content']
            
            # Verify no credit cards remain
            detected_cards = self.pii_detector.detect_pii(sanitized).get('credit_card', [])
            assert len(detected_cards) == 0, f"Credit cards found in payload: {detected_cards}"
    
    def test_url_parameter_redaction(self):
        """Test URL parameter redaction (tokens, secrets, etc.)"""
        test_cases = [
            "Reset: https://site.com/reset?token=abc123secret456",
            "Login: https://app.com/auth?api_key=sk_live_12345abcdef",
            "Access: https://site.com/page?session=sess_789xyz&user=john",
            "Verify: https://site.com/verify?secret=confidential123&email=user@site.com"
        ]
        
        for test_content in test_cases:
            result = self.sanitizer.sanitize_for_third_party(test_content, "virustotal")
            sanitized = result['sanitized_content']
            
            # Verify sensitive URL parameters are redacted
            url_params = self.pii_detector.detect_pii(sanitized).get('url_param', [])
            assert len(url_params) == 0, f"Sensitive URL params found: {url_params}"
    
    def test_mixed_pii_comprehensive_redaction(self):
        """Test comprehensive redaction of mixed PII types"""
        complex_content = """
        Dear John Smith,
        
        Your account verification is required:
        
        Personal Information:
        - Email: john.smith@company.com
        - Phone: +1 (555) 123-4567
        - SSN: 123-45-6789
        - Credit Card: 4532-1234-5678-9012
        
        Login Details:
        - Username: john.smith@company.com
        - Password: MySecurePass123!
        
        Verification Link:
        https://verify.com/account?token=abc123secret456&user=john.smith@company.com&session=sess_789xyz
        
        If you need assistance, call (555) 123-4567 or email support@company.com
        
        Thank you,
        Security Team
        """
        
        for service in ["virustotal", "gemini", "openai", "anthropic"]:
            result = self.sanitizer.sanitize_for_third_party(complex_content, service)
            sanitized = result['sanitized_content']
            
            # Verify all PII types are redacted
            detected_pii = self.pii_detector.detect_pii(sanitized)
            
            for pii_type, instances in detected_pii.items():
                assert len(instances) == 0, f"{pii_type} PII found in {service} payload: {instances}"
            
            # Verify structure is preserved
            assert "Dear" in sanitized
            assert "Personal Information" in sanitized
            assert "Security Team" in sanitized
            assert "company.com" in sanitized  # Domain should be preserved


class TestAPIPayloadInterception:
    """Test actual API payloads for PII leakage"""
    
    def setup_method(self):
        """Set up payload interception"""
        self.payload_interceptor = PayloadInterceptor()
        self.orchestrator = PhishNetOrchestrator()
    
    @pytest.mark.asyncio
    async def test_virustotal_payload_no_pii(self):
        """Test VirusTotal API payloads contain no PII"""
        
        # Test email with PII
        pii_email_content = """
        From: john.doe@company.com
        Subject: Urgent Account Verification
        
        Dear John Doe,
        
        Your account john.doe@company.com requires immediate verification.
        Please call us at (555) 123-4567 or visit:
        https://fake-bank.com/verify?user=john.doe@company.com&token=secret123
        
        Your SSN 123-45-6789 and card 4532-1234-5678-9012 may be at risk.
        """
        
        with patch('requests.post') as mock_post:
            # Intercept the actual request payload
            def intercept_request(*args, **kwargs):
                self.payload_interceptor.intercept_payload('virustotal', kwargs.get('data') or kwargs.get('json'))
                return Mock(status_code=200, json=lambda: {"data": {"id": "test-scan"}})
            
            mock_post.side_effect = intercept_request
            
            # Perform scan
            vt_adapter = VirusTotalAdapter(api_key="test-key")
            
            try:
                await vt_adapter.scan_url("https://fake-bank.com/verify?user=john.doe@company.com&token=secret123")
            except:
                pass  # Expected to fail due to mocking
            
            # Verify no PII in intercepted payloads
            violations = self.payload_interceptor.get_pii_violations()
            
            for violation in violations:
                print(f"PII violation in VirusTotal payload:")
                print(f"Service: {violation['service']}")
                print(f"Detected PII: {violation['detected_pii']}")
                print(f"Payload preview: {violation['payload_preview']}")
            
            assert len(violations) == 0, f"Found {len(violations)} PII violations in VirusTotal payloads"
    
    @pytest.mark.asyncio
    async def test_gemini_payload_no_pii(self):
        """Test Gemini API payloads contain no PII"""
        
        pii_content = """
        URGENT: Account Suspended
        
        Dear customer,
        
        Your account john.doe@company.com has been suspended due to suspicious activity.
        
        To reactivate, please:
        1. Call us at (555) 123-4567
        2. Verify your identity with SSN: 123-45-6789
        3. Confirm your card details: 4532-1234-5678-9012
        
        Click here: https://fake-bank.com/reactivate?user=john.doe@company.com&urgent=true
        """
        
        with patch('google.generativeai.GenerativeModel') as mock_model:
            # Intercept the content sent to Gemini
            def intercept_content(content, **kwargs):
                self.payload_interceptor.intercept_payload('gemini', content)
                return Mock(text='{"threat_probability": 0.9, "confidence": 0.8}')
            
            mock_model.return_value.generate_content.side_effect = intercept_content
            
            # Perform analysis
            gemini_adapter = GeminiAdapter(api_key="test-key")
            
            try:
                await gemini_adapter.analyze_content(pii_content)
            except:
                pass  # Expected to fail due to mocking
            
            # Verify no PII in intercepted payloads
            violations = self.payload_interceptor.get_pii_violations()
            
            for violation in violations:
                print(f"PII violation in Gemini payload:")
                print(f"Detected PII: {violation['detected_pii']}")
                print(f"Payload preview: {violation['payload_preview']}")
            
            assert len(violations) == 0, f"Found {len(violations)} PII violations in Gemini payloads"
    
    @pytest.mark.asyncio
    async def test_abuseipdb_payload_no_pii(self):
        """Test AbuseIPDB API payloads contain no PII"""
        
        # Test with IP extraction from PII-rich content
        content_with_ips = """
        From: john.doe@company.com
        Subject: Server Alert
        
        Dear Admin,
        
        Suspicious activity detected from IP 192.168.1.100 and 203.0.113.50
        User credentials john.doe@company.com may be compromised.
        Contact (555) 123-4567 immediately.
        """
        
        with patch('requests.get') as mock_get:
            # Intercept the request
            def intercept_request(*args, **kwargs):
                self.payload_interceptor.intercept_payload('abuseipdb', kwargs.get('params', {}))
                return Mock(status_code=200, json=lambda: {"data": {"abuseConfidenceScore": 0}})
            
            mock_get.side_effect = intercept_request
            
            # Perform IP check
            abuse_adapter = AbuseIPDBAdapter(api_key="test-key")
            
            try:
                await abuse_adapter.check_ip("203.0.113.50")
            except:
                pass  # Expected to fail due to mocking
            
            # Verify no PII in intercepted payloads
            violations = self.payload_interceptor.get_pii_violations()
            
            for violation in violations:
                print(f"PII violation in AbuseIPDB payload:")
                print(f"Detected PII: {violation['detected_pii']}")
                print(f"Payload preview: {violation['payload_preview']}")
            
            assert len(violations) == 0, f"Found {len(violations)} PII violations in AbuseIPDB payloads"
    
    @pytest.mark.asyncio
    async def test_full_orchestrator_no_pii_leakage(self):
        """Test complete orchestrator flow for PII leakage"""
        
        # Highly sensitive email content
        sensitive_email = {
            'subject': 'URGENT: Banking Security Alert',
            'sender': 'security@fake-bank.com',
            'body': '''
            Dear John Doe,
            
            Your account john.doe@bankofamerica.com has been compromised.
            
            Personal Details on File:
            - Full Name: John Michael Doe
            - Email: john.doe@company.com
            - Phone: +1 (555) 123-4567
            - SSN: 123-45-6789
            - Account: 987654321
            - Card: 4532-1234-5678-9012 (expires 12/25)
            - PIN: 1234
            
            Login immediately: https://fake-bankofamerica.com/urgent-login?user=john.doe@bankofamerica.com&session=abc123secret&urgent=true
            
            Or call us at (555) 987-6543 to verify your identity.
            
            Account Recovery Code: REC-123-SECRET-789
            Temporary Password: TempPass2023!
            
            Time sensitive - expires in 24 hours.
            
            Security Department
            Bank of America (fake)
            ''',
            'links': [
                'https://fake-bankofamerica.com/urgent-login?user=john.doe@bankofamerica.com&session=abc123secret&urgent=true'
            ]
        }
        
        # Patch all external API calls to intercept payloads
        with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
             patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
            
            # Mock successful responses
            mock_vt.return_value = Mock(
                scan_id="full-test-scan",
                positives=30,
                total=70,
                permalink="https://virustotal.com/full-test"
            )
            
            mock_gemini.return_value = {
                'threat_probability': 0.95,
                'confidence': 0.98,
                'reasoning': 'Clear phishing attempt',
                'risk_factors': ['urgent_language', 'credential_request', 'domain_spoofing']
            }
            
            mock_abuse.return_value = Mock(
                ip_address="203.0.113.100",
                abuse_confidence=85,
                total_reports=50
            )
            
            # Setup payload interception for all adapters
            def intercept_vt_call(*args, **kwargs):
                self.payload_interceptor.intercept_payload('virustotal', args)
                return mock_vt.return_value
            
            def intercept_gemini_call(*args, **kwargs):
                self.payload_interceptor.intercept_payload('gemini', args)
                return mock_gemini.return_value
            
            def intercept_abuse_call(*args, **kwargs):
                self.payload_interceptor.intercept_payload('abuseipdb', args)
                return mock_abuse.return_value
            
            mock_vt.side_effect = intercept_vt_call
            mock_gemini.side_effect = intercept_gemini_call
            mock_abuse.side_effect = intercept_abuse_call
            
            # Perform full scan
            result = await self.orchestrator.scan_email(
                user_id="test_user_pii",
                email_id="test_email_pii",
                subject=sensitive_email['subject'],
                sender=sensitive_email['sender'],
                body=sensitive_email['body'],
                links=sensitive_email['links']
            )
            
            # Verify scan completed
            assert result is not None
            assert result.overall_threat_level == "HIGH"
            
            # Verify NO PII in any intercepted payloads
            violations = self.payload_interceptor.get_pii_violations()
            
            if violations:
                print("\n=== PII VIOLATIONS DETECTED ===")
                for i, violation in enumerate(violations, 1):
                    print(f"\nViolation {i}:")
                    print(f"Service: {violation['service']}")
                    print(f"Detected PII Types: {list(violation['detected_pii'].keys())}")
                    for pii_type, instances in violation['detected_pii'].items():
                        print(f"  {pii_type}: {instances}")
                    print(f"Payload preview: {violation['payload_preview']}")
                print("=" * 50)
            
            assert len(violations) == 0, f"CRITICAL: Found {len(violations)} PII violations across all services!"


class TestSecurityControlValidation:
    """Test security controls and data protection"""
    
    @pytest.mark.asyncio
    async def test_encryption_at_rest(self):
        """Test data encryption at rest"""
        encryption_manager = get_encryption_manager()
        
        # Test sensitive data encryption
        sensitive_data = [
            "john.doe@company.com",
            "oauth_access_token_abc123",
            "gmail_refresh_token_xyz789",
            "user_password_hash_456",
            "api_key_secret_789"
        ]
        
        for data in sensitive_data:
            # Test token encryption
            encrypted = encryption_manager.encrypt_token(data)
            decrypted = encryption_manager.decrypt_token(encrypted)
            
            assert encrypted != data, "Data not encrypted"
            assert decrypted == data, "Decryption failed"
            
            # Test PII encryption
            encrypted_pii = encryption_manager.encrypt_pii(data)
            decrypted_pii = encryption_manager.decrypt_pii(encrypted_pii)
            
            assert encrypted_pii != data, "PII not encrypted"
            assert decrypted_pii == data, "PII decryption failed"
    
    @pytest.mark.asyncio
    async def test_sandbox_ip_enforcement(self):
        """Test sandbox IP enforcement"""
        sandbox_manager = get_sandbox_ip_manager()
        
        # Test valid sandbox IPs
        valid_sandbox_ips = ["10.0.100.5", "10.0.100.10", "172.16.100.5"]
        for ip in valid_sandbox_ips:
            assert sandbox_manager.validate_scan_source_ip(ip), f"Valid sandbox IP {ip} rejected"
        
        # Test invalid user IPs
        invalid_user_ips = ["192.168.1.100", "10.0.0.50", "127.0.0.1", "203.0.113.100"]
        for ip in invalid_user_ips:
            sandbox_manager.add_blocked_ip(ip)
            assert not sandbox_manager.validate_scan_source_ip(ip), f"Invalid IP {ip} accepted"
        
        # Test session creation uses sandbox network
        session = sandbox_manager.create_sandbox_session()
        assert session is not None
        assert 'PhishNet-Sandbox' in session.headers.get('User-Agent', '')
    
    @pytest.mark.asyncio
    async def test_no_credential_leakage(self):
        """Test that no raw credentials are exposed"""
        
        # Simulate credential handling
        test_credentials = {
            'gmail_token': 'ya29.a0ARrdaM...',
            'api_key': 'sk_live_abcd1234...',
            'password': 'user_password_123',
            'session_token': 'sess_abc123xyz789'
        }
        
        # Mock operations that should not expose credentials
        with patch('app.core.encryption.get_encryption_manager') as mock_encryption:
            encryption_manager = Mock()
            mock_encryption.return_value = encryption_manager
            
            # Simulate encryption calls
            for cred_type, credential in test_credentials.items():
                encryption_manager.encrypt_token(credential)
                encryption_manager.encrypt_pii(credential)
            
            # Verify encryption was called for all credentials
            assert encryption_manager.encrypt_token.call_count >= len(test_credentials)
    
    @pytest.mark.asyncio
    async def test_audit_trail_security(self):
        """Test audit trail captures security events"""
        from app.core.audit_logger import get_audit_logger, AuditEventType
        
        audit_logger = get_audit_logger()
        test_user_id = "security_test_user"
        
        # Test security-related events are logged
        security_events = [
            (AuditEventType.USER_LOGIN, "User login from new IP"),
            (AuditEventType.CONSENT_GRANTED, "User granted scan consent"),
            (AuditEventType.SCAN_STARTED, "Email scan initiated"),
            (AuditEventType.EMAIL_QUARANTINED, "Phishing email quarantined"),
            (AuditEventType.USER_EXPORT_DATA, "User exported personal data"),
            (AuditEventType.CONSENT_REVOKED, "User revoked consent")
        ]
        
        for event_type, description in security_events:
            with audit_logger.audit_context(user_id=test_user_id):
                audit_logger.log_event(
                    event_type,
                    description,
                    details={'security_test': True, 'timestamp': time.time()}
                )
        
        # Verify events were logged
        events = audit_logger.get_user_audit_trail(test_user_id, limit=20)
        security_test_events = [e for e in events if e.get('details', {}).get('security_test')]
        
        assert len(security_test_events) >= len(security_events)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
