"""
Privacy Compliance Testing Suite

Comprehensive testing for privacy compliance features including:
- GDPR compliance verification
- CCPA compliance verification  
- Consent management testing
- PII redaction testing
- Data retention policy testing
- Audit trail testing
- Data subject rights testing
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any
from unittest.mock import AsyncMock, MagicMock

from backend.app.privacy import (
    PrivacyComplianceManager,
    ConsentManager,
    DataSubjectRightsManager,
    PIIRedactor,
    ConsentType,
    PrivacyRightType
)
from backend.app.privacy.models import ConsentRecord, DataSubjectRequest
from backend.app.observability import get_logger

logger = get_logger(__name__)

@pytest.fixture
async def privacy_manager():
    """Create privacy compliance manager for testing."""
    manager = PrivacyComplianceManager(
        db_manager=AsyncMock(),
        encryption_key="test_key_12345678901234567890123"
    )
    return manager

@pytest.fixture
async def consent_manager():
    """Create consent manager for testing."""
    return ConsentManager(db_manager=AsyncMock())

@pytest.fixture
async def rights_manager():
    """Create data subject rights manager for testing."""
    return DataSubjectRightsManager(db_manager=AsyncMock())

class TestConsentManagement:
    """Test consent management functionality."""
    
    @pytest.mark.asyncio
    async def test_consent_recording(self, consent_manager):
        """Test consent recording and retrieval."""
        user_id = "test_user_123"
        
        # Record consent
        await consent_manager.record_consent(
            user_id=user_id,
            consent_type=ConsentType.DATA_PROCESSING,
            granted=True,
            legal_basis="consent",
            purpose="email_threat_analysis",
            metadata={"ip_address": "192.168.1.1"}
        )
        
        # Verify consent recorded
        has_consent = await consent_manager.has_consent(user_id, ConsentType.DATA_PROCESSING)
        assert has_consent, "Consent should be recorded"
        
        # Get consent details
        consent_record = await consent_manager.get_consent_record(user_id, ConsentType.DATA_PROCESSING)
        assert consent_record is not None
        assert consent_record.granted is True
        assert consent_record.legal_basis == "consent"
    
    @pytest.mark.asyncio
    async def test_consent_withdrawal(self, consent_manager):
        """Test consent withdrawal."""
        user_id = "test_user_124"
        
        # Record initial consent
        await consent_manager.record_consent(
            user_id=user_id,
            consent_type=ConsentType.ANALYTICS,
            granted=True,
            legal_basis="consent",
            purpose="analytics"
        )
        
        # Withdraw consent
        await consent_manager.withdraw_consent(
            user_id=user_id,
            consent_type=ConsentType.ANALYTICS,
            reason="User requested withdrawal"
        )
        
        # Verify withdrawal
        has_consent = await consent_manager.has_consent(user_id, ConsentType.ANALYTICS)
        assert not has_consent, "Consent should be withdrawn"
    
    @pytest.mark.asyncio
    async def test_consent_expiration(self, consent_manager):
        """Test consent expiration handling."""
        user_id = "test_user_125"
        
        # Record consent with short expiration
        await consent_manager.record_consent(
            user_id=user_id,
            consent_type=ConsentType.MARKETING,
            granted=True,
            legal_basis="consent",
            purpose="marketing",
            expires_at=datetime.utcnow() + timedelta(seconds=1)
        )
        
        # Verify consent initially active
        has_consent = await consent_manager.has_consent(user_id, ConsentType.MARKETING)
        assert has_consent, "Consent should be active"
        
        # Wait for expiration
        await asyncio.sleep(2)
        
        # Verify consent expired
        has_consent = await consent_manager.has_consent(user_id, ConsentType.MARKETING)
        assert not has_consent, "Consent should be expired"
    
    @pytest.mark.asyncio
    async def test_granular_consent(self, consent_manager):
        """Test granular consent management."""
        user_id = "test_user_126"
        
        # Record multiple consent types
        consent_types = [
            (ConsentType.DATA_PROCESSING, True),
            (ConsentType.ANALYTICS, False),
            (ConsentType.MARKETING, False),
            (ConsentType.THIRD_PARTY_SHARING, True)
        ]
        
        for consent_type, granted in consent_types:
            await consent_manager.record_consent(
                user_id=user_id,
                consent_type=consent_type,
                granted=granted,
                legal_basis="consent" if granted else "objection",
                purpose=consent_type.value
            )
        
        # Verify individual consents
        for consent_type, expected in consent_types:
            has_consent = await consent_manager.has_consent(user_id, consent_type)
            assert has_consent == expected, f"Consent for {consent_type} should be {expected}"

class TestPIIRedaction:
    """Test PII redaction functionality."""
    
    def test_email_redaction(self):
        """Test email address redaction."""
        text = "Contact us at support@example.com or admin@company.org"
        redacted = PIIRedactor.redact_pii(text)
        
        assert "support@example.com" not in redacted
        assert "admin@company.org" not in redacted
        assert "[EMAIL]" in redacted or "[PII]" in redacted
    
    def test_phone_redaction(self):
        """Test phone number redaction."""
        text = "Call us at +1-555-123-4567 or (555) 987-6543"
        redacted = PIIRedactor.redact_pii(text)
        
        assert "+1-555-123-4567" not in redacted
        assert "(555) 987-6543" not in redacted
        assert "[PHONE]" in redacted or "[PII]" in redacted
    
    def test_ssn_redaction(self):
        """Test SSN redaction."""
        text = "SSN: 123-45-6789 for verification"
        redacted = PIIRedactor.redact_pii(text)
        
        assert "123-45-6789" not in redacted
        assert "[SSN]" in redacted or "[PII]" in redacted
    
    def test_credit_card_redaction(self):
        """Test credit card number redaction."""
        text = "Card ending in 4532-1234-5678-9012"
        redacted = PIIRedactor.redact_pii(text)
        
        assert "4532-1234-5678-9012" not in redacted
        assert "[CREDIT_CARD]" in redacted or "[PII]" in redacted
    
    def test_ip_address_redaction(self):
        """Test IP address redaction."""
        text = "Request from 192.168.1.100 and 2001:db8::1"
        redacted = PIIRedactor.redact_pii(text)
        
        assert "192.168.1.100" not in redacted
        assert "2001:db8::1" not in redacted
        assert "[IP]" in redacted or "[PII]" in redacted
    
    def test_selective_redaction(self):
        """Test selective PII redaction."""
        text = "Email john@example.com, keep domain example.com"
        redacted = PIIRedactor.redact_pii(text, preserve_domains=True)
        
        assert "john@example.com" not in redacted
        assert "example.com" in redacted  # Domain preserved
    
    def test_custom_patterns(self):
        """Test custom PII pattern redaction."""
        custom_patterns = {
            "employee_id": r"EMP-\d{6}",
            "project_code": r"PROJ-[A-Z]{3}-\d{4}"
        }
        
        text = "Employee EMP-123456 on project PROJ-ABC-2024"
        redacted = PIIRedactor.redact_pii(text, custom_patterns=custom_patterns)
        
        assert "EMP-123456" not in redacted
        assert "PROJ-ABC-2024" not in redacted
        assert "[EMPLOYEE_ID]" in redacted or "[PII]" in redacted

class TestDataSubjectRights:
    """Test data subject rights functionality."""
    
    @pytest.mark.asyncio
    async def test_data_access_request(self, rights_manager):
        """Test data access request processing."""
        user_id = "test_user_127"
        
        # Submit access request
        request_id = await rights_manager.submit_request(
            user_id=user_id,
            request_type=PrivacyRightType.ACCESS,
            description="Request all my personal data",
            contact_email="user@example.com"
        )
        
        assert request_id is not None
        
        # Process request
        await rights_manager.process_request(
            request_id=request_id,
            processor_id="admin_123",
            action="approve",
            response_data={"data_export": "user_data.json"}
        )
        
        # Verify request processed
        request_status = await rights_manager.get_request_status(request_id)
        assert request_status.status == "completed"
        assert request_status.response_data is not None
    
    @pytest.mark.asyncio
    async def test_data_erasure_request(self, rights_manager):
        """Test data erasure (right to be forgotten) request."""
        user_id = "test_user_128"
        
        # Submit erasure request
        request_id = await rights_manager.submit_request(
            user_id=user_id,
            request_type=PrivacyRightType.ERASURE,
            description="Delete all my personal data",
            contact_email="user@example.com"
        )
        
        # Process erasure
        await rights_manager.process_request(
            request_id=request_id,
            processor_id="admin_123", 
            action="approve",
            response_data={"records_deleted": 150}
        )
        
        # Verify erasure processed
        request_status = await rights_manager.get_request_status(request_id)
        assert request_status.status == "completed"
        assert request_status.response_data["records_deleted"] > 0
    
    @pytest.mark.asyncio
    async def test_data_portability_request(self, rights_manager):
        """Test data portability request."""
        user_id = "test_user_129"
        
        # Submit portability request
        request_id = await rights_manager.submit_request(
            user_id=user_id,
            request_type=PrivacyRightType.PORTABILITY,
            description="Export my data in JSON format",
            contact_email="user@example.com"
        )
        
        # Process request
        await rights_manager.process_request(
            request_id=request_id,
            processor_id="admin_123",
            action="approve",
            response_data={
                "export_format": "JSON",
                "download_url": "https://secure.example.com/exports/user_129.json",
                "expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat()
            }
        )
        
        # Verify export available
        request_status = await rights_manager.get_request_status(request_id)
        assert request_status.status == "completed"
        assert "download_url" in request_status.response_data
    
    @pytest.mark.asyncio
    async def test_request_deadline_compliance(self, rights_manager):
        """Test compliance with request processing deadlines."""
        user_id = "test_user_130"
        
        # Submit request
        request_id = await rights_manager.submit_request(
            user_id=user_id,
            request_type=PrivacyRightType.RECTIFICATION,
            description="Correct my email address",
            contact_email="user@example.com"
        )
        
        # Check deadline compliance
        request_details = await rights_manager.get_request_details(request_id)
        
        # GDPR requires response within 30 days
        deadline = request_details.submitted_at + timedelta(days=30)
        assert deadline > datetime.utcnow(), "Request deadline should be in future"
        
        # Check if approaching deadline
        days_remaining = (deadline - datetime.utcnow()).days
        if days_remaining <= 5:
            assert request_details.urgency_level == "high", "Should be marked high urgency near deadline"

class TestDataRetention:
    """Test data retention policy enforcement."""
    
    @pytest.mark.asyncio
    async def test_retention_policy_application(self, privacy_manager):
        """Test retention policy application."""
        # Test data with different retention categories
        test_data = [
            {
                "category": "operational",
                "retention_days": 90,
                "data": {"email_id": "123", "scan_result": "safe"}
            },
            {
                "category": "security",
                "retention_days": 365,
                "data": {"threat_id": "456", "severity": "high"}
            },
            {
                "category": "analytics",
                "retention_days": 30,
                "data": {"metric_id": "789", "value": 42}
            }
        ]
        
        # Apply retention policies
        for data_item in test_data:
            await privacy_manager.apply_retention_policy(
                data_id=data_item["data"]["email_id"] if "email_id" in data_item["data"] else data_item["data"].get("threat_id", data_item["data"].get("metric_id")),
                category=data_item["category"],
                retention_days=data_item["retention_days"],
                created_at=datetime.utcnow()
            )
        
        # Verify policies applied
        for data_item in test_data:
            data_id = data_item["data"]["email_id"] if "email_id" in data_item["data"] else data_item["data"].get("threat_id", data_item["data"].get("metric_id"))
            retention_info = await privacy_manager.get_retention_info(data_id)
            
            assert retention_info is not None
            assert retention_info.category == data_item["category"]
            assert retention_info.retention_days == data_item["retention_days"]
    
    @pytest.mark.asyncio
    async def test_automated_data_deletion(self, privacy_manager):
        """Test automated deletion of expired data."""
        # Create data that should be expired
        expired_data_id = "expired_data_123"
        await privacy_manager.apply_retention_policy(
            data_id=expired_data_id,
            category="temporary",
            retention_days=1,
            created_at=datetime.utcnow() - timedelta(days=2)  # 2 days ago
        )
        
        # Run retention cleanup
        deleted_count = await privacy_manager.cleanup_expired_data()
        
        assert deleted_count > 0, "Should have deleted expired data"
        
        # Verify data no longer exists
        retention_info = await privacy_manager.get_retention_info(expired_data_id)
        assert retention_info is None or retention_info.deleted_at is not None

class TestAuditTrail:
    """Test privacy audit trail functionality."""
    
    @pytest.mark.asyncio
    async def test_privacy_event_logging(self, privacy_manager):
        """Test privacy event audit logging."""
        user_id = "test_user_131"
        
        # Perform privacy-sensitive operation
        await privacy_manager.log_privacy_event(
            event_type="data_processing",
            user_id=user_id,
            action="email_scan",
            legal_basis="consent",
            purpose="threat_detection",
            data_categories=["email_content", "metadata"],
            metadata={"scan_id": "scan_123"}
        )
        
        # Verify audit entry created
        audit_entries = await privacy_manager.get_audit_trail(
            user_id=user_id,
            start_date=datetime.utcnow() - timedelta(hours=1)
        )
        
        assert len(audit_entries) > 0
        assert audit_entries[0].event_type == "data_processing"
        assert audit_entries[0].action == "email_scan"
        assert audit_entries[0].legal_basis == "consent"
    
    @pytest.mark.asyncio
    async def test_consent_audit_trail(self, consent_manager):
        """Test consent change audit trail."""
        user_id = "test_user_132"
        
        # Record consent
        await consent_manager.record_consent(
            user_id=user_id,
            consent_type=ConsentType.DATA_PROCESSING,
            granted=True,
            legal_basis="consent",
            purpose="testing"
        )
        
        # Withdraw consent
        await consent_manager.withdraw_consent(
            user_id=user_id,
            consent_type=ConsentType.DATA_PROCESSING,
            reason="Testing consent withdrawal"
        )
        
        # Get consent history
        consent_history = await consent_manager.get_consent_history(user_id)
        
        assert len(consent_history) >= 2
        assert any(record.granted is True for record in consent_history)
        assert any(record.granted is False for record in consent_history)
    
    @pytest.mark.asyncio
    async def test_data_subject_request_audit(self, rights_manager):
        """Test data subject request audit trail."""
        user_id = "test_user_133"
        
        # Submit and process request
        request_id = await rights_manager.submit_request(
            user_id=user_id,
            request_type=PrivacyRightType.ACCESS,
            description="Audit trail test",
            contact_email="user@example.com"
        )
        
        await rights_manager.process_request(
            request_id=request_id,
            processor_id="admin_123",
            action="approve",
            response_data={"test": "audit"}
        )
        
        # Get request audit trail
        request_audit = await rights_manager.get_request_audit_trail(request_id)
        
        assert len(request_audit) >= 2  # Submit and process events
        assert any(event.action == "submitted" for event in request_audit)
        assert any(event.action == "processed" for event in request_audit)

class TestGDPRCompliance:
    """Test GDPR compliance requirements."""
    
    @pytest.mark.asyncio
    async def test_lawful_basis_documentation(self, privacy_manager):
        """Test that lawful basis is documented for all processing."""
        user_id = "test_user_134"
        
        # Process data with different lawful bases
        lawful_bases = [
            "consent",
            "contract", 
            "legal_obligation",
            "vital_interests",
            "public_task",
            "legitimate_interests"
        ]
        
        for basis in lawful_bases:
            await privacy_manager.log_privacy_event(
                event_type="data_processing",
                user_id=user_id,
                action=f"test_{basis}",
                legal_basis=basis,
                purpose=f"Testing {basis} basis",
                data_categories=["test_data"]
            )
        
        # Verify all lawful bases documented
        audit_entries = await privacy_manager.get_audit_trail(user_id)
        documented_bases = {entry.legal_basis for entry in audit_entries}
        
        for basis in lawful_bases:
            assert basis in documented_bases, f"Lawful basis {basis} not documented"
    
    @pytest.mark.asyncio
    async def test_data_minimization(self, privacy_manager):
        """Test data minimization principle compliance."""
        user_id = "test_user_135"
        
        # Test that only necessary data is processed
        processed_data = {
            "email_content": "needed for threat analysis",
            "sender_info": "needed for reputation check", 
            "recipient_info": "needed for phishing detection",
            "irrelevant_metadata": "not needed"  # This should trigger warning
        }
        
        # Check data minimization compliance
        compliance_check = await privacy_manager.check_data_minimization(
            purpose="threat_analysis",
            data_categories=list(processed_data.keys())
        )
        
        assert not compliance_check.compliant, "Should flag unnecessary data"
        assert "irrelevant_metadata" in compliance_check.unnecessary_data
    
    @pytest.mark.asyncio
    async def test_data_protection_by_design(self, privacy_manager):
        """Test data protection by design implementation."""
        # Verify privacy is built into system design
        design_checks = await privacy_manager.verify_privacy_by_design()
        
        assert design_checks.encryption_enabled, "Encryption should be enabled by design"
        assert design_checks.pii_redaction_active, "PII redaction should be active by design"
        assert design_checks.consent_management_integrated, "Consent management should be integrated"
        assert design_checks.audit_logging_enabled, "Audit logging should be enabled by design"

class TestCCPACompliance:
    """Test CCPA compliance requirements."""
    
    @pytest.mark.asyncio
    async def test_consumer_rights_notice(self, rights_manager):
        """Test that consumers are notified of their rights."""
        # Verify privacy notice includes required CCPA rights
        privacy_notice = await rights_manager.get_privacy_notice()
        
        required_rights = [
            "right_to_know",
            "right_to_delete", 
            "right_to_opt_out",
            "right_to_non_discrimination"
        ]
        
        for right in required_rights:
            assert right in privacy_notice.ccpa_rights, f"CCPA right {right} not in notice"
    
    @pytest.mark.asyncio
    async def test_opt_out_mechanism(self, consent_manager):
        """Test opt-out mechanism for data sales."""
        user_id = "test_user_136"
        
        # Test opt-out request
        await consent_manager.process_opt_out_request(
            user_id=user_id,
            opt_out_type="data_sale",
            request_source="web_form"
        )
        
        # Verify opt-out recorded
        opt_out_status = await consent_manager.get_opt_out_status(user_id)
        assert opt_out_status.data_sale_opted_out, "Should be opted out of data sales"
    
    @pytest.mark.asyncio
    async def test_data_sale_disclosure(self, privacy_manager):
        """Test disclosure of data sales."""
        # Verify data sale disclosures are maintained
        disclosures = await privacy_manager.get_data_sale_disclosures()
        
        assert "categories_sold" in disclosures
        assert "third_parties" in disclosures
        assert "business_purposes" in disclosures

# Performance tests for privacy operations
class TestPrivacyPerformance:
    """Test performance of privacy operations."""
    
    @pytest.mark.asyncio
    async def test_consent_check_performance(self, consent_manager):
        """Test consent checking performance."""
        user_id = "test_user_performance"
        
        # Record consent
        await consent_manager.record_consent(
            user_id=user_id,
            consent_type=ConsentType.DATA_PROCESSING,
            granted=True,
            legal_basis="consent",
            purpose="performance_test"
        )
        
        # Measure consent check performance
        start_time = asyncio.get_event_loop().time()
        
        # Perform multiple consent checks
        for _ in range(100):
            await consent_manager.has_consent(user_id, ConsentType.DATA_PROCESSING)
        
        end_time = asyncio.get_event_loop().time()
        duration = end_time - start_time
        
        # Should complete 100 checks in under 1 second
        assert duration < 1.0, f"Consent checks too slow: {duration:.3f}s for 100 checks"
    
    @pytest.mark.asyncio  
    async def test_pii_redaction_performance(self):
        """Test PII redaction performance."""
        # Large text with multiple PII instances
        large_text = """
        Contact information:
        Email: john.doe@example.com, jane.smith@company.org
        Phone: +1-555-123-4567, (555) 987-6543
        SSN: 123-45-6789, 987-65-4321
        Credit Cards: 4532-1234-5678-9012, 5555-4444-3333-2222
        IP Addresses: 192.168.1.100, 10.0.0.1, 2001:db8::1
        """ * 50  # Repeat to create large text
        
        start_time = asyncio.get_event_loop().time()
        
        # Perform redaction
        redacted = PIIRedactor.redact_pii(large_text)
        
        end_time = asyncio.get_event_loop().time()
        duration = end_time - start_time
        
        # Should complete redaction in under 1 second
        assert duration < 1.0, f"PII redaction too slow: {duration:.3f}s"
        
        # Verify redaction worked
        assert "john.doe@example.com" not in redacted
        assert "123-45-6789" not in redacted
        assert "4532-1234-5678-9012" not in redacted

# Integration tests
class TestPrivacyIntegration:
    """Test privacy component integration."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_privacy_flow(self, privacy_manager, consent_manager, rights_manager):
        """Test complete privacy compliance flow."""
        user_id = "test_user_e2e_privacy"
        
        # Step 1: Collect consent
        await consent_manager.record_consent(
            user_id=user_id,
            consent_type=ConsentType.DATA_PROCESSING,
            granted=True,
            legal_basis="consent",
            purpose="email_threat_analysis"
        )
        
        # Step 2: Process data with privacy protection
        await privacy_manager.log_privacy_event(
            event_type="data_processing",
            user_id=user_id,
            action="email_scan",
            legal_basis="consent",
            purpose="threat_detection",
            data_categories=["email_content"]
        )
        
        # Step 3: Handle data subject request
        request_id = await rights_manager.submit_request(
            user_id=user_id,
            request_type=PrivacyRightType.ACCESS,
            description="Request my data",
            contact_email="user@example.com"
        )
        
        await rights_manager.process_request(
            request_id=request_id,
            processor_id="system",
            action="approve",
            response_data={"data": "user_data.json"}
        )
        
        # Step 4: Verify complete audit trail
        audit_trail = await privacy_manager.get_audit_trail(user_id)
        
        assert len(audit_trail) >= 2  # Consent and processing events
        
        # Verify consent recorded
        has_consent = await consent_manager.has_consent(user_id, ConsentType.DATA_PROCESSING)
        assert has_consent
        
        # Verify request processed
        request_status = await rights_manager.get_request_status(request_id)
        assert request_status.status == "completed"

if __name__ == "__main__":
    # Run privacy compliance tests
    pytest.main([__file__, "-v", "--tb=short"])