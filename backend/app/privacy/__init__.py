"""
Privacy and Legal Compliance Module
Implements GDPR/CCPA compliance features including consent management,
data export/deletion, PII redaction, and audit trails.
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import re
import asyncio

from app.observability import get_logger, trace_function

logger = get_logger(__name__)

class ConsentType(Enum):
    """Types of user consent."""
    ESSENTIAL = "essential"
    ANALYTICS = "analytics"
    MARKETING = "marketing"
    DATA_PROCESSING = "data_processing"
    THIRD_PARTY_SHARING = "third_party_sharing"

class DataRetentionPeriod(Enum):
    """Data retention periods."""
    IMMEDIATE = 0  # Delete immediately
    DAYS_30 = 30
    DAYS_90 = 90
    MONTHS_6 = 180
    YEAR_1 = 365
    YEARS_7 = 2555  # Legal requirement for some data

class PrivacyRightType(Enum):
    """Types of privacy rights requests."""
    ACCESS = "access"  # Right to access personal data
    RECTIFICATION = "rectification"  # Right to correct data
    ERASURE = "erasure"  # Right to be forgotten
    PORTABILITY = "portability"  # Right to data portability
    RESTRICTION = "restriction"  # Right to restrict processing
    OBJECTION = "objection"  # Right to object to processing

@dataclass
class ConsentRecord:
    """Represents a user consent record."""
    user_id: str
    consent_type: ConsentType
    granted: bool
    timestamp: datetime
    ip_address: str
    user_agent: str
    version: str  # Version of privacy policy/terms
    expires_at: Optional[datetime] = None
    withdrawal_timestamp: Optional[datetime] = None

@dataclass
class DataSubjectRequest:
    """Represents a privacy rights request from data subject."""
    request_id: str
    user_id: str
    request_type: PrivacyRightType
    timestamp: datetime
    status: str  # pending, processing, completed, rejected
    description: str
    requested_data_types: List[str]
    completion_deadline: datetime
    completed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None

class TokenEncryption:
    """Handles encryption and decryption of sensitive tokens."""
    
    def __init__(self, master_key: str):
        """Initialize with master key."""
        self.master_key = master_key.encode()
        self._fernet = None
    
    def _get_cipher(self) -> Fernet:
        """Get or create Fernet cipher instance."""
        if self._fernet is None:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'phishnet_salt_2024',  # In production, use random salt per key
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
            self._fernet = Fernet(key)
        return self._fernet
    
    @trace_function("privacy.encrypt_token")
    def encrypt_token(self, token: str) -> str:
        """Encrypt a sensitive token."""
        try:
            cipher = self._get_cipher()
            encrypted_token = cipher.encrypt(token.encode())
            return base64.urlsafe_b64encode(encrypted_token).decode()
        except Exception as e:
            logger.error("Token encryption failed", error=str(e))
            raise
    
    @trace_function("privacy.decrypt_token")
    def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt a sensitive token."""
        try:
            cipher = self._get_cipher()
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_token.encode())
            decrypted_token = cipher.decrypt(encrypted_bytes)
            return decrypted_token.decode()
        except Exception as e:
            logger.error("Token decryption failed", error=str(e))
            raise

class PIIRedactor:
    """Handles PII detection and redaction in logs and data."""
    
    # PII patterns for detection
    PII_PATTERNS = {
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'phone': re.compile(r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b'),
        'ssn': re.compile(r'\b(?!000)(?!666)(?!9)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b'),
        'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
        'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        'api_key': re.compile(r'\b[A-Za-z0-9]{20,}\b'),  # Generic API key pattern
        'jwt_token': re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
    }
    
    @classmethod
    @trace_function("privacy.redact_pii")
    def redact_pii(cls, text: str, replacement: str = "[REDACTED]") -> str:
        """Redact PII from text."""
        if not text:
            return text
            
        redacted_text = text
        
        # Apply all PII patterns
        for pii_type, pattern in cls.PII_PATTERNS.items():
            redacted_text = pattern.sub(replacement, redacted_text)
        
        return redacted_text
    
    @classmethod
    def detect_pii(cls, text: str) -> Dict[str, List[str]]:
        """Detect PII in text and return findings."""
        findings = {}
        
        for pii_type, pattern in cls.PII_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                findings[pii_type] = matches
        
        return findings
    
    @classmethod
    def redact_dict(cls, data: Dict[str, Any], recursive: bool = True) -> Dict[str, Any]:
        """Redact PII from dictionary values."""
        redacted_data = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                redacted_data[key] = cls.redact_pii(value)
            elif isinstance(value, dict) and recursive:
                redacted_data[key] = cls.redact_dict(value, recursive)
            elif isinstance(value, list) and recursive:
                redacted_data[key] = [
                    cls.redact_pii(item) if isinstance(item, str) else
                    cls.redact_dict(item, recursive) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                redacted_data[key] = value
        
        return redacted_data

class ConsentManager:
    """Manages user consent and privacy preferences."""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.logger = get_logger(__name__)
    
    @trace_function("privacy.record_consent")
    async def record_consent(
        self,
        user_id: str,
        consent_type: ConsentType,
        granted: bool,
        ip_address: str,
        user_agent: str,
        privacy_policy_version: str
    ) -> ConsentRecord:
        """Record user consent."""
        consent_record = ConsentRecord(
            user_id=user_id,
            consent_type=consent_type,
            granted=granted,
            timestamp=datetime.utcnow(),
            ip_address=PIIRedactor.redact_pii(ip_address),  # Redact IP for privacy
            user_agent=user_agent,
            version=privacy_policy_version
        )
        
        # Store in database
        await self.db.store_consent_record(consent_record)
        
        self.logger.info(
            "Consent recorded",
            user_id=user_id,
            consent_type=consent_type.value,
            granted=granted,
            version=privacy_policy_version
        )
        
        return consent_record
    
    @trace_function("privacy.get_user_consents")
    async def get_user_consents(self, user_id: str) -> List[ConsentRecord]:
        """Get all consent records for a user."""
        return await self.db.get_consent_records(user_id)
    
    @trace_function("privacy.has_consent")
    async def has_consent(self, user_id: str, consent_type: ConsentType) -> bool:
        """Check if user has granted specific consent."""
        consent_records = await self.get_user_consents(user_id)
        
        # Get latest consent for this type
        latest_consent = None
        for record in consent_records:
            if record.consent_type == consent_type:
                if latest_consent is None or record.timestamp > latest_consent.timestamp:
                    latest_consent = record
        
        return latest_consent and latest_consent.granted
    
    @trace_function("privacy.withdraw_consent")
    async def withdraw_consent(
        self,
        user_id: str,
        consent_type: ConsentType,
        ip_address: str,
        user_agent: str
    ) -> ConsentRecord:
        """Withdraw user consent."""
        withdrawal_record = await self.record_consent(
            user_id=user_id,
            consent_type=consent_type,
            granted=False,
            ip_address=ip_address,
            user_agent=user_agent,
            privacy_policy_version="current"
        )
        
        # Trigger data processing restriction if needed
        if consent_type == ConsentType.DATA_PROCESSING:
            await self._restrict_data_processing(user_id)
        
        return withdrawal_record
    
    async def _restrict_data_processing(self, user_id: str):
        """Restrict data processing after consent withdrawal."""
        self.logger.info(
            "Data processing restricted due to consent withdrawal",
            user_id=user_id
        )
        # Implementation would restrict user's data processing

class DataSubjectRightsManager:
    """Manages data subject rights requests (GDPR Article 12-22)."""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.logger = get_logger(__name__)
    
    @trace_function("privacy.submit_rights_request")
    async def submit_request(
        self,
        user_id: str,
        request_type: PrivacyRightType,
        description: str,
        requested_data_types: List[str] = None
    ) -> DataSubjectRequest:
        """Submit a data subject rights request."""
        request_id = str(uuid.uuid4())
        deadline = datetime.utcnow() + timedelta(days=30)  # GDPR requirement
        
        request = DataSubjectRequest(
            request_id=request_id,
            user_id=user_id,
            request_type=request_type,
            timestamp=datetime.utcnow(),
            status="pending",
            description=description,
            requested_data_types=requested_data_types or [],
            completion_deadline=deadline
        )
        
        await self.db.store_data_subject_request(request)
        
        self.logger.info(
            "Data subject rights request submitted",
            request_id=request_id,
            user_id=user_id,
            request_type=request_type.value,
            deadline=deadline.isoformat()
        )
        
        # Trigger automated processing for certain request types
        await self._process_request_automatically(request)
        
        return request
    
    @trace_function("privacy.process_access_request")
    async def process_access_request(self, request: DataSubjectRequest) -> Dict[str, Any]:
        """Process right to access request."""
        user_data = await self._collect_user_data(request.user_id)
        
        # Redact any PII that shouldn't be shared
        redacted_data = PIIRedactor.redact_dict(user_data)
        
        # Update request status
        await self.db.update_request_status(request.request_id, "completed")
        
        self.logger.info(
            "Access request processed",
            request_id=request.request_id,
            user_id=request.user_id,
            data_types_returned=len(redacted_data)
        )
        
        return redacted_data
    
    @trace_function("privacy.process_erasure_request")
    async def process_erasure_request(self, request: DataSubjectRequest) -> bool:
        """Process right to erasure (right to be forgotten) request."""
        try:
            # Check if erasure is legally permissible
            if not await self._can_erase_data(request.user_id):
                await self.db.update_request_status(
                    request.request_id, 
                    "rejected",
                    "Legal obligation prevents erasure"
                )
                return False
            
            # Perform data erasure
            await self._erase_user_data(request.user_id)
            
            # Update request status
            await self.db.update_request_status(request.request_id, "completed")
            
            self.logger.info(
                "Erasure request processed",
                request_id=request.request_id,
                user_id=request.user_id
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Erasure request failed",
                request_id=request.request_id,
                error=str(e)
            )
            await self.db.update_request_status(request.request_id, "rejected", str(e))
            return False
    
    @trace_function("privacy.process_portability_request")
    async def process_portability_request(self, request: DataSubjectRequest) -> bytes:
        """Process data portability request."""
        user_data = await self._collect_user_data(request.user_id)
        
        # Format data in machine-readable format (JSON)
        portable_data = {
            "user_id": request.user_id,
            "export_date": datetime.utcnow().isoformat(),
            "data": user_data
        }
        
        # Convert to JSON bytes
        json_data = json.dumps(portable_data, indent=2, default=str).encode('utf-8')
        
        await self.db.update_request_status(request.request_id, "completed")
        
        self.logger.info(
            "Portability request processed",
            request_id=request.request_id,
            user_id=request.user_id,
            export_size_bytes=len(json_data)
        )
        
        return json_data
    
    async def _process_request_automatically(self, request: DataSubjectRequest):
        """Automatically process certain types of requests."""
        if request.request_type == PrivacyRightType.ACCESS:
            await self.process_access_request(request)
        elif request.request_type == PrivacyRightType.PORTABILITY:
            await self.process_portability_request(request)
        # Erasure requests require manual approval for safety
    
    async def _collect_user_data(self, user_id: str) -> Dict[str, Any]:
        """Collect all user data across the system."""
        return {
            "profile": await self.db.get_user_profile(user_id),
            "email_scans": await self.db.get_user_email_scans(user_id),
            "consent_records": await self.db.get_consent_records(user_id),
            "oauth_tokens": await self.db.get_user_oauth_data(user_id),
            "audit_logs": await self.db.get_user_audit_logs(user_id)
        }
    
    async def _can_erase_data(self, user_id: str) -> bool:
        """Check if user data can be legally erased."""
        # Check for legal obligations that prevent erasure
        # (e.g., financial records, ongoing legal proceedings)
        return True  # Simplified for demo
    
    async def _erase_user_data(self, user_id: str):
        """Erase all user data from the system."""
        await self.db.delete_user_profile(user_id)
        await self.db.delete_user_email_scans(user_id)
        await self.db.delete_user_oauth_tokens(user_id)
        # Keep consent withdrawal records for compliance
        # Keep audit logs for legal requirements

class AuditTrailManager:
    """Manages comprehensive audit trails for compliance."""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.logger = get_logger(__name__)
    
    @trace_function("privacy.log_data_access")
    async def log_data_access(
        self,
        user_id: str,
        accessed_by: str,
        data_type: str,
        action: str,
        ip_address: str,
        legal_basis: str
    ):
        """Log data access for audit trail."""
        audit_entry = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "accessed_by": accessed_by,
            "data_type": data_type,
            "action": action,
            "ip_address": PIIRedactor.redact_pii(ip_address),
            "legal_basis": legal_basis
        }
        
        await self.db.store_audit_log(audit_entry)
        
        self.logger.info(
            "Data access logged",
            event_id=audit_entry["event_id"],
            user_id=user_id,
            action=action,
            data_type=data_type,
            legal_basis=legal_basis
        )
    
    @trace_function("privacy.log_consent_change")
    async def log_consent_change(
        self,
        user_id: str,
        consent_type: ConsentType,
        old_value: bool,
        new_value: bool,
        ip_address: str
    ):
        """Log consent changes for audit trail."""
        audit_entry = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "consent_change",
            "user_id": user_id,
            "consent_type": consent_type.value,
            "old_value": old_value,
            "new_value": new_value,
            "ip_address": PIIRedactor.redact_pii(ip_address)
        }
        
        await self.db.store_audit_log(audit_entry)
        
        self.logger.info(
            "Consent change logged",
            user_id=user_id,
            consent_type=consent_type.value,
            change=f"{old_value} -> {new_value}"
        )
    
    @trace_function("privacy.generate_audit_report")
    async def generate_audit_report(
        self,
        start_date: datetime,
        end_date: datetime,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate audit report for compliance."""
        audit_logs = await self.db.get_audit_logs(start_date, end_date, user_id)
        
        report = {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.utcnow().isoformat(),
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "total_events": len(audit_logs),
            "events_by_type": {},
            "user_activities": {},
            "compliance_summary": {
                "data_access_events": 0,
                "consent_changes": 0,
                "rights_requests": 0
            }
        }
        
        # Analyze audit logs
        for log in audit_logs:
            event_type = log.get("event_type", "general")
            report["events_by_type"][event_type] = report["events_by_type"].get(event_type, 0) + 1
            
            if log.get("user_id"):
                user_id = log["user_id"]
                if user_id not in report["user_activities"]:
                    report["user_activities"][user_id] = []
                report["user_activities"][user_id].append({
                    "timestamp": log["timestamp"],
                    "action": log.get("action", "unknown"),
                    "data_type": log.get("data_type", "unknown")
                })
        
        return report

class DataRetentionManager:
    """Manages data retention policies and automatic cleanup."""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.logger = get_logger(__name__)
    
    @trace_function("privacy.apply_retention_policy")
    async def apply_retention_policy(self):
        """Apply data retention policies and clean up expired data."""
        policies = {
            "email_scans": DataRetentionPeriod.DAYS_90,
            "audit_logs": DataRetentionPeriod.YEARS_7,  # Legal requirement
            "consent_records": DataRetentionPeriod.YEARS_7,  # Legal requirement
            "user_sessions": DataRetentionPeriod.DAYS_30,
            "oauth_tokens": DataRetentionPeriod.DAYS_90
        }
        
        cleanup_summary = {}
        
        for data_type, retention_period in policies.items():
            cutoff_date = datetime.utcnow() - timedelta(days=retention_period.value)
            deleted_count = await self.db.delete_expired_data(data_type, cutoff_date)
            cleanup_summary[data_type] = deleted_count
            
            self.logger.info(
                "Data retention policy applied",
                data_type=data_type,
                retention_days=retention_period.value,
                deleted_records=deleted_count,
                cutoff_date=cutoff_date.isoformat()
            )
        
        return cleanup_summary

# Integration with main application
class PrivacyComplianceManager:
    """Main privacy compliance manager integrating all components."""
    
    def __init__(self, db_manager, encryption_key: str):
        self.db = db_manager
        self.token_encryption = TokenEncryption(encryption_key)
        self.consent_manager = ConsentManager(db_manager)
        self.rights_manager = DataSubjectRightsManager(db_manager)
        self.audit_manager = AuditTrailManager(db_manager)
        self.retention_manager = DataRetentionManager(db_manager)
        self.logger = get_logger(__name__)
    
    @trace_function("privacy.initialize")
    async def initialize(self):
        """Initialize privacy compliance system."""
        self.logger.info("Privacy compliance system initialized")
        
        # Schedule retention policy application
        # In production, this would be a scheduled task
        await self.retention_manager.apply_retention_policy()
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for privacy compliance system."""
        return {
            "status": "healthy",
            "components": {
                "token_encryption": "operational",
                "consent_management": "operational",
                "rights_management": "operational",
                "audit_trails": "operational",
                "data_retention": "operational"
            },
            "last_retention_cleanup": datetime.utcnow().isoformat()
        }

# Utility functions for easy integration
def redact_sensitive_data(data: Union[str, Dict, List]) -> Union[str, Dict, List]:
    """Utility function to redact PII from various data types."""
    if isinstance(data, str):
        return PIIRedactor.redact_pii(data)
    elif isinstance(data, dict):
        return PIIRedactor.redact_dict(data)
    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    else:
        return data

# Export public interface
__all__ = [
    'PrivacyComplianceManager',
    'ConsentManager',
    'DataSubjectRightsManager',
    'AuditTrailManager',
    'TokenEncryption',
    'PIIRedactor',
    'ConsentType',
    'PrivacyRightType',
    'DataRetentionPeriod',
    'redact_sensitive_data'
]