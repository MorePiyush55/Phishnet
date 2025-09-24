"""
Database models for privacy and compliance data.
MongoDB models for consent records, data subject requests, and audit trails.
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from beanie import Document, Indexed
from pydantic import Field

from backend.app.privacy import ConsentType, PrivacyRightType, DataRetentionPeriod

class ConsentRecord(Document):
    """MongoDB model for user consent records."""
    
    user_id: Indexed(str)
    consent_type: ConsentType
    granted: bool
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ip_address: str  # Redacted IP
    user_agent: str
    privacy_policy_version: str
    expires_at: Optional[datetime] = None
    withdrawal_timestamp: Optional[datetime] = None
    
    class Settings:
        name = "consent_records"
        indexes = [
            [("user_id", 1), ("consent_type", 1), ("timestamp", -1)],
            [("timestamp", 1)],  # For retention policy cleanup
        ]

class DataSubjectRequest(Document):
    """MongoDB model for data subject rights requests."""
    
    request_id: Indexed(str, unique=True)
    user_id: Indexed(str)
    request_type: PrivacyRightType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: str = "pending"  # pending, processing, completed, rejected
    description: str
    requested_data_types: List[str] = Field(default_factory=list)
    completion_deadline: datetime
    completed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    processed_by: Optional[str] = None  # Admin who processed the request
    
    class Settings:
        name = "data_subject_requests"
        indexes = [
            [("user_id", 1), ("timestamp", -1)],
            [("request_id", 1)],
            [("status", 1), ("completion_deadline", 1)],
            [("timestamp", 1)],  # For retention policy
        ]

class AuditLog(Document):
    """MongoDB model for audit trail logs."""
    
    event_id: Indexed(str, unique=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str  # consent_change, data_access, rights_request, etc.
    user_id: Optional[str] = None
    accessed_by: Optional[str] = None  # Who accessed the data
    data_type: Optional[str] = None
    action: str
    ip_address: Optional[str] = None  # Redacted
    legal_basis: str  # GDPR legal basis for processing
    details: Dict[str, Any] = Field(default_factory=dict)
    
    class Settings:
        name = "audit_logs"
        indexes = [
            [("timestamp", -1)],
            [("user_id", 1), ("timestamp", -1)],
            [("event_type", 1), ("timestamp", -1)],
            [("timestamp", 1)],  # For retention policy cleanup
        ]

class EncryptedToken(Document):
    """MongoDB model for encrypted OAuth tokens."""
    
    user_id: Indexed(str)
    token_type: str  # access_token, refresh_token
    encrypted_token: str  # Encrypted token data
    provider: str  # google, microsoft, etc.
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    scope: Optional[str] = None
    
    class Settings:
        name = "encrypted_tokens"
        indexes = [
            [("user_id", 1), ("provider", 1), ("token_type", 1)],
            [("expires_at", 1)],  # For cleanup of expired tokens
            [("created_at", 1)],  # For retention policy
        ]

class PrivacySettings(Document):
    """MongoDB model for user privacy settings."""
    
    user_id: Indexed(str, unique=True)
    data_retention_preference: DataRetentionPeriod = DataRetentionPeriod.DAYS_90
    marketing_emails: bool = False
    analytics_tracking: bool = True
    third_party_sharing: bool = False
    data_export_format: str = "json"  # json, xml, csv
    notification_preferences: Dict[str, bool] = Field(default_factory=dict)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    
    class Settings:
        name = "privacy_settings"

class DataProcessingLog(Document):
    """MongoDB model for data processing activity logs."""
    
    user_id: Indexed(str)
    processing_activity: str  # email_scan, ml_prediction, threat_analysis
    purpose: str  # fraud_detection, security_analysis, service_improvement
    legal_basis: str  # consent, legitimate_interest, contract
    data_categories: List[str]  # email_content, metadata, ip_address
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    retention_period: DataRetentionPeriod
    automated_processing: bool = True
    
    class Settings:
        name = "data_processing_logs"
        indexes = [
            [("user_id", 1), ("timestamp", -1)],
            [("processing_activity", 1), ("timestamp", -1)],
            [("timestamp", 1)],  # For retention cleanup
        ]

class ComplianceReport(Document):
    """MongoDB model for compliance reports."""
    
    report_id: Indexed(str, unique=True)
    report_type: str  # gdpr_audit, ccpa_audit, data_breach, monthly_summary
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    period_start: datetime
    period_end: datetime
    generated_by: str  # admin user or system
    report_data: Dict[str, Any]
    compliance_status: str  # compliant, issues_found, action_required
    recommendations: List[str] = Field(default_factory=list)
    
    class Settings:
        name = "compliance_reports"
        indexes = [
            [("report_type", 1), ("generated_at", -1)],
            [("generated_at", -1)],
            [("compliance_status", 1)],
        ]

class DataBreachLog(Document):
    """MongoDB model for data breach incident logs."""
    
    incident_id: Indexed(str, unique=True)
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    incident_type: str  # unauthorized_access, data_leak, system_compromise
    severity: str  # low, medium, high, critical
    affected_users_count: int
    affected_data_types: List[str]
    containment_actions: List[str] = Field(default_factory=list)
    notification_sent: bool = False
    notification_sent_at: Optional[datetime] = None
    regulatory_notification: bool = False
    regulatory_notification_at: Optional[datetime] = None
    resolution_status: str = "investigating"  # investigating, contained, resolved
    resolved_at: Optional[datetime] = None
    lessons_learned: Optional[str] = None
    
    class Settings:
        name = "data_breach_logs"
        indexes = [
            [("detected_at", -1)],
            [("severity", 1), ("detected_at", -1)],
            [("resolution_status", 1)],
        ]

# List all privacy-related document models for Beanie initialization
PRIVACY_DOCUMENT_MODELS = [
    ConsentRecord,
    DataSubjectRequest,
    AuditLog,
    EncryptedToken,
    PrivacySettings,
    DataProcessingLog,
    ComplianceReport,
    DataBreachLog
]