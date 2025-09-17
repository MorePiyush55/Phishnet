"""
OAuth Consent and Permissions Models
Database models for tracking user consent, permissions, and data retention policies.
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
import json

from backend.app.core.database import Base

class ConsentScope(Enum):
    """OAuth scopes for Gmail access"""
    GMAIL_READONLY = "https://www.googleapis.com/auth/gmail.readonly"
    GMAIL_MODIFY = "https://www.googleapis.com/auth/gmail.modify"

class DataProcessingType(Enum):
    """Types of data processing activities"""
    SUBJECT_ANALYSIS = "subject_analysis"
    BODY_ANALYSIS = "body_analysis"
    ATTACHMENT_SCAN = "attachment_scan"
    LLM_PROCESSING = "llm_processing"
    THREAT_INTEL_LOOKUP = "threat_intel_lookup"
    METADATA_STORAGE = "metadata_storage"
    ARTIFACT_STORAGE = "artifact_storage"

class RetentionPolicy(Enum):
    """Data retention policies"""
    NO_STORAGE = "no_storage"  # Process only, don't store
    MINIMAL_7_DAYS = "minimal_7_days"  # Minimal metadata for 7 days
    STANDARD_30_DAYS = "standard_30_days"  # Standard retention for 30 days
    EXTENDED_90_DAYS = "extended_90_days"  # Extended for security investigations
    CUSTOM = "custom"  # User-defined retention period

class UserConsent(Base):
    """
    User consent tracking with granular permissions and data processing preferences.
    """
    __tablename__ = "user_consents"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), index=True, nullable=False)
    
    # OAuth and authentication
    google_user_id = Column(String(255), unique=True, index=True)
    access_token_hash = Column(String(255))  # Hashed for security
    refresh_token_hash = Column(String(255))  # Hashed for security
    token_expires_at = Column(DateTime)
    
    # Consent tracking
    consent_version = Column(String(50), default="1.0")
    consent_granted_at = Column(DateTime, default=datetime.utcnow)
    consent_updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    consent_revoked_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Granted scopes
    granted_scopes = Column(JSON, default=list)  # List of ConsentScope values
    
    # Data processing preferences
    allow_subject_analysis = Column(Boolean, default=True)
    allow_body_analysis = Column(Boolean, default=True)
    allow_attachment_scanning = Column(Boolean, default=False)
    allow_llm_processing = Column(Boolean, default=True)
    allow_threat_intel_lookup = Column(Boolean, default=True)
    opt_out_ai_analysis = Column(Boolean, default=False)
    opt_out_persistent_storage = Column(Boolean, default=False)
    
    # Retention and privacy settings
    retention_policy = Column(String(50), default=RetentionPolicy.STANDARD_30_DAYS.value)
    custom_retention_days = Column(Integer, nullable=True)
    data_processing_region = Column(String(50), default="US")
    
    # Privacy preferences
    allow_analytics = Column(Boolean, default=False)
    allow_performance_monitoring = Column(Boolean, default=True)
    share_threat_intelligence = Column(Boolean, default=True)  # Anonymous threat intel sharing
    
    # Compliance and audit
    privacy_policy_version = Column(String(50), default="1.0")
    terms_of_service_version = Column(String(50), default="1.0")
    gdpr_consent = Column(Boolean, default=False)
    ccpa_opt_out = Column(Boolean, default=False)
    
    # Metadata
    user_agent = Column(Text)
    ip_address = Column(String(45))  # IPv6 compatible
    consent_source = Column(String(50), default="web_ui")  # web_ui, api, mobile
    
    # Relationships
    audit_logs = relationship("ConsentAuditLog", back_populates="user_consent")
    data_artifacts = relationship("UserDataArtifact", back_populates="user_consent")

    @property
    def is_consent_valid(self) -> bool:
        """Check if consent is still valid"""
        if not self.is_active or self.consent_revoked_at:
            return False
        
        # Check if token is expired
        if self.token_expires_at and self.token_expires_at < datetime.utcnow():
            return False
            
        return True

    @property
    def effective_retention_days(self) -> int:
        """Get effective retention period in days"""
        if self.retention_policy == RetentionPolicy.NO_STORAGE.value:
            return 0
        elif self.retention_policy == RetentionPolicy.MINIMAL_7_DAYS.value:
            return 7
        elif self.retention_policy == RetentionPolicy.STANDARD_30_DAYS.value:
            return 30
        elif self.retention_policy == RetentionPolicy.EXTENDED_90_DAYS.value:
            return 90
        elif self.retention_policy == RetentionPolicy.CUSTOM.value:
            return self.custom_retention_days or 30
        else:
            return 30

    def has_scope(self, scope: ConsentScope) -> bool:
        """Check if user has granted specific scope"""
        return scope.value in (self.granted_scopes or [])

    def can_process_data(self, processing_type: DataProcessingType) -> bool:
        """Check if specific data processing is allowed"""
        if self.opt_out_ai_analysis and processing_type == DataProcessingType.LLM_PROCESSING:
            return False
        
        if self.opt_out_persistent_storage and processing_type in [
            DataProcessingType.METADATA_STORAGE, 
            DataProcessingType.ARTIFACT_STORAGE
        ]:
            return False
        
        processing_permissions = {
            DataProcessingType.SUBJECT_ANALYSIS: self.allow_subject_analysis,
            DataProcessingType.BODY_ANALYSIS: self.allow_body_analysis,
            DataProcessingType.ATTACHMENT_SCAN: self.allow_attachment_scanning,
            DataProcessingType.LLM_PROCESSING: self.allow_llm_processing,
            DataProcessingType.THREAT_INTEL_LOOKUP: self.allow_threat_intel_lookup,
            DataProcessingType.METADATA_STORAGE: not self.opt_out_persistent_storage,
            DataProcessingType.ARTIFACT_STORAGE: not self.opt_out_persistent_storage
        }
        
        return processing_permissions.get(processing_type, False)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            "user_id": self.user_id,
            "email": self.email,
            "consent_granted_at": self.consent_granted_at.isoformat() if self.consent_granted_at else None,
            "consent_updated_at": self.consent_updated_at.isoformat() if self.consent_updated_at else None,
            "is_active": self.is_active,
            "consent_version": self.consent_version,
            "granted_scopes": self.granted_scopes,
            "data_processing_preferences": {
                "allow_subject_analysis": self.allow_subject_analysis,
                "allow_body_analysis": self.allow_body_analysis,
                "allow_attachment_scanning": self.allow_attachment_scanning,
                "allow_llm_processing": self.allow_llm_processing,
                "allow_threat_intel_lookup": self.allow_threat_intel_lookup,
                "opt_out_ai_analysis": self.opt_out_ai_analysis,
                "opt_out_persistent_storage": self.opt_out_persistent_storage
            },
            "retention_settings": {
                "policy": self.retention_policy,
                "retention_days": self.effective_retention_days,
                "data_region": self.data_processing_region
            },
            "privacy_preferences": {
                "allow_analytics": self.allow_analytics,
                "allow_performance_monitoring": self.allow_performance_monitoring,
                "share_threat_intelligence": self.share_threat_intelligence
            },
            "compliance": {
                "privacy_policy_version": self.privacy_policy_version,
                "terms_version": self.terms_of_service_version,
                "gdpr_consent": self.gdpr_consent,
                "ccpa_opt_out": self.ccpa_opt_out
            }
        }

class ConsentAuditLog(Base):
    """
    Audit log for consent changes and access events.
    """
    __tablename__ = "consent_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_consent_id = Column(Integer, ForeignKey("user_consents.id"), nullable=False)
    
    # Event details
    event_type = Column(String(50), nullable=False)  # granted, updated, revoked, accessed
    event_timestamp = Column(DateTime, default=datetime.utcnow)
    event_details = Column(JSON)  # Detailed event information
    
    # Context
    ip_address = Column(String(45))
    user_agent = Column(Text)
    request_id = Column(String(255))
    
    # Changes (for update events)
    previous_values = Column(JSON)  # Previous consent state
    new_values = Column(JSON)  # New consent state
    
    # Relationships
    user_consent = relationship("UserConsent", back_populates="audit_logs")

class UserDataArtifact(Base):
    """
    Tracking of user data artifacts for retention and cleanup.
    """
    __tablename__ = "user_data_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    user_consent_id = Column(Integer, ForeignKey("user_consents.id"), nullable=False)
    
    # Artifact details
    artifact_type = Column(String(50), nullable=False)  # email_metadata, analysis_result, etc.
    artifact_id = Column(String(255), nullable=False)  # Reference to actual data
    storage_location = Column(String(255))  # Redis key, file path, etc.
    
    # Timing
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    
    # Metadata
    size_bytes = Column(Integer, default=0)
    content_hash = Column(String(255))  # For deduplication
    tags = Column(JSON, default=list)  # Searchable tags
    
    # Relationships
    user_consent = relationship("UserConsent", back_populates="data_artifacts")

    @property
    def is_expired(self) -> bool:
        """Check if artifact has expired"""
        return datetime.utcnow() > self.expires_at

    @property
    def days_until_expiry(self) -> int:
        """Days until artifact expires"""
        if self.is_expired:
            return 0
        delta = self.expires_at - datetime.utcnow()
        return delta.days

class ConsentTemplate(Base):
    """
    Consent form templates and versions for compliance tracking.
    """
    __tablename__ = "consent_templates"

    id = Column(Integer, primary_key=True, index=True)
    version = Column(String(50), unique=True, nullable=False)
    
    # Template content
    consent_text = Column(Text, nullable=False)
    privacy_policy_url = Column(String(500))
    terms_of_service_url = Column(String(500))
    
    # Scope definitions
    required_scopes = Column(JSON, default=list)
    optional_scopes = Column(JSON, default=list)
    
    # Legal and compliance
    legal_basis = Column(String(100))  # consent, legitimate_interest, etc.
    jurisdiction = Column(String(50), default="US")
    compliance_frameworks = Column(JSON, default=list)  # GDPR, CCPA, etc.
    
    # Lifecycle
    created_at = Column(DateTime, default=datetime.utcnow)
    effective_from = Column(DateTime, default=datetime.utcnow)
    deprecated_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

# Helper functions for consent management

def create_default_consent_template() -> ConsentTemplate:
    """Create default consent template"""
    return ConsentTemplate(
        version="1.0",
        consent_text="""
        PhishNet Email Security Analysis Consent

        By granting permission, you allow PhishNet to:
        
        ACCESS:
        • Read email subjects, content, and metadata
        • Analyze attachments for security threats
        • Monitor your Gmail inbox for new messages
        
        PROCESS:
        • Analyze email content using AI/ML models
        • Check URLs and attachments against threat intelligence
        • Generate security risk scores and recommendations
        
        STORE:
        • Email metadata (subject, sender, timestamp) for 30 days
        • Analysis results and threat indicators
        • Anonymous usage statistics for service improvement
        
        PRIVACY:
        • Email content is processed but not permanently stored
        • Personal information is encrypted and access-controlled
        • You can revoke access and delete data at any time
        """,
        privacy_policy_url="/privacy",
        terms_of_service_url="/terms",
        required_scopes=[ConsentScope.GMAIL_READONLY.value],
        optional_scopes=[ConsentScope.GMAIL_MODIFY.value],
        legal_basis="consent",
        compliance_frameworks=["GDPR", "CCPA"]
    )

def calculate_artifact_expiry(retention_policy: RetentionPolicy, 
                            custom_days: Optional[int] = None) -> datetime:
    """Calculate when an artifact should expire based on retention policy"""
    now = datetime.utcnow()
    
    if retention_policy == RetentionPolicy.NO_STORAGE:
        return now  # Immediate expiry
    elif retention_policy == RetentionPolicy.MINIMAL_7_DAYS:
        return now + timedelta(days=7)
    elif retention_policy == RetentionPolicy.STANDARD_30_DAYS:
        return now + timedelta(days=30)
    elif retention_policy == RetentionPolicy.EXTENDED_90_DAYS:
        return now + timedelta(days=90)
    elif retention_policy == RetentionPolicy.CUSTOM and custom_days:
        return now + timedelta(days=custom_days)
    else:
        return now + timedelta(days=30)  # Default to 30 days

def get_minimal_required_scopes() -> List[str]:
    """Get minimal required OAuth scopes"""
    return [ConsentScope.GMAIL_READONLY.value]

def get_optional_scopes() -> List[str]:
    """Get optional OAuth scopes with enhanced functionality"""
    return [ConsentScope.GMAIL_MODIFY.value]
