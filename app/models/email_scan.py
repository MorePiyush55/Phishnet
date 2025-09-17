"""Enhanced email scanning models for production-ready PhishNet."""

from datetime import datetime
from typing import Optional, Dict, Any, List
import enum
import json

from sqlalchemy import (
    Boolean, Column, DateTime, Integer, String, Text, 
    Enum, Float, JSON, ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


class ScanStatus(str, enum.Enum):
    """Email scan status enumeration."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    QUARANTINED = "quarantined"
    APPROVED = "approved"


class ThreatLevel(str, enum.Enum):
    """Threat level enumeration."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EmailScanRequest(Base):
    """Email scan request record with metadata only (privacy-first)."""
    
    __tablename__ = "email_scan_requests"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Email metadata (no PII content)
    gmail_message_id = Column(String(255), nullable=False, index=True)
    gmail_thread_id = Column(String(255), nullable=True, index=True)
    sender_domain = Column(String(255), nullable=True, index=True)  # Only domain, not full email
    subject_hash = Column(String(64), nullable=True)  # Hash of subject for deduplication
    content_hash = Column(String(64), nullable=False, index=True)  # Hash of content
    received_at = Column(DateTime, nullable=False, index=True)
    size_bytes = Column(Integer, nullable=True)
    
    # Scan metadata
    scan_request_id = Column(String(50), nullable=False, unique=True, index=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    priority = Column(Integer, default=5, nullable=False)  # 1-10, higher = more urgent
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Processing metadata
    worker_id = Column(String(100), nullable=True)
    retry_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="email_scan_requests")
    threat_result = relationship("ThreatResult", back_populates="scan_request", uselist=False)
    audit_logs = relationship("AuditLog", back_populates="scan_request")
    
    __table_args__ = (
        Index("ix_user_status_created", "user_id", "status", "created_at"),
        Index("ix_gmail_msg_user", "gmail_message_id", "user_id"),
        UniqueConstraint("gmail_message_id", "user_id", name="uq_gmail_msg_user"),
    )
    
    def __repr__(self) -> str:
        return f"<EmailScanRequest(id={self.id}, user_id={self.user_id}, status={self.status})>"


class ThreatResult(Base):
    """Aggregated threat analysis results."""
    
    __tablename__ = "threat_results"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_request_id = Column(UUID(as_uuid=True), ForeignKey("email_scan_requests.id"), 
                            nullable=False, unique=True, index=True)
    
    # Threat scoring
    threat_score = Column(Float, nullable=False, index=True)  # 0.0 - 1.0
    threat_level = Column(Enum(ThreatLevel), nullable=False, index=True)
    confidence = Column(Float, nullable=False)  # 0.0 - 1.0
    
    # Analysis results summary
    phishing_indicators = Column(JSON, nullable=True)  # List of indicators found
    malicious_links = Column(Integer, default=0)
    suspicious_attachments = Column(Integer, default=0)
    reputation_flags = Column(Integer, default=0)
    
    # Component scores
    link_analysis_score = Column(Float, nullable=True)
    content_analysis_score = Column(Float, nullable=True)  
    sender_reputation_score = Column(Float, nullable=True)
    ml_model_score = Column(Float, nullable=True)
    llm_analysis_score = Column(Float, nullable=True)
    
    # Explanation and recommendations
    explanation = Column(Text, nullable=True)  # Human-readable explanation
    recommendations = Column(JSON, nullable=True)  # Recommended actions
    false_positive_likelihood = Column(Float, nullable=True)
    
    # Processing metadata
    analysis_duration_seconds = Column(Float, nullable=True)
    analyzers_used = Column(JSON, nullable=True)  # List of analyzers that ran
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    scan_request = relationship("EmailScanRequest", back_populates="threat_result")
    component_results = relationship("AnalysisComponentResult", back_populates="threat_result")
    
    __table_args__ = (
        Index("ix_threat_level_score", "threat_level", "threat_score"),
        Index("ix_created_threat_level", "created_at", "threat_level"),
    )
    
    def __repr__(self) -> str:
        return f"<ThreatResult(id={self.id}, threat_level={self.threat_level}, score={self.threat_score})>"


class AnalysisComponentResult(Base):
    """Individual component analysis results."""
    
    __tablename__ = "analysis_component_results"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_result_id = Column(UUID(as_uuid=True), ForeignKey("threat_results.id"), 
                             nullable=False, index=True)
    
    # Component details
    component_name = Column(String(100), nullable=False, index=True)  # e.g., "LinkRedirectAnalyzer"
    component_version = Column(String(50), nullable=True)
    
    # Results
    score = Column(Float, nullable=True)  # Component-specific score
    verdict = Column(String(50), nullable=True)  # "safe", "suspicious", "malicious"
    confidence = Column(Float, nullable=True)
    
    # Findings
    findings = Column(JSON, nullable=True)  # Component-specific findings
    indicators = Column(JSON, nullable=True)  # Specific indicators found
    entry_metadata = Column(JSON, nullable=True)  # Additional metadata (renamed from metadata)
    
    # Processing info
    execution_time_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    threat_result = relationship("ThreatResult", back_populates="component_results")
    
    __table_args__ = (
        Index("ix_component_name_created", "component_name", "created_at"),
    )
    
    def __repr__(self) -> str:
        return f"<AnalysisComponentResult(component={self.component_name}, verdict={self.verdict})>"


class QuarantineAction(Base):
    """Gmail quarantine/action tracking."""
    
    __tablename__ = "quarantine_actions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_request_id = Column(UUID(as_uuid=True), ForeignKey("email_scan_requests.id"),
                            nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Action details
    action_type = Column(String(50), nullable=False)  # "quarantine", "approve", "label", "delete"
    action_method = Column(String(50), nullable=False)  # "auto", "manual", "policy"
    
    # Gmail API details
    gmail_message_id = Column(String(255), nullable=False)
    gmail_labels_applied = Column(JSON, nullable=True)  # Labels added/removed
    gmail_action_successful = Column(Boolean, default=False)
    
    # Policy and reasoning
    policy_rule = Column(String(200), nullable=True)  # Which policy triggered this
    threat_level_at_action = Column(Enum(ThreatLevel), nullable=False)
    
    # Timestamps
    requested_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    executed_at = Column(DateTime, nullable=True)
    
    # User interaction
    user_override = Column(Boolean, default=False)  # User manually changed action
    user_feedback = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User")
    scan_request = relationship("EmailScanRequest")
    
    __table_args__ = (
        Index("ix_action_user_created", "action_type", "user_id", "requested_at"),
    )
    
    def __repr__(self) -> str:
        return f"<QuarantineAction(action={self.action_type}, method={self.action_method})>"


class AuditLog(Base):
    """Comprehensive audit logging for GDPR compliance."""
    
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    scan_request_id = Column(UUID(as_uuid=True), ForeignKey("email_scan_requests.id"), 
                            nullable=True, index=True)
    
    # Action details
    action = Column(String(100), nullable=False, index=True)  # "oauth_grant", "email_scan", "data_delete"
    resource_type = Column(String(50), nullable=False)  # "email", "token", "user_data"
    resource_id = Column(String(255), nullable=True)
    
    # Context
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    user_agent = Column(Text, nullable=True)
    session_id = Column(String(255), nullable=True)
    
    # Details
    details = Column(JSON, nullable=True)  # Structured action details
    success = Column(Boolean, nullable=False, default=True)
    error_message = Column(Text, nullable=True)
    
    # GDPR compliance
    data_processed = Column(JSON, nullable=True)  # Types of data processed
    legal_basis = Column(String(100), nullable=True)  # GDPR legal basis
    retention_period_days = Column(Integer, nullable=True)
    
    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    user = relationship("User")
    scan_request = relationship("EmailScanRequest", back_populates="audit_logs")
    
    __table_args__ = (
        Index("ix_user_action_timestamp", "user_id", "action", "timestamp"),
        Index("ix_resource_timestamp", "resource_type", "resource_id", "timestamp"),
    )
    
    def __repr__(self) -> str:
        return f"<AuditLog(action={self.action}, user_id={self.user_id}, timestamp={self.timestamp})>"


class UserConsent(Base):
    """Track user consent for GDPR compliance."""
    
    __tablename__ = "user_consents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Consent details
    consent_type = Column(String(100), nullable=False)  # "gmail_scanning", "data_processing"
    granted = Column(Boolean, nullable=False)
    
    # Scope and details
    scopes = Column(JSON, nullable=True)  # OAuth scopes granted
    purposes = Column(JSON, nullable=True)  # Data processing purposes
    retention_period_days = Column(Integer, nullable=True)
    
    # Tracking
    consent_version = Column(String(50), nullable=False)  # Version of consent form
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Timestamps
    granted_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    revoked_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User")
    
    __table_args__ = (
        Index("ix_user_consent_type", "user_id", "consent_type", "granted"),
        UniqueConstraint("user_id", "consent_type", name="uq_user_consent"),
    )
    
    def __repr__(self) -> str:
        return f"<UserConsent(user_id={self.user_id}, type={self.consent_type}, granted={self.granted})>"


class DataRetention(Base):
    """Data retention and deletion tracking."""
    
    __tablename__ = "data_retention"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Retention policy
    data_type = Column(String(100), nullable=False)  # "email_metadata", "scan_results", "oauth_tokens"
    retention_period_days = Column(Integer, nullable=False)
    
    # Deletion tracking
    scheduled_deletion_date = Column(DateTime, nullable=False, index=True)
    deleted_at = Column(DateTime, nullable=True)
    deletion_method = Column(String(50), nullable=True)  # "automated", "user_request", "admin"
    
    # Records affected
    records_scheduled = Column(Integer, default=0)
    records_deleted = Column(Integer, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    notes = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User")
    
    __table_args__ = (
        Index("ix_scheduled_deletion", "scheduled_deletion_date", "deleted_at"),
    )
    
    def __repr__(self) -> str:
        return f"<DataRetention(user_id={self.user_id}, data_type={self.data_type})>"
