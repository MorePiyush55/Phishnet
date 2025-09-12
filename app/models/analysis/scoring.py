"""Models for scoring, response actions, and audit logging."""

from datetime import datetime
from typing import Optional, Dict, Any
import enum

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON, Float, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy import Enum

from app.core.database import Base


class ActionType(str, enum.Enum):
    """Types of actions that can be taken on emails."""
    QUARANTINE = "quarantine"
    UNQUARANTINE = "unquarantine"
    LABEL = "label"
    REMOVE_LABEL = "remove_label"
    DELETE = "delete"
    MARK_SAFE = "mark_safe"
    MARK_PHISHING = "mark_phishing"
    REANALYZE = "reanalyze"
    WHITELIST_SENDER = "whitelist_sender"
    BLACKLIST_SENDER = "blacklist_sender"


class ActionStatus(str, enum.Enum):
    """Status of an action."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AuditEventType(str, enum.Enum):
    """Types of audit events."""
    EMAIL_RECEIVED = "email_received"
    EMAIL_ANALYZED = "email_analyzed"
    EMAIL_SCORED = "email_scored"
    ACTION_TAKEN = "action_taken"
    ACTION_COMPLETED = "action_completed"
    ACTION_FAILED = "action_failed"
    CONFIG_CHANGED = "config_changed"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    PERMISSION_DENIED = "permission_denied"
    SYSTEM_ERROR = "system_error"


class EmailAction(Base):
    """Actions taken on emails with audit trail."""
    
    __tablename__ = "actions"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    action_type = Column(Enum(ActionType), nullable=False, index=True)
    status = Column(Enum(ActionStatus), default=ActionStatus.PENDING, index=True)
    
    # Action parameters (e.g., label name, reason, etc.)
    parameters = Column(JSON, nullable=True)
    
    # Execution details
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Results and error handling
    result = Column(JSON, nullable=True)  # Success/failure details
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)
    
    # Gmail integration
    gmail_message_id = Column(String(255), nullable=True)
    gmail_label_id = Column(String(255), nullable=True)
    
    # Relationships
    email = relationship("Email", back_populates="actions")
    created_by_user = relationship("User", foreign_keys=[created_by])
    
    def __repr__(self) -> str:
        return f"<EmailAction(id={self.id}, type={self.action_type}, status={self.status})>"


class AuditAction(str, enum.Enum):
    """Types of actions to audit."""
    # Authentication
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    TOKEN_REFRESH = "token_refresh"
    
    # Email processing
    EMAIL_INGESTED = "email_ingested"
    EMAIL_ANALYZED = "email_analyzed"
    EMAIL_QUARANTINED = "email_quarantined"
    EMAIL_RELEASED = "email_released"
    
    # Analysis
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYSIS_FAILED = "analysis_failed"
    
    # Actions
    ACTION_CREATED = "action_created"
    ACTION_EXECUTED = "action_executed"
    ACTION_FAILED = "action_failed"
    
    # Configuration
    SETTINGS_CHANGED = "settings_changed"
    THRESHOLD_CHANGED = "threshold_changed"
    
    # Security
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PERMISSION_DENIED = "permission_denied"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class AuditLog(Base):
    """Comprehensive audit logging for all system activities."""
    
    __tablename__ = "audits"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Actor information
    actor_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    actor_email = Column(String(255), nullable=True)  # For failed logins
    
    # Action details
    action = Column(Enum(AuditAction), nullable=False, index=True)
    resource_type = Column(String(100), nullable=True, index=True)  # email, user, setting
    resource_id = Column(String(255), nullable=True, index=True)    # ID of affected resource
    
    # Context
    details = Column(JSON, nullable=True)  # Additional context data
    ip_address = Column(String(45), nullable=True, index=True)  # IPv4/IPv6
    user_agent = Column(Text, nullable=True)
    request_id = Column(String(100), nullable=True, index=True)  # For request correlation
    
    # Outcome
    success = Column(Boolean, default=True, index=True)
    error_message = Column(Text, nullable=True)
    
    # Timestamp
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    # Relationships
    actor = relationship("User", foreign_keys=[actor_id])
    
    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action}, actor_id={self.actor_id})>"


class ScoringRule(Base):
    """Configurable scoring rules for email analysis."""
    
    __tablename__ = "scoring_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    
    # Rule configuration
    component = Column(String(50), nullable=False)  # sanitization, links, ai, threat_intel
    weight = Column(Float, nullable=False, default=1.0)
    threshold = Column(Float, nullable=True)  # Optional component threshold
    
    # Rule logic
    rule_logic = Column(JSON, nullable=True)  # Complex rule definitions
    
    # Status
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Tenant support (for multi-tenant deployments)
    tenant_id = Column(String(100), nullable=True, index=True)


class EmailScore(Base):
    """Final scores and classifications for emails."""
    
    __tablename__ = "email_scores"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, unique=True, index=True)
    
    # Component scores
    sanitization_score = Column(Float, default=0.0)
    link_score = Column(Float, default=0.0)
    ai_score = Column(Float, default=0.0)
    threat_intel_score = Column(Float, default=0.0)
    
    # Final scoring
    final_score = Column(Float, nullable=False, index=True)
    risk_level = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    
    # Classification
    is_phishing = Column(Boolean, default=False, index=True)
    confidence = Column(Float, nullable=True)
    
    # Scoring metadata
    scoring_version = Column(String(20), default="v1.0")
    rules_applied = Column(JSON, nullable=True)  # Which rules were used
    
    # Timestamps
    scored_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    # Relationships
    email = relationship("Email", back_populates="email_score")
    
    def __repr__(self) -> str:
        return f"<EmailScore(email_id={self.email_id}, score={self.final_score}, risk={self.risk_level})>"
