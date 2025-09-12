"""
Enhanced async database models for PhishNet Postgres migration.
Comprehensive schema with proper relationships, indexes, and async support.
"""

from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional, List, Dict, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Column, String, Text, DateTime, Boolean, Integer, Float, 
    ForeignKey, Index, UniqueConstraint, CheckConstraint, JSON,
    Enum, LargeBinary, func
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB, ARRAY
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import expression


class AsyncBase(AsyncAttrs, DeclarativeBase):
    """Async-enabled base class for all database models."""
    pass


class TimestampMixin:
    """Mixin for created_at and updated_at timestamps."""
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        server_onupdate=func.now()
    )


# Enums for type safety
class UserRole(PyEnum):
    """User roles for RBAC."""
    ADMIN = "admin"
    ANALYST = "analyst" 
    USER = "user"
    READONLY = "readonly"


class ThreatLevel(PyEnum):
    """Threat classification levels."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class EmailStatus(PyEnum):
    """Email processing status."""
    PENDING = "pending"
    PROCESSING = "processing"
    ANALYZED = "analyzed"
    FAILED = "failed"
    QUARANTINED = "quarantined"


class AuditAction(PyEnum):
    """Audit log action types."""
    LOGIN = "login"
    LOGOUT = "logout"
    EMAIL_ANALYZED = "email_analyzed"
    THREAT_DETECTED = "threat_detected"
    SETTINGS_CHANGED = "settings_changed"
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    API_ACCESS = "api_access"


# Core Models
class AsyncUser(AsyncBase, TimestampMixin):
    """Enhanced async user model with authentication and RBAC."""
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(255))
    
    # Authentication
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=expression.true())
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default=expression.false())
    
    # RBAC
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.USER)
    permissions: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, server_default='{}')
    
    # Profile
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    login_count: Mapped[int] = mapped_column(Integer, default=0, server_default='0')
    
    # Relationships
    emails: Mapped[List["AsyncEmail"]] = relationship("AsyncEmail", back_populates="user", cascade="all, delete-orphan")
    oauth_tokens: Mapped[List["AsyncOAuthToken"]] = relationship("AsyncOAuthToken", back_populates="user", cascade="all, delete-orphan")
    revoked_tokens: Mapped[List["AsyncRevokedToken"]] = relationship("AsyncRevokedToken", back_populates="user", cascade="all, delete-orphan")
    audit_logs: Mapped[List["AsyncAuditLog"]] = relationship("AsyncAuditLog", back_populates="user", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('ix_users_email_active', 'email', 'is_active'),
        Index('ix_users_role_active', 'role', 'is_active'),
    )

    def __repr__(self) -> str:
        return f"<AsyncUser(id={self.id}, email='{self.email}', role='{self.role.value}')>"


class AsyncEmail(AsyncBase, TimestampMixin):
    """Async email model for phishing analysis."""
    __tablename__ = "emails"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Email metadata
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    sender: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    recipients: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False)
    message_id: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    
    # Email content
    body_text: Mapped[Optional[str]] = mapped_column(Text)
    body_html: Mapped[Optional[str]] = mapped_column(Text)
    headers: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, server_default='{}')
    
    # Analysis status
    status: Mapped[EmailStatus] = mapped_column(Enum(EmailStatus), default=EmailStatus.PENDING, index=True)
    threat_level: Mapped[ThreatLevel] = mapped_column(Enum(ThreatLevel), default=ThreatLevel.UNKNOWN, index=True)
    confidence_score: Mapped[Optional[float]] = mapped_column(Float)
    
    # Processing metadata
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), index=True)  # SHA-256
    file_size: Mapped[Optional[int]] = mapped_column(Integer)
    processing_time: Mapped[Optional[float]] = mapped_column(Float)  # seconds
    
    # User association
    user_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    
    # Relationships
    user: Mapped["AsyncUser"] = relationship("AsyncUser", back_populates="emails")
    threat_results: Mapped[List["AsyncThreatResult"]] = relationship("AsyncThreatResult", back_populates="email", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('ix_emails_sender_threat', 'sender', 'threat_level'),
        Index('ix_emails_status_created', 'status', 'created_at'),
        Index('ix_emails_user_created', 'user_id', 'created_at'),
        Index('ix_emails_hash', 'file_hash'),
    )

    def __repr__(self) -> str:
        return f"<AsyncEmail(id={self.id}, sender='{self.sender}', threat_level='{self.threat_level.value}')>"


class AsyncThreatResult(AsyncBase, TimestampMixin):
    """Async threat analysis results from various sources."""
    __tablename__ = "threat_results"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Analysis source
    source: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # 'virustotal', 'abuseipdb', 'gemini', etc.
    source_id: Mapped[Optional[str]] = mapped_column(String(100))  # External ID from source
    
    # Results
    threat_level: Mapped[ThreatLevel] = mapped_column(Enum(ThreatLevel), nullable=False, index=True)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    raw_response: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, server_default='{}')
    
    # Analysis details
    indicators: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, server_default='{}')
    categories: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, server_default='{}')
    tags: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, server_default='{}')
    
    # Processing metadata
    analysis_duration: Mapped[Optional[float]] = mapped_column(Float)  # seconds
    cached: Mapped[bool] = mapped_column(Boolean, default=False, server_default=expression.false())
    
    # Email association
    email_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("emails.id"), nullable=False, index=True)
    
    # Relationships
    email: Mapped["AsyncEmail"] = relationship("AsyncEmail", back_populates="threat_results")
    
    # Indexes
    __table_args__ = (
        Index('ix_threat_results_source_level', 'source', 'threat_level'),
        Index('ix_threat_results_email_source', 'email_id', 'source'),
        Index('ix_threat_results_confidence', 'confidence_score'),
    )

    def __repr__(self) -> str:
        return f"<AsyncThreatResult(id={self.id}, source='{self.source}', threat_level='{self.threat_level.value}')>"


class AsyncAuditLog(AsyncBase, TimestampMixin):
    """Async audit logging for security and compliance."""
    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Action details
    action: Mapped[AuditAction] = mapped_column(Enum(AuditAction), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Context
    resource_type: Mapped[Optional[str]] = mapped_column(String(50), index=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    
    # Request metadata
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 compatible
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    request_id: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    
    # Additional context
    audit_metadata: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, server_default='{}')
    
    # User association (nullable for system actions)
    user_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), index=True)
    
    # Relationships
    user: Mapped[Optional["AsyncUser"]] = relationship("AsyncUser", back_populates="audit_logs")
    
    # Indexes
    __table_args__ = (
        Index('ix_audit_logs_action_created', 'action', 'created_at'),
        Index('ix_audit_logs_user_action', 'user_id', 'action'),
        Index('ix_audit_logs_ip_created', 'ip_address', 'created_at'),
        Index('ix_audit_logs_resource', 'resource_type', 'resource_id'),
    )

    def __repr__(self) -> str:
        return f"<AsyncAuditLog(id={self.id}, action='{self.action.value}', user_id={self.user_id})>"


class AsyncFeatureFlag(AsyncBase, TimestampMixin):
    """Async feature flags for A/B testing and gradual rollouts."""
    __tablename__ = "feature_flags"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Flag details
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    
    # State
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=expression.false(), index=True)
    percentage: Mapped[int] = mapped_column(Integer, default=0)  # 0-100 for gradual rollout
    
    # Targeting
    user_roles: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, server_default='{}')
    user_emails: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, server_default='{}')
    
    # Configuration
    config: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, server_default='{}')
    
    # Lifecycle
    start_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    end_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    
    # Constraints
    __table_args__ = (
        CheckConstraint('percentage >= 0 AND percentage <= 100', name='ck_feature_flags_percentage'),
        Index('ix_feature_flags_enabled_name', 'is_enabled', 'name'),
    )

    def __repr__(self) -> str:
        return f"<AsyncFeatureFlag(name='{self.name}', enabled={self.is_enabled})>"


class AsyncOAuthToken(AsyncBase, TimestampMixin):
    """Async OAuth tokens with encryption support."""
    __tablename__ = "oauth_tokens"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # OAuth details
    provider: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    provider_user_id: Mapped[str] = mapped_column(String(100), nullable=False)
    
    # Encrypted tokens
    access_token_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    refresh_token_encrypted: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
    
    # Token metadata
    token_type: Mapped[str] = mapped_column(String(20), default="Bearer")
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True)
    scopes: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, server_default='{}')
    
    # User association
    user_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    
    # Relationships
    user: Mapped["AsyncUser"] = relationship("AsyncUser", back_populates="oauth_tokens")
    
    # Indexes
    __table_args__ = (
        UniqueConstraint('provider', 'provider_user_id', name='uq_oauth_tokens_provider_user'),
        Index('ix_oauth_tokens_user_provider', 'user_id', 'provider'),
        Index('ix_oauth_tokens_expires', 'expires_at'),
    )

    def __repr__(self) -> str:
        return f"<AsyncOAuthToken(id={self.id}, provider='{self.provider}', user_id={self.user_id})>"


class AsyncRevokedToken(AsyncBase):
    """Async revoked JWT tokens for security."""
    __tablename__ = "revoked_tokens"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Token identification
    jti: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)  # JWT ID
    token_type: Mapped[str] = mapped_column(String(20), nullable=False)  # 'access' or 'refresh'
    
    # Revocation details
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now()
    )
    reason: Mapped[Optional[str]] = mapped_column(String(100))
    
    # Token metadata
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    
    # User association
    user_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    
    # Relationships
    user: Mapped["AsyncUser"] = relationship("AsyncUser", back_populates="revoked_tokens")
    
    # Indexes
    __table_args__ = (
        Index('ix_revoked_tokens_expires', 'expires_at'),
        Index('ix_revoked_tokens_user_type', 'user_id', 'token_type'),
    )

    def __repr__(self) -> str:
        return f"<AsyncRevokedToken(jti='{self.jti}', token_type='{self.token_type}')>"


class AsyncCacheEntry(AsyncBase):
    """Async cache entries for Redis fallback and persistence."""
    __tablename__ = "cache_entries"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Cache key and data
    cache_key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    data: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    
    # Cache metadata
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    
    # Cache tags for invalidation
    tags: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, server_default='{}')
    
    # Indexes
    __table_args__ = (
        Index('ix_cache_entries_expires', 'expires_at'),
        Index('ix_cache_entries_tags', 'tags', postgresql_using='gin'),
    )

    def __repr__(self) -> str:
        return f"<AsyncCacheEntry(key='{self.cache_key}', expires_at={self.expires_at})>"


# Export all async models
__all__ = [
    "AsyncBase",
    "TimestampMixin",
    "UserRole",
    "ThreatLevel", 
    "EmailStatus",
    "AuditAction",
    "AsyncUser",
    "AsyncEmail",
    "AsyncThreatResult",
    "AsyncAuditLog",
    "AsyncFeatureFlag", 
    "AsyncOAuthToken",
    "AsyncRevokedToken",
    "AsyncCacheEntry"
]
