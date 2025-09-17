"""
Database models based on the comprehensive schema (SQLite compatible)
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, Numeric, 
    ForeignKey, JSON, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship, Session
from app.core.database import Base
from sqlalchemy.sql import func
import enum

 

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

class EmailStatus(str, enum.Enum):
    PENDING = "pending"
    ANALYZED = "analyzed"
    QUARANTINED = "quarantined"
    SAFE = "safe"
    FAILED = "failed"

class LinkRisk(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class ActionType(str, enum.Enum):
    QUARANTINE = "quarantine"
    RELEASE = "release"
    DELETE = "delete"
    MARK_SAFE = "mark_safe"
    RESCAN = "rescan"

class IndicatorType(str, enum.Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"

# Core User Management
class User(Base):
    """User accounts with role-based access control"""
    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default=UserRole.ANALYST)
    disabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Additional user fields
    name = Column(String(255))
    last_login = Column(DateTime(timezone=True))
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))
    
    # Relationships
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    actions = relationship("Action", back_populates="created_by_user")
    audits = relationship("Audit", back_populates="actor")
    
    def __repr__(self):
        return f"<User(email='{self.email}', role='{self.role}')>"

# Email Processing
class Email(Base):
    """Email messages with full metadata and analysis results"""
    __tablename__ = "emails"
    
    id = Column(Integer, primary_key=True, index=True)
    gmail_msg_id = Column(String(255), unique=True, nullable=False, index=True)
    thread_id = Column(String(255), index=True)
    from_addr = Column(String(255), nullable=False, index=True)
    to_addr = Column(String(255), nullable=False, index=True)
    subject = Column(Text)
    received_at = Column(DateTime(timezone=True), nullable=False, index=True)
    raw_headers = Column(JSON)
    raw_text = Column(Text)
    raw_html = Column(Text)
    sanitized_html = Column(Text)
    score = Column(Numeric(5, 3), index=True)  # Risk score 0.000-1.000
    status = Column(String(50), nullable=False, default=EmailStatus.PENDING, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Analysis tracking
    last_analyzed = Column(DateTime(timezone=True))
    analysis_version = Column(String(50))
    processing_time_ms = Column(Integer)
    
    # Relationships
    links = relationship("Link", back_populates="email", cascade="all, delete-orphan")
    ai_results = relationship("EmailAIResult", back_populates="email", cascade="all, delete-orphan")
    indicators = relationship("EmailIndicator", back_populates="email", cascade="all, delete-orphan")
    actions = relationship("Action", back_populates="email", cascade="all, delete-orphan")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_emails_status_received', 'status', 'received_at'),
        Index('idx_emails_from_received', 'from_addr', 'received_at'),
        Index('idx_emails_score_status', 'score', 'status'),
        {"extend_existing": True},
    )
    
    def __repr__(self):
        return f"<Email(id={self.id}, from='{self.from_addr}', subject='{self.subject[:50]}')>"

# Link Analysis
class Link(Base):
    """URLs found in emails with analysis results"""
    __tablename__ = "links"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    original_url = Column(Text, nullable=False)
    final_url = Column(Text)  # After following redirects
    chain = Column(JSON)  # Full redirect chain
    risk = Column(String(50), nullable=False, default=LinkRisk.LOW, index=True)
    reasons = Column(JSON)  # Risk assessment reasons
    analyzed_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Analysis metadata
    redirect_count = Column(Integer, default=0)
    response_time_ms = Column(Integer)
    status_code = Column(Integer)
    content_type = Column(String(255))
    
    # Relationships
    email = relationship("Email", back_populates="links")
    
    __table_args__ = (
        Index('idx_links_email_risk', 'email_id', 'risk'),
        Index('idx_links_analyzed_risk', 'analyzed_at', 'risk'),
        {"extend_existing": True},
    )
    
    def __repr__(self):
        return f"<Link(id={self.id}, url='{self.original_url[:50]}', risk='{self.risk}')>"

# AI Analysis Results
class EmailAIResult(Base):
    """AI model analysis results for emails"""
    __tablename__ = "email_ai_results"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    model = Column(String(100), nullable=False, index=True)  # e.g., 'gemini-pro', 'gpt-4'
    score = Column(Numeric(5, 3), nullable=False, index=True)  # Confidence score
    labels = Column(JSON)  # Classification labels and probabilities
    summary = Column(Text)  # Human-readable analysis summary
    prompt_version = Column(String(50))  # For prompt engineering tracking
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Performance tracking
    processing_time_ms = Column(Integer)
    tokens_used = Column(Integer)
    api_cost = Column(Numeric(10, 6))  # Cost tracking for AI APIs
    
    # Relationships
    email = relationship("Email", back_populates="ai_results")
    
    __table_args__ = (
        Index('idx_ai_results_email_model', 'email_id', 'model'),
        Index('idx_ai_results_score_created', 'score', 'created_at'),
        {"extend_existing": True},
    )
    
    def __repr__(self):
        return f"<EmailAIResult(id={self.id}, model='{self.model}', score={self.score})>"

# Threat Intelligence
class EmailIndicator(Base):
    """Threat intelligence indicators found in emails"""
    __tablename__ = "email_indicators"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    indicator = Column(String(255), nullable=False, index=True)  # The actual indicator value
    type = Column(String(50), nullable=False, index=True)  # domain, ip, url, hash, email
    source = Column(String(100), nullable=False, index=True)  # virustotal, abuseipdb, etc.
    reputation = Column(String(50), nullable=False, index=True)  # clean, suspicious, malicious
    details = Column(JSON)  # Full threat intel response
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Cache management
    expires_at = Column(DateTime(timezone=True))
    last_updated = Column(DateTime(timezone=True))
    
    # Relationships
    email = relationship("Email", back_populates="indicators")
    
    __table_args__ = (
        Index('idx_indicators_indicator_type', 'indicator', 'type'),
        Index('idx_indicators_reputation_created', 'reputation', 'created_at'),
        Index('idx_indicators_source_type', 'source', 'type'),
        {"extend_existing": True},
    )
    
    def __repr__(self):
        return f"<EmailIndicator(indicator='{self.indicator}', type='{self.type}', reputation='{self.reputation}')>"

# User Actions
class Action(Base):
    """User and system actions performed on emails"""
    __tablename__ = "actions"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    type = Column(String(50), nullable=False, index=True)  # quarantine, release, delete, etc.
    params = Column(JSON)  # Action-specific parameters
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)  # NULL for system actions
    result = Column(JSON)  # Action execution result
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Action tracking
    success = Column(Boolean, nullable=False, default=True)
    error_message = Column(Text)
    execution_time_ms = Column(Integer)
    
    # Relationships
    email = relationship("Email", back_populates="actions")
    created_by_user = relationship("User", back_populates="actions")
    
    __table_args__ = (
        Index('idx_actions_email_type', 'email_id', 'type'),
        Index('idx_actions_created_by_type', 'created_by', 'type'),
        Index('idx_actions_created_success', 'created_at', 'success'),
        {"extend_existing": True},
    )
    
    def __repr__(self):
        return f"<Action(id={self.id}, type='{self.type}', email_id={self.email_id})>"

# Audit Logging
class Audit(Base):
    """Comprehensive audit trail for all system activities"""
    __tablename__ = "audits"
    
    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)  # NULL for system actions
    action = Column(String(100), nullable=False, index=True)  # login, email_analyzed, etc.
    resource = Column(String(100), index=True)  # email, user, system
    details = Column(JSON)  # Action-specific details
    ip = Column(String(45))  # Support IPv4 and IPv6
    request_id = Column(String(36), index=True)  # Correlation ID for request tracing
    ts = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    # Request context
    user_agent = Column(Text)
    endpoint = Column(String(255))
    method = Column(String(10))
    status_code = Column(Integer)
    response_time_ms = Column(Integer)
    
    # Relationships
    actor = relationship("User", back_populates="audits")
    
    __table_args__ = (
        Index('idx_audits_action_ts', 'action', 'ts'),
        Index('idx_audits_actor_action', 'actor_id', 'action'),
        Index('idx_audits_resource_ts', 'resource', 'ts'),
        Index('idx_audits_request_id', 'request_id'),
        {"extend_existing": True},
    )
    
    def __repr__(self):
        return f"<Audit(id={self.id}, action='{self.action}', actor_id={self.actor_id})>"

# Authentication
class RefreshToken(Base):
    """Refresh tokens for JWT authentication"""
    __tablename__ = "refresh_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(255), nullable=False, unique=True, index=True)
    exp = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Token metadata
    last_used = Column(DateTime(timezone=True))
    client_info = Column(JSON)  # User agent, IP, etc.
    
    # Relationships
    user = relationship("User", back_populates="refresh_tokens")
    
    __table_args__ = (
        Index('idx_refresh_tokens_user_exp', 'user_id', 'exp'),
        Index('idx_refresh_tokens_revoked_exp', 'revoked', 'exp'),
        {"extend_existing": True},
    )
    
    def __repr__(self):
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, revoked={self.revoked})>"

# Utility functions for database operations
class DatabaseUtils:
    """Utility functions for common database operations"""
    
    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        """Get user by email address"""
        return db.query(User).filter(User.email == email).first()
    
    @staticmethod
    def get_emails_by_status(db: Session, status: EmailStatus, limit: int = 50, offset: int = 0) -> List[Email]:
        """Get emails filtered by status with pagination"""
        return db.query(Email).filter(Email.status == status).order_by(Email.received_at.desc()).limit(limit).offset(offset).all()
    
    @staticmethod
    def get_high_risk_emails(db: Session, threshold: float = 0.7, limit: int = 50) -> List[Email]:
        """Get emails with risk score above threshold"""
        return db.query(Email).filter(Email.score >= threshold).order_by(Email.score.desc()).limit(limit).all()
    
    @staticmethod
    def create_audit_entry(db: Session, actor_id: Optional[int], action: str, resource: str, 
                          details: Dict[str, Any], ip: str = None, request_id: str = None) -> Audit:
        """Create audit trail entry"""
        audit = Audit(
            actor_id=actor_id,
            action=action,
            resource=resource,
            details=details,
            ip=ip,
            request_id=request_id
        )
        db.add(audit)
        db.commit()
        db.refresh(audit)
        return audit
    
    @staticmethod
    def get_threat_indicators(db: Session, email_id: int) -> List[EmailIndicator]:
        """Get all threat intelligence indicators for an email"""
        return db.query(EmailIndicator).filter(EmailIndicator.email_id == email_id).all()
    
    @staticmethod
    def cleanup_expired_tokens(db: Session) -> int:
        """Remove expired refresh tokens"""
        count = db.query(RefreshToken).filter(RefreshToken.exp < datetime.utcnow()).delete()
        db.commit()
        return count
