"""
AuditLog model for comprehensive audit trail tracking.

This model stores all user actions, system events, and security incidents
for compliance and security monitoring.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Index, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
import uuid
import json

from app.db.base import Base
from app.config.logging import get_logger

logger = get_logger(__name__)


class AuditLog(Base):
    """
    Comprehensive audit log for tracking all system activities.
    
    Tracks:
    - User actions (login, logout, view email, quarantine, etc.)
    - System events (scan started/finished, API calls, failures)
    - Security incidents (failed logins, XSS attempts, etc.)
    - Admin actions (user management, configuration changes)
    """
    
    __tablename__ = "audit_logs"
    
    # Primary fields
    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(50), nullable=True, index=True)  # Request correlation ID
    
    # Correlation and tracing fields
    correlation_id = Column(String(50), nullable=True, index=True)  # Cross-request correlation ID
    span_id = Column(String(32), nullable=True)  # OpenTelemetry span ID
    trace_id = Column(String(64), nullable=True)  # OpenTelemetry trace ID
    
    # User/Actor information
    user_id = Column(Integer, nullable=True, index=True)  # User who performed action
    session_id = Column(String(100), nullable=True, index=True)  # Session identifier
    user_ip = Column(String(45), nullable=True)  # IPv4/IPv6 address
    user_agent = Column(String(500), nullable=True)  # Browser/client info
    
    # Action details
    action = Column(String(100), nullable=False, index=True)  # Action type
    resource_type = Column(String(50), nullable=True, index=True)  # Resource type (email, user, etc.)
    resource_id = Column(String(100), nullable=True, index=True)  # Resource identifier
    
    # Event details
    severity = Column(String(20), nullable=False, default='info', index=True)  # info, warning, error, critical
    category = Column(String(50), nullable=False, index=True)  # auth, email, scan, admin, security
    description = Column(Text, nullable=False)  # Human-readable description
    
    # Technical details
    details = Column(JSON, nullable=True)  # Structured event data
    request_path = Column(String(500), nullable=True)  # API endpoint or page
    request_method = Column(String(10), nullable=True)  # GET, POST, etc.
    response_status = Column(Integer, nullable=True)  # HTTP status code
    
    # Timing
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    duration_ms = Column(Integer, nullable=True)  # Action duration in milliseconds
    
    # Security flags
    is_suspicious = Column(Boolean, default=False, index=True)  # Flagged as suspicious
    security_violation = Column(Boolean, default=False, index=True)  # Security policy violation
    
    # Compliance fields
    retention_days = Column(Integer, default=365)  # How long to retain this record
    compliance_tags = Column(JSON, nullable=True)  # Compliance-related tags
    
    # Database indexes for performance
    __table_args__ = (
        Index('idx_audit_user_action_time', 'user_id', 'action', 'created_at'),
        Index('idx_audit_category_severity_time', 'category', 'severity', 'created_at'),
        Index('idx_audit_request_time', 'request_id', 'created_at'),
        Index('idx_audit_correlation_time', 'correlation_id', 'created_at'),
        Index('idx_audit_trace_time', 'trace_id', 'created_at'),
        Index('idx_audit_security_flags', 'is_suspicious', 'security_violation', 'created_at'),
        Index('idx_audit_resource', 'resource_type', 'resource_id', 'created_at'),
    )
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, user_id={self.user_id}, action='{self.action}', created_at={self.created_at})>"
    
    @property
    def timestamp(self):
        """Alias for created_at for backward compatibility."""
        return self.created_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit log to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'request_id': self.request_id,
            'correlation_id': self.correlation_id,
            'span_id': self.span_id,
            'trace_id': self.trace_id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'user_ip': self.user_ip,
            'user_agent': self.user_agent,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'severity': self.severity,
            'category': self.category,
            'description': self.description,
            'details': self.details,
            'request_path': self.request_path,
            'request_method': self.request_method,
            'response_status': self.response_status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'duration_ms': self.duration_ms,
            'is_suspicious': self.is_suspicious,
            'security_violation': self.security_violation,
            'retention_days': self.retention_days,
            'compliance_tags': self.compliance_tags
        }
    
    @classmethod
    def create_user_action(
        cls,
        action: str,
        user_id: int,
        description: str,
        details: Optional[Dict[str, Any]] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        request_id: Optional[str] = None,
        severity: str = 'info'
    ) -> 'AuditLog':
        """Create audit log entry for user action."""
        return cls(
            action=action,
            user_id=user_id,
            description=description,
            details=details or {},
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id,
            severity=severity,
            category='user'
        )
    
    @classmethod
    def create_system_event(
        cls,
        action: str,
        description: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = 'info',
        category: str = 'system',
        request_id: Optional[str] = None
    ) -> 'AuditLog':
        """Create audit log entry for system event."""
        return cls(
            action=action,
            description=description,
            details=details or {},
            severity=severity,
            category=category,
            request_id=request_id
        )
    
    @classmethod
    def create_security_event(
        cls,
        action: str,
        description: str,
        user_id: Optional[int] = None,
        user_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        is_suspicious: bool = True,
        security_violation: bool = False,
        request_id: Optional[str] = None
    ) -> 'AuditLog':
        """Create audit log entry for security event."""
        return cls(
            action=action,
            user_id=user_id,
            user_ip=user_ip,
            description=description,
            details=details or {},
            severity='warning' if is_suspicious else 'critical',
            category='security',
            is_suspicious=is_suspicious,
            security_violation=security_violation,
            request_id=request_id
        )
