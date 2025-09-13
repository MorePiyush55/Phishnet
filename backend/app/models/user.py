"""User model for authentication and user management."""

from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, Enum, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship

from app.core.database import Base
from src.common.constants import UserRole


class User(Base):
    """User model for authentication and user management."""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(200), nullable=True)
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)
    disabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Google OAuth specific fields per specifications
    google_sub = Column(String(255), unique=True, nullable=True, index=True)  # Google user ID
    display_name = Column(String(200), nullable=True)  # Google display name
    connected_at = Column(DateTime, nullable=True)  # When OAuth was completed
    disconnected_at = Column(DateTime, nullable=True)  # When OAuth was revoked
    status = Column(String(50), default="disconnected")  # connected, disconnected, error, expired
    
    # Legacy Gmail fields (keeping for backward compatibility)
    gmail_credentials = Column(Text, nullable=True)
    gmail_watch_expiration = Column(DateTime, nullable=True)
    email_monitoring_enabled = Column(Boolean, default=False)
    last_email_scan = Column(DateTime, nullable=True)
    
    # Enhanced Gmail OAuth fields
    gmail_connected = Column(Boolean, default=False)
    gmail_email = Column(String(255), nullable=True)  # Connected Gmail address
    gmail_scopes_granted = Column(Text, nullable=True)  # JSON array of granted scopes
    gmail_connection_date = Column(DateTime, nullable=True)
    gmail_last_token_refresh = Column(DateTime, nullable=True)
    gmail_consent_version = Column(String(50), nullable=True)  # Track consent version
    gmail_status = Column(String(50), default="disconnected")  # connected, disconnected, error, expired
    
    # Gmail watch/real-time monitoring fields
    gmail_watch_history_id = Column(String(100), nullable=True)  # Gmail watch history ID
    gmail_watch_expiration = Column(DateTime, nullable=True)  # Watch expiration timestamp
    gmail_realtime_enabled = Column(Boolean, default=False)  # Real-time monitoring enabled
    
    # Relationships
    detections = relationship("Detection", back_populates="user")
    federated_clients = relationship("FederatedClient", back_populates="user")
    oauth_credentials = relationship("OAuthCredential", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    scan_results = relationship("ScanResult", back_populates="user")


class OAuthCredential(Base):
    """OAuth credentials storage with encryption."""
    
    __tablename__ = "oauth_credentials"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    client_id = Column(String(255), nullable=True)  # OAuth client ID used
    encrypted_refresh_token = Column(Text, nullable=False)  # Encrypted refresh token
    scopes = Column(Text, nullable=False)  # JSON array of granted scopes
    token_issued_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    token_expires_at = Column(DateTime, nullable=True)  # When refresh token expires
    last_refresh_at = Column(DateTime, nullable=True)  # Last time access token was refreshed
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="oauth_credentials")


class AuditLog(Base):
    """Audit log for tracking all OAuth and security events."""
    
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)  # Nullable for system events
    action = Column(String(100), nullable=False, index=True)  # oauth_start, oauth_callback, token_refresh, etc.
    actor = Column(String(100), nullable=True)  # user, system, admin
    ip_address = Column(String(45), nullable=True)  # IPv4/IPv6 address
    user_agent = Column(Text, nullable=True)  # Browser user agent
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    metadata = Column(JSON, nullable=True)  # Additional context data
    success = Column(Boolean, nullable=False, default=True)
    error_message = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")


class ScanResult(Base):
    """Email scan results storage."""
    
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    msg_id = Column(String(255), nullable=False, index=True)  # Gmail message ID
    thread_id = Column(String(255), nullable=True)  # Gmail thread ID
    verdict = Column(String(50), nullable=False, index=True)  # safe, suspicious, phishing, malicious
    score = Column(Float, nullable=False)  # Confidence score 0.0 - 1.0
    details = Column(JSON, nullable=True)  # Detailed analysis results
    scanned_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    scan_duration_ms = Column(Integer, nullable=True)  # Time taken to scan
    model_version = Column(String(50), nullable=True)  # ML model version used
    
    # Email metadata
    sender = Column(String(255), nullable=True)
    subject = Column(Text, nullable=True)
    received_at = Column(DateTime, nullable=True)  # When email was received
    
    # Relationships
    user = relationship("User", back_populates="scan_results")


# Keep legacy OAuth models for backward compatibility
class OAuthToken(Base):
    """Legacy OAuth token storage - deprecated, use OAuthCredential instead."""
    
    __tablename__ = "oauth_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_type = Column(String(50), nullable=False)  # access_token, refresh_token
    encrypted_token = Column(Text, nullable=False)
    scope = Column(String(500), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)


class OAuthAuditLog(Base):
    """Legacy OAuth audit log - deprecated, use AuditLog instead."""
    
    __tablename__ = "oauth_audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    event_type = Column(String(100), nullable=False)
    success = Column(Boolean, nullable=False)
    details = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    refresh_tokens = relationship("RefreshToken", back_populates="user")
    emails = relationship("Email", back_populates="user")
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}', username='{self.username}')>"
    
    @property
    def permissions(self) -> list:
        """Get user permissions based on role."""
        role_permissions = {
            UserRole.ADMIN: [
                "user:create", "user:read", "user:update", "user:delete",
                "email:read", "email:scan", "email:analyze",
                "detection:read", "detection:create", "detection:update", "detection:delete",
                "system:configure", "system:monitor"
            ],
            UserRole.ANALYST: [
                "email:read", "email:scan", "email:analyze",
                "detection:read", "detection:create", "detection:update",
                "system:monitor"
            ],
            UserRole.VIEWER: [
                "email:read", "detection:read"
            ]
        }
        return role_permissions.get(self.role, [])


class RevokedToken(Base):
    """Model to track revoked JWT tokens for security."""
    
    __tablename__ = "revoked_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(255), unique=True, index=True, nullable=False)  # JWT ID
    user_id = Column(String(255), nullable=True)  # For user-wide revocation
    revoked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    reason = Column(String(255), nullable=True)  # Reason for revocation
    
    def __repr__(self) -> str:
        return f"<RevokedToken(jti='{self.jti}', revoked_at={self.revoked_at})>"


class OAuthToken(Base):
    """Model to store encrypted OAuth refresh tokens."""
    
    __tablename__ = "oauth_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    provider = Column(String(50), nullable=False)  # 'gmail', 'outlook', etc.
    encrypted_refresh_token = Column(Text, nullable=False)  # Encrypted token
    encrypted_access_token = Column(Text, nullable=True)  # Encrypted current access token
    token_expires_at = Column(DateTime, nullable=True)
    scope = Column(String(500), nullable=True)  # OAuth scopes granted
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Security and audit fields
    creation_ip = Column(String(45), nullable=True)  # IP when token was created
    creation_user_agent = Column(String(500), nullable=True)
    revocation_reason = Column(String(255), nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    
    def __repr__(self) -> str:
        return f"<OAuthToken(user_id={self.user_id}, provider='{self.provider}', active={self.is_active})>"


class OAuthAuditLog(Base):
    """Audit log for OAuth-related events."""
    
    __tablename__ = "oauth_audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    event_type = Column(String(50), nullable=False)  # connect, disconnect, token_refresh, scope_change
    provider = Column(String(50), nullable=False)
    details = Column(Text, nullable=True)  # JSON details
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    success = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)
    
    def __repr__(self) -> str:
        return f"<OAuthAuditLog(user_id={self.user_id}, event='{self.event_type}', success={self.success})>"

