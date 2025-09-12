"""User model for authentication and user management."""

from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, Enum
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
    
    # Gmail integration fields
    gmail_credentials = Column(Text, nullable=True)
    gmail_watch_expiration = Column(DateTime, nullable=True)
    email_monitoring_enabled = Column(Boolean, default=False)
    last_email_scan = Column(DateTime, nullable=True)
    
    # Relationships
    detections = relationship("Detection", back_populates="user")
    federated_clients = relationship("FederatedClient", back_populates="user")
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
    token_expires_at = Column(DateTime, nullable=True)
    scope = Column(String(500), nullable=True)  # OAuth scopes granted
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    def __repr__(self) -> str:
        return f"<OAuthToken(user_id={self.user_id}, provider='{self.provider}')>"

