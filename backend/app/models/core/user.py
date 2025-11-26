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
    __table_args__ = {'extend_existing': True}
    
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

