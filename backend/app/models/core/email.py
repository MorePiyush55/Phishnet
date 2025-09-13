"""Email model for storing email analysis data."""

from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, ForeignKey, Enum
from sqlalchemy.orm import relationship

from app.core.database import Base


class EmailStatus(str, enum.Enum):
    """Email processing status."""
    PENDING = "pending"
    PROCESSING = "processing"
    ANALYZED = "analyzed"
    QUARANTINED = "quarantined"
    SAFE = "safe"
    ERROR = "error"


class Email(Base):
    """Email model for storing email analysis data."""
    
    __tablename__ = "emails"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Gmail specific fields
    gmail_msg_id = Column(String(255), unique=True, index=True, nullable=True)
    thread_id = Column(String(255), index=True, nullable=True)
    
    # Email metadata
    sender = Column(String(255), nullable=False, index=True)
    recipients = Column(Text, nullable=False)  # JSON array
    subject = Column(String(500), nullable=True, index=True)
    received_at = Column(DateTime, nullable=False, index=True)
    
    # Email content
    raw_headers = Column(Text, nullable=True)  # Raw email headers
    raw_html = Column(Text, nullable=True)     # Original HTML content
    raw_text = Column(Text, nullable=True)     # Plain text content
    sanitized_html = Column(Text, nullable=True)  # Sanitized HTML for display
    
    # Analysis fields
    content_hash = Column(String(64), unique=True, index=True, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    score = Column(Float, nullable=True, index=True)  # Phishing confidence score
    status = Column(Enum(EmailStatus), default=EmailStatus.PENDING, nullable=False, index=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    analyzed_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="emails")
    detections = relationship("Detection", back_populates="email")
    attachments = relationship("EmailAttachment", back_populates="email")
    link_analyses = relationship("LinkAnalysis", back_populates="email")
    ai_results = relationship("EmailAIResults", back_populates="email")
    indicators = relationship("EmailIndicators", back_populates="email")
    actions = relationship("EmailAction", back_populates="email")
    email_score = relationship("EmailScore", back_populates="email", uselist=False)
    
    def __repr__(self) -> str:
        return f"<Email(id={self.id}, subject='{self.subject}', sender='{self.sender}')>"


class EmailAttachment(Base):
    """Email attachment model."""
    
    __tablename__ = "email_attachments"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    content_type = Column(String(100), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    file_hash = Column(String(64), nullable=False, index=True)
    is_suspicious = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    email = relationship("Email", back_populates="attachments")
    
    def __repr__(self) -> str:
        return f"<EmailAttachment(id={self.id}, filename='{self.filename}')>"
        return f"<EmailAttachment(id={self.id}, filename='{self.filename}')>"

