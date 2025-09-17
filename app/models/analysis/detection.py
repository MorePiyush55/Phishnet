"""Detection model for storing phishing detection results."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, JSON, Index, ForeignKey
from sqlalchemy.orm import relationship

from app.core.database import Base


class Detection(Base):
    """Detection model for storing phishing detection results."""
    
    __tablename__ = "detections"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=True, index=True)
    
    # Detection results
    is_phishing = Column(Boolean, nullable=False)
    confidence_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Model information
    model_version = Column(String(50), nullable=False)
    model_type = Column(String(50), nullable=False)  # ensemble, neural, federated
    
    # Feature analysis
    features = Column(JSON, nullable=True)  # Extracted features
    risk_factors = Column(JSON, nullable=True)  # Identified risk factors
    
    # Processing metadata
    processing_time_ms = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="detections")
    email = relationship("Email", back_populates="detections")
    
    # Composite indexes for performance optimization
    __table_args__ = (
        Index('idx_user_created_risk', 'user_id', 'created_at', 'risk_level'),
        Index('idx_email_confidence', 'email_id', 'confidence_score'),
        Index('idx_phishing_user_date', 'is_phishing', 'user_id', 'created_at'),
        Index('idx_model_performance', 'model_type', 'processing_time_ms'),
    )
    
    def __repr__(self) -> str:
        return f"<Detection(id={self.id}, is_phishing={self.is_phishing}, confidence={self.confidence_score})>"


class DetectionRule(Base):
    """Custom detection rules for users/organizations."""
    
    __tablename__ = "detection_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)  # Null for global rules
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    
    # Rule conditions (JSON)
    conditions = Column(JSON, nullable=False)
    
    # Rule actions
    action = Column(String(50), nullable=False)  # block, flag, quarantine
    priority = Column(Integer, default=0)
    
    # Rule status
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self) -> str:
        return f"<DetectionRule(id={self.id}, name='{self.name}', action='{self.action}')>"

