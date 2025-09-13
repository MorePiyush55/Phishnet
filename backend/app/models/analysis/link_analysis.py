"""Link analysis models for tracking URL redirections and analysis."""

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base


class LinkAnalysis(Base):
    """Link redirection analysis results."""
    
    __tablename__ = "links"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    original_url = Column(Text, nullable=False)
    final_url = Column(Text, nullable=True)
    redirect_chain = Column(JSON, nullable=True)  # List of redirect steps
    analysis_details = Column(JSON, nullable=True)  # Detailed analysis data
    risk_score = Column(Float, default=0.0)
    risk_reasons = Column(JSON, nullable=True)  # List of risk indicators
    status = Column(String(50), default="pending")  # pending, analyzing, completed, failed
    error_message = Column(Text, nullable=True)
    
    # Analysis metadata
    analysis_duration = Column(Float, nullable=True)  # Seconds
    redirect_count = Column(Integer, default=0)
    has_javascript_redirect = Column(String(10), default="unknown")  # yes, no, unknown
    has_meta_redirect = Column(String(10), default="unknown")
    has_timed_redirect = Column(String(10), default="unknown")
    
    # Domain analysis
    original_domain = Column(String(255), nullable=True, index=True)
    final_domain = Column(String(255), nullable=True, index=True)
    domain_mismatch = Column(String(10), default="unknown")
    has_punycode = Column(String(10), default="unknown")
    is_lookalike = Column(String(10), default="unknown")
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    email = relationship("Email", back_populates="link_analyses")


class EmailAIResults(Base):
    """AI analysis results for emails."""
    
    __tablename__ = "email_ai_results"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    model_name = Column(String(100), nullable=False)  # gemini-pro, gpt-4, etc.
    ai_score = Column(Float, nullable=False)  # 0.0 - 1.0
    labels = Column(JSON, nullable=True)  # List of classification labels
    summary = Column(Text, nullable=True)  # AI-generated summary
    reasoning = Column(Text, nullable=True)  # AI reasoning
    confidence = Column(Float, nullable=True)  # Model confidence
    prompt_version = Column(String(50), nullable=False)  # For tracking prompt changes
    
    # Processing metadata
    processing_time = Column(Float, nullable=True)  # Seconds
    token_usage = Column(JSON, nullable=True)  # Token counts
    model_version = Column(String(100), nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    email = relationship("Email", back_populates="ai_results")


class ThreatIntelCache(Base):
    """Cached threat intelligence data."""
    
    __tablename__ = "intel_cache"
    
    id = Column(Integer, primary_key=True, index=True)
    cache_key = Column(String(255), nullable=False, unique=True, index=True)
    cache_value = Column(JSON, nullable=False)
    source = Column(String(100), nullable=False)  # virustotal, abuseipdb, etc.
    ttl_seconds = Column(Integer, nullable=False)
    stored_at = Column(DateTime(timezone=True), server_default=func.now())
    
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        from datetime import datetime, timezone
        return (datetime.now(timezone.utc) - self.stored_at).total_seconds() > self.ttl_seconds


class EmailIndicators(Base):
    """Threat indicators found in emails."""
    
    __tablename__ = "email_indicators"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    indicator = Column(String(500), nullable=False, index=True)  # URL, IP, domain, hash
    indicator_type = Column(String(50), nullable=False)  # url, domain, ip, file_hash
    source = Column(String(100), nullable=False)  # virustotal, abuseipdb, manual
    reputation_score = Column(Float, nullable=True)  # 0.0 (safe) to 1.0 (malicious)
    reputation_data = Column(JSON, nullable=True)  # Raw reputation data
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_updated = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    email = relationship("Email", back_populates="indicators")
