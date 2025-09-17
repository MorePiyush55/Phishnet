"""
Database models for redirect analysis results

Defines SQLAlchemy models for storing redirect chain analysis,
browser results, and cloaking detection data.
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base
from sqlalchemy.sql import func
import uuid



class RedirectAnalysis(Base):
    """Main redirect analysis record"""
    __tablename__ = 'redirect_analyses'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Basic information
    original_url = Column(String(2048), nullable=False, index=True)
    final_destination = Column(String(2048))
    analysis_timestamp = Column(DateTime, default=func.now(), index=True)
    total_execution_time_ms = Column(Integer)
    
    # Redirect chain info
    total_hops = Column(Integer, default=0)
    max_hops_reached = Column(Boolean, default=False)
    
    # Security assessment
    tls_chain_valid = Column(Boolean, default=True)
    mixed_content_detected = Column(Boolean, default=False)
    chain_reputation_score = Column(Float, default=0.0)
    threat_level = Column(String(20), default='low')  # low, medium, high, critical
    
    # Analysis flags
    cloaking_detected = Column(Boolean, default=False)
    partial_analysis = Column(Boolean, default=False)
    
    # JSON fields for complex data
    insecure_hops = Column(JSON)  # List of hop numbers with security issues
    malicious_hops = Column(JSON)  # List of hop numbers with reputation issues
    risk_factors = Column(JSON)  # List of risk factor strings
    recommendations = Column(JSON)  # List of recommendation strings
    analysis_errors = Column(JSON)  # List of error messages
    
    # Storage references
    screenshot_urls = Column(JSON)  # List of screenshot URLs
    log_file_paths = Column(JSON)  # List of log file paths
    
    # Foreign key to threat result if part of larger analysis
    threat_result_id = Column(String(36), index=True)
    
    # Relationships
    redirect_hops = relationship("RedirectHop", back_populates="analysis", cascade="all, delete-orphan")
    browser_results = relationship("BrowserAnalysisRecord", back_populates="analysis", cascade="all, delete-orphan")
    cloaking_analysis = relationship("CloakingAnalysisRecord", back_populates="analysis", uselist=False, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<RedirectAnalysis(id={self.id}, url={self.original_url[:50]}, threat_level={self.threat_level})>"


class RedirectHop(Base):
    """Individual hop in a redirect chain"""
    __tablename__ = 'redirect_hops'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String(36), ForeignKey('redirect_analyses.id'), nullable=False, index=True)
    
    # Hop information
    hop_number = Column(Integer, nullable=False)
    url = Column(String(2048), nullable=False)
    method = Column(String(10), default='GET')
    
    # Response details
    status_code = Column(Integer)
    redirect_type = Column(String(50))  # http_301, javascript, meta_refresh, etc.
    location_header = Column(String(2048))
    response_time_ms = Column(Integer)
    content_length = Column(Integer)
    content_type = Column(String(100))
    server_header = Column(String(200))
    
    # DNS resolution
    resolved_hostname = Column(String(255))
    resolved_ip = Column(String(45))  # IPv6 support
    
    # Reputation scores
    vt_score = Column(Float)
    abuse_score = Column(Float)
    domain_reputation = Column(Float)
    
    # JSON fields
    response_headers = Column(JSON)
    dom_changes = Column(JSON)  # List of DOM change descriptions
    javascript_redirects = Column(JSON)  # List of JS redirect URLs
    loaded_resources = Column(JSON)  # List of loaded resource URLs
    
    # Error handling
    error = Column(Text)
    timestamp = Column(DateTime, default=func.now())
    
    # TLS information (stored as JSON for flexibility)
    tls_info = Column(JSON)
    
    # Relationship
    analysis = relationship("RedirectAnalysis", back_populates="redirect_hops")
    
    def __repr__(self):
        return f"<RedirectHop(hop={self.hop_number}, url={self.url[:50]}, status={self.status_code})>"


class BrowserAnalysisRecord(Base):
    """Browser analysis results for different user agents"""
    __tablename__ = 'browser_analysis_records'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String(36), ForeignKey('redirect_analyses.id'), nullable=False, index=True)
    
    # Browser configuration
    user_agent_used = Column(String(500), nullable=False)
    browser_type = Column(String(50))  # chromium, firefox, webkit
    
    # Results
    final_url = Column(String(2048))
    page_title = Column(String(500))
    dom_content_hash = Column(String(64))  # SHA256 hash
    screenshot_path = Column(String(500))
    execution_time_ms = Column(Integer)
    
    # Analysis results (stored as JSON)
    console_logs = Column(JSON)
    network_requests = Column(JSON)
    javascript_errors = Column(JSON)
    loaded_scripts = Column(JSON)
    forms_detected = Column(JSON)
    
    # Security analysis
    credential_forms_detected = Column(Boolean, default=False)
    suspicious_scripts_count = Column(Integer, default=0)
    external_resources_count = Column(Integer, default=0)
    
    # Error handling
    error = Column(Text)
    timestamp = Column(DateTime, default=func.now())
    
    # Relationship
    analysis = relationship("RedirectAnalysis", back_populates="browser_results")
    
    def __repr__(self):
        return f"<BrowserAnalysisRecord(id={self.id}, user_agent={self.user_agent_used[:30]})>"


class CloakingAnalysisRecord(Base):
    """Cloaking detection analysis results"""
    __tablename__ = 'cloaking_analysis_records'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = Column(String(36), ForeignKey('redirect_analyses.id'), nullable=False, index=True)
    
    # Detection results
    is_cloaking_detected = Column(Boolean, default=False)
    confidence = Column(Float, default=0.0)
    
    # Comparison metrics
    user_agent_response_size = Column(Integer)
    bot_response_size = Column(Integer)
    content_similarity = Column(Float)  # 0.0-1.0
    
    # URL differences
    final_url_user = Column(String(2048))
    final_url_bot = Column(String(2048))
    redirect_count_user = Column(Integer)
    redirect_count_bot = Column(Integer)
    
    # Detection methods and indicators (stored as JSON)
    methods_used = Column(JSON)  # List of detection methods
    cloaking_indicators = Column(JSON)  # List of indicator strings
    suspicious_patterns = Column(JSON)  # List of suspicious pattern strings
    
    # Content differences (stored as JSON)
    title_differences = Column(JSON)
    dom_differences = Column(JSON)
    script_differences = Column(JSON)
    link_differences = Column(JSON)
    
    # Analysis metadata
    timestamp = Column(DateTime, default=func.now())
    
    # Relationship
    analysis = relationship("RedirectAnalysis", back_populates="cloaking_analysis")
    
    def __repr__(self):
        return f"<CloakingAnalysisRecord(id={self.id}, detected={self.is_cloaking_detected}, confidence={self.confidence})>"


class TLSCertificateRecord(Base):
    """TLS certificate information for HTTPS hops"""
    __tablename__ = 'tls_certificates'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hop_id = Column(String(36), ForeignKey('redirect_hops.id'), nullable=False, index=True)
    
    # Certificate details
    subject = Column(String(500))
    issuer = Column(String(500))
    not_before = Column(DateTime)
    not_after = Column(DateTime)
    serial_number = Column(String(100))
    fingerprint_sha256 = Column(String(95))  # SHA256 with colons
    
    # Validation status
    validation_status = Column(String(50))  # valid, invalid, expired, etc.
    hostname_validated = Column(Boolean, default=False)
    chain_trusted = Column(Boolean, default=False)
    
    # SAN domains and validation errors (stored as JSON)
    san_domains = Column(JSON)
    validation_errors = Column(JSON)
    
    # Analysis metadata
    analyzed_at = Column(DateTime, default=func.now())
    
    def __repr__(self):
        return f"<TLSCertificateRecord(id={self.id}, subject={self.subject[:50]}, status={self.validation_status})>"


# Index definitions for performance
from sqlalchemy import Index

# Composite indexes for common queries
Index('idx_redirect_analysis_url_timestamp', RedirectAnalysis.original_url, RedirectAnalysis.analysis_timestamp)
Index('idx_redirect_hop_analysis_hop', RedirectHop.analysis_id, RedirectHop.hop_number)
Index('idx_browser_analysis_agent', BrowserAnalysisRecord.analysis_id, BrowserAnalysisRecord.user_agent_used)

# Indexes for reputation scores
Index('idx_hop_vt_score', RedirectHop.vt_score)
Index('idx_hop_abuse_score', RedirectHop.abuse_score)
Index('idx_analysis_reputation', RedirectAnalysis.chain_reputation_score)

# Indexes for threat levels and detection
Index('idx_analysis_threat_level', RedirectAnalysis.threat_level)
Index('idx_analysis_cloaking', RedirectAnalysis.cloaking_detected)
Index('idx_cloaking_confidence', CloakingAnalysisRecord.confidence)
