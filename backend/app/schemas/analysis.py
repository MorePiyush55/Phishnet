"""Schemas for link analysis, AI results, and threat intelligence."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator


# Link Analysis Schemas
class LinkAnalysisBase(BaseModel):
    """Base schema for link analysis."""
    original_url: str
    final_url: Optional[str] = None
    redirect_count: int = 0
    risk_score: float = Field(ge=0.0, le=1.0)
    status: str = "pending"


class LinkAnalysisCreate(LinkAnalysisBase):
    """Schema for creating link analysis."""
    email_id: int


class LinkAnalysisResponse(LinkAnalysisBase):
    """Schema for link analysis response."""
    id: int
    email_id: int
    original_domain: Optional[str] = None
    final_domain: Optional[str] = None
    redirect_chain: Optional[List[Dict[str, Any]]] = None
    analysis_details: Optional[Dict[str, Any]] = None
    risk_reasons: Optional[List[str]] = None
    has_javascript_redirect: str = "unknown"
    has_meta_redirect: str = "unknown"
    has_timed_redirect: str = "unknown"
    domain_mismatch: str = "unknown"
    has_punycode: str = "unknown"
    is_lookalike: str = "unknown"
    analysis_duration: Optional[float] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class RedirectStep(BaseModel):
    """Schema for individual redirect step."""
    step: int
    url: str
    status_code: Optional[int] = None
    method: str  # http, javascript, meta_refresh, timed_redirect
    headers: Optional[Dict[str, str]] = None
    error: Optional[str] = None
    timestamp: Optional[float] = None


class LinkAnalysisDetail(LinkAnalysisResponse):
    """Detailed link analysis with full redirect chain."""
    redirect_steps: List[RedirectStep] = []


# AI Analysis Schemas
class EmailAIResultsBase(BaseModel):
    """Base schema for AI analysis results."""
    model_name: str = "gemini-pro"
    ai_score: float = Field(ge=0.0, le=1.0)
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    summary: Optional[str] = None
    reasoning: Optional[str] = None


class EmailAIResultsCreate(EmailAIResultsBase):
    """Schema for creating AI analysis results."""
    email_id: int
    labels: Optional[List[str]] = None
    prompt_version: str = "v1.0"


class EmailAIResultsResponse(EmailAIResultsBase):
    """Schema for AI analysis response."""
    id: int
    email_id: int
    labels: Optional[List[str]] = None
    prompt_version: str
    processing_time: Optional[float] = None
    token_usage: Optional[Dict[str, Any]] = None
    model_version: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class AIAnalysisRequest(BaseModel):
    """Schema for requesting AI analysis."""
    subject: str = Field(..., max_length=500)
    sender: str = Field(..., max_length=255)
    content_text: str = Field(..., max_length=50000)
    content_html: Optional[str] = Field(None, max_length=50000)
    link_domains: List[str] = Field(default_factory=list, max_items=50)
    
    @validator('content_text')
    def validate_content_text(cls, v):
        if len(v.strip()) < 10:
            raise ValueError("Content too short for analysis")
        return v


class AIAnalysisResponse(BaseModel):
    """Schema for AI analysis response."""
    is_phishing: bool
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    phishing_type: Optional[str] = None
    reasoning: str
    indicators: List[str] = Field(default_factory=list)
    summary: str
    processing_time: Optional[float] = None


# Threat Intelligence Schemas
class ThreatIntelCacheBase(BaseModel):
    """Base schema for threat intel cache."""
    cache_key: str
    source: str
    ttl_seconds: int


class ThreatIntelCacheResponse(ThreatIntelCacheBase):
    """Schema for threat intel cache response."""
    id: int
    cache_value: Dict[str, Any]
    stored_at: datetime

    class Config:
        from_attributes = True


class EmailIndicatorsBase(BaseModel):
    """Base schema for email indicators."""
    indicator: str = Field(..., max_length=500)
    indicator_type: str  # url, domain, ip, file_hash
    source: str = Field(..., max_length=100)
    reputation_score: Optional[float] = Field(None, ge=0.0, le=1.0)


class EmailIndicatorsCreate(EmailIndicatorsBase):
    """Schema for creating email indicators."""
    email_id: int
    reputation_data: Optional[Dict[str, Any]] = None


class EmailIndicatorsResponse(EmailIndicatorsBase):
    """Schema for email indicators response."""
    id: int
    email_id: int
    reputation_data: Optional[Dict[str, Any]] = None
    first_seen: datetime
    last_updated: Optional[datetime] = None

    class Config:
        from_attributes = True


class ReputationDetails(BaseModel):
    """Schema for detailed reputation information."""
    reputation: float = Field(ge=0.0, le=1.0)
    malicious_votes: Optional[int] = None
    suspicious_votes: Optional[int] = None
    total_engines: Optional[int] = None
    categories: Optional[Dict[str, Any]] = None
    last_analysis_date: Optional[datetime] = None
    additional_info: Optional[Dict[str, Any]] = None


class ThreatIntelResponse(BaseModel):
    """Schema for comprehensive threat intel response."""
    indicator: str
    indicator_type: str
    sources: List[str]
    overall_reputation: float = Field(ge=0.0, le=1.0)
    risk_level: str  # low, medium, high, critical
    details: Dict[str, ReputationDetails]
    last_updated: datetime


# Analysis Summary Schemas
class EmailAnalysisSummary(BaseModel):
    """Schema for complete email analysis summary."""
    email_id: int
    overall_risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: str  # low, medium, high, critical
    analysis_status: str  # pending, analyzing, completed, failed
    
    # Component analysis results
    link_analysis: Optional[List[LinkAnalysisResponse]] = None
    ai_analysis: Optional[EmailAIResultsResponse] = None
    threat_intel: Optional[List[EmailIndicatorsResponse]] = None
    
    # Summary statistics
    total_links: int = 0
    suspicious_links: int = 0
    malicious_indicators: int = 0
    analysis_duration: Optional[float] = None
    
    # Risk factors
    risk_factors: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class BulkAnalysisRequest(BaseModel):
    """Schema for bulk analysis request."""
    email_ids: List[int] = Field(..., min_items=1, max_items=100)
    analysis_types: List[str] = Field(
        default=["links", "ai", "threat_intel"],
        description="Types of analysis to perform"
    )
    priority: str = Field(default="normal", pattern="^(low|normal|high|urgent)$")


class BulkAnalysisResponse(BaseModel):
    """Schema for bulk analysis response."""
    job_id: str
    status: str  # queued, processing, completed, failed
    total_emails: int
    processed_emails: int = 0
    failed_emails: int = 0
    estimated_completion: Optional[datetime] = None
    results: List[EmailAnalysisSummary] = Field(default_factory=list)


# Dashboard/Frontend Schemas
class AnalysisDashboard(BaseModel):
    """Schema for analysis dashboard data."""
    total_emails_analyzed: int
    high_risk_emails: int
    quarantined_emails: int
    false_positives: int
    
    # Recent activity
    recent_analyses: List[EmailAnalysisSummary] = Field(default_factory=list)
    
    # Statistics
    avg_analysis_time: Optional[float] = None
    success_rate: Optional[float] = None
    
    # Top threats
    top_malicious_domains: List[Dict[str, Any]] = Field(default_factory=list)
    top_threat_types: List[Dict[str, Any]] = Field(default_factory=list)


class LinkChainViewer(BaseModel):
    """Schema for link chain visualization."""
    link_id: int
    original_url: str
    final_url: str
    chain_steps: List[RedirectStep]
    risk_assessment: Dict[str, Any]
    visual_data: Dict[str, Any]  # For frontend visualization


class ThreatBadge(BaseModel):
    """Schema for threat indicator badges."""
    indicator: str
    indicator_type: str
    threat_level: str  # safe, suspicious, malicious
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    tooltip: str
    color: str  # For UI styling
    icon: str   # For UI icons
