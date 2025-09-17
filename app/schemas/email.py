"""Email schemas for email analysis requests and responses."""

from datetime import datetime
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field, EmailStr, validator

from app.models.core.email import EmailStatus
from src.common.constants import ThreatLevel


class EmailRequest(BaseModel):
    """Schema for email analysis request."""
    content: str = Field(..., min_length=1, max_length=1000000)
    subject: Optional[str] = Field(None, max_length=500)
    sender: Optional[str] = Field(None, max_length=255)
    recipients: Optional[List[str]] = Field(None, max_items=100)
    content_type: str = Field(default="text/plain", max_length=50)


class EmailFileRequest(BaseModel):
    """Schema for email file upload request."""
    file_format: str = Field(..., pattern="^(eml|msg|txt)$")
    file_size: int = Field(..., gt=0, le=10485760)  # 10MB max


class EmailResponse(BaseModel):
    """Email response schema for list view."""
    id: int
    sender: str
    subject: str
    received_at: datetime
    status: EmailStatus
    score: Optional[float]
    is_phishing: bool
    threat_level: Optional[ThreatLevel]
    created_at: datetime

    class Config:
        orm_mode = True


class EmailDetailResponse(BaseModel):
    """Detailed email response schema."""
    id: int
    sender: str
    recipients: str  # JSON string
    subject: str
    received_at: datetime
    status: EmailStatus
    score: Optional[float]
    size_bytes: int
    sanitized_html: Optional[str]
    raw_text: Optional[str]
    created_at: datetime
    analyzed_at: Optional[datetime]
    
    # Detection fields
    is_phishing: Optional[bool] = False
    threat_level: Optional[ThreatLevel]
    confidence_score: Optional[float]
    indicators: Optional[str]  # JSON string
    analysis_metadata: Optional[str]  # JSON string

    class Config:
        orm_mode = True


class EmailListResponse(BaseModel):
    """Email list response with pagination."""
    emails: List[EmailResponse]
    total: int
    skip: int
    limit: int


class EmailFilterParams(BaseModel):
    """Email filtering parameters."""
    status: Optional[EmailStatus] = None
    threat_level: Optional[ThreatLevel] = None
    sender: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    phishing_only: bool = False


class EmailAnalysisRequest(BaseModel):
    """Request schema for email analysis."""
    content: str
    subject: Optional[str] = ""
    sender: Optional[str] = ""
    recipients: Optional[List[str]] = []

    @validator('content')
    def content_must_not_be_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Content cannot be empty')
        return v.strip()


class EmailAnalysisResponse(BaseModel):
    """Response schema for email analysis."""
    email_id: int
    is_phishing: bool
    confidence_score: float
    threat_level: ThreatLevel
    indicators: List[str]
    analysis_time: float
    timestamp: datetime


class GmailConnectionResponse(BaseModel):
    """Gmail connection response."""
    auth_url: str
    expires_in: int = 3600


class GmailScanResponse(BaseModel):
    """Gmail scan response."""
    scanned_count: int
    new_emails: int
    phishing_detected: int
    scan_time: float
    timestamp: datetime


class EmailAnalysis(BaseModel):
    """Schema for email analysis results."""
    email_id: int
    subject: Optional[str]
    sender: str
    recipients: List[str]
    content_hash: str
    size_bytes: int
    received_at: datetime
    
    class Config:
        from_attributes = True


class DetectionResult(BaseModel):
    """Schema for phishing detection result."""
    detection_id: int
    is_phishing: bool
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str = Field(..., pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    
    # Model information
    model_version: str
    model_type: str = Field(..., pattern="^(ensemble|neural|federated)$")
    
    # Analysis details
    features: Optional[Dict[str, Any]] = None
    risk_factors: Optional[List[str]] = None
    
    # Performance
    processing_time_ms: int
    
    # Timestamps
    created_at: datetime
    
    class Config:
        from_attributes = True


class EmailAnalysisResponse(BaseModel):
    """Schema for complete email analysis response."""
    email: EmailAnalysis
    detection: DetectionResult
    recommendations: List[str] = Field(default_factory=list)
    threat_indicators: Dict[str, Any] = Field(default_factory=dict)


class EmailAttachment(BaseModel):
    """Schema for email attachment."""
    filename: str
    content_type: str
    size_bytes: int
    file_hash: str
    is_suspicious: bool
    
    class Config:
        from_attributes = True


class EmailListResponse(BaseModel):
    """Schema for email list response."""
    emails: List[EmailAnalysis]
    total: int
    page: int
    size: int
    has_next: bool
    has_prev: bool


class DetectionListResponse(BaseModel):
    """Schema for detection list response."""
    detections: List[DetectionResult]
    total: int
    page: int
    size: int
    has_next: bool
    has_prev: bool


class EmailCreate(BaseModel):
    """Minimal EmailCreate schema expected by some tests."""
    sender: str
    subject: str
    content: str

    class Config:
        orm_mode = True

