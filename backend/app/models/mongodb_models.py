"""MongoDB document models using Beanie ODM."""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum

from beanie import Document, Indexed
from pydantic import Field, EmailStr
from pymongo import IndexModel, ASCENDING, DESCENDING


class ThreatLevel(str, Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EmailStatus(str, Enum):
    """Email analysis status."""
    PENDING = "pending"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    QUARANTINED = "quarantined"


class User(Document):
    """User document model."""
    
    email: Indexed(EmailStr, unique=True)
    username: Indexed(str, unique=True)
    full_name: Optional[str] = None
    hashed_password: str
    is_active: bool = True
    is_verified: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # OAuth tokens
    gmail_access_token: Optional[str] = None
    gmail_refresh_token: Optional[str] = None
    gmail_token_expires_at: Optional[datetime] = None
    
    class Settings:
        name = "users"
        indexes = [
            IndexModel([("email", ASCENDING)], unique=True),
            IndexModel([("username", ASCENDING)], unique=True),
            IndexModel([("created_at", DESCENDING)]),
        ]


class EmailAnalysis(Document):
    """Email analysis document model."""
    
    # Email identifiers
    user_id: str = Field(description="User who owns this email")
    gmail_message_id: str = Field(description="Gmail message ID")
    subject: str
    sender: EmailStr
    recipient: EmailStr
    received_at: datetime
    
    # Analysis results
    status: EmailStatus = EmailStatus.PENDING
    threat_level: Optional[ThreatLevel] = None
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    
    # Analysis details
    analysis_results: Dict[str, Any] = Field(default_factory=dict)
    detected_threats: List[str] = Field(default_factory=list)
    suspicious_links: List[str] = Field(default_factory=list)
    attachment_analysis: Dict[str, Any] = Field(default_factory=dict)
    
    # Processing metadata
    analyzed_at: Optional[datetime] = None
    analysis_duration_ms: Optional[int] = None
    analyzer_version: str = "1.0.0"
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Settings:
        name = "email_analyses"
        indexes = [
            IndexModel([("user_id", ASCENDING), ("created_at", DESCENDING)]),
            IndexModel([("gmail_message_id", ASCENDING)], unique=True),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("threat_level", ASCENDING)]),
            IndexModel([("sender", ASCENDING)]),
            IndexModel([("received_at", DESCENDING)]),
        ]


class ThreatIntelligence(Document):
    """Threat intelligence document model."""
    
    # Threat identifiers
    indicator: Indexed(str)  # URL, IP, domain, email, etc.
    indicator_type: str  # "url", "ip", "domain", "email", "hash"
    threat_type: str  # "phishing", "malware", "spam", etc.
    
    # Threat details
    threat_level: ThreatLevel
    confidence_score: float = Field(ge=0.0, le=1.0)
    description: Optional[str] = None
    
    # Source information
    source: str  # "virustotal", "abuseipdb", "manual", etc.
    source_reference: Optional[str] = None
    
    # Timestamps
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    
    # Metadata
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Settings:
        name = "threat_intelligence"
        indexes = [
            IndexModel([("indicator", ASCENDING)], unique=True),
            IndexModel([("indicator_type", ASCENDING)]),
            IndexModel([("threat_type", ASCENDING)]),
            IndexModel([("threat_level", ASCENDING)]),
            IndexModel([("source", ASCENDING)]),
            IndexModel([("last_seen", DESCENDING)]),
            IndexModel([("expires_at", ASCENDING)]),
        ]


class AnalysisJob(Document):
    """Background analysis job tracking."""
    
    # Job identifiers
    job_id: Indexed(str, unique=True)
    user_id: str
    email_id: Optional[str] = None  # Reference to EmailAnalysis
    
    # Job details
    job_type: str  # "email_analysis", "threat_scan", etc.
    status: str = "pending"  # "pending", "running", "completed", "failed"
    priority: int = 5  # 1-10, higher is more priority
    
    # Execution details
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    
    # Metadata
    parameters: Dict[str, Any] = Field(default_factory=dict)
    progress: int = 0  # 0-100
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Settings:
        name = "analysis_jobs"
        indexes = [
            IndexModel([("job_id", ASCENDING)], unique=True),
            IndexModel([("user_id", ASCENDING), ("created_at", DESCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("priority", DESCENDING), ("created_at", ASCENDING)]),
            IndexModel([("job_type", ASCENDING)]),
        ]


class AuditLog(Document):
    """System audit log."""
    
    # Event details
    event_type: str  # "user_login", "email_analysis", "threat_detected", etc.
    user_id: Optional[str] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    
    # Event data
    action: str
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Request details
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    
    # Timestamp
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Settings:
        name = "audit_logs"
        indexes = [
            IndexModel([("timestamp", DESCENDING)]),
            IndexModel([("event_type", ASCENDING)]),
            IndexModel([("user_id", ASCENDING), ("timestamp", DESCENDING)]),
            IndexModel([("resource_type", ASCENDING), ("resource_id", ASCENDING)]),
        ]


class Email(Document):
    """Email document for analytics dashboard."""
    
    user_id: int
    subject: str
    sender: str
    recipients: str  # Comma-separated
    content_hash: str
    content: str
    content_type: str = "text/html"
    size_bytes: int
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Settings:
        name = "emails"
        indexes = [
            IndexModel([("user_id", ASCENDING)]),
            IndexModel([("received_at", DESCENDING)]),
            IndexModel([("content_hash", ASCENDING)]),
        ]


class Detection(Document):
    """Threat detection results for analytics dashboard."""
    
    user_id: int
    email_id: str
    is_phishing: bool
    confidence_score: float
    risk_level: str
    detection_model_version: str  # renamed to avoid conflict
    detection_model_type: str     # renamed to avoid conflict
    features: Optional[Dict[str, Any]] = None
    risk_factors: Optional[List[str]] = None
    processing_time_ms: int
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    model_config = {"protected_namespaces": ()}  # Allow model_ fields if needed
    
    class Settings:
        name = "detections"
        indexes = [
            IndexModel([("user_id", ASCENDING)]),
            IndexModel([("created_at", DESCENDING)]),
            IndexModel([("is_phishing", ASCENDING)]),
            IndexModel([("risk_level", ASCENDING)]),
        ]


class Incident(Document):
    """Security incident tracking for analytics dashboard."""
    
    title: str
    description: str
    incident_type: str
    severity: str  # low, medium, high, critical
    status: str  # open, investigating, resolved, closed
    assigned_to: Optional[str] = None
    escalated: bool = False
    
    # Detection details
    detection_id: Optional[str] = None
    threat_indicators: List[str] = Field(default_factory=list)
    
    # Timeline
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    first_response_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Settings:
        name = "incidents"
        indexes = [
            IndexModel([("created_at", DESCENDING)]),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("severity", ASCENDING)]),
            IndexModel([("assigned_to", ASCENDING)]),
        ]


class WorkflowExecution(Document):
    """Workflow execution tracking for performance analytics."""
    
    workflow_type: str
    workflow_id: str
    status: str  # pending, running, completed, failed
    execution_time_ms: Optional[int] = None
    
    # Timestamps
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    
    # Details
    input_data: Dict[str, Any] = Field(default_factory=dict)
    output_data: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    
    class Settings:
        name = "workflow_executions"
        indexes = [
            IndexModel([("started_at", DESCENDING)]),
            IndexModel([("workflow_type", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
        ]


class FileAnalysis(Document):
    """File analysis results for security dashboard."""
    
    file_hash: str
    file_name: str
    file_size: int
    file_type: str
    analysis_result: str  # clean, suspicious, malicious
    confidence_score: float
    analysis_engine: str
    
    # Metadata
    analysis_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Settings:
        name = "file_analyses"
        indexes = [
            IndexModel([("file_hash", ASCENDING)]),
            IndexModel([("analysis_date", DESCENDING)]),
            IndexModel([("analysis_result", ASCENDING)]),
        ]


# List of all document models for Beanie initialization
DOCUMENT_MODELS = [
    User,
    EmailAnalysis,
    Email,
    Detection,
    Incident,
    WorkflowExecution,
    FileAnalysis,
    ThreatIntelligence,
    AnalysisJob,
    AuditLog,
]