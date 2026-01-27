"""
Abstract Base Classes for Email Processing Modes
=================================================
Defines the interfaces that all processing modes must implement.
This ensures consistent behavior and enables mode-agnostic code.

Design Principles:
- Each mode must implement EmailFetcher for retrieving emails
- Each mode must implement ModeOrchestrator for processing pipeline
- Shared analysis logic lives in app.core.analysis
- Mode-specific logic lives in the respective mode package
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, Optional, List


class ModeType(str, Enum):
    """
    Supported operating modes for PhishNet.
    
    IMAP_BULK: Mode 1 - Users forward emails to central inbox for automatic analysis
    GMAIL_ONDEMAND: Mode 2 - Users click to check specific emails via Gmail API
    """
    IMAP_BULK = "imap_bulk"
    GMAIL_ONDEMAND = "gmail_ondemand"


class AnalysisStatus(str, Enum):
    """Status of an analysis request."""
    PENDING = "pending"
    FETCHING = "fetching"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"  # For deduplicated emails


class Verdict(str, Enum):
    """Analysis verdict categories."""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


@dataclass
class EmailMetadata:
    """
    Standardized email metadata used across all modes.
    Contains only the essential fields for analysis.
    """
    message_id: str
    subject: str
    sender: str
    recipients: List[str]
    date: Optional[datetime] = None
    size_bytes: Optional[int] = None
    has_attachments: bool = False
    attachment_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "subject": self.subject,
            "sender": self.sender,
            "recipients": self.recipients,
            "date": self.date.isoformat() if self.date else None,
            "size_bytes": self.size_bytes,
            "has_attachments": self.has_attachments,
            "attachment_count": self.attachment_count,
        }


@dataclass
class AnalysisRequest:
    """
    Generic analysis request that works for both modes.
    
    This is the input to any mode's orchestrator.
    """
    request_id: str
    mode: ModeType
    email_identifier: str  # UID for IMAP, Message ID for Gmail
    
    # Optional context
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    access_token: Optional[str] = None  # For Gmail mode
    store_consent: bool = True  # Whether to persist results
    
    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "mode": self.mode.value,
            "email_identifier": self.email_identifier,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "store_consent": self.store_consent,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class AnalysisResult:
    """
    Generic analysis result that works for both modes.
    
    This is the output from any mode's orchestrator.
    """
    request_id: str
    mode: ModeType
    status: AnalysisStatus
    
    # Verdict
    verdict: Verdict = Verdict.UNKNOWN
    score: float = 0.0  # 0-100 threat score
    confidence: float = 0.0  # 0-1 confidence level
    
    # Email metadata
    email_metadata: Optional[EmailMetadata] = None
    
    # Detailed analysis results
    details: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # AI interpretation (if available)
    ai_summary: Optional[str] = None
    ai_explanation: Optional[str] = None
    
    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    
    # Error tracking
    error: Optional[str] = None
    error_stage: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "mode": self.mode.value,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "score": self.score,
            "confidence": self.confidence,
            "email_metadata": self.email_metadata.to_dict() if self.email_metadata else None,
            "details": self.details,
            "indicators": self.indicators,
            "recommendations": self.recommendations,
            "ai_summary": self.ai_summary,
            "ai_explanation": self.ai_explanation,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "error_stage": self.error_stage,
        }
    
    @property
    def is_success(self) -> bool:
        return self.status == AnalysisStatus.COMPLETED
    
    @property
    def is_threat(self) -> bool:
        return self.verdict in (Verdict.SUSPICIOUS, Verdict.PHISHING, Verdict.MALICIOUS)


@dataclass
class FetchedEmail:
    """
    Standardized email content returned by EmailFetcher.
    Contains all data needed for analysis.
    """
    identifier: str  # UID or Message ID
    metadata: EmailMetadata
    
    # Content
    raw_email: bytes  # Original raw email
    body_text: str = ""
    body_html: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Attachments
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    
    # For forwarded emails (Mode 1)
    is_forwarded: bool = False
    original_email: Optional[bytes] = None  # Extracted .eml attachment
    forwarded_by: Optional[str] = None


class EmailFetcher(ABC):
    """
    Abstract interface for fetching emails from any source.
    
    Each mode implements this to retrieve emails from their respective source:
    - IMAP mode: Fetches from IMAP server
    - Gmail mode: Fetches via Gmail API
    """
    
    @property
    @abstractmethod
    def mode(self) -> ModeType:
        """Return the mode type this fetcher supports."""
        pass
    
    @abstractmethod
    async def fetch_email(self, identifier: str, **kwargs) -> Optional[FetchedEmail]:
        """
        Fetch email content by identifier.
        
        Args:
            identifier: Email identifier (UID for IMAP, Message ID for Gmail)
            **kwargs: Mode-specific options (e.g., access_token for Gmail)
            
        Returns:
            FetchedEmail with content and metadata, or None if not found
        """
        pass
    
    @abstractmethod
    async def list_pending(self, limit: int = 50, **kwargs) -> List[Dict[str, Any]]:
        """
        List emails pending analysis.
        
        For IMAP mode: Returns recent/unread emails in inbox
        For Gmail mode: May raise NotImplementedError (user-driven)
        
        Args:
            limit: Maximum number of emails to return
            **kwargs: Mode-specific options
            
        Returns:
            List of email metadata dicts
        """
        pass
    
    @abstractmethod
    async def mark_processed(self, identifier: str, **kwargs) -> bool:
        """
        Mark email as processed/analyzed.
        
        For IMAP mode: May mark as read or move to folder
        For Gmail mode: May be no-op (no server-side state change)
        
        Args:
            identifier: Email identifier
            **kwargs: Mode-specific options
            
        Returns:
            True if successful
        """
        pass
    
    async def test_connection(self) -> bool:
        """
        Test connection to the email source.
        
        Returns:
            True if connection is healthy
        """
        return True  # Default implementation


class ModeOrchestrator(ABC):
    """
    Abstract orchestrator interface for any processing mode.
    
    The orchestrator coordinates the complete analysis pipeline:
    1. Receive request
    2. Fetch email
    3. Run analysis
    4. Apply policies (if applicable)
    5. Store results (if consented)
    6. Send notifications (if applicable)
    7. Return result
    """
    
    @property
    @abstractmethod
    def mode(self) -> ModeType:
        """Return the mode type this orchestrator handles."""
        pass
    
    @abstractmethod
    async def process_email(self, request: AnalysisRequest) -> AnalysisResult:
        """
        Process a single email through the analysis pipeline.
        
        This is the main entry point for email analysis.
        
        Args:
            request: AnalysisRequest with email identifier and options
            
        Returns:
            AnalysisResult with verdict and details
        """
        pass
    
    @abstractmethod
    async def start(self) -> None:
        """
        Start the orchestrator.
        
        For IMAP mode: Start background polling
        For Gmail mode: Initialize services (may be no-op)
        """
        pass
    
    @abstractmethod
    async def stop(self) -> None:
        """
        Stop the orchestrator gracefully.
        
        Should wait for in-flight requests to complete.
        """
        pass
    
    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """
        Get current status of the orchestrator.
        
        Returns:
            Dict with status information (running, job counts, metrics, etc.)
        """
        pass
    
    def is_running(self) -> bool:
        """Check if orchestrator is running."""
        status = self.get_status()
        return status.get("running", False)


class AnalysisEngine(ABC):
    """
    Abstract interface for the core analysis engine.
    
    This is implemented in app.core.analysis and used by all modes.
    The engine is mode-agnostic - it only cares about email content.
    """
    
    @abstractmethod
    def analyze(self, email: FetchedEmail) -> Dict[str, Any]:
        """
        Analyze email content for threats.
        
        Args:
            email: FetchedEmail with content to analyze
            
        Returns:
            Dict with analysis results (scores, indicators, etc.)
        """
        pass
    
    @abstractmethod
    def get_verdict(self, analysis: Dict[str, Any]) -> Verdict:
        """
        Determine verdict from analysis results.
        
        Args:
            analysis: Analysis results from analyze()
            
        Returns:
            Verdict enum value
        """
        pass
