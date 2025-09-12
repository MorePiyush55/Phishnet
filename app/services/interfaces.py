"""
Service interfaces and base classes for external API adapters.
Provides unified contracts for threat analysis services.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass
from enum import Enum
import time


class AnalysisType(Enum):
    """Types of analysis that can be performed."""
    URL_SCAN = "url_scan"
    IP_REPUTATION = "ip_reputation"
    TEXT_ANALYSIS = "text_analysis"
    FILE_HASH = "file_hash"


class ServiceStatus(Enum):
    """Status of external service availability."""
    AVAILABLE = "available"
    RATE_LIMITED = "rate_limited"
    CIRCUIT_OPEN = "circuit_open"
    UNAVAILABLE = "unavailable"


@dataclass
class AnalysisResult:
    """Normalized result from any analysis service."""
    
    # Core fields (always present)
    service_name: str
    analysis_type: AnalysisType
    target: str  # URL, IP, text hash, etc.
    
    # Scoring (0.0 to 1.0, where 1.0 = most malicious)
    threat_score: float
    confidence: float  # 0.0 to 1.0
    
    # Service-specific data
    raw_response: Dict[str, Any]
    
    # Metadata
    timestamp: float
    execution_time_ms: int
    
    # Optional fields
    verdict: Optional[str] = None
    explanation: Optional[str] = None
    indicators: Optional[List[str]] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        """Validate scoring ranges."""
        if not 0.0 <= self.threat_score <= 1.0:
            raise ValueError(f"threat_score must be 0.0-1.0, got {self.threat_score}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be 0.0-1.0, got {self.confidence}")


@dataclass
class ServiceHealth:
    """Health status of an external service."""
    status: ServiceStatus
    last_success: Optional[float] = None
    last_failure: Optional[float] = None
    consecutive_failures: int = 0
    rate_limit_reset: Optional[float] = None
    circuit_breaker_until: Optional[float] = None


class IAnalyzer(ABC):
    """
    Interface for all external analysis services.
    Provides unified contract and error handling.
    """
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self._health = ServiceHealth(ServiceStatus.AVAILABLE)
    
    @abstractmethod
    async def analyze(self, target: str, analysis_type: AnalysisType) -> AnalysisResult:
        """
        Perform analysis on target (URL, IP, text, etc.).
        
        Args:
            target: The item to analyze (URL, IP address, text content, etc.)
            analysis_type: Type of analysis to perform
            
        Returns:
            AnalysisResult with normalized scoring and metadata
            
        Raises:
            ServiceUnavailableError: When service is down or rate limited
            InvalidTargetError: When target format is invalid
            AnalysisError: For other analysis failures
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> ServiceHealth:
        """Check service health and update internal status."""
        pass
    
    @property
    def is_available(self) -> bool:
        """Check if service is currently available for requests."""
        now = time.time()
        
        # Check circuit breaker
        if (self._health.circuit_breaker_until and 
            now < self._health.circuit_breaker_until):
            return False
            
        # Check rate limits
        if (self._health.rate_limit_reset and 
            now < self._health.rate_limit_reset):
            return False
            
        return self._health.status in [ServiceStatus.AVAILABLE]
    
    def _update_health_success(self):
        """Update health status after successful operation."""
        self._health.status = ServiceStatus.AVAILABLE
        self._health.last_success = time.time()
        self._health.consecutive_failures = 0
        self._health.circuit_breaker_until = None
    
    def _update_health_failure(self, error_type: str = "general"):
        """Update health status after failed operation."""
        now = time.time()
        self._health.last_failure = now
        self._health.consecutive_failures += 1
        
        # Implement circuit breaker (open after 3 consecutive failures)
        if self._health.consecutive_failures >= 3:
            self._health.status = ServiceStatus.CIRCUIT_OPEN
            # Circuit breaker timeout increases with failures
            timeout_minutes = min(self._health.consecutive_failures * 2, 30)
            self._health.circuit_breaker_until = now + (timeout_minutes * 60)
    
    def _update_rate_limit(self, reset_time: float):
        """Update rate limit status."""
        self._health.status = ServiceStatus.RATE_LIMITED
        self._health.rate_limit_reset = reset_time


class ServiceUnavailableError(Exception):
    """Raised when external service is unavailable."""
    pass


class InvalidTargetError(Exception):
    """Raised when analysis target format is invalid."""
    pass


class AnalysisError(Exception):
    """Raised for general analysis failures."""
    pass


class RateLimitError(Exception):
    """Raised when rate limit is exceeded."""
    def __init__(self, reset_time: Optional[float] = None):
        self.reset_time = reset_time
        super().__init__(f"Rate limit exceeded, resets at {reset_time}")


# Service-specific result schemas for type safety
@dataclass
class VirusTotalResult:
    """VirusTotal-specific analysis result."""
    vt_score: float  # 0.0 to 1.0
    positives: int
    total_engines: int
    engine_hits: List[str]
    last_seen: Optional[str] = None
    scan_id: Optional[str] = None


@dataclass
class AbuseIPDBResult:
    """AbuseIPDB-specific analysis result."""
    abuse_confidence: float  # 0-100, normalized to 0.0-1.0
    report_count: int
    last_reported: Optional[str] = None
    country_code: Optional[str] = None
    usage_type: Optional[str] = None


@dataclass
class GeminiResult:
    """Gemini LLM-specific analysis result."""
    llm_score: float  # 0.0 to 1.0
    verdict: str
    explanation_snippets: List[str]
    confidence_reasoning: Optional[str] = None
    detected_techniques: Optional[List[str]] = None
