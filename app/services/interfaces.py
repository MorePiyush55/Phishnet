"""Service interfaces and base classes used by the orchestrator tests.

This file provides lightweight enums and a dataclass shape for AnalysisResult
that the unit tests expect. These implementations are intentionally simple
and focused on test compatibility.
"""


from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
import time


class AnalysisType(Enum):
    # Specific service scans
    VIRUSTOTAL_SCAN = "virustotal_scan"
    URLVOID_SCAN = "urlvoid_scan"
    CUSTOM_SCAN = "custom_scan"

    # Generic analysis types used across the codebase/tests
    URL_SCAN = "url_scan"
    FILE_HASH = "file_hash"
    IP_REPUTATION = "ip_reputation"
    CONTENT_ANALYSIS = "content_analysis"
    URL = "url"
    TEXT = "text"


class ServiceStatus(Enum):
    AVAILABLE = "available"
    RATE_LIMITED = "rate_limited"
    CIRCUIT_OPEN = "circuit_open"
    UNAVAILABLE = "unavailable"


@dataclass
class AnalysisResult:
    # Core fields used by unit tests and service adapters
    service_name: str
    analysis_type: AnalysisType
    target: str
    threat_score: float
    confidence: float
    verdict: str
    explanation: Optional[str]
    indicators: Optional[List[str]]
    raw_response: Optional[Dict[str, Any]]
    timestamp: Any
    execution_time_ms: int = 0
    error: Optional[str] = None
    # Optional fields
    redirect_count: Optional[int] = None
    final_url: Optional[str] = None


@dataclass
class VirusTotalResult:
    vt_score: float
    positives: int
    total_engines: int
    engine_hits: List[str]
    last_seen: Optional[str] = None
    scan_id: Optional[str] = None


@dataclass
class AbuseIPDBResult:
    """AbuseIPDB-specific analysis result."""
    abuse_confidence: float  # normalized 0.0-1.0
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


@dataclass
class ServiceHealth:
    """Health status of an external service."""
    status: ServiceStatus
    last_success: Optional[float] = None
    last_failure: Optional[float] = None
    consecutive_failures: int = 0
    rate_limit_reset: Optional[float] = None
    circuit_breaker_until: Optional[float] = None


class IAnalyzer:
    """Minimal base analyzer used by service clients in tests.

    Provides a lightweight health tracking implementation used by VirusTotalClient
    and other service adapters. This is intentionally minimal to avoid importing
    large dependency chains during test collection.
    """
    def __init__(self, service_name: str):
        self.service_name = service_name
        self._health = ServiceHealth(ServiceStatus.AVAILABLE)

    @property
    def is_available(self) -> bool:
        now = time.time()
        if (self._health.circuit_breaker_until and now < self._health.circuit_breaker_until):
            return False
        if (self._health.rate_limit_reset and now < self._health.rate_limit_reset):
            return False
        return self._health.status == ServiceStatus.AVAILABLE

    def _update_health_success(self):
        self._health.status = ServiceStatus.AVAILABLE
        self._health.last_success = time.time()
        self._health.consecutive_failures = 0
        self._health.circuit_breaker_until = None

    def _update_health_failure(self, error_type: str = "general"):
        now = time.time()
        self._health.last_failure = now
        self._health.consecutive_failures += 1
        if self._health.consecutive_failures >= 3:
            self._health.status = ServiceStatus.CIRCUIT_OPEN
            timeout_minutes = min(self._health.consecutive_failures * 2, 30)
            self._health.circuit_breaker_until = now + (timeout_minutes * 60)

    def _update_rate_limit(self, reset_time: float):
        self._health.status = ServiceStatus.RATE_LIMITED
        self._health.rate_limit_reset = reset_time


class ServiceUnavailableError(Exception):
    pass


class InvalidTargetError(Exception):
    pass


class AnalysisError(Exception):
    pass


class RateLimitError(Exception):
    def __init__(self, reset_time: Optional[float] = None):
        self.reset_time = reset_time
        super().__init__(f"Rate limit exceeded, resets at {reset_time}")


class ThreatVerdict(Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


__all__ = ["AnalysisResult", "AnalysisType", "ThreatVerdict", "IAnalyzer"]
