"""
Base classes and interfaces for third-party API adapters.

This module defines the common interface and data structures for all external API integrations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import logging

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Standardized threat levels across all adapters."""
    SAFE = "safe"
    LOW = "low" 
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ResourceType(Enum):
    """Types of resources that can be analyzed."""
    URL = "url"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    FILE_HASH = "file_hash"
    EMAIL_ADDRESS = "email_address"


class APIStatus(Enum):
    """Status of external API calls."""
    SUCCESS = "success"
    CACHED = "cached"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    ERROR = "error"
    CIRCUIT_OPEN = "circuit_open"
    QUOTA_EXCEEDED = "quota_exceeded"
    UNAUTHORIZED = "unauthorized"


@dataclass
class ThreatIntelligence:
    """Normalized threat intelligence data from external sources."""
    resource: str
    resource_type: ResourceType
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    source: str
    detected_threats: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    reputation_score: Optional[float] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APIResponse:
    """Standardized response wrapper for all API calls."""
    success: bool
    status: APIStatus
    data: Optional[ThreatIntelligence] = None
    error_message: Optional[str] = None
    response_time: Optional[float] = None
    cached: bool = False
    cache_ttl: Optional[int] = None
    quota_remaining: Optional[int] = None
    retry_after: Optional[int] = None
    raw_response: Optional[Dict[str, Any]] = None


@dataclass
class APIQuota:
    """Quota tracking for API usage."""
    api_name: str
    requests_made: int = 0
    requests_limit: int = 1000
    window_start: datetime = field(default_factory=datetime.utcnow)
    window_duration: timedelta = field(default_factory=lambda: timedelta(hours=24))
    
    @property
    def requests_remaining(self) -> int:
        return max(0, self.requests_limit - self.requests_made)
    
    @property
    def quota_exceeded(self) -> bool:
        return self.requests_made >= self.requests_limit
    
    def reset_if_expired(self) -> bool:
        """Reset quota if window has expired. Returns True if reset occurred."""
        if datetime.utcnow() >= self.window_start + self.window_duration:
            self.requests_made = 0
            self.window_start = datetime.utcnow()
            return True
        return False


class ThreatIntelligenceAdapter(ABC):
    """Abstract base class for all threat intelligence adapters."""
    
    def __init__(self, api_key: str, base_url: str, name: str):
        self.api_key = api_key
        self.base_url = base_url
        self.name = name
        self.quota = APIQuota(api_name=name)
        self.logger = logging.getLogger(f"{__name__}.{name}")
    
    @abstractmethod
    async def analyze_url(self, url: str) -> APIResponse:
        """Analyze a URL for threats."""
        pass
    
    @abstractmethod
    async def analyze_domain(self, domain: str) -> APIResponse:
        """Analyze a domain for threats."""
        pass
    
    @abstractmethod
    async def analyze_ip(self, ip_address: str) -> APIResponse:
        """Analyze an IP address for threats."""
        pass
    
    @abstractmethod
    async def analyze_file_hash(self, file_hash: str) -> APIResponse:
        """Analyze a file hash for threats."""
        pass
    
    @abstractmethod
    def normalize_response(self, raw_response: Dict[str, Any], 
                          resource: str, resource_type: ResourceType) -> ThreatIntelligence:
        """Normalize the API response to standard format."""
        pass
    
    def check_quota(self) -> bool:
        """Check if API quota allows for another request."""
        self.quota.reset_if_expired()
        return not self.quota.quota_exceeded
    
    def consume_quota(self) -> None:
        """Consume one API request from quota."""
        self.quota.requests_made += 1
        self.logger.debug(f"Quota consumed. Remaining: {self.quota.requests_remaining}")
    
    def get_quota_status(self) -> Dict[str, Any]:
        """Get current quota status."""
        self.quota.reset_if_expired()
        return {
            "api_name": self.quota.api_name,
            "requests_made": self.quota.requests_made,
            "requests_remaining": self.quota.requests_remaining,
            "requests_limit": self.quota.requests_limit,
            "quota_exceeded": self.quota.quota_exceeded,
            "window_start": self.quota.window_start.isoformat(),
            "window_duration_hours": self.quota.window_duration.total_seconds() / 3600
        }


class AdapterError(Exception):
    """Base exception for adapter errors."""
    def __init__(self, message: str, status: APIStatus, retry_after: Optional[int] = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class QuotaExceededError(AdapterError):
    """Raised when API quota is exceeded."""
    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message, APIStatus.QUOTA_EXCEEDED, retry_after)


class RateLimitError(AdapterError):
    """Raised when rate limit is hit."""
    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message, APIStatus.RATE_LIMITED, retry_after)


class CircuitOpenError(AdapterError):
    """Raised when circuit breaker is open."""
    def __init__(self, message: str):
        super().__init__(message, APIStatus.CIRCUIT_OPEN)


class TimeoutError(AdapterError):
    """Raised when API call times out."""
    def __init__(self, message: str):
        super().__init__(message, APIStatus.TIMEOUT)


class UnauthorizedError(AdapterError):
    """Raised when API key is invalid or unauthorized."""
    def __init__(self, message: str):
        super().__init__(message, APIStatus.UNAUTHORIZED)


def calculate_threat_score(threat_level: ThreatLevel, confidence: float) -> float:
    """Calculate normalized threat score from level and confidence."""
    level_scores = {
        ThreatLevel.SAFE: 0.0,
        ThreatLevel.LOW: 0.2,
        ThreatLevel.MEDIUM: 0.5,
        ThreatLevel.HIGH: 0.8,
        ThreatLevel.CRITICAL: 1.0,
        ThreatLevel.UNKNOWN: 0.1
    }
    
    base_score = level_scores.get(threat_level, 0.1)
    return min(1.0, base_score * confidence)


def normalize_url(url: str) -> str:
    """Normalize URL for consistent caching and analysis."""
    url = url.strip().lower()
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    
    # Remove trailing slashes and fragments
    if url.endswith('/'):
        url = url[:-1]
    if '#' in url:
        url = url.split('#')[0]
    
    return url


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    from urllib.parse import urlparse
    parsed = urlparse(normalize_url(url))
    return parsed.netloc


def is_valid_ip(ip_address: str) -> bool:
    """Validate if string is a valid IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Validate if string is a valid domain."""
    import re
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(domain_pattern.match(domain))


def is_valid_file_hash(file_hash: str, hash_type: str = "any") -> bool:
    """Validate if string is a valid file hash."""
    hash_lengths = {
        "md5": 32,
        "sha1": 40,
        "sha256": 64,
        "sha512": 128
    }
    
    if hash_type == "any":
        valid_lengths = hash_lengths.values()
    else:
        valid_lengths = [hash_lengths.get(hash_type.lower(), 0)]
    
    return (
        len(file_hash) in valid_lengths and
        all(c in '0123456789abcdefABCDEF' for c in file_hash)
    )