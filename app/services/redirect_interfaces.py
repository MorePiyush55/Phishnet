"""
Redirect Analyzer Interface and Data Structures

Defines the interface for redirect tracing and cloaking detection services,
along with standardized data structures for redirect chain analysis.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import time


class RedirectType(Enum):
    """Types of redirects detected during analysis"""
    HTTP_301 = "http_301"
    HTTP_302 = "http_302"
    HTTP_303 = "http_303"
    HTTP_307 = "http_307"
    HTTP_308 = "http_308"
    META_REFRESH = "meta_refresh"
    JAVASCRIPT = "javascript"
    LOCATION_HREF = "location_href"
    WINDOW_OPEN = "window_open"
    IFRAME = "iframe"
    FORM_SUBMIT = "form_submit"


class CloakingMethod(Enum):
    """Methods used for cloaking detection"""
    USER_AGENT_SWITCHING = "user_agent_switching"
    CONTENT_FINGERPRINTING = "content_fingerprinting"
    DOM_COMPARISON = "dom_comparison"
    RESPONSE_TIME_ANALYSIS = "response_time_analysis"
    GEOLOCATION_BASED = "geolocation_based"
    IP_BASED = "ip_based"


class TLSValidationStatus(Enum):
    """TLS certificate validation results"""
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    SELF_SIGNED = "self_signed"
    UNTRUSTED_CA = "untrusted_ca"
    HOSTNAME_MISMATCH = "hostname_mismatch"
    NOT_HTTPS = "not_https"
    UNKNOWN = "unknown"


@dataclass
class TLSCertificateInfo:
    """TLS certificate information for HTTPS hops"""
    subject: Optional[str] = None
    issuer: Optional[str] = None
    san_domains: List[str] = field(default_factory=list)
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    validation_status: TLSValidationStatus = TLSValidationStatus.UNKNOWN
    validation_errors: List[str] = field(default_factory=list)


@dataclass
class RedirectHop:
    """Information about a single redirect hop in the chain"""
    hop_number: int
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    redirect_type: Optional[RedirectType] = None
    location_header: Optional[str] = None
    resolved_hostname: Optional[str] = None
    resolved_ip: Optional[str] = None
    response_time_ms: Optional[int] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    server_header: Optional[str] = None
    tls_info: Optional[TLSCertificateInfo] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    
    # Reputation analysis
    vt_score: Optional[float] = None
    abuse_score: Optional[float] = None
    domain_reputation: Optional[float] = None
    
    # Browser-specific data
    dom_changes: Optional[List[str]] = None
    javascript_redirects: Optional[List[str]] = None
    loaded_resources: Optional[List[str]] = None


@dataclass
class CloakingDetection:
    """Cloaking analysis results comparing different request types"""
    is_cloaking_detected: bool = False
    confidence: float = 0.0
    methods_used: List[CloakingMethod] = field(default_factory=list)
    
    # User agent comparison
    user_agent_response_size: Optional[int] = None
    bot_response_size: Optional[int] = None
    content_similarity: Optional[float] = None  # 0.0-1.0
    
    # Content analysis
    title_differences: Optional[List[str]] = None
    dom_differences: Optional[List[str]] = None
    script_differences: Optional[List[str]] = None
    link_differences: Optional[List[str]] = None
    
    # Behavior differences
    final_url_user: Optional[str] = None
    final_url_bot: Optional[str] = None
    redirect_count_user: Optional[int] = None
    redirect_count_bot: Optional[int] = None
    
    # Evidence
    cloaking_indicators: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)


@dataclass
class BrowserAnalysisResult:
    """Results from headless browser analysis"""
    user_agent_used: str
    final_url: str
    page_title: Optional[str] = None
    dom_content_hash: Optional[str] = None
    screenshot_path: Optional[str] = None
    console_logs: List[str] = field(default_factory=list)
    network_requests: List[Dict[str, Any]] = field(default_factory=list)
    javascript_errors: List[str] = field(default_factory=list)
    loaded_scripts: List[str] = field(default_factory=list)
    forms_detected: List[Dict[str, Any]] = field(default_factory=list)
    execution_time_ms: int = 0
    error: Optional[str] = None


@dataclass
class RedirectAnalysisResult:
    """Complete redirect analysis result"""
    # Basic information
    original_url: str
    final_destination: str
    analysis_timestamp: float = field(default_factory=time.time)
    total_execution_time_ms: int = 0
    
    # Redirect chain
    redirect_chain: List[RedirectHop] = field(default_factory=list)
    total_hops: int = 0
    max_hops_reached: bool = False
    
    # Security analysis
    tls_chain_valid: bool = True
    insecure_hops: List[int] = field(default_factory=list)  # Hop numbers with security issues
    mixed_content_detected: bool = False
    
    # Cloaking detection
    cloaking_analysis: Optional[CloakingDetection] = None
    
    # Browser analysis results
    user_browser_result: Optional[BrowserAnalysisResult] = None
    bot_browser_result: Optional[BrowserAnalysisResult] = None
    
    # Reputation aggregation
    chain_reputation_score: float = 0.0  # Weighted average across all hops
    highest_threat_hop: Optional[int] = None
    malicious_hops: List[int] = field(default_factory=list)
    
    # Overall assessment
    threat_level: str = "low"  # low, medium, high, critical
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Error handling
    analysis_errors: List[str] = field(default_factory=list)
    partial_analysis: bool = False
    
    # Storage references
    screenshot_urls: List[str] = field(default_factory=list)
    log_file_paths: List[str] = field(default_factory=list)


class IRedirectAnalyzer(ABC):
    """Interface for redirect analysis services"""
    
    @abstractmethod
    async def analyze_redirects(
        self,
        url: str,
        max_hops: int = 10,
        timeout_seconds: int = 30,
        include_browser_analysis: bool = True,
        include_cloaking_detection: bool = True,
        include_reputation_checks: bool = True
    ) -> RedirectAnalysisResult:
        """
        Analyze redirect chain for a given URL
        
        Args:
            url: The URL to analyze
            max_hops: Maximum number of redirects to follow
            timeout_seconds: Timeout for the entire analysis
            include_browser_analysis: Whether to run headless browser analysis
            include_cloaking_detection: Whether to perform cloaking detection
            include_reputation_checks: Whether to check reputation for each hop
            
        Returns:
            Complete redirect analysis result
        """
        pass
    
    @abstractmethod
    async def trace_http_redirects(
        self,
        url: str,
        max_hops: int = 10,
        timeout_seconds: int = 15
    ) -> List[RedirectHop]:
        """
        Trace HTTP redirects synchronously without browser
        
        Args:
            url: The URL to trace
            max_hops: Maximum redirects to follow
            timeout_seconds: Request timeout
            
        Returns:
            List of redirect hops
        """
        pass
    
    @abstractmethod
    async def analyze_with_browser(
        self,
        url: str,
        user_agents: List[str],
        timeout_seconds: int = 30,
        take_screenshots: bool = True
    ) -> List[BrowserAnalysisResult]:
        """
        Analyze URL with headless browser using different user agents
        
        Args:
            url: The URL to analyze
            user_agents: List of user agents to test
            timeout_seconds: Browser timeout
            take_screenshots: Whether to capture screenshots
            
        Returns:
            List of browser analysis results (one per user agent)
        """
        pass
    
    @abstractmethod
    async def detect_cloaking(
        self,
        url: str,
        user_browser_result: BrowserAnalysisResult,
        bot_browser_result: BrowserAnalysisResult
    ) -> CloakingDetection:
        """
        Compare browser results to detect cloaking
        
        Args:
            url: The analyzed URL
            user_browser_result: Result from user-agent browser
            bot_browser_result: Result from bot user-agent browser
            
        Returns:
            Cloaking detection analysis
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """
        Check the health of the redirect analyzer service
        
        Returns:
            Health status information
        """
        pass


class IRedirectRepository(ABC):
    """Interface for storing redirect analysis results"""
    
    @abstractmethod
    async def save_redirect_analysis(
        self,
        analysis_result: RedirectAnalysisResult,
        threat_result_id: Optional[str] = None
    ) -> str:
        """
        Save redirect analysis to database
        
        Args:
            analysis_result: The analysis result to save
            threat_result_id: Optional ID to link to existing threat result
            
        Returns:
            The ID of the saved analysis
        """
        pass
    
    @abstractmethod
    async def get_redirect_analysis(self, analysis_id: str) -> Optional[RedirectAnalysisResult]:
        """
        Retrieve redirect analysis by ID
        
        Args:
            analysis_id: The analysis ID
            
        Returns:
            The redirect analysis result if found
        """
        pass
    
    @abstractmethod
    async def get_analyses_for_url(
        self,
        url: str,
        limit: int = 10
    ) -> List[RedirectAnalysisResult]:
        """
        Get recent analyses for a specific URL
        
        Args:
            url: The URL to search for
            limit: Maximum number of results
            
        Returns:
            List of recent analyses for the URL
        """
        pass


# Common user agents for cloaking detection
COMMON_USER_AGENTS = {
    "chrome_user": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "firefox_user": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "safari_user": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/17.0 Safari/537.36",
    "chrome_bot": "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.70 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "generic_bot": "Mozilla/5.0 (compatible; phishnet-analyzer/1.0; +https://phishnet.com/bot)",
    "curl_bot": "curl/7.68.0"
}

# TLS cipher suites and protocols to validate
SECURE_TLS_PROTOCOLS = ["TLSv1.2", "TLSv1.3"]
INSECURE_TLS_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]

# Content similarity thresholds for cloaking detection
CLOAKING_THRESHOLDS = {
    "content_similarity_min": 0.3,  # Below this = likely cloaking
    "size_difference_max": 0.5,     # Above this ratio = suspicious
    "dom_difference_max": 0.7,      # DOM structure difference threshold
    "confidence_threshold": 0.6     # Minimum confidence for positive detection
}
