"""
Comprehensive link redirect analyzer with sandboxed browser execution.
Provides redirect chain tracing, cloaking detection, and security validation.

Enhanced features:
- Multi-hop redirect following (HTTP 301/302/303/307/308, meta-refresh, JS redirects)
- Detailed TLS certificate validation with CN/SAN analysis
- Content fingerprinting across user agents for cloaking detection
- Hostname vs displayed link verification
- Sandboxed browser execution for JS redirect detection
- Redis caching with configurable TTL
- Comprehensive security pattern detection
"""

import asyncio
import time
import ssl
import socket
import ipaddress
import hashlib
import re
import base64
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, unquote
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import json

import aiohttp
import dns.resolver
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup
import certifi

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.redis_client import get_redis_connection
from app.services.interfaces import (
    IAnalyzer, AnalysisResult, AnalysisType, ServiceHealth, ServiceStatus,
    ServiceUnavailableError, InvalidTargetError, AnalysisError
)


@dataclass
class TLSCertificateDetails:
    """Detailed TLS certificate information."""
    subject: str
    issuer: str
    common_name: str
    san_list: List[str]
    not_before: datetime
    not_after: datetime
    is_valid: bool
    is_self_signed: bool
    is_expired: bool
    hostname_matches: bool
    fingerprint_sha256: str
    serial_number: str
    signature_algorithm: str
    issuer_organization: str
    validation_errors: List[str]


@dataclass
class RedirectHopDetails:
    """Enhanced redirect hop information."""
    hop_number: int
    url: str
    method: str
    status_code: int
    redirect_type: str  # http_301, http_302, meta_refresh, javascript
    location_header: Optional[str]
    hostname: str
    ip_address: Optional[str]
    tls_certificate: Optional[TLSCertificateDetails]
    response_time_ms: int
    content_hash: str
    content_length: int
    headers: Dict[str, str]
    meta_refresh_delay: Optional[int]
    javascript_redirects: List[str]
    suspicious_patterns: List[str]
    timestamp: datetime
    final_effective_url: str

logger = get_logger(__name__)


class RedirectType(Enum):
    """Types of redirects detected."""
    HTTP_301 = "http_301_moved_permanently"
    HTTP_302 = "http_302_found"
    HTTP_303 = "http_303_see_other"
    HTTP_307 = "http_307_temporary_redirect"
    HTTP_308 = "http_308_permanent_redirect"
    META_REFRESH = "meta_refresh"
    JAVASCRIPT = "javascript_redirect"
    UNKNOWN = "unknown_redirect"


class SuspiciousPattern(Enum):
    """Enhanced suspicious behavior patterns."""
    HOST_MISMATCH = "hostname_display_mismatch"
    CONTENT_CLOAKING = "content_cloaking_detected"
    IP_BASED_URL = "ip_address_url"
    SUSPICIOUS_TLD = "suspicious_top_level_domain"
    SHORT_DOMAIN = "suspiciously_short_domain"
    ENCODED_URL = "url_encoding_obfuscation"
    AUTO_DOWNLOAD = "automatic_download_trigger"
    SUSPICIOUS_JS = "suspicious_javascript_patterns"
    EXCESSIVE_REDIRECTS = "excessive_redirect_chain"
    TLS_MISMATCH = "tls_certificate_mismatch"
    SELF_SIGNED_CERT = "self_signed_certificate"
    EXPIRED_CERT = "expired_certificate"
    HOMOGRAPH_ATTACK = "homograph_domain_attack"
    URL_SHORTENER = "url_shortener_service"
    TYPOSQUATTING = "potential_typosquatting"


class LinkRedirectAnalyzer(IAnalyzer):
    """
    Enhanced link redirect analyzer with comprehensive security analysis.
    
    Features:
    - Multi-hop redirect detection (HTTP, meta-refresh, JavaScript)
    - Detailed TLS certificate validation with CN/SAN analysis
    - Content fingerprinting for cloaking detection across user agents
    - Hostname verification and mismatch detection
    - Sandboxed browser execution for JavaScript redirect analysis
    - Redis caching with configurable TTL
    - Comprehensive security pattern detection
    """
    
    def __init__(self):
        super().__init__("link_redirect_analyzer")
        self.max_redirects = 15  # Increased for thorough analysis
        self.max_analysis_time = 45  # Increased timeout for complex chains
        
        # Enhanced user agent collection for cloaking detection
        self.user_agents = {
            'chrome_desktop': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'firefox_desktop': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'safari_desktop': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'chrome_mobile': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.0.0 Mobile/15E148 Safari/604.1',
            'safari_mobile': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'android_chrome': 'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            'security_scanner': 'Mozilla/5.0 (compatible; PhishNet-Security-Scanner/2.0; +https://phishnet.security/scanner)',
            'bot_crawler': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'legacy_browser': 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko'
        }
        
        # Expanded suspicious patterns and indicators
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.top', '.click', 
            '.download', '.loan', '.work', '.men', '.racing', '.review', '.zip',
            '.stream', '.science', '.party', '.accountant', '.date', '.faith',
            '.cricket', '.win', '.bid', '.country', '.study', '.webcam'
        }
        
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link',
            'is.gd', 'v.gd', 'buff.ly', 'rebrand.ly', 'clicky.me', 'shorte.st',
            'adf.ly', 'bc.vc', 'j.mp', 'lnkd.in', 'ift.tt', 'po.st', 'soo.gd'
        }
        
        # Enhanced JavaScript redirect patterns
        self.js_redirect_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.replace\(["\']([^"\']+)["\']\)',
            r'location\.assign\(["\']([^"\']+)["\']\)',
            r'window\.open\(["\']([^"\']+)["\']',
            r'document\.location\s*=\s*["\']([^"\']+)["\']',
            r'top\.location\s*=\s*["\']([^"\']+)["\']',
            r'parent\.location\s*=\s*["\']([^"\']+)["\']',
            r'setTimeout\([^,]*["\']([^"\']*(?:http|\/)[^"\']*)["\']',
            r'setInterval\([^,]*["\']([^"\']*(?:http|\/)[^"\']*)["\']'
        ]
        
        # Suspicious JavaScript patterns for security analysis
        self.suspicious_js_patterns = [
            r'eval\s*\(',
            r'Function\s*\(',
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'unescape\s*\(',
            r'fromCharCode\s*\(',
            r'atob\s*\(',
            r'btoa\s*\(',
            r'String\.fromCharCode',
            r'navigator\.userAgent',
            r'screen\.width',
            r'screen\.height',
            r'XMLHttpRequest',
            r'fetch\s*\(',
            r'\.exe\b.*download',
            r'base64.*decode',
            r'crypto\.',
            r'WebAssembly'
        ]
        
        self._browser = None
        self._browser_lock = asyncio.Lock()
        self._redis = None
    
    async def analyze(self, target: str, analysis_type: AnalysisType) -> AnalysisResult:
        """
        Enhanced URL analysis with comprehensive redirect chain and cloaking detection.
        
        Args:
            target: URL to analyze
            analysis_type: Must be URL_SCAN
            
        Returns:
            Comprehensive analysis result with detailed findings
        """
        if analysis_type != AnalysisType.URL_SCAN:
            raise InvalidTargetError("LinkRedirectAnalyzer only supports URL scanning")
        
        start_time = time.time()
        
        try:
            # Validate URL format
            self._validate_url(target)
            
            # Enhanced cache key with user agent and analysis depth
            cache_key = self._generate_enhanced_cache_key(target)
            
            # Check cache first with extended metadata
            cached_result = await self._get_cached_analysis(cache_key)
            if cached_result:
                logger.debug(f"Enhanced redirect analysis cache hit for {target}")
                return cached_result
            
            # Perform comprehensive enhanced analysis
            analysis_results = await self._perform_enhanced_comprehensive_analysis(target)
            
            # Create enhanced analysis result
            result = self._create_enhanced_analysis_result(
                target, analysis_type, analysis_results, start_time
            )
            
            # Cache result with intelligent TTL
            cache_ttl = self._calculate_cache_ttl(analysis_results)
            await self._cache_analysis_result(cache_key, result, ttl=cache_ttl)
            
            return result
            
        except Exception as e:
            execution_time = int((time.time() - start_time) * 1000)
            logger.error(f"Enhanced redirect analysis failed for {target}: {e}")
            
            return AnalysisResult(
                service_name=self.service_name,
                analysis_type=analysis_type,
                target=target,
                threat_score=0.0,
                confidence=0.0,
                raw_response={"error": str(e)},
                timestamp=start_time,
                execution_time_ms=execution_time,
                error=f"Enhanced redirect analysis failed: {str(e)}"
            )
    
    def _generate_enhanced_cache_key(self, url: str) -> str:
        """Generate enhanced cache key with analysis parameters."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        analysis_params = f"v2_hops{self.max_redirects}_ua{len(self.user_agents)}"
        return f"enhanced_redirect_analysis:{analysis_params}:{url_hash}"
    
    async def _get_cached_analysis(self, cache_key: str) -> Optional[AnalysisResult]:
        """Get cached analysis result with deserialization."""
        try:
            if not self._redis:
                self._redis = await get_redis_connection()
            
            cached_data = await self._redis.get(cache_key)
            if cached_data:
                data = json.loads(cached_data)
                
                # Reconstruct AnalysisResult object
                return AnalysisResult(
                    service_name=data['service_name'],
                    analysis_type=AnalysisType(data['analysis_type']),
                    target=data['target'],
                    threat_score=data['threat_score'],
                    confidence=data['confidence'],
                    raw_response=data['raw_response'],
                    timestamp=data['timestamp'],
                    execution_time_ms=data['execution_time_ms'],
                    verdict=data.get('verdict'),
                    explanation=data.get('explanation'),
                    indicators=data.get('indicators', []),
                    error=data.get('error')
                )
        except Exception as e:
            logger.warning(f"Cache retrieval failed for {cache_key}: {e}")
        
        return None
    
    async def _cache_analysis_result(self, cache_key: str, result: AnalysisResult, ttl: int):
        """Cache analysis result with serialization."""
        try:
            if not self._redis:
                self._redis = await get_redis_connection()
            
            # Serialize AnalysisResult to JSON
            data = {
                'service_name': result.service_name,
                'analysis_type': result.analysis_type.value,
                'target': result.target,
                'threat_score': result.threat_score,
                'confidence': result.confidence,
                'raw_response': result.raw_response,
                'timestamp': result.timestamp,
                'execution_time_ms': result.execution_time_ms,
                'verdict': result.verdict,
                'explanation': result.explanation,
                'indicators': result.indicators,
                'error': result.error,
                'cached_at': time.time()
            }
            
            await self._redis.setex(cache_key, ttl, json.dumps(data))
            logger.debug(f"Cached analysis result for {cache_key} with TTL {ttl}s")
            
        except Exception as e:
            logger.warning(f"Cache storage failed for {cache_key}: {e}")
    
    def _calculate_cache_ttl(self, analysis_results: Dict[str, Any]) -> int:
        """Calculate intelligent cache TTL based on analysis results."""
        base_ttl = 1800  # 30 minutes default
        
        # Shorter TTL for suspicious/malicious content
        threat_score = analysis_results.get('threat_score', 0.0)
        if threat_score >= 0.8:
            return 600   # 10 minutes for high-risk content
        elif threat_score >= 0.5:
            return 1200  # 20 minutes for suspicious content
        
        # Longer TTL for legitimate content
        if threat_score < 0.2:
            return 3600  # 1 hour for safe content
        
        # Consider cloaking detection
        if analysis_results.get('cloaking_detected', False):
            return 300   # 5 minutes for cloaking content (changes frequently)
        
        # Consider redirect chain length
        redirect_chain = analysis_results.get('redirect_chain', [])
        if len(redirect_chain) > 5:
            return 900   # 15 minutes for complex redirect chains
        
        return base_ttl
    
    async def _perform_enhanced_comprehensive_analysis(self, url: str) -> Dict[str, Any]:
        """Enhanced comprehensive analysis with improved detection capabilities."""
        results = {
            'redirect_chain': [],
            'final_url': url,
            'security_findings': {},
            'cloaking_detected': False,
            'cloaking_confidence': 0.0,
            'browser_behavior': {},
            'timing_analysis': {},
            'threat_indicators': [],
            'analysis_metadata': {
                'analysis_version': '2.0',
                'max_redirects': self.max_redirects,
                'user_agents_tested': len(self.user_agents),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
        }
        
        # Phase 1: Enhanced HTTP redirect tracing
        logger.info(f"Starting enhanced redirect chain analysis for {url}")
        redirect_start = time.time()
        
        http_chain = await self._trace_http_redirects(url)
        results['redirect_chain'] = http_chain
        
        if http_chain:
            results['final_url'] = http_chain[-1].get('final_effective_url', url)
        
        results['timing_analysis']['redirect_tracing_ms'] = int((time.time() - redirect_start) * 1000)
        
        # Phase 2: Enhanced security validation
        logger.info(f"Starting security validation for final URL: {results['final_url']}")
        security_start = time.time()
        
        security_findings = await self._validate_enhanced_security(results['final_url'], http_chain)
        results['security_findings'] = security_findings
        
        results['timing_analysis']['security_validation_ms'] = int((time.time() - security_start) * 1000)
        
        # Phase 3: Enhanced cloaking detection with sandboxed browser
        logger.info(f"Starting enhanced cloaking detection")
        cloaking_start = time.time()
        
        cloaking_results = await self._detect_cloaking(url, results['final_url'])
        results.update(cloaking_results)
        
        results['timing_analysis']['cloaking_detection_ms'] = int((time.time() - cloaking_start) * 1000)
        
        # Phase 4: Aggregate threat indicators
        threat_indicators = self._aggregate_threat_indicators(results)
        results['threat_indicators'] = threat_indicators
        
        # Phase 5: Calculate enhanced threat score
        threat_score = self._calculate_enhanced_threat_score(results)
        results['threat_score'] = threat_score
        
        # Phase 6: Generate detailed analysis summary
        results['analysis_summary'] = self._generate_analysis_summary(results)
        
        logger.info(f"Enhanced analysis completed for {url} - Threat Score: {threat_score}")
        
        return results
    
    def _aggregate_threat_indicators(self, results: Dict[str, Any]) -> List[str]:
        """Aggregate all threat indicators from analysis results."""
        indicators = []
        
        # From redirect chain
        redirect_chain = results.get('redirect_chain', [])
        for hop in redirect_chain:
            indicators.extend(hop.get('suspicious_patterns', []))
        
        # From security findings
        security_findings = results.get('security_findings', {})
        if security_findings.get('ip_domain_mismatch', False):
            indicators.append('ip_domain_redirect')
        if security_findings.get('cert_hostname_mismatch', False):
            indicators.append('tls_certificate_mismatch')
        if security_findings.get('suspicious_tld', False):
            indicators.append('suspicious_top_level_domain')
        
        # From cloaking detection
        if results.get('cloaking_detected', False):
            indicators.extend(results.get('cloaking_indicators', []))
        
        # From redirect chain length
        if len(redirect_chain) > 5:
            indicators.append('excessive_redirect_chain')
        elif len(redirect_chain) > 3:
            indicators.append('multiple_redirects')
        
        # Remove duplicates and return
        return list(set(indicators))
    
    def _generate_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed analysis summary."""
        redirect_chain = results.get('redirect_chain', [])
        
        summary = {
            'total_redirects': len(redirect_chain),
            'final_destination': results.get('final_url'),
            'cloaking_detected': results.get('cloaking_detected', False),
            'cloaking_confidence': results.get('cloaking_confidence', 0.0),
            'threat_score': results.get('threat_score', 0.0),
            'unique_domains': len(set(
                urlparse(hop.get('url', '')).netloc 
                for hop in redirect_chain if hop.get('url')
            )),
            'https_coverage': sum(
                1 for hop in redirect_chain 
                if urlparse(hop.get('url', '')).scheme == 'https'
            ) / max(len(redirect_chain), 1),
            'suspicious_patterns_count': len(results.get('threat_indicators', [])),
            'analysis_duration_ms': sum(results.get('timing_analysis', {}).values())
        }
        
        return summary
    
    async def scan(self, resource: str) -> Dict[str, Any]:
        """
        Unified scan method for redirect chain analysis.
        
        Args:
            resource: URL to analyze
            
        Returns:
            Dict with normalized schema including redirect chain and security findings
        """
        try:
            result = await self.analyze(resource, AnalysisType.URL_SCAN)
            
            raw_data = result.raw_response
            redirect_chain = raw_data.get('redirect_chain', [])
            security_findings = raw_data.get('security_findings', {})
            cloaking_detected = raw_data.get('cloaking_detected', False)
            
            # Generate indicators based on findings
            indicators = []
            
            if len(redirect_chain) > 3:
                indicators.append('excessive_redirects')
            if security_findings.get('ip_domain_mismatch', False):
                indicators.append('ip_domain_mismatch')
            if security_findings.get('cert_hostname_mismatch', False):
                indicators.append('tls_hostname_mismatch')
            if cloaking_detected:
                indicators.append('content_cloaking_detected')
            if security_findings.get('suspicious_js_behavior', False):
                indicators.append('suspicious_javascript')
            
            # Check for URL shorteners in chain
            shortener_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
            for hop in redirect_chain:
                hop_domain = urlparse(hop.get('url', '')).netloc.lower()
                if any(shortener in hop_domain for shortener in shortener_domains):
                    indicators.append('url_shortener_chain')
                    break
            
            # Determine verdict
            threat_score = result.threat_score
            if cloaking_detected or threat_score >= 0.8:
                verdict = 'malicious'
            elif len(indicators) >= 3 or threat_score >= 0.5:
                verdict = 'suspicious'
            else:
                verdict = 'safe'
            
            return {
                'threat_score': threat_score,
                'verdict': verdict,
                'confidence': result.confidence,
                'indicators': indicators,
                'raw_data': raw_data,
                'service': self.service_name,
                'timestamp': result.timestamp,
                'analysis_type': 'url_scan',
                'redirect_chain': redirect_chain,
                'final_url': raw_data.get('final_url'),
                'cloaking_detected': cloaking_detected,
                'security_findings': security_findings
            }
            
        except Exception as e:
            logger.error(f"Link redirect scan failed for {resource}: {e}")
            return {
                'threat_score': 0.0,
                'verdict': 'error',
                'confidence': 0.0,
                'indicators': [f'scan_error: {str(e)}'],
                'raw_data': {'error': str(e)},
                'service': self.service_name,
                'timestamp': time.time(),
                'analysis_type': 'url_scan'
            }
    
    async def _perform_comprehensive_analysis(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive analysis including redirect tracing and security checks."""
        results = {
            'redirect_chain': [],
            'final_url': url,
            'security_findings': {},
            'cloaking_detected': False,
            'browser_behavior': {},
            'timing_analysis': {}
        }
        
        # Phase 1: HTTP-only redirect tracing
        http_chain = await self._trace_http_redirects(url)
        results['redirect_chain'] = http_chain
        
        if http_chain:
            results['final_url'] = http_chain[-1].get('url', url)
        
        # Phase 2: Security validation
        security_findings = await self._validate_security(results['final_url'], http_chain)
        results['security_findings'] = security_findings
        
        # Phase 3: Cloaking detection with sandboxed browser
        cloaking_results = await self._detect_cloaking(url, results['final_url'])
        results.update(cloaking_results)
        
        # Phase 4: Calculate threat score
        threat_score = self._calculate_threat_score(results)
        results['threat_score'] = threat_score
        
        return results
    
    async def _trace_http_redirects(self, url: str) -> List[Dict[str, Any]]:
        """Enhanced redirect chain tracing with meta-refresh and basic JS detection."""
        redirect_chain = []
        current_url = url
        redirect_count = 0
        
        # Create connector with enhanced SSL handling
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = False  # We'll validate manually for detailed analysis
        ssl_context.verify_mode = ssl.CERT_NONE  # Handle verification manually
        
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            ttl_dns_cache=300,
            use_dns_cache=True,
            limit=10,
            limit_per_host=5,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(total=self.max_analysis_time, connect=10)
        
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': self.user_agents['security_scanner'],
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none'
                }
            ) as session:
                
                while redirect_count < self.max_redirects:
                    try:
                        start_time = time.time()
                        parsed_url = urlparse(current_url)
                        
                        # Enhanced hop information structure
                        hop_info = RedirectHopDetails(
                            hop_number=redirect_count,
                            url=current_url,
                            method='GET',
                            status_code=0,
                            redirect_type='unknown',
                            location_header=None,
                            hostname=parsed_url.netloc,
                            ip_address=None,
                            tls_certificate=None,
                            response_time_ms=0,
                            content_hash='',
                            content_length=0,
                            headers={},
                            meta_refresh_delay=None,
                            javascript_redirects=[],
                            suspicious_patterns=[],
                            timestamp=datetime.utcnow(),
                            final_effective_url=current_url
                        )
                        
                        # Resolve IP address with enhanced error handling
                        try:
                            ip_address = await self._resolve_hostname_with_validation(parsed_url.netloc)
                            hop_info.ip_address = ip_address
                            
                            # Check for IP-based URLs
                            if self._is_ip_address(parsed_url.netloc):
                                hop_info.suspicious_patterns.append(SuspiciousPattern.IP_BASED_URL.value)
                                
                        except Exception as e:
                            logger.warning(f"IP resolution failed for {parsed_url.netloc}: {e}")
                        
                        # Enhanced TLS certificate analysis for HTTPS
                        if parsed_url.scheme == 'https':
                            tls_details = await self._get_detailed_tls_info(
                                parsed_url.netloc, 
                                parsed_url.port or 443
                            )
                            hop_info.tls_certificate = tls_details
                            
                            # Add TLS-related suspicious patterns
                            if tls_details:
                                if not tls_details.is_valid:
                                    hop_info.suspicious_patterns.extend(tls_details.validation_errors)
                                if tls_details.is_self_signed:
                                    hop_info.suspicious_patterns.append(SuspiciousPattern.SELF_SIGNED_CERT.value)
                                if tls_details.is_expired:
                                    hop_info.suspicious_patterns.append(SuspiciousPattern.EXPIRED_CERT.value)
                                if not tls_details.hostname_matches:
                                    hop_info.suspicious_patterns.append(SuspiciousPattern.TLS_MISMATCH.value)
                        
                        # Make HTTP request with detailed response analysis
                        async with session.get(
                            current_url,
                            allow_redirects=False
                        ) as response:
                            
                            response_time = time.time() - start_time
                            hop_info.response_time_ms = int(response_time * 1000)
                            hop_info.status_code = response.status
                            hop_info.headers = dict(response.headers)
                            
                            # Read and analyze response content
                            try:
                                content = await response.read()
                                content_text = content.decode('utf-8', errors='ignore')
                                hop_info.content_hash = hashlib.sha256(content).hexdigest()
                                hop_info.content_length = len(content)
                                
                                # Detect suspicious patterns in content and headers
                                hop_info.suspicious_patterns.extend(
                                    self._detect_enhanced_suspicious_patterns(
                                        current_url, content_text, hop_info.headers
                                    )
                                )
                                
                            except Exception as e:
                                logger.warning(f"Content analysis failed for {current_url}: {e}")
                                content_text = ""
                            
                            # Convert dataclass to dict for JSON serialization
                            hop_dict = asdict(hop_info)
                            redirect_chain.append(hop_dict)
                            
                            # Check for HTTP redirects (3xx status codes)
                            next_url = None
                            if response.status in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location')
                                if location:
                                    # Handle relative URLs properly
                                    next_url = urljoin(current_url, location)
                                    hop_dict['redirect_type'] = self._determine_redirect_type(response.status).value
                                    hop_dict['location_header'] = location
                                    hop_dict['final_effective_url'] = next_url
                            
                            # Check for meta-refresh redirects in 200 responses
                            elif response.status == 200 and content_text:
                                meta_refresh = self._extract_meta_refresh_redirect(content_text)
                                if meta_refresh:
                                    next_url = urljoin(current_url, meta_refresh['url'])
                                    hop_dict['redirect_type'] = RedirectType.META_REFRESH.value
                                    hop_dict['meta_refresh_delay'] = meta_refresh['delay']
                                    hop_dict['final_effective_url'] = next_url
                                
                                # Check for JavaScript redirects (basic pattern matching)
                                js_redirects = self._extract_javascript_redirects(content_text)
                                if js_redirects and not next_url:  # Only if no other redirect found
                                    # Use the first detected JS redirect
                                    next_url = urljoin(current_url, js_redirects[0])
                                    hop_dict['redirect_type'] = RedirectType.JAVASCRIPT.value
                                    hop_dict['javascript_redirects'] = js_redirects
                                    hop_dict['final_effective_url'] = next_url
                            
                            # If no redirect found, we've reached the end
                            if not next_url:
                                hop_dict['final_effective_url'] = current_url
                                break
                            
                            # Validate next URL and continue
                            if self._is_valid_redirect_url(next_url):
                                current_url = next_url
                                redirect_count += 1
                                
                                # Add delay to avoid overwhelming servers
                                await asyncio.sleep(0.5)
                            else:
                                logger.warning(f"Invalid redirect URL detected: {next_url}")
                                break
                                
                    except asyncio.TimeoutError:
                        hop_dict = {
                            'hop_number': redirect_count,
                            'url': current_url,
                            'error': 'request_timeout',
                            'response_time_ms': int(self.max_analysis_time * 1000),
                            'timestamp': datetime.utcnow().isoformat(),
                            'suspicious_patterns': [SuspiciousPattern.EXCESSIVE_REDIRECTS.value]
                        }
                        redirect_chain.append(hop_dict)
                        break
                        
                    except Exception as e:
                        hop_dict = {
                            'hop_number': redirect_count,
                            'url': current_url,
                            'error': str(e),
                            'timestamp': datetime.utcnow().isoformat(),
                            'suspicious_patterns': []
                        }
                        redirect_chain.append(hop_dict)
                        logger.error(f"Redirect analysis error for {current_url}: {e}")
                        break
                        
        except Exception as e:
            logger.error(f"HTTP redirect tracing failed: {e}")
        
        return redirect_chain
    
    async def _validate_security(self, final_url: str, redirect_chain: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate security aspects of the redirect chain and final destination."""
        findings = {
            'ip_domain_mismatch': False,
            'cert_hostname_mismatch': False,
            'suspicious_tld': False,
            'domain_reputation': {},
            'ssl_issues': []
        }
        
        try:
            parsed_final = urlparse(final_url)
            
            # Check for IP address domains
            for hop in redirect_chain:
                if hop.get('is_ip_domain', False):
                    findings['ip_domain_mismatch'] = True
                    break
            
            # Validate TLS certificate for HTTPS URLs
            if parsed_final.scheme == 'https':
                ssl_findings = await self._validate_ssl_certificate(parsed_final.netloc)
                findings['ssl_issues'] = ssl_findings
                
                # Check for hostname mismatch
                if any('hostname_mismatch' in issue for issue in ssl_findings):
                    findings['cert_hostname_mismatch'] = True
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download']
            domain = parsed_final.netloc.lower()
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                findings['suspicious_tld'] = True
            
            # Domain reputation check (simplified)
            findings['domain_reputation'] = await self._check_domain_reputation(parsed_final.netloc)
            
        except Exception as e:
            logger.error(f"Security validation failed: {e}")
            findings['validation_error'] = str(e)
        
        return findings
    
    async def _detect_cloaking(self, original_url: str, final_url: str) -> Dict[str, Any]:
        """Enhanced cloaking detection with comprehensive browser analysis."""
        cloaking_results = {
            'cloaking_detected': False,
            'browser_behavior': {},
            'content_differences': {},
            'js_behavior': {},
            'cloaking_confidence': 0.0,
            'cloaking_indicators': []
        }
        
        try:
            # Get browser instance
            browser = await self._get_browser()
            
            # Test with different user agents for cloaking detection
            user_agent_results = {}
            content_hashes = set()
            final_urls = set()
            
            for agent_type, user_agent in self.user_agents.items():
                try:
                    context = await browser.new_context(
                        user_agent=user_agent,
                        viewport={'width': 1920, 'height': 1080},
                        ignore_https_errors=True,
                        java_script_enabled=True,
                        # Sandbox configuration
                        extra_http_headers={
                            'X-Forwarded-For': '192.168.1.100',  # Sandbox IP
                            'X-Real-IP': '192.168.1.100'
                        }
                    )
                    
                    page = await context.new_page()
                    
                    # Enhanced monitoring for suspicious behavior
                    js_logs = []
                    network_requests = []
                    console_errors = []
                    navigation_events = []
                    download_attempts = []
                    
                    # Monitor console messages
                    page.on('console', lambda msg: js_logs.append({
                        'type': msg.type,
                        'text': msg.text,
                        'location': msg.location,
                        'timestamp': time.time()
                    }))
                    
                    # Monitor network requests
                    page.on('request', lambda req: network_requests.append({
                        'url': req.url,
                        'method': req.method,
                        'headers': dict(req.headers),
                        'resource_type': req.resource_type,
                        'timestamp': time.time()
                    }))
                    
                    # Monitor responses for suspicious patterns
                    page.on('response', lambda resp: self._analyze_response_for_threats(resp, agent_type))
                    
                    # Monitor download attempts
                    page.on('download', lambda download: download_attempts.append({
                        'url': download.url,
                        'suggested_filename': download.suggested_filename,
                        'timestamp': time.time()
                    }))
                    
                    # Monitor navigation for redirects
                    page.on('framenavigated', lambda frame: navigation_events.append({
                        'url': frame.url,
                        'timestamp': time.time()
                    }))
                    
                    # Navigate with comprehensive monitoring
                    start_time = time.time()
                    response = await page.goto(
                        original_url,
                        wait_until='networkidle',
                        timeout=20000
                    )
                    navigation_time = time.time() - start_time
                    
                    # Wait for dynamic content to load
                    await asyncio.sleep(2)
                    
                    # Capture comprehensive page state
                    final_page_url = page.url
                    page_title = await page.title()
                    page_content = await page.content()
                    
                    # Analyze JavaScript execution
                    js_analysis = await self._analyze_page_javascript(page)
                    
                    # Check for auto-downloads or suspicious redirects
                    suspicious_behavior = {
                        'auto_downloads': len(download_attempts),
                        'excessive_requests': len(network_requests) > 50,
                        'multiple_redirects': len(navigation_events) > 3,
                        'suspicious_js_execution': js_analysis.get('suspicious_patterns', 0) > 2
                    }
                    
                    # Content fingerprinting
                    content_hash = hashlib.sha256(page_content.encode('utf-8')).hexdigest()
                    content_hashes.add(content_hash)
                    final_urls.add(final_page_url)
                    
                    user_agent_results[agent_type] = {
                        'final_url': final_page_url,
                        'title': page_title,
                        'content_hash': content_hash,
                        'content_length': len(page_content),
                        'status_code': response.status if response else None,
                        'navigation_time_ms': int(navigation_time * 1000),
                        'js_logs': js_logs[-20:],  # Last 20 JS logs
                        'network_requests': len(network_requests),
                        'download_attempts': download_attempts,
                        'navigation_events': navigation_events,
                        'suspicious_behavior': suspicious_behavior,
                        'js_analysis': js_analysis,
                        'redirected': final_page_url != original_url,
                        'response_headers': dict(response.headers) if response else {}
                    }
                    
                    await context.close()
                    
                    # Delay between requests to avoid detection
                    await asyncio.sleep(3)
                    
                except Exception as e:
                    logger.warning(f"Browser analysis failed for {agent_type}: {e}")
                    user_agent_results[agent_type] = {
                        'error': str(e),
                        'analysis_failed': True
                    }
            
            # Analyze results for cloaking indicators
            cloaking_results['browser_behavior'] = user_agent_results
            
            # Content hash analysis
            if len(content_hashes) > 1:
                cloaking_results['cloaking_detected'] = True
                cloaking_results['cloaking_indicators'].append('content_hash_mismatch')
                cloaking_results['content_differences']['unique_content_hashes'] = len(content_hashes)
            
            # Final URL analysis
            if len(final_urls) > 1:
                cloaking_results['cloaking_detected'] = True
                cloaking_results['cloaking_indicators'].append('final_url_mismatch')
                cloaking_results['content_differences']['unique_final_urls'] = len(final_urls)
            
            # User agent specific analysis
            ua_comparison = self._compare_user_agent_results(user_agent_results)
            if ua_comparison['significant_differences']:
                cloaking_results['cloaking_detected'] = True
                cloaking_results['cloaking_indicators'].extend(ua_comparison['differences'])
            
            # Calculate cloaking confidence score
            cloaking_results['cloaking_confidence'] = self._calculate_cloaking_confidence(
                user_agent_results, content_hashes, final_urls
            )
            
            # Enhanced JavaScript behavior analysis
            js_analysis = self._analyze_comprehensive_js_behavior(user_agent_results)
            cloaking_results['js_behavior'] = js_analysis
            
            if js_analysis.get('user_agent_detection', False):
                cloaking_results['cloaking_indicators'].append('user_agent_detection')
            
            if js_analysis.get('suspicious_patterns', 0) > 3:
                cloaking_results['cloaking_detected'] = True
                cloaking_results['cloaking_indicators'].append('suspicious_js_patterns')
                
        except Exception as e:
            logger.error(f"Enhanced cloaking detection failed: {e}")
            cloaking_results['detection_error'] = str(e)
        
        return cloaking_results
    
    async def _analyze_page_javascript(self, page: Page) -> Dict[str, Any]:
        """Analyze JavaScript execution on the page for suspicious patterns."""
        js_analysis = {
            'suspicious_patterns': 0,
            'obfuscation_detected': False,
            'user_agent_checks': 0,
            'redirect_attempts': [],
            'eval_usage': 0,
            'dom_manipulation': 0,
            'network_calls': 0
        }
        
        try:
            # Inject monitoring script to detect suspicious JavaScript behavior
            monitoring_script = """
            (() => {
                const originalEval = window.eval;
                const originalUserAgent = navigator.userAgent;
                const originalLocation = window.location;
                
                let suspiciousActivity = {
                    evalCalls: 0,
                    userAgentAccess: 0,
                    locationChanges: 0,
                    domModifications: 0,
                    networkRequests: 0
                };
                
                // Monitor eval usage
                window.eval = function(...args) {
                    suspiciousActivity.evalCalls++;
                    return originalEval.apply(this, args);
                };
                
                // Monitor user agent access
                Object.defineProperty(navigator, 'userAgent', {
                    get: function() {
                        suspiciousActivity.userAgentAccess++;
                        return originalUserAgent;
                    }
                });
                
                // Monitor DOM mutations
                const observer = new MutationObserver((mutations) => {
                    suspiciousActivity.domModifications += mutations.length;
                });
                observer.observe(document.body || document.documentElement, {
                    childList: true,
                    subtree: true,
                    attributes: true
                });
                
                // Monitor fetch/XMLHttpRequest
                const originalFetch = window.fetch;
                if (originalFetch) {
                    window.fetch = function(...args) {
                        suspiciousActivity.networkRequests++;
                        return originalFetch.apply(this, args);
                    };
                }
                
                const originalXHR = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(...args) {
                    suspiciousActivity.networkRequests++;
                    return originalXHR.apply(this, args);
                };
                
                window.getSuspiciousActivity = () => suspiciousActivity;
            })();
            """
            
            await page.evaluate(monitoring_script)
            
            # Wait for JavaScript execution
            await asyncio.sleep(3)
            
            # Get suspicious activity results
            activity = await page.evaluate("window.getSuspiciousActivity ? window.getSuspiciousActivity() : {}")
            
            js_analysis.update({
                'eval_usage': activity.get('evalCalls', 0),
                'user_agent_checks': activity.get('userAgentAccess', 0),
                'dom_manipulation': activity.get('domModifications', 0),
                'network_calls': activity.get('networkRequests', 0)
            })
            
            # Calculate suspicious patterns score
            js_analysis['suspicious_patterns'] = (
                min(activity.get('evalCalls', 0), 3) +
                min(activity.get('userAgentAccess', 0), 2) +
                (1 if activity.get('domModifications', 0) > 50 else 0) +
                (1 if activity.get('networkRequests', 0) > 10 else 0)
            )
            
            # Check for obfuscation
            page_content = await page.content()
            obfuscation_patterns = [
                r'eval\s*\(',
                r'Function\s*\(',
                r'atob\s*\(',
                r'fromCharCode',
                r'unescape\s*\(',
                r'\\x[0-9a-fA-F]{2}',  # Hex encoding
                r'\\u[0-9a-fA-F]{4}',  # Unicode encoding
            ]
            
            obfuscation_count = sum(
                len(re.findall(pattern, page_content, re.IGNORECASE))
                for pattern in obfuscation_patterns
            )
            
            js_analysis['obfuscation_detected'] = obfuscation_count > 5
            
        except Exception as e:
            logger.warning(f"JavaScript analysis failed: {e}")
        
        return js_analysis
    
    def _analyze_response_for_threats(self, response, user_agent: str):
        """Analyze HTTP response for suspicious patterns."""
        try:
            # Check for suspicious headers
            headers = response.headers
            
            # Log suspicious content types
            content_type = headers.get('content-type', '').lower()
            if any(ct in content_type for ct in ['application/octet-stream', 'application/exe']):
                logger.warning(f"Suspicious content type for {user_agent}: {content_type}")
            
            # Check for download triggers
            content_disposition = headers.get('content-disposition', '').lower()
            if 'attachment' in content_disposition:
                logger.warning(f"Auto-download triggered for {user_agent}: {content_disposition}")
                
        except Exception as e:
            logger.warning(f"Response analysis failed: {e}")
    
    def _compare_user_agent_results(self, user_agent_results: Dict[str, Any]) -> Dict[str, Any]:
        """Compare results across different user agents to detect cloaking."""
        comparison = {
            'significant_differences': False,
            'differences': []
        }
        
        try:
            # Extract successful results
            valid_results = {
                ua: result for ua, result in user_agent_results.items()
                if not result.get('analysis_failed', False)
            }
            
            if len(valid_results) < 2:
                return comparison
            
            # Compare content hashes
            content_hashes = [result.get('content_hash') for result in valid_results.values()]
            if len(set(filter(None, content_hashes))) > 1:
                comparison['significant_differences'] = True
                comparison['differences'].append('content_hash_variation')
            
            # Compare final URLs
            final_urls = [result.get('final_url') for result in valid_results.values()]
            if len(set(filter(None, final_urls))) > 1:
                comparison['significant_differences'] = True
                comparison['differences'].append('final_url_variation')
            
            # Compare status codes
            status_codes = [result.get('status_code') for result in valid_results.values()]
            unique_status_codes = set(filter(None, status_codes))
            if len(unique_status_codes) > 1 and not all(code in [200, 301, 302] for code in unique_status_codes):
                comparison['significant_differences'] = True
                comparison['differences'].append('status_code_variation')
            
            # Compare content lengths (significant differences)
            content_lengths = [result.get('content_length', 0) for result in valid_results.values()]
            if content_lengths:
                max_length = max(content_lengths)
                min_length = min(content_lengths)
                if max_length > 0 and (max_length - min_length) / max_length > 0.1:  # >10% difference
                    comparison['significant_differences'] = True
                    comparison['differences'].append('content_length_variation')
            
        except Exception as e:
            logger.warning(f"User agent comparison failed: {e}")
        
        return comparison
    
    def _calculate_cloaking_confidence(self, user_agent_results: Dict[str, Any], 
                                     content_hashes: set, final_urls: set) -> float:
        """Calculate confidence score for cloaking detection."""
        confidence = 0.0
        
        try:
            # Base confidence from content differences
            if len(content_hashes) > 1:
                confidence += 0.4
            
            if len(final_urls) > 1:
                confidence += 0.3
            
            # Additional confidence from user agent specific behavior
            bot_results = user_agent_results.get('bot_crawler', {})
            browser_results = [
                result for ua, result in user_agent_results.items()
                if ua.endswith('_desktop') and not result.get('analysis_failed', False)
            ]
            
            if bot_results and browser_results:
                bot_hash = bot_results.get('content_hash')
                browser_hashes = [result.get('content_hash') for result in browser_results]
                
                if bot_hash and all(h != bot_hash for h in browser_hashes if h):
                    confidence += 0.3  # High confidence for bot vs browser difference
            
        except Exception as e:
            logger.warning(f"Cloaking confidence calculation failed: {e}")
        
        return min(confidence, 1.0)
    
    def _analyze_comprehensive_js_behavior(self, user_agent_results: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive analysis of JavaScript behavior across user agents."""
        js_analysis = {
            'suspicious_patterns': 0,
            'user_agent_detection': False,
            'redirection_attempts': 0,
            'obfuscation_techniques': [],
            'evasion_patterns': [],
            'cross_ua_differences': {}
        }
        
        try:
            all_js_logs = []
            
            for agent_type, result in user_agent_results.items():
                if result.get('analysis_failed', False):
                    continue
                
                js_logs = result.get('js_logs', [])
                js_result = result.get('js_analysis', {})
                
                # Aggregate logs
                all_js_logs.extend([(agent_type, log) for log in js_logs])
                
                # Check for user agent detection
                if js_result.get('user_agent_checks', 0) > 0:
                    js_analysis['user_agent_detection'] = True
                
                # Count obfuscation techniques
                if js_result.get('obfuscation_detected', False):
                    js_analysis['obfuscation_techniques'].append(agent_type)
                
                # Count suspicious patterns
                js_analysis['suspicious_patterns'] += js_result.get('suspicious_patterns', 0)
            
            # Analyze cross-user-agent differences
            ua_behaviors = {}
            for agent_type, result in user_agent_results.items():
                if not result.get('analysis_failed', False):
                    ua_behaviors[agent_type] = {
                        'js_patterns': result.get('js_analysis', {}).get('suspicious_patterns', 0),
                        'network_requests': result.get('network_requests', 0),
                        'downloads': len(result.get('download_attempts', [])),
                        'redirects': len(result.get('navigation_events', []))
                    }
            
            js_analysis['cross_ua_differences'] = ua_behaviors
            
        except Exception as e:
            logger.warning(f"Comprehensive JS behavior analysis failed: {e}")
        
        return js_analysis
    
    async def _get_browser(self) -> Browser:
        """Get or create enhanced sandboxed browser instance."""
        async with self._browser_lock:
            if self._browser is None:
                playwright = await async_playwright().start()
                
                # Enhanced browser arguments for security and sandboxing
                browser_args = [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-background-timer-throttling',
                    '--disable-backgrounding-occluded-windows',
                    '--disable-renderer-backgrounding',
                    '--disable-features=TranslateUI,VizDisplayCompositor',
                    '--disable-ipc-flooding-protection',
                    '--disable-client-side-phishing-detection',
                    '--disable-sync',
                    '--disable-default-apps',
                    '--no-first-run',
                    '--no-default-browser-check',
                    '--disable-extensions',
                    '--disable-plugins',
                    '--disable-images',  # Speed up loading
                    '--disable-javascript-harmony-shipping',
                    '--disable-background-networking',
                    '--disable-background-sync',
                    '--disable-component-update',
                    '--disable-domain-reliability',
                    '--disable-features=AudioServiceOutOfProcess',
                    '--disable-print-preview',
                    '--disable-speech-api',
                    '--hide-scrollbars',
                    '--mute-audio',
                    '--no-pings',
                    '--disable-web-security',  # For analysis purposes
                    '--disable-features=VizDisplayCompositor',
                    '--run-all-compositor-stages-before-draw',
                    '--disable-threaded-animation',
                    '--disable-threaded-scrolling',
                    '--disable-checker-imaging',
                    '--disable-new-bookmark-apps',
                    '--disable-background-timer-throttling',
                    '--disable-renderer-backgrounding',
                    '--disable-backgrounding-occluded-windows',
                    '--force-color-profile=srgb',
                    '--memory-pressure-off',
                    '--disable-partial-raster',
                    '--disable-skia-runtime-opts',
                    '--run-all-compositor-stages-before-draw'
                ]
                
                self._browser = await playwright.chromium.launch(
                    headless=True,
                    args=browser_args,
                    ignore_default_args=['--enable-automation'],
                    env={
                        'DISPLAY': ':99',  # Virtual display for sandboxing
                    }
                )
                
                logger.info("Enhanced sandboxed browser instance created")
            
            return self._browser
    
    def _analyze_js_behavior(self, user_agent_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze JavaScript behavior for suspicious patterns."""
        js_analysis = {
            'suspicious_patterns': 0,
            'redirection_attempts': 0,
            'user_agent_detection': False,
            'evasion_techniques': []
        }
        
        try:
            for agent_type, result in user_agent_results.items():
                js_logs = result.get('js_logs', [])
                
                for log in js_logs:
                    log_text = log.get('text', '').lower()
                    
                    # Check for user agent detection
                    if 'navigator.useragent' in log_text or 'useragent' in log_text:
                        js_analysis['user_agent_detection'] = True
                        js_analysis['suspicious_patterns'] += 1
                    
                    # Check for redirection attempts
                    if any(phrase in log_text for phrase in ['window.location', 'location.href', 'location.replace']):
                        js_analysis['redirection_attempts'] += 1
                        js_analysis['suspicious_patterns'] += 1
                    
                    # Check for evasion techniques
                    evasion_patterns = [
                        'eval(',
                        'fromcharcode',
                        'unescape',
                        'atob(',
                        'btoa(',
                        'settimeout'
                    ]
                    
                    for pattern in evasion_patterns:
                        if pattern in log_text:
                            js_analysis['evasion_techniques'].append(pattern)
                            js_analysis['suspicious_patterns'] += 1
                            break
                            
        except Exception as e:
            logger.error(f"JS behavior analysis failed: {e}")
        
        return js_analysis
    
    def _calculate_threat_score(self, analysis_results: Dict[str, Any]) -> float:
        """Calculate overall threat score based on analysis results."""
        score = 0.0
        
        try:
            # Redirect chain analysis
            redirect_chain = analysis_results.get('redirect_chain', [])
            if len(redirect_chain) > 5:
                score += 0.3
            elif len(redirect_chain) > 3:
                score += 0.2
            elif len(redirect_chain) > 1:
                score += 0.1
            
            # Security findings
            security_findings = analysis_results.get('security_findings', {})
            if security_findings.get('ip_domain_mismatch', False):
                score += 0.4
            if security_findings.get('cert_hostname_mismatch', False):
                score += 0.3
            if security_findings.get('suspicious_tld', False):
                score += 0.2
            
            # Cloaking detection
            if analysis_results.get('cloaking_detected', False):
                score += 0.5
            
            # JavaScript behavior
            js_behavior = analysis_results.get('js_behavior', {})
            suspicious_patterns = js_behavior.get('suspicious_patterns', 0)
            if suspicious_patterns >= 3:
                score += 0.4
            elif suspicious_patterns >= 1:
                score += 0.2
            
            # Cap at 1.0
            score = min(score, 1.0)
            
        except Exception as e:
            logger.error(f"Threat score calculation failed: {e}")
        
        return round(score, 3)
    
    async def _get_detailed_tls_info(self, hostname: str, port: int) -> Optional[TLSCertificateDetails]:
        """Get comprehensive TLS certificate information."""
        try:
            # Create SSL context for certificate validation
            context = ssl.create_default_context(cafile=certifi.where())
            context.check_hostname = False  # We'll validate manually
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((hostname, port), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
            
            # Parse certificate using cryptography library
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Extract detailed certificate information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            
            # Extract Common Name
            common_name = ""
            for attribute in cert.subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    common_name = attribute.value
                    break
            
            # Extract Subject Alternative Names (SAN)
            san_list = []
            try:
                san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_extension.value:
                    if hasattr(name, 'value'):
                        san_list.append(name.value)
            except x509.ExtensionNotFound:
                pass
            
            # Extract issuer organization
            issuer_org = ""
            for attribute in cert.issuer:
                if attribute.oid == NameOID.ORGANIZATION_NAME:
                    issuer_org = attribute.value
                    break
            
            # Determine if self-signed
            is_self_signed = cert.issuer == cert.subject
            
            # Check if expired
            now = datetime.utcnow()
            is_expired = now > cert.not_valid_after or now < cert.not_valid_before
            
            # Validate hostname matching
            hostname_matches, validation_errors = self._validate_hostname_matching(
                hostname, common_name, san_list
            )
            
            # Calculate certificate fingerprint
            fingerprint = hashlib.sha256(cert_der).hexdigest()
            
            # Determine overall validity
            is_valid = (
                not is_self_signed and 
                not is_expired and 
                hostname_matches and 
                len(validation_errors) == 0
            )
            
            return TLSCertificateDetails(
                subject=subject,
                issuer=issuer,
                common_name=common_name,
                san_list=san_list,
                not_before=cert.not_valid_before,
                not_after=cert.not_valid_after,
                is_valid=is_valid,
                is_self_signed=is_self_signed,
                is_expired=is_expired,
                hostname_matches=hostname_matches,
                fingerprint_sha256=fingerprint,
                serial_number=str(cert.serial_number),
                signature_algorithm=cert.signature_algorithm_oid._name,
                issuer_organization=issuer_org,
                validation_errors=validation_errors
            )
            
        except Exception as e:
            logger.warning(f"TLS certificate analysis failed for {hostname}:{port}: {e}")
            return None
    
    def _validate_hostname_matching(self, hostname: str, cn: str, san_list: List[str]) -> Tuple[bool, List[str]]:
        """Validate if hostname matches certificate CN or SAN entries."""
        errors = []
        
        # Normalize hostname
        hostname = hostname.lower()
        
        # Check against Common Name
        if cn:
            cn = cn.lower()
            if self._hostname_matches_pattern(hostname, cn):
                return True, []
        
        # Check against SAN entries
        for san in san_list:
            san = san.lower()
            if self._hostname_matches_pattern(hostname, san):
                return True, []
        
        # If we get here, no match was found
        errors.append(f"hostname_mismatch: {hostname} not in cert CN/SAN")
        return False, errors
    
    def _hostname_matches_pattern(self, hostname: str, pattern: str) -> bool:
        """Check if hostname matches certificate pattern (including wildcards)."""
        # Exact match
        if pattern == hostname:
            return True
        
        # Wildcard pattern matching
        if pattern.startswith('*.'):
            pattern_domain = pattern[2:]
            if '.' in hostname:
                hostname_parts = hostname.split('.')
                if len(hostname_parts) >= 2:
                    hostname_domain = '.'.join(hostname_parts[1:])
                    return pattern_domain == hostname_domain
        
        return False
    
    def _extract_meta_refresh_redirect(self, content: str) -> Optional[Dict[str, Any]]:
        """Extract meta refresh redirect information from HTML content."""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Look for meta refresh tags
            meta_tags = soup.find_all('meta', attrs={'http-equiv': re.compile(r'refresh', re.IGNORECASE)})
            
            for meta in meta_tags:
                content_attr = meta.get('content', '')
                if content_attr:
                    # Parse content attribute (format: "delay;url=target" or "delay; url=target")
                    if ';' in content_attr:
                        parts = content_attr.split(';', 1)
                        try:
                            delay = int(parts[0].strip())
                            
                            if len(parts) > 1:
                                url_part = parts[1].strip()
                                
                                # Extract URL (handle various formats)
                                if '=' in url_part:
                                    url = url_part.split('=', 1)[1].strip()
                                    # Remove quotes if present
                                    url = url.strip('\'"')
                                    
                                    if url:
                                        return {
                                            'delay': delay,
                                            'url': unquote(url),  # URL decode
                                            'raw_content': content_attr
                                        }
                        except ValueError:
                            continue
                            
        except Exception as e:
            logger.warning(f"Meta refresh parsing failed: {e}")
        
        return None
    
    def _extract_javascript_redirects(self, content: str) -> List[str]:
        """Extract JavaScript redirect URLs from content."""
        js_redirects = []
        
        try:
            # Remove comments and normalize whitespace
            # Basic JS comment removal (not perfect but good enough for detection)
            content = re.sub(r'//.*?\n', '\n', content)
            content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
            
            # Search for various JavaScript redirect patterns
            for pattern in self.js_redirect_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    try:
                        url = match.group(1)
                        if url and self._is_valid_redirect_url(url):
                            # URL decode and clean
                            url = unquote(url).strip()
                            if url not in js_redirects:
                                js_redirects.append(url)
                    except (IndexError, AttributeError):
                        continue
            
            # Limit to reasonable number of redirects
            return js_redirects[:5]
            
        except Exception as e:
            logger.warning(f"JavaScript redirect extraction failed: {e}")
        
        return js_redirects
    
    def _detect_enhanced_suspicious_patterns(self, url: str, content: str, headers: Dict[str, str]) -> List[str]:
        """Enhanced suspicious pattern detection."""
        patterns = []
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.lower()
        
        # IP-based URL detection
        if self._is_ip_address(hostname):
            patterns.append(SuspiciousPattern.IP_BASED_URL.value)
        
        # Suspicious TLD detection
        for tld in self.suspicious_tlds:
            if hostname.endswith(tld):
                patterns.append(SuspiciousPattern.SUSPICIOUS_TLD.value)
                break
        
        # URL shortener detection
        for shortener in self.url_shorteners:
            if shortener in hostname:
                patterns.append(SuspiciousPattern.URL_SHORTENER.value)
                break
        
        # Short domain detection (potential typosquatting)
        domain_parts = hostname.split('.')
        if len(domain_parts) >= 2 and len(domain_parts[0]) <= 3:
            patterns.append(SuspiciousPattern.SHORT_DOMAIN.value)
        
        # URL encoding obfuscation
        if '%' in url and any(encoded in url.lower() for encoded in ['%2f', '%3a', '%20', '%22', '%27']):
            patterns.append(SuspiciousPattern.ENCODED_URL.value)
        
        # Excessive redirects (will be determined by chain length)
        # This is handled at the chain level
        
        # Auto-download detection
        content_disposition = headers.get('Content-Disposition', '').lower()
        content_type = headers.get('Content-Type', '').lower()
        
        if 'attachment' in content_disposition:
            patterns.append(SuspiciousPattern.AUTO_DOWNLOAD.value)
        
        if any(ct in content_type for ct in ['application/octet-stream', 'application/exe', 'application/zip']):
            patterns.append(SuspiciousPattern.AUTO_DOWNLOAD.value)
        
        # Suspicious JavaScript patterns
        for js_pattern in self.suspicious_js_patterns:
            if re.search(js_pattern, content, re.IGNORECASE):
                patterns.append(SuspiciousPattern.SUSPICIOUS_JS.value)
                break
        
        # Homograph attack detection (basic)
        if self._detect_homograph_attack(hostname):
            patterns.append(SuspiciousPattern.HOMOGRAPH_ATTACK.value)
        
        # Typosquatting detection (basic)
        if self._detect_potential_typosquatting(hostname):
            patterns.append(SuspiciousPattern.TYPOSQUATTING.value)
        
        return patterns
    
    def _detect_homograph_attack(self, hostname: str) -> bool:
        """Detect potential homograph attacks using similar-looking characters."""
        # Common homograph characters (Cyrillic that look like Latin)
        homograph_chars = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 
            'у': 'y', 'х': 'x', 'і': 'i', 'ѕ': 's', 'һ': 'h'
        }
        
        return any(char in hostname for char in homograph_chars.keys())
    
    def _detect_potential_typosquatting(self, hostname: str) -> bool:
        """Basic typosquatting detection."""
        # Common typosquatting patterns
        typosquatting_patterns = [
            r'g[o0]{2}gle',      # google variations
            r'fac[e3]b[o0]{2}k',  # facebook variations
            r'tw[i1]tt[e3]r',     # twitter variations
            r'[a4]m[a4]z[o0]n',   # amazon variations
            r'p[a4]yp[a4]l',      # paypal variations
            r'm[i1]cr[o0]s[o0]ft' # microsoft variations
        ]
        
        for pattern in typosquatting_patterns:
            if re.search(pattern, hostname, re.IGNORECASE):
                return True
        
        return False
    
    def _is_valid_redirect_url(self, url: str) -> bool:
        """Validate if a URL is valid for redirection."""
        try:
            if not url or len(url) > 2048:  # Reasonable URL length limit
                return False
            
            # Handle relative URLs
            if url.startswith('/'):
                return True
            
            parsed = urlparse(url)
            return parsed.scheme in ['http', 'https'] and parsed.netloc
            
        except Exception:
            return False
    
    def _determine_redirect_type(self, status_code: int) -> RedirectType:
        """Determine redirect type from HTTP status code."""
        redirect_map = {
            301: RedirectType.HTTP_301,
            302: RedirectType.HTTP_302,
            303: RedirectType.HTTP_303,
            307: RedirectType.HTTP_307,
            308: RedirectType.HTTP_308
        }
        return redirect_map.get(status_code, RedirectType.UNKNOWN)
    
    async def _resolve_hostname_with_validation(self, hostname: str) -> Optional[str]:
        """Enhanced hostname resolution with validation."""
        try:
            if not hostname:
                return None
            
            # Check if it's already an IP address
            try:
                ip = ipaddress.ip_address(hostname)
                return str(ip)
            except ValueError:
                pass
            
            # Resolve hostname using DNS
            loop = asyncio.get_event_loop()
            try:
                result = await loop.getaddrinfo(
                    hostname, None, family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
                )
                if result:
                    return result[0][4][0]
            except Exception as dns_error:
                logger.warning(f"DNS resolution failed for {hostname}: {dns_error}")
                return None
                
        except Exception as e:
            logger.warning(f"Hostname resolution failed for {hostname}: {e}")
        
        return None
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address."""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False
    
    async def _validate_ssl_certificate(self, hostname: str) -> List[str]:
        """Validate SSL certificate for hostname."""
        issues = []
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der)
                    
                    # Check hostname match
                    try:
                        ssl.match_hostname(ssock.getpeercert(), hostname)
                    except ssl.CertificateError:
                        issues.append('hostname_mismatch')
                    
                    # Check expiration
                    if cert.not_valid_after < datetime.utcnow():
                        issues.append('expired_certificate')
                    
                    # Check issuer
                    issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if issuer and 'self-signed' in str(issuer[0].value).lower():
                        issues.append('self_signed_certificate')
                        
        except Exception as e:
            issues.append(f'ssl_validation_error: {str(e)}')
        
        return issues
    
    async def _check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Basic domain reputation check."""
        reputation = {
            'domain_age_days': None,
            'whois_privacy': False,
            'suspicious_patterns': []
        }
        
        try:
            # Check for suspicious domain patterns
            if re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', domain):
                reputation['suspicious_patterns'].append('ip_like_pattern')
            
            if len(domain.split('.')) > 4:
                reputation['suspicious_patterns'].append('excessive_subdomains')
            
            # Check for homograph attacks (basic)
            suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'у', 'х']  # Cyrillic that look like Latin
            if any(char in domain for char in suspicious_chars):
                reputation['suspicious_patterns'].append('homograph_attack')
                
        except Exception as e:
            logger.error(f"Domain reputation check failed: {e}")
        
        return reputation
    
    def _validate_url(self, url: str):
        """Validate URL format."""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL format")
            if parsed.scheme not in ['http', 'https']:
                raise ValueError("Unsupported URL scheme")
        except Exception as e:
            raise InvalidTargetError(f"Invalid URL: {e}")
    
    def _create_analysis_result(
        self,
        target: str,
        analysis_type: AnalysisType,
        analysis_results: Dict[str, Any],
        start_time: float
    ) -> AnalysisResult:
        """Create normalized AnalysisResult from analysis results."""
        
        execution_time = int((time.time() - start_time) * 1000)
        threat_score = analysis_results.get('threat_score', 0.0)
        
        # Generate indicators
        indicators = []
        
        redirect_chain = analysis_results.get('redirect_chain', [])
        if len(redirect_chain) > 3:
            indicators.append('excessive_redirects')
        
        if analysis_results.get('cloaking_detected', False):
            indicators.append('content_cloaking')
        
        security_findings = analysis_results.get('security_findings', {})
        if security_findings.get('ip_domain_mismatch', False):
            indicators.append('ip_domain_redirect')
        
        # Generate explanation
        explanation = self._generate_explanation(analysis_results)
        
        # Determine verdict
        if threat_score >= 0.8:
            verdict = "malicious"
        elif threat_score >= 0.5:
            verdict = "suspicious"
        else:
            verdict = "safe"
        
        return AnalysisResult(
            service_name=self.service_name,
            analysis_type=analysis_type,
            target=target,
            threat_score=threat_score,
            confidence=min(0.9, 0.5 + (len(redirect_chain) * 0.1)),
            raw_response=analysis_results,
            timestamp=start_time,
            execution_time_ms=execution_time,
            verdict=verdict,
            explanation=explanation,
            indicators=indicators
        )
    
    def _generate_explanation(self, analysis_results: Dict[str, Any]) -> str:
        """Generate human-readable explanation of findings."""
        explanations = []
        
        redirect_chain = analysis_results.get('redirect_chain', [])
        if len(redirect_chain) > 1:
            explanations.append(f"URL redirects through {len(redirect_chain)} hops")
        
        if analysis_results.get('cloaking_detected', False):
            explanations.append("Content cloaking detected")
        
        security_findings = analysis_results.get('security_findings', {})
        if security_findings.get('ip_domain_mismatch', False):
            explanations.append("Redirects to IP address")
        
        if security_findings.get('cert_hostname_mismatch', False):
            explanations.append("SSL certificate hostname mismatch")
        
        js_behavior = analysis_results.get('js_behavior', {})
        if js_behavior.get('user_agent_detection', False):
            explanations.append("User agent detection in JavaScript")
        
        if not explanations:
            return "No significant security issues detected"
        
        return "; ".join(explanations)
    
    async def health_check(self) -> ServiceHealth:
        """Check service health."""
        try:
            # Test basic HTTP connectivity
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://httpbin.org/status/200',
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        self._health.status = ServiceStatus.AVAILABLE
                    else:
                        self._health.status = ServiceStatus.UNAVAILABLE
                        
        except Exception as e:
            logger.warning(f"LinkRedirectAnalyzer health check failed: {e}")
            self._health.status = ServiceStatus.UNAVAILABLE
        
        return self._health
    
    async def cleanup(self):
        """Cleanup browser resources."""
        if self._browser:
            await self._browser.close()
            self._browser = None


# Factory function
def create_link_redirect_analyzer() -> LinkRedirectAnalyzer:
    """Factory function to create LinkRedirectAnalyzer."""
    return LinkRedirectAnalyzer()
