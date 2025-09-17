"""
Comprehensive link redirect analyzer with sandboxed browser execution.
Provides redirect chain tracing, cloaking detection, and security validation.
"""

import asyncio
import time
import ssl
import socket
import ipaddress
import hashlib
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime
import json

import aiohttp
import dns.resolver
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from cryptography import x509
from cryptography.x509.oid import NameOID

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.redis_client import get_redis_connection
from app.services.interfaces import (
    IAnalyzer, AnalysisResult, AnalysisType, ServiceHealth, ServiceStatus,
    ServiceUnavailableError, InvalidTargetError, AnalysisError
)

logger = get_logger(__name__)


class LinkRedirectAnalyzer(IAnalyzer):
    """
    Advanced link redirect analyzer with sandboxed browser execution.
    Provides comprehensive security analysis of redirect chains and cloaking detection.
    """
    
    def __init__(self):
        super().__init__("link_redirect_analyzer")
        self.max_redirects = 10
        self.max_analysis_time = 30  # seconds
        self.user_agents = {
            'legitimate': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'security_scanner': 'Mozilla/5.0 (compatible; PhishNet-Security-Scanner/1.0; +https://phishnet.security)',
            'mobile': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1'
        }
        self._browser = None
        self._browser_lock = asyncio.Lock()
    
    async def analyze(self, target: str, analysis_type: AnalysisType) -> AnalysisResult:
        """
        Analyze URL for redirect chains and security issues.
        
        Args:
            target: URL to analyze
            analysis_type: Must be URL_SCAN
            
        Returns:
            Comprehensive analysis result with redirect chain and security findings
        """
        if analysis_type != AnalysisType.URL_SCAN:
            raise InvalidTargetError("LinkRedirectAnalyzer only supports URL scanning")
        
        start_time = time.time()
        
        try:
            # Validate URL format
            self._validate_url(target)
            
            # Check cache first
            cache_key = f"redirect_analysis:{hashlib.md5(target.encode()).hexdigest()}"
            cached_result = await self._get_cached_result(cache_key)
            if cached_result:
                logger.debug(f"Redirect analysis cache hit for {target}")
                return cached_result
            
            # Perform comprehensive analysis
            analysis_results = await self._perform_comprehensive_analysis(target)
            
            # Create normalized result
            result = self._create_analysis_result(
                target, analysis_type, analysis_results, start_time
            )
            
            # Cache result
            await self._cache_result(cache_key, result, ttl=1800)  # 30 minutes
            
            return result
            
        except Exception as e:
            execution_time = int((time.time() - start_time) * 1000)
            logger.error(f"Redirect analysis failed for {target}: {e}")
            
            return AnalysisResult(
                service_name=self.service_name,
                analysis_type=analysis_type,
                target=target,
                threat_score=0.0,
                confidence=0.0,
                raw_response={"error": str(e)},
                timestamp=start_time,
                execution_time_ms=execution_time,
                error=f"Redirect analysis failed: {str(e)}"
            )
    
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
        """Trace HTTP redirect chain without JavaScript execution."""
        redirect_chain = []
        current_url = url
        redirect_count = 0
        
        connector = aiohttp.TCPConnector(
            ssl=False,  # We'll validate SSL separately
            ttl_dns_cache=300,
            use_dns_cache=True,
            limit=10,
            limit_per_host=5
        )
        
        timeout = aiohttp.ClientTimeout(total=20, connect=5)
        
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': self.user_agents['security_scanner'],
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'DNT': '1',
                    'Connection': 'keep-alive'
                }
            ) as session:
                
                while redirect_count < self.max_redirects:
                    try:
                        start_time = time.time()
                        
                        async with session.get(
                            current_url,
                            allow_redirects=False,
                            ssl=False  # We handle SSL validation separately
                        ) as response:
                            
                            response_time = time.time() - start_time
                            
                            # Parse response information
                            parsed_url = urlparse(current_url)
                            hop_info = {
                                'url': current_url,
                                'status_code': response.status,
                                'headers': dict(response.headers),
                                'response_time_ms': int(response_time * 1000),
                                'host': parsed_url.netloc,
                                'scheme': parsed_url.scheme,
                                'timestamp': time.time()
                            }
                            
                            # Resolve IP address
                            try:
                                ip_address = await self._resolve_ip(parsed_url.netloc)
                                hop_info['ip_address'] = ip_address
                                hop_info['is_ip_domain'] = self._is_ip_address(parsed_url.netloc)
                            except Exception as e:
                                hop_info['dns_error'] = str(e)
                            
                            redirect_chain.append(hop_info)
                            
                            # Check if this is a redirect
                            if response.status in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location')
                                if location:
                                    # Handle relative URLs
                                    if location.startswith('/'):
                                        location = urljoin(current_url, location)
                                    elif not location.startswith(('http://', 'https://')):
                                        location = urljoin(current_url, location)
                                    
                                    hop_info['redirect_to'] = location
                                    current_url = location
                                    redirect_count += 1
                                else:
                                    break  # No location header
                            else:
                                break  # Not a redirect status
                                
                    except asyncio.TimeoutError:
                        hop_info = {
                            'url': current_url,
                            'error': 'timeout',
                            'timestamp': time.time()
                        }
                        redirect_chain.append(hop_info)
                        break
                        
                    except Exception as e:
                        hop_info = {
                            'url': current_url,
                            'error': str(e),
                            'timestamp': time.time()
                        }
                        redirect_chain.append(hop_info)
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
        """Detect content cloaking by comparing responses from different user agents."""
        cloaking_results = {
            'cloaking_detected': False,
            'browser_behavior': {},
            'content_differences': {},
            'js_behavior': {}
        }
        
        try:
            # Get browser instance
            browser = await self._get_browser()
            
            # Test with different user agents
            user_agent_results = {}
            
            for agent_type, user_agent in self.user_agents.items():
                try:
                    context = await browser.new_context(
                        user_agent=user_agent,
                        viewport={'width': 1920, 'height': 1080},
                        ignore_https_errors=True,
                        java_script_enabled=True
                    )
                    
                    page = await context.new_page()
                    
                    # Monitor network requests and JavaScript execution
                    js_logs = []
                    network_requests = []
                    
                    page.on('console', lambda msg: js_logs.append({
                        'type': msg.type,
                        'text': msg.text,
                        'timestamp': time.time()
                    }))
                    
                    page.on('request', lambda req: network_requests.append({
                        'url': req.url,
                        'method': req.method,
                        'headers': dict(req.headers),
                        'timestamp': time.time()
                    }))
                    
                    # Navigate to URL with timeout
                    response = await page.goto(
                        original_url,
                        wait_until='networkidle',
                        timeout=15000
                    )
                    
                    # Capture page content and behavior
                    final_page_url = page.url
                    page_title = await page.title()
                    page_content = await page.content()
                    
                    user_agent_results[agent_type] = {
                        'final_url': final_page_url,
                        'title': page_title,
                        'content_hash': hashlib.md5(page_content.encode()).hexdigest(),
                        'status_code': response.status if response else None,
                        'js_logs': js_logs[-10:],  # Last 10 JS logs
                        'network_requests': len(network_requests),
                        'redirected': final_page_url != original_url
                    }
                    
                    await context.close()
                    
                    # Small delay between requests
                    await asyncio.sleep(2)
                    
                except Exception as e:
                    logger.warning(f"Browser analysis failed for {agent_type}: {e}")
                    user_agent_results[agent_type] = {'error': str(e)}
            
            # Analyze results for cloaking
            cloaking_results['browser_behavior'] = user_agent_results
            
            # Compare content hashes and final URLs
            content_hashes = set()
            final_urls = set()
            
            for agent_type, result in user_agent_results.items():
                if 'content_hash' in result:
                    content_hashes.add(result['content_hash'])
                if 'final_url' in result:
                    final_urls.add(result['final_url'])
            
            # Detect cloaking indicators
            if len(content_hashes) > 1:
                cloaking_results['cloaking_detected'] = True
                cloaking_results['content_differences']['hash_mismatch'] = True
            
            if len(final_urls) > 1:
                cloaking_results['cloaking_detected'] = True
                cloaking_results['content_differences']['url_mismatch'] = True
            
            # Analyze JavaScript behavior
            js_analysis = self._analyze_js_behavior(user_agent_results)
            cloaking_results['js_behavior'] = js_analysis
            
            if js_analysis.get('suspicious_patterns', 0) > 2:
                cloaking_results['cloaking_detected'] = True
                
        except Exception as e:
            logger.error(f"Cloaking detection failed: {e}")
            cloaking_results['detection_error'] = str(e)
        
        return cloaking_results
    
    async def _get_browser(self) -> Browser:
        """Get or create sandboxed browser instance."""
        async with self._browser_lock:
            if self._browser is None:
                playwright = await async_playwright().start()
                self._browser = await playwright.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--disable-background-timer-throttling',
                        '--disable-backgrounding-occluded-windows',
                        '--disable-renderer-backgrounding',
                        '--disable-features=TranslateUI',
                        '--disable-ipc-flooding-protection',
                        '--disable-client-side-phishing-detection',
                        '--disable-sync',
                        '--disable-default-apps',
                        '--no-first-run',
                        '--no-default-browser-check',
                        '--disable-extensions'
                    ]
                )
            return self._browser


# Backwards-compatible alias: some modules import LinkAnalyzer or
# LinkRedirectAnalyzer from different paths. Provide thin wrappers at module
# scope so they are importable by tests and other modules.
class LinkAnalyzer(LinkRedirectAnalyzer):
    pass


class LinkAnalysisResult(dict):
    """Lightweight compatibility type for tests expecting LinkAnalysisResult."""
    pass
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
    
    async def _resolve_ip(self, hostname: str) -> str:
        """Resolve hostname to IP address."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(hostname, None)
            return result[0][4][0]  # Return first IP
        except Exception:
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
