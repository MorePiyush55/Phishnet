"""
HTTP Redirect Tracer

Synchronous redirect tracing using aiohttp to follow HTTP redirects,
capture certificate information, and build the redirect chain.
"""

import asyncio
import ssl
import socket
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
import hashlib
import json

import aiohttp
import certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .redirect_interfaces import (
    RedirectHop, RedirectType, TLSCertificateInfo, TLSValidationStatus,
    SECURE_TLS_PROTOCOLS, INSECURE_TLS_PROTOCOLS
)


class HTTPRedirectTracer:
    """Traces HTTP redirects synchronously and captures detailed hop information"""
    
    def __init__(
        self,
        max_concurrent_requests: int = 3,
        default_timeout: int = 15,
        verify_ssl: bool = True
    ):
        self.max_concurrent_requests = max_concurrent_requests
        self.default_timeout = default_timeout
        self.verify_ssl = verify_ssl
        
        # Configure SSL context
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        if not verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
    
    async def trace_redirects(
        self,
        url: str,
        max_hops: int = 10,
        timeout_seconds: int = 15,
        user_agent: str = "Mozilla/5.0 (compatible; phishnet-analyzer/1.0)"
    ) -> List[RedirectHop]:
        """
        Trace HTTP redirects for a URL
        
        Args:
            url: The URL to trace
            max_hops: Maximum number of redirects to follow
            timeout_seconds: Timeout for each request
            user_agent: User agent string to use
            
        Returns:
            List of redirect hops
        """
        hops = []
        current_url = url
        hop_number = 0
        
        # Configure aiohttp session
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers=headers,
            connector=aiohttp.TCPConnector(ssl=self.ssl_context)
        ) as session:
            
            while hop_number < max_hops:
                hop = await self._analyze_hop(
                    session=session,
                    url=current_url,
                    hop_number=hop_number,
                    method='GET'
                )
                
                hops.append(hop)
                
                # Check if we should continue following redirects
                if hop.error or not hop.location_header:
                    break
                
                # Check for redirect status codes
                if hop.status_code not in [301, 302, 303, 307, 308]:
                    break
                
                # Prepare next URL
                current_url = self._resolve_redirect_url(current_url, hop.location_header)
                hop_number += 1
        
        return hops
    
    async def _analyze_hop(
        self,
        session: aiohttp.ClientSession,
        url: str,
        hop_number: int,
        method: str = 'GET'
    ) -> RedirectHop:
        """Analyze a single hop in the redirect chain"""
        start_time = time.time()
        
        hop = RedirectHop(
            hop_number=hop_number,
            url=url,
            method=method,
            timestamp=start_time
        )
        
        try:
            # Parse URL for hostname resolution
            parsed_url = urlparse(url)
            hop.resolved_hostname = parsed_url.hostname
            
            # Resolve IP address
            if parsed_url.hostname:
                try:
                    hop.resolved_ip = socket.gethostbyname(parsed_url.hostname)
                except socket.gaierror:
                    hop.resolved_ip = None
            
            # Make HTTP request
            async with session.get(
                url,
                allow_redirects=False,  # We handle redirects manually
                ssl=self.ssl_context
            ) as response:
                
                # Capture response details
                hop.status_code = response.status
                hop.response_time_ms = int((time.time() - start_time) * 1000)
                hop.content_length = response.headers.get('content-length')
                hop.content_type = response.headers.get('content-type')
                hop.server_header = response.headers.get('server')
                hop.location_header = response.headers.get('location')
                
                # Store all response headers
                hop.response_headers = dict(response.headers)
                
                # Determine redirect type
                if hop.status_code in [301, 302, 303, 307, 308]:
                    hop.redirect_type = self._get_redirect_type(hop.status_code)
                
                # Analyze TLS certificate for HTTPS
                if parsed_url.scheme == 'https':
                    hop.tls_info = await self._analyze_tls_certificate(
                        hostname=parsed_url.hostname,
                        port=parsed_url.port or 443,
                        response=response
                    )
                
        except asyncio.TimeoutError:
            hop.error = "Request timeout"
        except aiohttp.ClientConnectorError as e:
            hop.error = f"Connection error: {str(e)}"
        except aiohttp.ClientError as e:
            hop.error = f"HTTP client error: {str(e)}"
        except Exception as e:
            hop.error = f"Unexpected error: {str(e)}"
        
        return hop
    
    async def _analyze_tls_certificate(
        self,
        hostname: str,
        port: int,
        response: aiohttp.ClientResponse
    ) -> TLSCertificateInfo:
        """Analyze TLS certificate information"""
        tls_info = TLSCertificateInfo()
        
        try:
            # Get certificate from the connection
            if hasattr(response.connection, 'transport') and response.connection.transport:
                ssl_object = response.connection.transport.get_extra_info('ssl_object')
                if ssl_object:
                    # Get peer certificate
                    peer_cert_der = ssl_object.getpeercert(binary_form=True)
                    if peer_cert_der:
                        cert = x509.load_der_x509_certificate(peer_cert_der, default_backend())
                        
                        # Extract certificate details
                        tls_info.subject = cert.subject.rfc4514_string()
                        tls_info.issuer = cert.issuer.rfc4514_string()
                        tls_info.not_before = cert.not_valid_before.isoformat()
                        tls_info.not_after = cert.not_valid_after.isoformat()
                        tls_info.serial_number = str(cert.serial_number)
                        
                        # Calculate SHA256 fingerprint
                        fingerprint = hashlib.sha256(peer_cert_der).hexdigest()
                        tls_info.fingerprint_sha256 = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
                        
                        # Extract SAN domains
                        try:
                            san_extension = cert.extensions.get_extension_for_oid(
                                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                            )
                            san_names = san_extension.value.get_values_for_type(x509.DNSName)
                            tls_info.san_domains = list(san_names)
                        except x509.ExtensionNotFound:
                            pass
                        
                        # Validate certificate
                        tls_info.validation_status, tls_info.validation_errors = self._validate_certificate(
                            cert, hostname
                        )
                        
                        # Check protocol version
                        protocol_version = ssl_object.version()
                        if protocol_version in INSECURE_TLS_PROTOCOLS:
                            tls_info.validation_errors.append(f"Insecure protocol: {protocol_version}")
                            if tls_info.validation_status == TLSValidationStatus.VALID:
                                tls_info.validation_status = TLSValidationStatus.INVALID
        
        except Exception as e:
            tls_info.validation_status = TLSValidationStatus.UNKNOWN
            tls_info.validation_errors.append(f"Certificate analysis error: {str(e)}")
        
        return tls_info
    
    def _validate_certificate(self, cert: x509.Certificate, hostname: str) -> Tuple[TLSValidationStatus, List[str]]:
        """Validate TLS certificate"""
        errors = []
        
        # Check if certificate is expired
        now = time.time()
        if cert.not_valid_after.timestamp() < now:
            return TLSValidationStatus.EXPIRED, ["Certificate has expired"]
        
        if cert.not_valid_before.timestamp() > now:
            return TLSValidationStatus.INVALID, ["Certificate not yet valid"]
        
        # Check hostname matching
        hostname_valid = False
        
        # Check subject common name
        try:
            subject_cn = None
            for attribute in cert.subject:
                if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                    subject_cn = attribute.value
                    break
            
            if subject_cn and self._hostname_matches(hostname, subject_cn):
                hostname_valid = True
        except Exception:
            pass
        
        # Check SAN domains
        if not hostname_valid:
            try:
                san_extension = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                san_names = san_extension.value.get_values_for_type(x509.DNSName)
                for san_name in san_names:
                    if self._hostname_matches(hostname, san_name):
                        hostname_valid = True
                        break
            except x509.ExtensionNotFound:
                pass
        
        if not hostname_valid:
            errors.append(f"Hostname {hostname} does not match certificate")
            return TLSValidationStatus.HOSTNAME_MISMATCH, errors
        
        # Check if self-signed
        if cert.subject == cert.issuer:
            return TLSValidationStatus.SELF_SIGNED, ["Certificate is self-signed"]
        
        # If we get here, certificate appears valid
        return TLSValidationStatus.VALID, errors
    
    def _hostname_matches(self, hostname: str, cert_name: str) -> bool:
        """Check if hostname matches certificate name (supports wildcards)"""
        hostname = hostname.lower()
        cert_name = cert_name.lower()
        
        if cert_name == hostname:
            return True
        
        # Handle wildcard certificates
        if cert_name.startswith('*.'):
            cert_domain = cert_name[2:]
            if '.' in hostname:
                hostname_domain = hostname.split('.', 1)[1]
                return cert_domain == hostname_domain
        
        return False
    
    def _get_redirect_type(self, status_code: int) -> RedirectType:
        """Convert HTTP status code to redirect type"""
        redirect_map = {
            301: RedirectType.HTTP_301,
            302: RedirectType.HTTP_302,
            303: RedirectType.HTTP_303,
            307: RedirectType.HTTP_307,
            308: RedirectType.HTTP_308
        }
        return redirect_map.get(status_code, RedirectType.HTTP_302)
    
    def _resolve_redirect_url(self, base_url: str, location: str) -> str:
        """Resolve relative redirect URLs to absolute URLs"""
        if location.startswith(('http://', 'https://')):
            return location
        return urljoin(base_url, location)


class MetaRefreshDetector:
    """Detects meta refresh redirects in HTML content"""
    
    @staticmethod
    def extract_meta_refresh(html_content: str) -> Optional[Tuple[int, str]]:
        """
        Extract meta refresh directive from HTML content
        
        Returns:
            Tuple of (delay_seconds, url) if found, None otherwise
        """
        import re
        
        # Look for meta refresh tags
        meta_pattern = r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\']([^"\']*)["\'][^>]*>'
        matches = re.finditer(meta_pattern, html_content, re.IGNORECASE)
        
        for match in matches:
            content = match.group(1)
            
            # Parse content attribute (format: "delay;url=...")
            if ';' in content:
                parts = content.split(';', 1)
                try:
                    delay = int(parts[0].strip())
                    url_part = parts[1].strip()
                    
                    # Extract URL
                    if url_part.lower().startswith('url='):
                        url = url_part[4:].strip()
                        return delay, url
                except ValueError:
                    continue
            else:
                # Just a delay, no URL
                try:
                    delay = int(content.strip())
                    return delay, ""
                except ValueError:
                    continue
        
        return None


class JavaScriptRedirectDetector:
    """Detects JavaScript-based redirects in HTML/JS content"""
    
    @staticmethod
    def extract_js_redirects(content: str) -> List[Tuple[str, str]]:
        """
        Extract JavaScript redirects from content
        
        Returns:
            List of (redirect_type, url) tuples
        """
        import re
        
        redirects = []
        
        # Common JavaScript redirect patterns
        patterns = [
            # window.location = "url"
            (r'window\.location\s*=\s*["\']([^"\']+)["\']', 'location_assignment'),
            # window.location.href = "url"
            (r'window\.location\.href\s*=\s*["\']([^"\']+)["\']', 'location_href'),
            # window.location.replace("url")
            (r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)', 'location_replace'),
            # location.href = "url"
            (r'location\.href\s*=\s*["\']([^"\']+)["\']', 'location_href'),
            # document.location = "url"
            (r'document\.location\s*=\s*["\']([^"\']+)["\']', 'document_location'),
            # window.open("url", "_self")
            (r'window\.open\s*\(\s*["\']([^"\']+)["\'][\s,]*["\']_self["\']', 'window_open_self'),
        ]
        
        for pattern, redirect_type in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                url = match.group(1)
                redirects.append((redirect_type, url))
        
        return redirects


class RedirectChainAnalyzer:
    """Analyzes complete redirect chains for security issues"""
    
    @staticmethod
    def analyze_security_issues(hops: List[RedirectHop]) -> Dict[str, any]:
        """
        Analyze redirect chain for security issues
        
        Returns:
            Dictionary with security analysis results
        """
        analysis = {
            'insecure_hops': [],
            'mixed_content': False,
            'tls_issues': [],
            'suspicious_patterns': [],
            'reputation_issues': []
        }
        
        https_seen = False
        http_seen = False
        
        for hop in hops:
            parsed_url = urlparse(hop.url)
            
            # Track protocol usage
            if parsed_url.scheme == 'https':
                https_seen = True
            elif parsed_url.scheme == 'http':
                http_seen = True
            
            # Check for TLS issues
            if hop.tls_info and hop.tls_info.validation_status != TLSValidationStatus.VALID:
                analysis['tls_issues'].append({
                    'hop': hop.hop_number,
                    'url': hop.url,
                    'status': hop.tls_info.validation_status.value,
                    'errors': hop.tls_info.validation_errors
                })
                analysis['insecure_hops'].append(hop.hop_number)
            
            # Check for HTTP after HTTPS (protocol downgrade)
            if https_seen and parsed_url.scheme == 'http':
                analysis['suspicious_patterns'].append(
                    f"Protocol downgrade from HTTPS to HTTP at hop {hop.hop_number}"
                )
                analysis['insecure_hops'].append(hop.hop_number)
            
            # Check for reputation issues
            if hop.vt_score and hop.vt_score > 0.3:
                analysis['reputation_issues'].append({
                    'hop': hop.hop_number,
                    'url': hop.url,
                    'vt_score': hop.vt_score
                })
            
            if hop.abuse_score and hop.abuse_score > 0.3:
                analysis['reputation_issues'].append({
                    'hop': hop.hop_number,
                    'url': hop.url,
                    'abuse_score': hop.abuse_score
                })
        
        # Check for mixed content
        if https_seen and http_seen:
            analysis['mixed_content'] = True
        
        return analysis
    
    @staticmethod
    def calculate_chain_reputation(hops: List[RedirectHop]) -> float:
        """Calculate weighted reputation score for the entire chain"""
        if not hops:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        for i, hop in enumerate(hops):
            # Weight later hops more heavily (final destination most important)
            weight = 1.0 + (i * 0.2)
            
            hop_score = 0.0
            if hop.vt_score:
                hop_score = max(hop_score, hop.vt_score)
            if hop.abuse_score:
                hop_score = max(hop_score, hop.abuse_score)
            if hop.domain_reputation:
                hop_score = max(hop_score, hop.domain_reputation)
            
            total_score += hop_score * weight
            total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
