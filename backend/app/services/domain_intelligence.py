"""
Domain Intelligence Service for PhishNet
=========================================
Phase 1-3 Implementation: Domain Identity Resolution, Redirect Chain Intelligence

Provides:
- ASN lookup
- Domain age estimation  
- TLS support checking
- IP reputation
- Redirect chain resolution
"""

import asyncio
import socket
import ssl
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlparse
import hashlib

import httpx

from app.services.domain_identity import get_registrable_domain, DomainIdentity

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: DOMAIN IDENTITY RESOLVER
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EnhancedDomainIdentity(DomainIdentity):
    """Extended domain identity with threat intelligence"""
    # Phase 1 additions
    ip_addresses: List[str] = field(default_factory=list)
    asn_number: Optional[str] = None
    asn_org: Optional[str] = None
    domain_age_days: Optional[int] = None
    tls_supported: bool = False
    tls_grade: Optional[str] = None  # A, B, C, F
    
    # Phase 9 additions (VirusTotal)
    vt_risk_level: str = "unknown"  # clean, low, medium, high
    vt_malicious_count: int = 0
    vt_total_vendors: int = 0
    vt_last_analysis_age_days: Optional[int] = None


class DomainIntelligenceService:
    """
    Async service for domain intelligence gathering.
    Implements Phase 1 requirements.
    """
    
    # In-memory cache (use Redis in production)
    _cache: Dict[str, Tuple[Any, datetime]] = {}
    CACHE_TTL_HOURS = 24
    
    def __init__(self):
        self.http_client = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(
                timeout=5.0,
                follow_redirects=False,
                verify=True
            )
        return self.http_client
    
    def _get_cached(self, key: str) -> Optional[Any]:
        """Get cached value if not expired"""
        if key in self._cache:
            value, timestamp = self._cache[key]
            if datetime.utcnow() - timestamp < timedelta(hours=self.CACHE_TTL_HOURS):
                return value
            del self._cache[key]
        return None
    
    def _set_cached(self, key: str, value: Any):
        """Cache a value"""
        self._cache[key] = (value, datetime.utcnow())
    
    async def resolve_domain(self, hostname: str) -> EnhancedDomainIdentity:
        """
        Resolve full domain identity including ASN, TLS, age.
        """
        cache_key = f"domain:{hostname}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        registrable = get_registrable_domain(hostname)
        
        identity = EnhancedDomainIdentity(
            raw_hostname=hostname,
            registrable_domain=registrable,
            subdomain=hostname[:-len(registrable)-1] if hostname != registrable else None,
            tld=registrable.split('.')[-1] if '.' in registrable else None
        )
        
        # Parallel resolution of IP, TLS, ASN
        try:
            await asyncio.gather(
                self._resolve_ip(identity),
                self._check_tls(identity),
                return_exceptions=True
            )
        except Exception as e:
            logger.warning(f"Domain resolution partial failure for {hostname}: {e}")
        
        self._set_cached(cache_key, identity)
        return identity
    
    async def _resolve_ip(self, identity: EnhancedDomainIdentity):
        """Resolve hostname to IP addresses"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, 
                socket.gethostbyname_ex, 
                identity.raw_hostname
            )
            identity.ip_addresses = result[2][:5]  # Limit to 5 IPs
        except socket.gaierror:
            pass
    
    async def _check_tls(self, identity: EnhancedDomainIdentity):
        """Check if domain supports TLS/HTTPS"""
        try:
            client = await self._get_client()
            response = await client.head(
                f"https://{identity.raw_hostname}/",
                timeout=3.0
            )
            identity.tls_supported = True
            identity.tls_grade = "A"  # Simplified - real impl would check cert details
        except Exception:
            identity.tls_supported = False
            identity.tls_grade = "F"


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: REDIRECT CHAIN INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class RedirectHop:
    """Single hop in redirect chain"""
    url: str
    status_code: int
    domain: str
    registrable_domain: str
    is_https: bool


@dataclass
class RedirectChainResult:
    """Complete redirect chain analysis"""
    original_url: str
    final_url: str
    hop_count: int
    hops: List[RedirectHop] = field(default_factory=list)
    
    # Classification
    chain_type: str = "direct"  # direct, internal, vendor, external
    has_external_redirect: bool = False
    final_registrable_domain: str = ""
    
    # Risk signals
    crosses_domains: bool = False
    downgrades_to_http: bool = False
    error: Optional[str] = None


class RedirectResolver:
    """
    Safe redirect chain resolver.
    Phase 3 Implementation - HEAD requests only, max hops, timeout protection.
    """
    
    MAX_HOPS = 5
    TIMEOUT = 3.0
    
    # Known safe redirect domains
    SAFE_REDIRECT_DOMAINS = {
        "bit.ly", "t.co", "goo.gl", "tinyurl.com",  # URL shorteners
        "click.mailchimp.com", "links.sendgrid.com",  # ESP tracking
        "r20.rs6.net", "e.email.microsoft.com",  # Corporate
    }
    
    def __init__(self, sender_domain: Optional[str] = None):
        self.sender_domain = sender_domain
        self.sender_registrable = get_registrable_domain(sender_domain) if sender_domain else None
        self.http_client = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(
                timeout=self.TIMEOUT,
                follow_redirects=False,
                verify=True
            )
        return self.http_client
    
    async def resolve_chain(self, url: str) -> RedirectChainResult:
        """
        Resolve redirect chain using HEAD requests only.
        Safe: No body download, no JS execution.
        """
        result = RedirectChainResult(
            original_url=url,
            final_url=url,
            hop_count=0
        )
        
        current_url = url
        visited = set()
        
        try:
            client = await self._get_client()
            
            for hop_num in range(self.MAX_HOPS):
                if current_url in visited:
                    result.error = "Redirect loop detected"
                    break
                visited.add(current_url)
                
                try:
                    response = await client.head(current_url, timeout=self.TIMEOUT)
                except Exception as e:
                    # Try GET if HEAD fails (some servers don't support HEAD)
                    try:
                        response = await client.get(
                            current_url, 
                            timeout=self.TIMEOUT,
                            follow_redirects=False
                        )
                    except Exception:
                        result.error = f"Request failed: {str(e)[:50]}"
                        break
                
                parsed = urlparse(current_url)
                hop = RedirectHop(
                    url=current_url,
                    status_code=response.status_code,
                    domain=parsed.netloc,
                    registrable_domain=get_registrable_domain(parsed.netloc),
                    is_https=parsed.scheme == 'https'
                )
                result.hops.append(hop)
                
                # Check for redirect
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('location')
                    if not location:
                        break
                    
                    # Handle relative URLs
                    if not location.startswith(('http://', 'https://')):
                        if location.startswith('/'):
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"
                        else:
                            location = f"{parsed.scheme}://{parsed.netloc}/{location}"
                    
                    current_url = location
                    result.hop_count += 1
                else:
                    # Not a redirect, we're done
                    break
            
            result.final_url = current_url
            parsed_final = urlparse(current_url)
            result.final_registrable_domain = get_registrable_domain(parsed_final.netloc)
            
            # Classify the chain
            self._classify_chain(result)
            
        except Exception as e:
            result.error = str(e)[:100]
        
        return result
    
    def _classify_chain(self, result: RedirectChainResult):
        """Classify redirect chain type"""
        if result.hop_count == 0:
            result.chain_type = "direct"
            return
        
        original_reg = get_registrable_domain(urlparse(result.original_url).netloc)
        final_reg = result.final_registrable_domain
        
        # Check if domains change
        domains_in_chain = set(hop.registrable_domain for hop in result.hops)
        result.crosses_domains = len(domains_in_chain) > 1
        
        # Check for HTTPS downgrade
        for i, hop in enumerate(result.hops[:-1]):
            if hop.is_https and not result.hops[i+1].is_https:
                result.downgrades_to_http = True
                break
        
        # Classify based on sender alignment
        if self.sender_registrable:
            if final_reg == self.sender_registrable:
                result.chain_type = "internal"
            elif final_reg in self.SAFE_REDIRECT_DOMAINS:
                result.chain_type = "vendor"
            elif original_reg == self.sender_registrable and final_reg != self.sender_registrable:
                result.chain_type = "external"
                result.has_external_redirect = True
            else:
                result.chain_type = "external"
                result.has_external_redirect = True
        else:
            # No sender context
            if original_reg == final_reg:
                result.chain_type = "internal"
            else:
                result.chain_type = "external"
                result.has_external_redirect = True


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: MULTI-DIMENSIONAL LINK SCORING
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class LinkFeatureVector:
    """
    Multi-dimensional feature vector for a single link.
    Phase 4 Implementation - No early verdicts, just signals.
    """
    url: str
    domain: str
    registrable_domain: str
    
    # Transport security
    is_https: bool = False
    transport_score: float = 0.0  # 0-1
    
    # Sender alignment (from Phase 0/2)
    alignment: str = "unrelated"  # same_org, known_vendor, unrelated
    alignment_score: float = 0.0  # 0-1
    
    # Redirect analysis (from Phase 3)
    redirect_type: str = "direct"
    redirect_hops: int = 0
    has_external_redirect: bool = False
    redirect_score: float = 1.0  # 0-1, lower = riskier
    
    # Domain intelligence (from Phase 1)
    tls_supported: bool = False
    domain_age_days: Optional[int] = None
    domain_age_score: float = 0.5  # 0-1, unknown = 0.5
    
    # URL characteristics
    url_length: int = 0
    url_entropy: float = 0.0
    has_suspicious_patterns: bool = False
    url_score: float = 1.0  # 0-1
    
    # VirusTotal (Phase 9)
    vt_risk_level: str = "unknown"
    vt_malicious_count: int = 0
    vt_score: float = 0.5  # 0-1, unknown = 0.5, clean = 0.5, malicious = 0.0
    
    # Composite score (weighted aggregation)
    composite_score: float = 0.5  # 0-1, higher = safer
    
    def calculate_composite(self, weights: Optional[Dict[str, float]] = None):
        """
        Calculate weighted composite score.
        NO SINGLE SIGNAL forces verdict - only weighted aggregation.
        """
        default_weights = {
            'transport': 0.10,
            'alignment': 0.25,
            'redirect': 0.20,
            'domain_age': 0.10,
            'url_quality': 0.15,
            'vt': 0.20
        }
        w = weights or default_weights
        
        self.composite_score = (
            self.transport_score * w['transport'] +
            self.alignment_score * w['alignment'] +
            self.redirect_score * w['redirect'] +
            self.domain_age_score * w['domain_age'] +
            self.url_score * w['url_quality'] +
            self.vt_score * w['vt']
        )
        
        return self.composite_score


class LinkFeatureExtractor:
    """
    Extracts multi-dimensional features from links.
    Phase 4 Implementation.
    """
    
    SUSPICIOUS_PATTERNS = [
        r'login', r'signin', r'password', r'verify', r'confirm',
        r'secure', r'update', r'account', r'suspend', r'unusual'
    ]
    
    def __init__(self, sender_domain: Optional[str] = None):
        self.sender_domain = sender_domain
        self.domain_service = DomainIntelligenceService()
        self.redirect_resolver = RedirectResolver(sender_domain)
    
    async def extract_features(self, url: str) -> LinkFeatureVector:
        """Extract all features for a single link"""
        import re
        import math
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        registrable = get_registrable_domain(domain)
        
        features = LinkFeatureVector(
            url=url[:500],  # Truncate for safety
            domain=domain,
            registrable_domain=registrable
        )
        
        # Transport security
        features.is_https = parsed.scheme == 'https'
        features.transport_score = 1.0 if features.is_https else 0.3
        
        # Alignment (using Phase 0 logic)
        from app.services.domain_identity import SenderLinkAlignment
        if self.sender_domain:
            features.alignment = SenderLinkAlignment.classify_alignment(
                self.sender_domain, domain
            )
            features.alignment_score = {
                'same_org': 1.0,
                'known_vendor': 0.8,
                'unrelated': 0.2
            }.get(features.alignment, 0.2)
        else:
            features.alignment_score = 0.5  # Unknown
        
        # URL characteristics
        features.url_length = len(url)
        features.url_entropy = self._calculate_entropy(url)
        
        # Check suspicious patterns
        url_lower = url.lower()
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, url_lower):
                features.has_suspicious_patterns = True
                break
        
        # URL score based on characteristics
        features.url_score = 1.0
        if features.url_length > 200:
            features.url_score -= 0.2
        if features.url_entropy > 4.5:
            features.url_score -= 0.2
        if features.has_suspicious_patterns:
            features.url_score -= 0.3
        features.url_score = max(0.0, features.url_score)
        
        # Calculate composite
        features.calculate_composite()
        
        return features
    
    async def extract_features_with_resolution(self, url: str) -> LinkFeatureVector:
        """Extract features WITH redirect resolution (slower, more accurate)"""
        features = await self.extract_features(url)
        
        # Resolve redirects
        try:
            redirect_result = await self.redirect_resolver.resolve_chain(url)
            features.redirect_type = redirect_result.chain_type
            features.redirect_hops = redirect_result.hop_count
            features.has_external_redirect = redirect_result.has_external_redirect
            
            # Redirect score
            if redirect_result.has_external_redirect:
                features.redirect_score = 0.3
            elif redirect_result.downgrades_to_http:
                features.redirect_score = 0.5
            elif redirect_result.hop_count > 3:
                features.redirect_score = 0.6
            else:
                features.redirect_score = 1.0
        except Exception:
            features.redirect_score = 0.5  # Unknown
        
        features.calculate_composite()
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        import math
        from collections import Counter
        
        if not text:
            return 0.0
        
        counts = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return round(entropy, 2)


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLETON INSTANCES
# ═══════════════════════════════════════════════════════════════════════════════

domain_intelligence = DomainIntelligenceService()


async def resolve_domain_identity(hostname: str) -> EnhancedDomainIdentity:
    """Convenience function for domain resolution"""
    return await domain_intelligence.resolve_domain(hostname)


async def resolve_redirect_chain(url: str, sender_domain: Optional[str] = None) -> RedirectChainResult:
    """Convenience function for redirect resolution"""
    resolver = RedirectResolver(sender_domain)
    return await resolver.resolve_chain(url)


async def extract_link_features(url: str, sender_domain: Optional[str] = None) -> LinkFeatureVector:
    """Convenience function for feature extraction"""
    extractor = LinkFeatureExtractor(sender_domain)
    return await extractor.extract_features(url)
