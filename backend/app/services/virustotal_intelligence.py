"""
VirusTotal Threat Intelligence Service for PhishNet
=====================================================
Phase 9 Implementation: Context-aware VT integration

Key Principles:
1. VT is ONE signal, not a verdict
2. Query only final destinations + eTLD+1
3. Clean VT = neutral (never positive)
4. Context arbitration: authenticated + aligned downgrades severity
5. Cache + conditional querying for cost control
"""

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from enum import Enum

import httpx

from app.config.settings import get_settings
from app.services.domain_identity import get_registrable_domain

logger = logging.getLogger(__name__)
settings = get_settings()


class VTRiskLevel(str, Enum):
    """VirusTotal risk levels - normalized"""
    UNKNOWN = "unknown"
    CLEAN = "clean"
    LOW_CONFIDENCE = "low_confidence"
    MEDIUM_CONFIDENCE = "medium_confidence"
    HIGH_CONFIDENCE = "high_confidence"


@dataclass
class VTResult:
    """Normalized VirusTotal result"""
    url_or_hash: str
    risk_level: VTRiskLevel = VTRiskLevel.UNKNOWN
    malicious_count: int = 0
    suspicious_count: int = 0
    total_vendors: int = 0
    
    # Analysis metadata
    last_analysis_date: Optional[datetime] = None
    analysis_age_days: Optional[int] = None
    
    # Score contribution (0-1, 0.5 = neutral)
    score: float = 0.5
    
    # Raw data
    categories: List[str] = field(default_factory=list)
    error: Optional[str] = None
    from_cache: bool = False


class VirusTotalService:
    """
    Phase 9: VirusTotal Integration Service
    
    Implements:
    - Smart query control (only query suspicious links)
    - Result normalization
    - Context-aware scoring
    - Caching with TTL
    """
    
    # Cache with TTL
    _cache: Dict[str, tuple] = {}  # key -> (result, timestamp)
    CACHE_TTL_HOURS = 24
    
    # API configuration
    API_BASE = "https://www.virustotal.com/api/v3"
    
    def __init__(self):
        self.api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
        self.http_client = None
        
    @property
    def is_available(self) -> bool:
        return bool(self.api_key)
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(
                timeout=10.0,
                headers={"x-apikey": self.api_key or ""}
            )
        return self.http_client
    
    def _get_cache_key(self, url_or_hash: str) -> str:
        """Generate cache key from URL or hash"""
        # For URLs, use registrable domain as cache key
        if url_or_hash.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            domain = urlparse(url_or_hash).netloc
            return f"vt:domain:{get_registrable_domain(domain)}"
        else:
            return f"vt:hash:{url_or_hash}"
    
    def _get_cached(self, key: str) -> Optional[VTResult]:
        """Get cached result if not expired"""
        if key in self._cache:
            result, timestamp = self._cache[key]
            if datetime.utcnow() - timestamp < timedelta(hours=self.CACHE_TTL_HOURS):
                result.from_cache = True
                return result
            del self._cache[key]
        return None
    
    def _set_cached(self, key: str, result: VTResult):
        """Cache a result"""
        self._cache[key] = (result, datetime.utcnow())
    
    async def check_url(self, url: str) -> VTResult:
        """
        Check URL against VirusTotal.
        
        Query Strategy (Phase 9 Step 1):
        - Uses registrable domain for efficiency
        - Caches results
        """
        if not self.is_available:
            return VTResult(url_or_hash=url, error="VT API key not configured")
        
        cache_key = self._get_cache_key(url)
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        try:
            # Use domain lookup (cheaper than URL scan)
            from urllib.parse import urlparse
            domain = get_registrable_domain(urlparse(url).netloc)
            
            client = await self._get_client()
            response = await client.get(f"{self.API_BASE}/domains/{domain}")
            
            if response.status_code == 200:
                result = self._parse_domain_response(url, response.json())
            elif response.status_code == 404:
                # Domain not in VT database = clean (unknown)
                result = VTResult(url_or_hash=url, risk_level=VTRiskLevel.CLEAN)
            else:
                result = VTResult(
                    url_or_hash=url, 
                    error=f"VT API error: {response.status_code}"
                )
            
            self._set_cached(cache_key, result)
            return result
            
        except Exception as e:
            logger.warning(f"VT check failed for {url[:50]}: {e}")
            return VTResult(url_or_hash=url, error=str(e)[:100])
    
    async def check_hash(self, file_hash: str) -> VTResult:
        """Check file hash against VirusTotal"""
        if not self.is_available:
            return VTResult(url_or_hash=file_hash, error="VT API key not configured")
        
        cache_key = self._get_cache_key(file_hash)
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        try:
            client = await self._get_client()
            response = await client.get(f"{self.API_BASE}/files/{file_hash}")
            
            if response.status_code == 200:
                result = self._parse_file_response(file_hash, response.json())
            elif response.status_code == 404:
                result = VTResult(url_or_hash=file_hash, risk_level=VTRiskLevel.UNKNOWN)
            else:
                result = VTResult(
                    url_or_hash=file_hash,
                    error=f"VT API error: {response.status_code}"
                )
            
            self._set_cached(cache_key, result)
            return result
            
        except Exception as e:
            logger.warning(f"VT hash check failed for {file_hash[:16]}: {e}")
            return VTResult(url_or_hash=file_hash, error=str(e)[:100])
    
    def _parse_domain_response(self, url: str, data: Dict[str, Any]) -> VTResult:
        """Parse VT domain response and normalize"""
        result = VTResult(url_or_hash=url)
        
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            result.malicious_count = stats.get('malicious', 0)
            result.suspicious_count = stats.get('suspicious', 0)
            result.total_vendors = sum(stats.values())
            
            # Parse last analysis date
            last_analysis = attributes.get('last_analysis_date')
            if last_analysis:
                result.last_analysis_date = datetime.fromtimestamp(last_analysis)
                result.analysis_age_days = (datetime.utcnow() - result.last_analysis_date).days
            
            # Categories
            result.categories = list(attributes.get('categories', {}).values())
            
            # Normalize risk level (Phase 9 Step 3)
            result.risk_level = self._normalize_risk_level(
                result.malicious_count,
                result.suspicious_count,
                result.analysis_age_days
            )
            
            # Calculate score (Phase 9 Step 4)
            result.score = self._calculate_score(result.risk_level)
            
        except Exception as e:
            result.error = f"Parse error: {str(e)[:50]}"
        
        return result
    
    def _parse_file_response(self, file_hash: str, data: Dict[str, Any]) -> VTResult:
        """Parse VT file response and normalize"""
        result = VTResult(url_or_hash=file_hash)
        
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            result.malicious_count = stats.get('malicious', 0)
            result.suspicious_count = stats.get('suspicious', 0)
            result.total_vendors = sum(stats.values())
            
            last_analysis = attributes.get('last_analysis_date')
            if last_analysis:
                result.last_analysis_date = datetime.fromtimestamp(last_analysis)
                result.analysis_age_days = (datetime.utcnow() - result.last_analysis_date).days
            
            result.risk_level = self._normalize_risk_level(
                result.malicious_count,
                result.suspicious_count,
                result.analysis_age_days
            )
            
            result.score = self._calculate_score(result.risk_level)
            
        except Exception as e:
            result.error = f"Parse error: {str(e)[:50]}"
        
        return result
    
    def _normalize_risk_level(
        self, 
        malicious: int, 
        suspicious: int,
        age_days: Optional[int]
    ) -> VTRiskLevel:
        """
        Normalize VT output to risk level.
        Phase 9 Step 3 Implementation.
        
        Do NOT use raw "X/90 engines flagged".
        """
        total_bad = malicious + suspicious
        
        if total_bad == 0:
            return VTRiskLevel.CLEAN
        
        # High confidence: 10+ engines flagged
        if malicious >= 10:
            return VTRiskLevel.HIGH_CONFIDENCE
        
        # Medium confidence: 3-9 engines
        if malicious >= 3:
            return VTRiskLevel.MEDIUM_CONFIDENCE
        
        # Low confidence: 1-2 engines AND old analysis
        if malicious >= 1:
            if age_days and age_days > 30:
                return VTRiskLevel.LOW_CONFIDENCE
            else:
                return VTRiskLevel.MEDIUM_CONFIDENCE
        
        # Just suspicious flags
        if suspicious >= 3:
            return VTRiskLevel.LOW_CONFIDENCE
        
        return VTRiskLevel.CLEAN
    
    def _calculate_score(self, risk_level: VTRiskLevel) -> float:
        """
        Calculate score contribution.
        Phase 9 Step 4 Implementation.
        
        IMPORTANT: Clean = 0.5 (neutral), NOT positive!
        """
        scores = {
            VTRiskLevel.UNKNOWN: 0.5,      # Neutral
            VTRiskLevel.CLEAN: 0.5,         # Neutral (NOT positive!)
            VTRiskLevel.LOW_CONFIDENCE: 0.35,
            VTRiskLevel.MEDIUM_CONFIDENCE: 0.2,
            VTRiskLevel.HIGH_CONFIDENCE: 0.05
        }
        return scores.get(risk_level, 0.5)
    
    def should_query(
        self, 
        url: str, 
        alignment: str = "unrelated",
        has_redirect: bool = False,
        url_entropy: float = 0.0
    ) -> bool:
        """
        Determine if URL should be queried.
        Phase 9 Step 6: Conditional querying.
        
        Only query if:
        - Domain misaligned OR
        - External redirect OR
        - High entropy URL
        """
        if alignment == "unrelated":
            return True
        if has_redirect:
            return True
        if url_entropy > 4.5:
            return True
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: EXPLAINABILITY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class ExplainabilityEngine:
    """
    Phase 6: SOC-grade explanation generation.
    
    Replaces alarmist language with precise, actionable descriptions.
    """
    
    def explain_vt_result(self, vt_result: VTResult) -> str:
        """
        Generate SOC-grade VT explanation.
        Phase 9 Step 7 Implementation.
        """
        if vt_result.error:
            return "Threat intelligence check unavailable"
        
        if vt_result.risk_level == VTRiskLevel.UNKNOWN:
            return "No data available in threat intelligence databases"
        
        if vt_result.risk_level == VTRiskLevel.CLEAN:
            return "No known reports in threat intelligence databases"
        
        # For flagged items, be specific
        total_flags = vt_result.malicious_count + vt_result.suspicious_count
        
        age_context = ""
        if vt_result.analysis_age_days:
            if vt_result.analysis_age_days > 30:
                age_context = f" (last checked {vt_result.analysis_age_days} days ago)"
            else:
                age_context = " (recently verified)"
        
        if vt_result.risk_level == VTRiskLevel.HIGH_CONFIDENCE:
            return f"Flagged by {vt_result.malicious_count}/{vt_result.total_vendors} security vendors{age_context}"
        
        if vt_result.risk_level == VTRiskLevel.MEDIUM_CONFIDENCE:
            return f"Flagged by {total_flags}/{vt_result.total_vendors} security vendors{age_context}"
        
        if vt_result.risk_level == VTRiskLevel.LOW_CONFIDENCE:
            return f"Minor flags ({total_flags} vendor(s)){age_context} - may be false positive"
        
        return "No known reports in threat intelligence databases"
    
    def explain_link_score(
        self, 
        https_count: int, 
        http_count: int,
        aligned_count: int,
        unrelated_count: int
    ) -> str:
        """Generate link analysis explanation"""
        parts = []
        
        if http_count > 0:
            if aligned_count == http_count:
                parts.append(f"{http_count} HTTP link(s) to verified domains")
            elif aligned_count > 0:
                parts.append(f"{aligned_count} HTTP link(s) to verified domains")
                if unrelated_count > 0:
                    parts.append(f"{unrelated_count} HTTP link(s) to unknown domains")
            else:
                parts.append(f"{http_count} unencrypted HTTP link(s)")
        
        if https_count > 0:
            parts.append(f"{https_count} secure HTTPS link(s)")
        
        return "; ".join(parts) if parts else "No links found"
    
    def explain_authentication(
        self,
        spf: str,
        dkim: str,
        dmarc: str
    ) -> str:
        """Generate authentication explanation"""
        all_pass = all(r.lower() == 'pass' for r in [spf, dkim, dmarc])
        
        if all_pass:
            return "Email authenticated: SPF, DKIM, and DMARC all passed"
        
        failures = []
        if spf.lower() != 'pass':
            failures.append(f"SPF={spf}")
        if dkim.lower() != 'pass':
            failures.append(f"DKIM={dkim}")
        if dmarc.lower() != 'pass':
            failures.append(f"DMARC={dmarc}")
        
        return f"Authentication issues: {', '.join(failures)}"
    
    def explain_redirect(
        self,
        hop_count: int,
        chain_type: str,
        has_external: bool
    ) -> str:
        """Generate redirect chain explanation"""
        if hop_count == 0:
            return "Direct link (no redirects)"
        
        if chain_type == "internal":
            return f"{hop_count} redirect(s) within sender organization"
        
        if chain_type == "vendor":
            return f"{hop_count} redirect(s) through known email vendor"
        
        if has_external:
            return f"{hop_count} redirect(s) to external destination (verify before clicking)"
        
        return f"{hop_count} redirect(s) detected"


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLETON INSTANCES
# ═══════════════════════════════════════════════════════════════════════════════

virustotal_service = VirusTotalService()
explainability_engine = ExplainabilityEngine()


async def check_url_virustotal(url: str) -> VTResult:
    """Convenience function for VT URL check"""
    return await virustotal_service.check_url(url)


async def check_hash_virustotal(file_hash: str) -> VTResult:
    """Convenience function for VT hash check"""
    return await virustotal_service.check_hash(file_hash)


def explain_vt(result: VTResult) -> str:
    """Convenience function for VT explanation"""
    return explainability_engine.explain_vt_result(result)
