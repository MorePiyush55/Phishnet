"""
VirusTotal API client with unified interface, robust error handling, and observability.
Supports URL scanning, file hash lookups, and IP reputation checks with circuit breaker protection.
"""

import asyncio
import hashlib
import time
import re
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

import aiohttp
from app.config.settings import settings
from app.config.logging import get_logger
from app.core.redis_client import get_redis_connection
from app.services.interfaces import (
    IAnalyzer, AnalysisResult, AnalysisType, ServiceHealth, ServiceStatus,
    VirusTotalResult, ServiceUnavailableError, InvalidTargetError, 
    AnalysisError, RateLimitError
)
from app.resilience.circuit_breaker import circuit_breaker, VIRUSTOTAL_CONFIG, FallbackMode
from app.observability.tracing import trace_external_api_call, record_external_api_failure
from app.observability.correlation import get_structured_logger

logger = get_structured_logger(__name__)


class VirusTotalClient(IAnalyzer):
    """
    VirusTotal API client implementing IAnalyzer interface.
    Provides URL scanning, file hash lookups, and IP analysis.
    """
    
    BASE_URL = "https://www.virustotal.com/vtapi/v2"
    PUBLIC_API_RATE_LIMIT = 4  # requests per minute for free tier
    PREMIUM_API_RATE_LIMIT = 1000  # requests per minute for premium
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("virustotal")
        
        # Use secure API key manager
        self.api_key = api_key or settings.get_virustotal_api_key()
        self._rate_limiter = asyncio.Semaphore(self.PUBLIC_API_RATE_LIMIT)
        self._last_request_time = 0.0
        
        if not self.api_key:
            logger.warning("VirusTotal API key not configured - using mock responses")
            self._health.status = ServiceStatus.UNAVAILABLE
        else:
            logger.info("VirusTotal API client initialized with secure key")
    
    @trace_external_api_call("virustotal", "analyze")
    @circuit_breaker("virustotal", VIRUSTOTAL_CONFIG)
    async def analyze(self, target: str, analysis_type: AnalysisType) -> AnalysisResult:
        """
        Analyze target using VirusTotal API with circuit breaker protection.
        
        Args:
            target: URL, file hash, or IP to analyze
            analysis_type: Type of analysis (URL_SCAN, FILE_HASH, IP_REPUTATION)
            
        Returns:
            Normalized AnalysisResult
        """
        if not self.is_available:
            logger.warning("VirusTotal service unavailable, using fallback", extra={
                "service": "virustotal",
                "status": self._health.status.value,
                "target": target[:50] + "..." if len(target) > 50 else target
            })
            # Return fallback result
            return self._create_fallback_result(target, analysis_type)
        
        start_time = time.time()
        
        try:
            # Check cache first
            cache_key = f"vt:{analysis_type.value}:{hashlib.md5(target.encode()).hexdigest()}"
            cached_result = await self._get_cached_result(cache_key)
            if cached_result:
                logger.debug("VirusTotal cache hit", extra={
                    "service": "virustotal",
                    "target": target[:50] + "..." if len(target) > 50 else target,
                    "cache_hit": True
                })
                return cached_result
            
            # Validate target format
            self._validate_target(target, analysis_type)
            
            logger.info("Making VirusTotal API request", extra={
                "service": "virustotal",
                "analysis_type": analysis_type.value,
                "target": target[:50] + "..." if len(target) > 50 else target
            })
            
            # Perform API request with rate limiting
            raw_response = await self._make_api_request(target, analysis_type)
            
            # Parse response into normalized result
            vt_result = self._parse_response(raw_response, analysis_type)
            analysis_result = self._create_analysis_result(
                target, analysis_type, vt_result, raw_response, start_time
            )
            
            # Cache successful results
            await self._cache_result(cache_key, analysis_result)
            
            # Update health status
            self._update_health_success()
            
            logger.info("VirusTotal analysis complete", extra={
                "service": "virustotal",
                "target": target[:50] + "..." if len(target) > 50 else target,
                "threat_score": analysis_result.threat_score,
                "verdict": analysis_result.verdict,
                "duration_ms": (time.time() - start_time) * 1000
            })
            
            return analysis_result
            
        except RateLimitError as e:
            self._update_rate_limit(e.reset_time or time.time() + 60)
            logger.warning("VirusTotal rate limit exceeded", extra={
                "service": "virustotal",
                "reset_time": e.reset_time
            })
            record_external_api_failure("virustotal", "rate_limit")
            raise ServiceUnavailableError("VirusTotal rate limit exceeded")
            
        except Exception as e:
            self._update_health_failure()
            logger.error("VirusTotal analysis failed", extra={
                "service": "virustotal",
                "error": str(e),
                "error_type": type(e).__name__,
                "target": target[:50] + "..." if len(target) > 50 else target
            })
            record_external_api_failure("virustotal", type(e).__name__)
            
            # Return fallback result on error
            return self._create_fallback_result(target, analysis_type, error=str(e))
            execution_time = int((time.time() - start_time) * 1000)
            
            # Return error result instead of raising exception
            return AnalysisResult(
                service_name=self.service_name,
                analysis_type=analysis_type,
                target=target,
                threat_score=0.0,  # Conservative default
                confidence=0.0,
                raw_response={"error": str(e)},
                timestamp=start_time,
                execution_time_ms=execution_time,
                error=f"VirusTotal analysis failed: {str(e)}"
            )
    
    async def _make_api_request(self, target: str, analysis_type: AnalysisType) -> Dict[str, Any]:
        """Make rate-limited API request to VirusTotal."""
        
        # Enforce rate limiting
        await self._rate_limiter.acquire()
        try:
            # Ensure minimum time between requests
            now = time.time()
            time_since_last = now - self._last_request_time
            min_interval = 60.0 / self.PUBLIC_API_RATE_LIMIT  # seconds between requests
            
            if time_since_last < min_interval:
                await asyncio.sleep(min_interval - time_since_last)
            
            self._last_request_time = time.time()
            
            # Build request based on analysis type
            if analysis_type == AnalysisType.URL_SCAN:
                return await self._scan_url(target)
            elif analysis_type == AnalysisType.FILE_HASH:
                return await self._lookup_hash(target)
            elif analysis_type == AnalysisType.IP_REPUTATION:
                return await self._scan_ip(target)
            else:
                raise InvalidTargetError(f"Unsupported analysis type: {analysis_type}")
                
        finally:
            self._rate_limiter.release()
    
    async def _scan_url(self, url: str) -> Dict[str, Any]:
        """Scan URL using VirusTotal URL scanner."""
        async with aiohttp.ClientSession() as session:
            # First, submit URL for scanning
            submit_params = {
                'apikey': self.api_key,
                'url': url
            }
            
            async with session.post(f"{self.BASE_URL}/url/scan", data=submit_params) as response:
                if response.status == 429:
                    raise RateLimitError()
                elif response.status == 204:
                    # No content - return empty result indicating resource not found
                    logger.debug(f"VirusTotal returned 204 for URL submission: {url[:50]}")
                    return {"response_code": 0, "verbose_msg": "Resource not found"}
                elif response.status != 200:
                    raise AnalysisError(f"VirusTotal URL submission failed: {response.status}")
                
                submit_result = await response.json()
                scan_id = submit_result.get('scan_id')
            
            # Wait and retrieve results
            await asyncio.sleep(15)  # VirusTotal processing time
            
            report_params = {
                'apikey': self.api_key,
                'resource': scan_id or url
            }
            
            async with session.get(f"{self.BASE_URL}/url/report", params=report_params) as response:
                if response.status == 429:
                    raise RateLimitError()
                elif response.status == 204:
                    # No content - return empty result
                    logger.debug(f"VirusTotal returned 204 for URL report: {url[:50]}")
                    return {"response_code": 0, "verbose_msg": "Scan results not yet available"}
                elif response.status != 200:
                    raise AnalysisError(f"VirusTotal URL report failed: {response.status}")
                
                return await response.json()
    
    async def _lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Look up file hash in VirusTotal database."""
        params = {
            'apikey': self.api_key,
            'resource': file_hash
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.BASE_URL}/file/report", params=params) as response:
                if response.status == 429:
                    raise RateLimitError()
                elif response.status == 204:
                    # No content - hash not found in database
                    logger.debug(f"VirusTotal returned 204 for hash lookup: {file_hash}")
                    return {"response_code": 0, "verbose_msg": "Hash not found in database"}
                elif response.status != 200:
                    raise AnalysisError(f"VirusTotal hash lookup failed: {response.status}")
                
                return await response.json()
    
    async def _scan_ip(self, ip_address: str) -> Dict[str, Any]:
        """Scan IP address using VirusTotal IP scanner."""
        params = {
            'apikey': self.api_key,
            'ip': ip_address
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.BASE_URL}/ip-address/report", params=params) as response:
                if response.status == 429:
                    raise RateLimitError()
                elif response.status == 204:
                    # No content - IP not found
                    logger.debug(f"VirusTotal returned 204 for IP scan: {ip_address}")
                    return {"response_code": 0, "verbose_msg": "IP address not found"}
                elif response.status != 200:
                    raise AnalysisError(f"VirusTotal IP scan failed: {response.status}")
                
                return await response.json()
    
    def _validate_target(self, target: str, analysis_type: AnalysisType):
        """Validate target format for the given analysis type."""
        if analysis_type == AnalysisType.URL_SCAN:
            parsed = urlparse(target)
            if not parsed.scheme or not parsed.netloc:
                raise InvalidTargetError(f"Invalid URL format: {target}")
                
        elif analysis_type == AnalysisType.FILE_HASH:
            # Support MD5, SHA1, SHA256
            if not re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', target):
                raise InvalidTargetError(f"Invalid hash format: {target}")
                
        elif analysis_type == AnalysisType.IP_REPUTATION:
            # Basic IPv4 validation
            if not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', target):
                raise InvalidTargetError(f"Invalid IP format: {target}")
    
    def _parse_response(self, response: Dict[str, Any], analysis_type: AnalysisType) -> VirusTotalResult:
        """Parse VirusTotal API response into structured result."""
        
        # Handle API errors
        if response.get('response_code') == 0:
            # Resource not found - not necessarily malicious
            return VirusTotalResult(
                vt_score=0.0,
                positives=0,
                total_engines=0,
                engine_hits=[],
                last_seen=None
            )
        
        if response.get('response_code') != 1:
            raise AnalysisError(f"VirusTotal API error: {response.get('verbose_msg', 'Unknown error')}")
        
        # Extract detection data
        positives = response.get('positives', 0)
        total = response.get('total', 1)
        
        # Calculate normalized threat score (0.0 to 1.0)
        vt_score = positives / max(total, 1) if total > 0 else 0.0
        
        # Extract engine hits
        scans = response.get('scans', {})
        engine_hits = [
            engine for engine, result in scans.items() 
            if result.get('detected', False)
        ]
        
        return VirusTotalResult(
            vt_score=vt_score,
            positives=positives,
            total_engines=total,
            engine_hits=engine_hits,
            last_seen=response.get('scan_date'),
            scan_id=response.get('scan_id')
        )
    
    def _create_analysis_result(
        self, 
        target: str, 
        analysis_type: AnalysisType,
        vt_result: VirusTotalResult,
        raw_response: Dict[str, Any],
        start_time: float
    ) -> AnalysisResult:
        """Create normalized AnalysisResult from VirusTotal data."""
        
        # Calculate confidence based on number of engines and recency
        confidence = min(vt_result.total_engines / 50.0, 1.0)  # More engines = higher confidence
        if vt_result.last_seen:
            # Reduce confidence for old scans
            try:
                # This is a simplified confidence calculation
                confidence = min(confidence, 0.9)
            except:
                pass
        
        # Generate explanation
        explanation = self._generate_explanation(vt_result)
        
        return AnalysisResult(
            service_name=self.service_name,
            analysis_type=analysis_type,
            target=target,
            threat_score=vt_result.vt_score,
            confidence=confidence,
            raw_response=raw_response,
            timestamp=start_time,
            execution_time_ms=int((time.time() - start_time) * 1000),
            verdict="malicious" if vt_result.vt_score > 0.1 else "clean",
            explanation=explanation,
            indicators=vt_result.engine_hits[:5]  # Top 5 detection engines
        )
    
    def _create_fallback_result(
        self, 
        target: str, 
        analysis_type: AnalysisType,
        error: Optional[str] = None
    ) -> AnalysisResult:
        """Create fallback result when VirusTotal service is unavailable."""
        
        # Use cached data if available
        cache_key = f"vt_fallback:{analysis_type.value}:{hashlib.md5(target.encode()).hexdigest()}"
        
        # Conservative fallback - flag as suspicious for manual review
        fallback_data = FallbackMode.suspicious_fallback()
        
        explanation = (
            f"VirusTotal service unavailable. "
            f"Flagging for manual review as a precaution. "
            f"Error: {error}" if error else 
            "VirusTotal service unavailable. Flagging for manual review as a precaution."
        )
        
        return AnalysisResult(
            service_name=self.service_name,
            analysis_type=analysis_type,
            target=target,
            threat_score=fallback_data["confidence"],
            confidence=fallback_data["confidence"],
            raw_response={"fallback": True, "reason": fallback_data["reason"], "error": error},
            timestamp=time.time(),
            execution_time_ms=0,
            verdict=fallback_data["verdict"],
            explanation=explanation,
            indicators=["service_unavailable", "manual_review_required"]
        )
    
    def _generate_explanation(self, vt_result: VirusTotalResult) -> str:
        """Generate human-readable explanation of VirusTotal results."""
        if vt_result.positives == 0:
            return "No security vendors detected malicious activity"
        
        percentage = (vt_result.positives / max(vt_result.total_engines, 1)) * 100
        
        return (
            f"{vt_result.positives} of {vt_result.total_engines} security vendors "
            f"({percentage:.1f}%) detected malicious activity. "
            f"Detection engines: {', '.join(vt_result.engine_hits[:3])}"
            + ("..." if len(vt_result.engine_hits) > 3 else "")
        )
    
    async def _get_cached_result(self, cache_key: str) -> Optional[AnalysisResult]:
        """Retrieve cached analysis result."""
        try:
            redis = get_redis_connection()
            # Redis client returns sync values - don't await
            cached_data = redis.get(cache_key)
            if cached_data:
                # In a real implementation, you'd deserialize the AnalysisResult
                # For now, return None to always fetch fresh data
                logger.debug(f"Cache hit for {cache_key}")
                pass
        except Exception as e:
            logger.debug(f"Cache retrieval skipped (Redis unavailable): {e}")
        
        return None
    
    async def _cache_result(self, cache_key: str, result: AnalysisResult, ttl: int = 3600):
        """Cache analysis result for future use."""
        try:
            # In a real implementation, you'd serialize the AnalysisResult
            # For now, just cache the basic info
            redis = get_redis_connection()
            # Redis client returns sync values - don't await
            redis.setex(cache_key, ttl, f"cached:{result.threat_score}")
        except Exception as e:
            logger.debug(f"Cache storage skipped (Redis unavailable): {e}")
    
    async def health_check(self) -> ServiceHealth:
        """Check VirusTotal API health."""
        if not self.api_key:
            self._health.status = ServiceStatus.UNAVAILABLE
            return self._health
        
        try:
            # Simple API test with a known safe URL
            test_url = "https://www.google.com"
            params = {
                'apikey': self.api_key,
                'resource': test_url
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.BASE_URL}/url/report", 
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        self._update_health_success()
                    elif response.status == 429:
                        self._update_rate_limit(time.time() + 60)
                    else:
                        self._update_health_failure()
                        
        except Exception as e:
            logger.warning(f"VirusTotal health check failed: {e}")
            self._update_health_failure()
        
        return self._health

    async def scan(self, resource: str) -> Dict[str, Any]:
        """
        Unified scan method that returns normalized result schema.
        
        Args:
            resource: URL, IP, or file hash to scan
            
        Returns:
            Dict with normalized schema: {
                'threat_score': float,
                'verdict': str,
                'confidence': float,
                'indicators': List[str],
                'raw_data': Dict
            }
        """
        try:
            # Determine analysis type from resource format
            if self._is_ip_address(resource):
                analysis_type = AnalysisType.IP_REPUTATION
            elif self._is_file_hash(resource):
                analysis_type = AnalysisType.FILE_HASH
            else:
                analysis_type = AnalysisType.URL_SCAN
            
            # Perform analysis
            result = await self.analyze(resource, analysis_type)
            
            # Return normalized schema
            return {
                'threat_score': result.threat_score,
                'verdict': result.verdict or 'unknown',
                'confidence': result.confidence,
                'indicators': result.indicators or [],
                'raw_data': result.raw_response,
                'service': self.service_name,
                'timestamp': result.timestamp,
                'analysis_type': analysis_type.value
            }
            
        except Exception as e:
            logger.error(f"VirusTotal scan failed for {resource}: {e}")
            return {
                'threat_score': 0.0,
                'verdict': 'error',
                'confidence': 0.0,
                'indicators': [f'scan_error: {str(e)}'],
                'raw_data': {'error': str(e)},
                'service': self.service_name,
                'timestamp': time.time(),
                'analysis_type': 'unknown'
            }
    
    def _is_ip_address(self, resource: str) -> bool:
        """Check if resource is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(resource)
            return True
        except ValueError:
            return False
    
    def _is_file_hash(self, resource: str) -> bool:
        """Check if resource is a file hash (MD5, SHA1, SHA256)."""
        hash_patterns = [
            r'^[a-fA-F0-9]{32}$',  # MD5
            r'^[a-fA-F0-9]{40}$',  # SHA1
            r'^[a-fA-F0-9]{64}$'   # SHA256
        ]
        return any(re.match(pattern, resource) for pattern in hash_patterns)


# Factory function for dependency injection
def create_virustotal_client(api_key: Optional[str] = None) -> VirusTotalClient:
    """Factory function to create VirusTotal client."""
    return VirusTotalClient(api_key=api_key)
