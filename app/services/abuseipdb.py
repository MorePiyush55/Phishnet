"""
AbuseIPDB API client with unified interface and robust error handling.
Provides IP reputation checking and abuse confidence scoring.
"""

import asyncio
import hashlib
import time
import re
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

import aiohttp
from app.config.settings import settings
from app.config.logging import get_logger
from app.core.redis_client import get_redis_connection
from app.services.interfaces import (
    IAnalyzer, AnalysisResult, AnalysisType, ServiceHealth, ServiceStatus,
    AbuseIPDBResult, ServiceUnavailableError, InvalidTargetError, 
    AnalysisError, RateLimitError
)

logger = get_logger(__name__)


class AbuseIPDBClient(IAnalyzer):
    """
    AbuseIPDB API client implementing IAnalyzer interface.
    Provides IP reputation checking and abuse confidence scoring.
    """
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    RATE_LIMIT = 1000  # requests per day for free tier
    PREMIUM_RATE_LIMIT = 10000  # requests per day for premium
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("abuseipdb")
        
        # Use secure API key manager
        self.api_key = api_key or settings.get_abuseipdb_api_key()
        self._rate_limiter = asyncio.Semaphore(10)  # 10 concurrent requests
        self._daily_request_count = 0
        self._last_reset_date = datetime.now().date()
        
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured - using mock responses")
            self._health.status = ServiceStatus.UNAVAILABLE
        else:
            logger.info("AbuseIPDB API client initialized with secure key")
    
    async def analyze(self, target: str, analysis_type: AnalysisType) -> AnalysisResult:
        """
        Analyze IP address using AbuseIPDB API.
        
        Args:
            target: IP address to check
            analysis_type: Must be IP_REPUTATION
            
        Returns:
            Normalized AnalysisResult with abuse confidence and report data
        """
        if not self.is_available:
            raise ServiceUnavailableError(f"AbuseIPDB service unavailable: {self._health.status}")
        
        if analysis_type != AnalysisType.IP_REPUTATION:
            raise InvalidTargetError(f"AbuseIPDB only supports IP reputation analysis")
        
        start_time = time.time()
        
        try:
            # Check cache first
            cache_key = f"abuseipdb:{hashlib.md5(target.encode()).hexdigest()}"
            cached_result = await self._get_cached_result(cache_key)
            if cached_result:
                logger.debug(f"AbuseIPDB cache hit for {target}")
                return cached_result
            
            # Validate IP format
            self._validate_ip_address(target)
            
            # Check daily rate limit
            if not self._check_rate_limit():
                raise RateLimitError(self._get_rate_limit_reset_time())
            
            # Perform API request
            raw_response = await self._make_api_request(target)
            
            # Parse response into normalized result
            abuse_result = self._parse_response(raw_response)
            analysis_result = self._create_analysis_result(
                target, analysis_type, abuse_result, raw_response, start_time
            )
            
            # Cache successful results (longer TTL for IP reputation)
            await self._cache_result(cache_key, analysis_result, ttl=7200)  # 2 hours
            
            # Update health status
            self._update_health_success()
            
            logger.info(f"AbuseIPDB analysis complete: {target} -> confidence {abuse_result.abuse_confidence}%")
            return analysis_result
            
        except RateLimitError as e:
            self._update_rate_limit(e.reset_time or time.time() + 86400)  # 24 hours
            raise ServiceUnavailableError("AbuseIPDB daily rate limit exceeded")
            
        except Exception as e:
            self._update_health_failure()
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
                error=f"AbuseIPDB analysis failed: {str(e)}"
            )
    
    async def _make_api_request(self, ip_address: str) -> Dict[str, Any]:
        """Make rate-limited API request to AbuseIPDB."""
        
        await self._rate_limiter.acquire()
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,  # Check reports from last 90 days
                'verbose': ''  # Include country, usage type, etc.
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.BASE_URL}/check",
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    
                    # Update request count
                    self._daily_request_count += 1
                    
                    if response.status == 429:
                        raise RateLimitError(self._get_rate_limit_reset_time())
                    elif response.status == 422:
                        raise InvalidTargetError("Invalid IP address format")
                    elif response.status != 200:
                        raise AnalysisError(f"AbuseIPDB API error: {response.status}")
                    
                    return await response.json()
                    
        finally:
            self._rate_limiter.release()
    
    def _validate_ip_address(self, ip_address: str):
        """Validate IP address format."""
        # IPv4 validation
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        # IPv6 basic validation (simplified)
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
        
        if not (re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address)):
            raise InvalidTargetError(f"Invalid IP address format: {ip_address}")
        
        # Check for private/local IPs (not useful for reputation checking)
        if self._is_private_ip(ip_address):
            raise InvalidTargetError(f"Private IP addresses cannot be checked: {ip_address}")
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP address is in private ranges."""
        private_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12', 
            '192.168.0.0/16',
            '127.0.0.0/8',
            '169.254.0.0/16'
        ]
        
        # Simplified check for common private ranges
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False  # Not IPv4
            
        try:
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # 10.x.x.x
            if first_octet == 10:
                return True
            # 172.16.x.x - 172.31.x.x
            elif first_octet == 172 and 16 <= second_octet <= 31:
                return True
            # 192.168.x.x
            elif first_octet == 192 and second_octet == 168:
                return True
            # 127.x.x.x (localhost)
            elif first_octet == 127:
                return True
                
        except ValueError:
            pass
        
        return False
    
    def _parse_response(self, response: Dict[str, Any]) -> AbuseIPDBResult:
        """Parse AbuseIPDB API response into structured result."""
        
        data = response.get('data', {})
        
        # Extract core abuse metrics
        abuse_confidence = data.get('abuseConfidencePercentage', 0)
        total_reports = data.get('totalReports', 0)
        
        # Extract additional metadata
        country_code = data.get('countryCode')
        usage_type = data.get('usageType')
        last_reported_at = data.get('lastReportedAt')
        
        return AbuseIPDBResult(
            abuse_confidence=float(abuse_confidence) / 100.0,  # Normalize to 0.0-1.0
            report_count=total_reports,
            last_reported=last_reported_at,
            country_code=country_code,
            usage_type=usage_type
        )
    
    def _create_analysis_result(
        self,
        target: str,
        analysis_type: AnalysisType,
        abuse_result: AbuseIPDBResult,
        raw_response: Dict[str, Any],
        start_time: float
    ) -> AnalysisResult:
        """Create normalized AnalysisResult from AbuseIPDB data."""
        
        # Use abuse confidence as threat score (already normalized 0.0-1.0)
        threat_score = abuse_result.abuse_confidence
        
        # Calculate confidence based on number of reports and recency
        confidence = 0.5  # Base confidence
        
        # More reports = higher confidence (up to 95%)
        if abuse_result.report_count > 0:
            confidence = min(0.5 + (abuse_result.report_count / 100.0), 0.95)
        
        # Recent reports increase confidence
        if abuse_result.last_reported:
            try:
                # This would need proper date parsing in real implementation
                confidence = min(confidence + 0.1, 1.0)
            except:
                pass
        
        # Generate explanation
        explanation = self._generate_explanation(abuse_result)
        
        # Generate indicators
        indicators = []
        if abuse_result.abuse_confidence > 0:
            indicators.append(f"Abuse confidence: {abuse_result.abuse_confidence*100:.1f}%")
        if abuse_result.report_count > 0:
            indicators.append(f"Total reports: {abuse_result.report_count}")
        if abuse_result.country_code:
            indicators.append(f"Country: {abuse_result.country_code}")
        if abuse_result.usage_type:
            indicators.append(f"Usage: {abuse_result.usage_type}")
        
        return AnalysisResult(
            service_name=self.service_name,
            analysis_type=analysis_type,
            target=target,
            threat_score=threat_score,
            confidence=confidence,
            raw_response=raw_response,
            timestamp=start_time,
            execution_time_ms=int((time.time() - start_time) * 1000),
            verdict=self._determine_verdict(abuse_result),
            explanation=explanation,
            indicators=indicators
        )
    
    def _determine_verdict(self, abuse_result: AbuseIPDBResult) -> str:
        """Determine verdict based on abuse confidence."""
        if abuse_result.abuse_confidence >= 0.75:
            return "malicious"
        elif abuse_result.abuse_confidence >= 0.25:
            return "suspicious"
        else:
            return "clean"
    
    def _generate_explanation(self, abuse_result: AbuseIPDBResult) -> str:
        """Generate human-readable explanation of AbuseIPDB results."""
        
        if abuse_result.abuse_confidence == 0:
            return "No abuse reports found for this IP address"
        
        confidence_pct = abuse_result.abuse_confidence * 100
        
        explanation = f"IP has {confidence_pct:.1f}% abuse confidence"
        
        if abuse_result.report_count > 0:
            explanation += f" based on {abuse_result.report_count} reports"
        
        if abuse_result.last_reported:
            explanation += f", last reported: {abuse_result.last_reported}"
        
        if abuse_result.country_code:
            explanation += f" (Country: {abuse_result.country_code})"
        
        return explanation
    
    def _check_rate_limit(self) -> bool:
        """Check if we're within daily rate limits."""
        current_date = datetime.now().date()
        
        # Reset counter if it's a new day
        if current_date != self._last_reset_date:
            self._daily_request_count = 0
            self._last_reset_date = current_date
        
        return self._daily_request_count < self.RATE_LIMIT
    
    def _get_rate_limit_reset_time(self) -> float:
        """Get timestamp when rate limit will reset."""
        tomorrow = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        return tomorrow.timestamp()
    
    async def _get_cached_result(self, cache_key: str) -> Optional[AnalysisResult]:
        """Retrieve cached analysis result."""
        try:
            redis = get_redis_connection()
            cached_data = await redis.get(cache_key)
            if cached_data:
                # In a real implementation, you'd deserialize the AnalysisResult
                pass
        except Exception as e:
            logger.warning(f"Cache retrieval failed: {e}")
        
        return None
    
    async def _cache_result(self, cache_key: str, result: AnalysisResult, ttl: int = 7200):
        """Cache analysis result for future use."""
        try:
            # In a real implementation, you'd serialize the AnalysisResult
            redis = get_redis_connection()
            await redis.setex(cache_key, ttl, f"cached:{result.threat_score}")
        except Exception as e:
            logger.warning(f"Cache storage failed: {e}")
    
    async def health_check(self) -> ServiceHealth:
        """Check AbuseIPDB API health."""
        if not self.api_key:
            self._health.status = ServiceStatus.UNAVAILABLE
            return self._health
        
        try:
            # Test with a known safe IP (Google DNS)
            test_ip = "8.8.8.8"
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': test_ip,
                'maxAgeInDays': 1,
                'verbose': ''
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.BASE_URL}/check",
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    if response.status == 200:
                        self._update_health_success()
                    elif response.status == 429:
                        self._update_rate_limit(self._get_rate_limit_reset_time())
                    else:
                        self._update_health_failure()
                        
        except Exception as e:
            logger.warning(f"AbuseIPDB health check failed: {e}")
            self._update_health_failure()
        
        return self._health

    async def scan(self, resource: str) -> Dict[str, Any]:
        """
        Unified scan method for IP reputation checking.
        
        Args:
            resource: IP address to check
            
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
            # Validate IP address format
            self._validate_ip_address(resource)
            
            # Perform analysis
            result = await self.analyze(resource, AnalysisType.IP_REPUTATION)
            
            # Extract abuse confidence and report count from raw data
            raw_data = result.raw_response
            abuse_confidence = raw_data.get('abuseConfidencePercentage', 0)
            total_reports = raw_data.get('totalReports', 0)
            
            # Generate indicators based on abuse data
            indicators = []
            if abuse_confidence > 75:
                indicators.append('high_abuse_confidence')
            elif abuse_confidence > 25:
                indicators.append('medium_abuse_confidence')
            
            if total_reports > 10:
                indicators.append('multiple_abuse_reports')
            elif total_reports > 0:
                indicators.append('abuse_reports')
            
            if raw_data.get('isWhitelisted', False):
                indicators.append('whitelisted_ip')
            
            # Determine verdict based on abuse confidence
            if raw_data.get('isWhitelisted', False):
                verdict = 'safe'
            elif abuse_confidence >= 75:
                verdict = 'malicious'
            elif abuse_confidence >= 25 or total_reports > 0:
                verdict = 'suspicious'
            else:
                verdict = 'safe'
            
            return {
                'threat_score': result.threat_score,
                'verdict': verdict,
                'confidence': result.confidence,
                'indicators': indicators,
                'raw_data': raw_data,
                'service': self.service_name,
                'timestamp': result.timestamp,
                'analysis_type': 'ip_reputation',
                'abuse_confidence': abuse_confidence,
                'total_reports': total_reports,
                'country': raw_data.get('countryCode'),
                'isp': raw_data.get('isp')
            }
            
        except Exception as e:
            logger.error(f"AbuseIPDB scan failed for {resource}: {e}")
            return {
                'threat_score': 0.0,
                'verdict': 'error',
                'confidence': 0.0,
                'indicators': [f'scan_error: {str(e)}'],
                'raw_data': {'error': str(e)},
                'service': self.service_name,
                'timestamp': time.time(),
                'analysis_type': 'ip_reputation'
            }


# Factory function for dependency injection
def create_abuseipdb_client(api_key: Optional[str] = None) -> AbuseIPDBClient:
    """Factory function to create AbuseIPDB client."""
    return AbuseIPDBClient(api_key=api_key)
