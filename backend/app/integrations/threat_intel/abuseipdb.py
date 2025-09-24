"""
AbuseIPDB API adapter for IP address threat intelligence.

This module provides integration with AbuseIPDB API for IP reputation and abuse reports.
"""

import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import aiohttp
import asyncio

from .base import (
    ThreatIntelligenceAdapter, APIResponse, ThreatIntelligence, APIStatus,
    ThreatLevel, ResourceType, AdapterError, QuotaExceededError, 
    RateLimitError, TimeoutError, UnauthorizedError, is_valid_ip
)


class AbuseIPDBClient(ThreatIntelligenceAdapter):
    """AbuseIPDB API client with resilience patterns."""
    
    def __init__(self, api_key: str, requests_per_day: int = 1000):
        super().__init__(
            api_key=api_key,
            base_url="https://api.abuseipdb.com/api/v2",
            name="abuseipdb"
        )
        self.session: Optional[aiohttp.ClientSession] = None
        self.quota.requests_limit = requests_per_day
        
        # AbuseIPDB category mappings
        self.abuse_categories = {
            1: "DNS Compromise",
            2: "DNS Poisoning", 
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json',
                'User-Agent': 'PhishNet-ThreatIntel/1.0'
            }
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers
            )
        return self.session
    
    async def _make_request(self, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make authenticated request to AbuseIPDB API."""
        if not self.check_quota():
            raise QuotaExceededError(
                f"AbuseIPDB quota exceeded. Requests made: {self.quota.requests_made}/{self.quota.requests_limit}"
            )
        
        session = await self._get_session()
        url = f"{self.base_url}/{endpoint}"
        
        start_time = time.time()
        
        try:
            async with session.get(url, params=params) as response:
                response_time = time.time() - start_time
                
                if response.status == 200:
                    self.consume_quota()
                    data = await response.json()
                    self.logger.debug(f"AbuseIPDB API success: {endpoint}")
                    return data
                elif response.status == 401:
                    raise UnauthorizedError("Invalid AbuseIPDB API key")
                elif response.status == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    raise RateLimitError(
                        f"AbuseIPDB rate limit exceeded",
                        retry_after=retry_after
                    )
                elif response.status == 422:
                    error_data = await response.json()
                    errors = error_data.get('errors', [])
                    error_msg = '; '.join([e.get('detail', str(e)) for e in errors])
                    raise AdapterError(f"AbuseIPDB validation error: {error_msg}", APIStatus.ERROR)
                else:
                    error_text = await response.text()
                    raise AdapterError(
                        f"AbuseIPDB API error {response.status}: {error_text}",
                        APIStatus.ERROR
                    )
                    
        except asyncio.TimeoutError:
            raise TimeoutError("AbuseIPDB API request timed out")
        except aiohttp.ClientError as e:
            raise AdapterError(f"AbuseIPDB API connection error: {str(e)}", APIStatus.ERROR)
    
    async def analyze_url(self, url: str) -> APIResponse:
        """URLs not supported by AbuseIPDB - return appropriate response."""
        return APIResponse(
            success=False,
            status=APIStatus.ERROR,
            error_message="AbuseIPDB does not support URL analysis. Use IP address instead."
        )
    
    async def analyze_domain(self, domain: str) -> APIResponse:
        """Domains not supported by AbuseIPDB - return appropriate response."""
        return APIResponse(
            success=False,
            status=APIStatus.ERROR,
            error_message="AbuseIPDB does not support domain analysis. Use IP address instead."
        )
    
    async def analyze_ip(self, ip_address: str) -> APIResponse:
        """Analyze IP address using AbuseIPDB."""
        try:
            if not is_valid_ip(ip_address):
                return APIResponse(
                    success=False,
                    status=APIStatus.ERROR,
                    error_message=f"Invalid IP address format: {ip_address}"
                )
            
            # Check IP with detailed information
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,  # Last 90 days
                'verbose': ''  # Include country, usage type, ISP, domain, etc.
            }
            
            raw_response = await self._make_request("check", params)
            threat_intel = self.normalize_response(raw_response, ip_address, ResourceType.IP_ADDRESS)
            
            return APIResponse(
                success=True,
                status=APIStatus.SUCCESS,
                data=threat_intel,
                raw_response=raw_response,
                quota_remaining=self.quota.requests_remaining
            )
            
        except AdapterError as e:
            return APIResponse(
                success=False,
                status=e.status,
                error_message=str(e),
                retry_after=e.retry_after
            )
        except Exception as e:
            self.logger.error(f"Unexpected error analyzing IP {ip_address}: {str(e)}")
            return APIResponse(
                success=False,
                status=APIStatus.ERROR,
                error_message=f"Unexpected error: {str(e)}"
            )
    
    async def analyze_file_hash(self, file_hash: str) -> APIResponse:
        """File hashes not supported by AbuseIPDB - return appropriate response."""
        return APIResponse(
            success=False,
            status=APIStatus.ERROR,
            error_message="AbuseIPDB does not support file hash analysis. Use IP address instead."
        )
    
    async def get_reports(self, ip_address: str, max_age_days: int = 90, per_page: int = 25) -> APIResponse:
        """Get detailed abuse reports for an IP address."""
        try:
            if not is_valid_ip(ip_address):
                return APIResponse(
                    success=False,
                    status=APIStatus.ERROR,
                    error_message=f"Invalid IP address format: {ip_address}"
                )
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': max_age_days,
                'perPage': per_page
            }
            
            raw_response = await self._make_request("reports", params)
            
            return APIResponse(
                success=True,
                status=APIStatus.SUCCESS,
                raw_response=raw_response,
                quota_remaining=self.quota.requests_remaining
            )
            
        except AdapterError as e:
            return APIResponse(
                success=False,
                status=e.status,
                error_message=str(e),
                retry_after=e.retry_after
            )
    
    def normalize_response(self, raw_response: Dict[str, Any], 
                          resource: str, resource_type: ResourceType) -> ThreatIntelligence:
        """Normalize AbuseIPDB response to standard format."""
        try:
            data = raw_response.get("data", {})
            
            # Extract abuse confidence percentage (0-100)
            abuse_confidence = data.get("abuseConfidencePercentage", 0)
            
            # Determine threat level based on abuse confidence
            if abuse_confidence >= 80:
                threat_level = ThreatLevel.CRITICAL
            elif abuse_confidence >= 60:
                threat_level = ThreatLevel.HIGH
            elif abuse_confidence >= 30:
                threat_level = ThreatLevel.MEDIUM
            elif abuse_confidence > 0:
                threat_level = ThreatLevel.LOW
            else:
                threat_level = ThreatLevel.SAFE
            
            # Calculate confidence based on total reports and recency
            total_reports = data.get("totalReports", 0)
            is_public = data.get("isPublic", False)
            
            if total_reports >= 100:
                confidence = 0.95
            elif total_reports >= 50:
                confidence = 0.90
            elif total_reports >= 10:
                confidence = 0.80
            elif total_reports > 0:
                confidence = 0.70
            else:
                confidence = 0.60 if is_public else 0.40
            
            # Extract detected threats from categories
            detected_threats = []
            categories = data.get("categories", [])
            for category_id in categories:
                category_name = self.abuse_categories.get(category_id, f"Category {category_id}")
                detected_threats.append(category_name)
            
            # Build category list
            category_list = []
            if data.get("isPublic"):
                category_list.append("Public IP")
            if data.get("isWhitelisted"):
                category_list.append("Whitelisted")
            
            usage_type = data.get("usageType", "")
            if usage_type:
                category_list.append(f"Usage: {usage_type}")
            
            # Parse timestamps
            last_seen = None
            if "lastReportedAt" in data and data["lastReportedAt"]:
                try:
                    last_seen = datetime.fromisoformat(data["lastReportedAt"].replace('Z', '+00:00'))
                except ValueError:
                    pass
            
            # Calculate reputation score (inverse of abuse confidence)
            reputation_score = max(0, (100 - abuse_confidence) / 100)
            
            return ThreatIntelligence(
                resource=resource,
                resource_type=resource_type,
                threat_level=threat_level,
                confidence=confidence,
                source="abuseipdb",
                detected_threats=detected_threats,
                categories=category_list,
                reputation_score=reputation_score,
                first_seen=None,  # AbuseIPDB doesn't provide first seen
                last_seen=last_seen,
                metadata={
                    "abuse_confidence": abuse_confidence,
                    "total_reports": total_reports,
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "is_public": is_public,
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "country_code": data.get("countryCode", ""),
                    "usage_type": usage_type,
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "tor": data.get("tor", False)
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error normalizing AbuseIPDB response: {str(e)}")
            # Return safe fallback
            return ThreatIntelligence(
                resource=resource,
                resource_type=resource_type,
                threat_level=ThreatLevel.UNKNOWN,
                confidence=0.1,
                source="abuseipdb",
                detected_threats=[],
                categories=[],
                metadata={"error": f"Normalization failed: {str(e)}"}
            )
    
    async def close(self):
        """Close HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


# Example usage and testing
async def test_abuseipdb_client():
    """Test AbuseIPDB client with sample data."""
    import os
    
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        print("❌ ABUSEIPDB_API_KEY environment variable not set")
        return
    
    async with AbuseIPDBClient(api_key) as client:
        # Test IP analysis with known malicious IP
        print("Testing IP analysis...")
        ip_result = await client.analyze_ip("185.220.101.182")  # Known Tor exit node
        print(f"IP Result: {ip_result.success}")
        if ip_result.data:
            print(f"  Threat Level: {ip_result.data.threat_level}")
            print(f"  Confidence: {ip_result.data.confidence}")
            print(f"  Detected Threats: {ip_result.data.detected_threats}")
        
        # Test with clean IP
        print("Testing clean IP...")
        clean_result = await client.analyze_ip("8.8.8.8")  # Google DNS
        print(f"Clean IP Result: {clean_result.success}")
        if clean_result.data:
            print(f"  Threat Level: {clean_result.data.threat_level}")
            print(f"  Reputation Score: {clean_result.data.reputation_score}")
        
        # Test quota status
        print(f"Quota status: {client.get_quota_status()}")


if __name__ == "__main__":
    asyncio.run(test_abuseipdb_client())