"""
VirusTotal API adapter for threat intelligence.

This module provides integration with VirusTotal's API v3 for URL, domain, IP, and file hash analysis.
"""

import hashlib
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
import aiohttp
import asyncio

from .base import (
    ThreatIntelligenceAdapter, APIResponse, ThreatIntelligence, APIStatus,
    ThreatLevel, ResourceType, AdapterError, QuotaExceededError, 
    RateLimitError, TimeoutError, UnauthorizedError,
    normalize_url, extract_domain, is_valid_ip, is_valid_domain, is_valid_file_hash
)


class VirusTotalClient(ThreatIntelligenceAdapter):
    """VirusTotal API v3 client with resilience patterns."""
    
    def __init__(self, api_key: str, requests_per_minute: int = 4):
        super().__init__(
            api_key=api_key,
            base_url="https://www.virustotal.com/api/v3",
            name="virustotal"
        )
        self.requests_per_minute = requests_per_minute
        self.last_request_time = 0
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Configure quota based on API tier
        if requests_per_minute <= 4:  # Free tier
            self.quota.requests_limit = 500  # Daily limit for free tier
        else:  # Paid tier
            self.quota.requests_limit = requests_per_minute * 1440  # Per day
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            headers = {
                'X-Apikey': self.api_key,
                'Accept': 'application/json',
                'User-Agent': 'PhishNet-ThreatIntel/1.0'
            }
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers
            )
        return self.session
    
    async def _rate_limit(self) -> None:
        """Enforce rate limiting based on API tier."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        min_interval = 60.0 / self.requests_per_minute
        
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            self.logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            await asyncio.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    async def _make_request(self, endpoint: str, resource_id: str) -> Dict[str, Any]:
        """Make authenticated request to VirusTotal API."""
        if not self.check_quota():
            raise QuotaExceededError(
                f"VirusTotal quota exceeded. Requests made: {self.quota.requests_made}/{self.quota.requests_limit}"
            )
        
        await self._rate_limit()
        
        session = await self._get_session()
        url = f"{self.base_url}/{endpoint}/{resource_id}"
        
        start_time = time.time()
        
        try:
            async with session.get(url) as response:
                response_time = time.time() - start_time
                
                if response.status == 200:
                    self.consume_quota()
                    data = await response.json()
                    self.logger.debug(f"VirusTotal API success: {endpoint}/{resource_id[:16]}...")
                    return data
                elif response.status == 401:
                    raise UnauthorizedError("Invalid VirusTotal API key")
                elif response.status == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    raise RateLimitError(
                        f"VirusTotal rate limit exceeded",
                        retry_after=retry_after
                    )
                elif response.status == 404:
                    # Resource not found in VT database
                    return {"data": {"attributes": {"last_analysis_stats": {}}}}
                else:
                    error_text = await response.text()
                    raise AdapterError(
                        f"VirusTotal API error {response.status}: {error_text}",
                        APIStatus.ERROR
                    )
                    
        except asyncio.TimeoutError:
            raise TimeoutError("VirusTotal API request timed out")
        except aiohttp.ClientError as e:
            raise AdapterError(f"VirusTotal API connection error: {str(e)}", APIStatus.ERROR)
    
    async def analyze_url(self, url: str) -> APIResponse:
        """Analyze URL using VirusTotal."""
        try:
            normalized_url = normalize_url(url)
            url_id = self._encode_url_for_vt(normalized_url)
            
            raw_response = await self._make_request("urls", url_id)
            threat_intel = self.normalize_response(raw_response, normalized_url, ResourceType.URL)
            
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
            self.logger.error(f"Unexpected error analyzing URL {url}: {str(e)}")
            return APIResponse(
                success=False,
                status=APIStatus.ERROR,
                error_message=f"Unexpected error: {str(e)}"
            )
    
    async def analyze_domain(self, domain: str) -> APIResponse:
        """Analyze domain using VirusTotal."""
        try:
            if not is_valid_domain(domain):
                return APIResponse(
                    success=False,
                    status=APIStatus.ERROR,
                    error_message=f"Invalid domain format: {domain}"
                )
            
            raw_response = await self._make_request("domains", domain)
            threat_intel = self.normalize_response(raw_response, domain, ResourceType.DOMAIN)
            
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
            self.logger.error(f"Unexpected error analyzing domain {domain}: {str(e)}")
            return APIResponse(
                success=False,
                status=APIStatus.ERROR,
                error_message=f"Unexpected error: {str(e)}"
            )
    
    async def analyze_ip(self, ip_address: str) -> APIResponse:
        """Analyze IP address using VirusTotal."""
        try:
            if not is_valid_ip(ip_address):
                return APIResponse(
                    success=False,
                    status=APIStatus.ERROR,
                    error_message=f"Invalid IP address format: {ip_address}"
                )
            
            raw_response = await self._make_request("ip_addresses", ip_address)
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
        """Analyze file hash using VirusTotal."""
        try:
            if not is_valid_file_hash(file_hash):
                return APIResponse(
                    success=False,
                    status=APIStatus.ERROR,
                    error_message=f"Invalid file hash format: {file_hash}"
                )
            
            raw_response = await self._make_request("files", file_hash)
            threat_intel = self.normalize_response(raw_response, file_hash, ResourceType.FILE_HASH)
            
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
            self.logger.error(f"Unexpected error analyzing hash {file_hash}: {str(e)}")
            return APIResponse(
                success=False,
                status=APIStatus.ERROR,
                error_message=f"Unexpected error: {str(e)}"
            )
    
    def normalize_response(self, raw_response: Dict[str, Any], 
                          resource: str, resource_type: ResourceType) -> ThreatIntelligence:
        """Normalize VirusTotal response to standard format."""
        try:
            data = raw_response.get("data", {})
            attributes = data.get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            
            # Calculate threat metrics
            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            clean = last_analysis_stats.get("harmless", 0)
            undetected = last_analysis_stats.get("undetected", 0)
            total = malicious + suspicious + clean + undetected
            
            # Determine threat level and confidence
            if total == 0:
                threat_level = ThreatLevel.UNKNOWN
                confidence = 0.1
            else:
                malicious_ratio = malicious / total
                suspicious_ratio = suspicious / total
                threat_ratio = malicious_ratio + (suspicious_ratio * 0.5)
                
                if malicious_ratio >= 0.3:  # 30%+ malicious
                    threat_level = ThreatLevel.CRITICAL
                elif malicious_ratio >= 0.1:  # 10%+ malicious
                    threat_level = ThreatLevel.HIGH
                elif threat_ratio >= 0.2:  # 20%+ threat indicators
                    threat_level = ThreatLevel.MEDIUM
                elif threat_ratio > 0:
                    threat_level = ThreatLevel.LOW
                else:
                    threat_level = ThreatLevel.SAFE
                
                # Confidence based on number of engines
                if total >= 60:
                    confidence = 0.95
                elif total >= 30:
                    confidence = 0.85
                elif total >= 10:
                    confidence = 0.75
                else:
                    confidence = 0.6
            
            # Extract detected threats
            detected_threats = []
            last_analysis_results = attributes.get("last_analysis_results", {})
            for engine, result in last_analysis_results.items():
                if result.get("category") in ["malicious", "suspicious"]:
                    result_name = result.get("result", "").strip()
                    if result_name and result_name not in detected_threats:
                        detected_threats.append(result_name)
            
            # Extract categories and metadata
            categories = attributes.get("categories", {})
            category_list = [cat for cat in categories.values() if cat]
            
            # Parse timestamps
            first_seen = None
            last_seen = None
            if "first_submission_date" in attributes:
                first_seen = datetime.fromtimestamp(attributes["first_submission_date"])
            if "last_analysis_date" in attributes:
                last_seen = datetime.fromtimestamp(attributes["last_analysis_date"])
            
            # Calculate reputation score (0-100 scale converted to 0-1)
            reputation_score = None
            if "reputation" in attributes:
                reputation_score = max(0, min(1, attributes["reputation"] / 100))
            
            return ThreatIntelligence(
                resource=resource,
                resource_type=resource_type,
                threat_level=threat_level,
                confidence=confidence,
                source="virustotal",
                detected_threats=detected_threats[:10],  # Limit to top 10
                categories=category_list,
                reputation_score=reputation_score,
                first_seen=first_seen,
                last_seen=last_seen,
                metadata={
                    "analysis_stats": last_analysis_stats,
                    "total_engines": total,
                    "detection_ratio": f"{malicious + suspicious}/{total}" if total > 0 else "0/0",
                    "vt_id": data.get("id"),
                    "vt_type": data.get("type")
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error normalizing VirusTotal response: {str(e)}")
            # Return safe fallback
            return ThreatIntelligence(
                resource=resource,
                resource_type=resource_type,
                threat_level=ThreatLevel.UNKNOWN,
                confidence=0.1,
                source="virustotal",
                detected_threats=[],
                categories=[],
                metadata={"error": f"Normalization failed: {str(e)}"}
            )
    
    def _encode_url_for_vt(self, url: str) -> str:
        """Encode URL for VirusTotal API (base64 without padding)."""
        import base64
        url_bytes = url.encode('utf-8')
        b64_encoded = base64.urlsafe_b64encode(url_bytes).decode('utf-8')
        # Remove padding
        return b64_encoded.rstrip('=')
    
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
async def test_virustotal_client():
    """Test VirusTotal client with sample data."""
    import os
    
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("❌ VIRUSTOTAL_API_KEY environment variable not set")
        return
    
    async with VirusTotalClient(api_key) as client:
        # Test URL analysis
        print("Testing URL analysis...")
        url_result = await client.analyze_url("https://www.google.com")
        print(f"URL Result: {url_result.success}, Level: {url_result.data.threat_level if url_result.data else 'N/A'}")
        
        # Test domain analysis
        print("Testing domain analysis...")
        domain_result = await client.analyze_domain("google.com")
        print(f"Domain Result: {domain_result.success}, Level: {domain_result.data.threat_level if domain_result.data else 'N/A'}")
        
        # Test quota status
        print(f"Quota status: {client.get_quota_status()}")


if __name__ == "__main__":
    asyncio.run(test_virustotal_client())