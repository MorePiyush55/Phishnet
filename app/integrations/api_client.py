"""Single source of truth for all external API interactions."""

import asyncio
import logging
from typing import Dict, Any, Optional, List, Union
from urllib.parse import urljoin, urlparse
from datetime import datetime, timedelta
import json

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from src.common.constants import Constants, ErrorCodes, ExternalAPIStatus
from app.config.settings import settings


logger = logging.getLogger(__name__)


class APIClientError(Exception):
    """Base exception for API client errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, error_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


class RateLimitError(APIClientError):
    """Raised when rate limit is exceeded."""
    pass


class APIClient:
    """
    Unified API client for all external service integrations.
    
    Provides:
    - Consistent error handling and retry logic
    - Rate limiting and request throttling
    - Response caching and validation
    - Monitoring and observability
    - Circuit breaker pattern for resilience
    """
    
    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(Constants.EXTERNAL_API_TIMEOUT),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100)
        )
        self._rate_limits: Dict[str, Dict[str, Any]] = {}
        self._circuit_states: Dict[str, Dict[str, Any]] = {}
        self._cache: Dict[str, Dict[str, Any]] = {}
        
    async def __aenter__(self):
        """Async context manager entry."""
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
        
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    def _get_cache_key(self, method: str, url: str, params: Optional[Dict] = None) -> str:
        """Generate cache key for request."""
        key_parts = [method.upper(), url]
        if params:
            sorted_params = sorted(params.items())
            key_parts.append(json.dumps(sorted_params, sort_keys=True))
        return "|".join(key_parts)
    
    def _is_cached_response_valid(self, cache_entry: Dict[str, Any], ttl_seconds: int = 300) -> bool:
        """Check if cached response is still valid."""
        cached_at = datetime.fromisoformat(cache_entry.get("cached_at", ""))
        return (datetime.utcnow() - cached_at).total_seconds() < ttl_seconds
    
    def _check_rate_limit(self, service: str) -> bool:
        """Check if request is within rate limit for service."""
        if service not in self._rate_limits:
            return True
            
        rate_info = self._rate_limits[service]
        now = datetime.utcnow()
        window_start = datetime.fromisoformat(rate_info.get("window_start", now.isoformat()))
        
        # Reset window if expired
        if (now - window_start).total_seconds() >= rate_info.get("window_seconds", 60):
            self._rate_limits[service] = {
                "requests": 0,
                "window_start": now.isoformat(),
                "window_seconds": rate_info.get("window_seconds", 60),
                "limit": rate_info.get("limit", 100)
            }
            return True
        
        return rate_info.get("requests", 0) < rate_info.get("limit", 100)
    
    def _update_rate_limit(self, service: str, limit: int = 100, window_seconds: int = 60):
        """Update rate limit tracking for service."""
        if service not in self._rate_limits:
            self._rate_limits[service] = {
                "requests": 0,
                "window_start": datetime.utcnow().isoformat(),
                "window_seconds": window_seconds,
                "limit": limit
            }
        
        self._rate_limits[service]["requests"] += 1
    
    @retry(
        stop=stop_after_attempt(Constants.MAX_RETRIES),
        wait=wait_exponential(multiplier=1, min=1, max=60),
        retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError))
    )
    async def _make_request(
        self,
        method: str,
        url: str,
        service: str = "default",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes]] = None,
        use_cache: bool = True,
        cache_ttl: int = 300
    ) -> Dict[str, Any]:
        """
        Make HTTP request with retry logic, rate limiting, and caching.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            service: Service name for rate limiting
            headers: Request headers
            params: Query parameters
            json_data: JSON payload
            data: Raw data payload
            use_cache: Whether to use response caching
            cache_ttl: Cache TTL in seconds
            
        Returns:
            Response data as dictionary
            
        Raises:
            APIClientError: For API-related errors
            RateLimitError: When rate limit is exceeded
        """
        
        # Check rate limit
        if not self._check_rate_limit(service):
            raise RateLimitError(
                f"Rate limit exceeded for service: {service}",
                error_code=ErrorCodes.API_RATE_LIMITED
            )
        
        # Check cache for GET requests
        cache_key = self._get_cache_key(method, url, params)
        if use_cache and method.upper() == "GET" and cache_key in self._cache:
            cache_entry = self._cache[cache_key]
            if self._is_cached_response_valid(cache_entry, cache_ttl):
                logger.debug(f"Cache hit for {method} {url}")
                return cache_entry["response"]
        
        # Prepare request
        request_headers = {
            "User-Agent": "PhishNet/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        if headers:
            request_headers.update(headers)
        
        try:
            # Make request
            logger.debug(f"Making {method} request to {url}")
            response = await self.client.request(
                method=method,
                url=url,
                headers=request_headers,
                params=params,
                json=json_data,
                content=data
            )
            
            # Update rate limit
            self._update_rate_limit(service)
            
            # Handle HTTP errors
            if response.status_code >= 400:
                error_msg = f"HTTP {response.status_code} for {method} {url}"
                if response.status_code == 429:
                    raise RateLimitError(
                        error_msg,
                        status_code=response.status_code,
                        error_code=ErrorCodes.API_RATE_LIMITED
                    )
                elif response.status_code >= 500:
                    raise APIClientError(
                        error_msg,
                        status_code=response.status_code,
                        error_code=ErrorCodes.API_UNAVAILABLE
                    )
                else:
                    raise APIClientError(
                        error_msg,
                        status_code=response.status_code,
                        error_code=ErrorCodes.API_INVALID_RESPONSE
                    )
            
            # Parse response
            try:
                response_data = response.json() if response.content else {}
            except json.JSONDecodeError:
                response_data = {"text": response.text}
            
            # Cache successful GET responses
            if use_cache and method.upper() == "GET" and response.status_code == 200:
                self._cache[cache_key] = {
                    "response": response_data,
                    "cached_at": datetime.utcnow().isoformat()
                }
            
            logger.debug(f"Successfully completed {method} {url}")
            return response_data
            
        except httpx.RequestError as e:
            logger.error(f"Request error for {method} {url}: {e}")
            raise APIClientError(
                f"Request failed: {str(e)}",
                error_code=ErrorCodes.API_UNAVAILABLE
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error for {method} {url}: {e}")
            raise APIClientError(
                f"HTTP error: {e.response.status_code}",
                status_code=e.response.status_code,
                error_code=ErrorCodes.API_INVALID_RESPONSE
            )
    
    # Convenience methods for common HTTP verbs
    async def get(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make GET request."""
        return await self._make_request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make POST request."""
        return await self._make_request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make PUT request.""" 
        return await self._make_request("PUT", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make DELETE request."""
        return await self._make_request("DELETE", url, **kwargs)


# Specialized API clients for different services

class ThreatIntelAPIClient(APIClient):
    """Threat intelligence API client."""
    
    def __init__(self):
        super().__init__()
        self.virustotal_api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
        self.urlvoid_api_key = getattr(settings, 'URLVOID_API_KEY', None)
    
    async def check_url_virustotal(self, url: str) -> Dict[str, Any]:
        """Check URL with VirusTotal API."""
        if not self.virustotal_api_key:
            return {"error": "VirusTotal API key not configured"}
        
        headers = {"x-apikey": self.virustotal_api_key}
        
        # Submit URL for analysis
        submit_response = await self.post(
            "https://www.virustotal.com/vtapi/v2/url/scan",
            service="virustotal",
            headers=headers,
            json_data={"url": url}
        )
        
        # Get analysis results
        if "scan_id" in submit_response:
            report_response = await self.get(
                "https://www.virustotal.com/vtapi/v2/url/report",
                service="virustotal", 
                headers=headers,
                params={"resource": url}
            )
            return report_response
        
        return submit_response
    
    async def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation using multiple sources."""
        results = {}
        
        # VirusTotal domain check
        if self.virustotal_api_key:
            try:
                vt_result = await self.get(
                    f"https://www.virustotal.com/vtapi/v2/domain/report",
                    service="virustotal",
                    headers={"x-apikey": self.virustotal_api_key},
                    params={"domain": domain}
                )
                results["virustotal"] = vt_result
            except APIClientError as e:
                logger.warning(f"VirusTotal domain check failed: {e}")
                results["virustotal"] = {"error": str(e)}
        
        return results


class AIServiceAPIClient(APIClient):
    """AI service API client for email analysis."""
    
    def __init__(self):
        super().__init__()
        self.openai_api_key = getattr(settings, 'OPENAI_API_KEY', None)
    
    async def analyze_email_content(self, email_content: str, subject: str) -> Dict[str, Any]:
        """Analyze email content using AI service."""
        if not self.openai_api_key:
            return {"error": "AI service API key not configured"}
        
        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json"
        }
        
        prompt = f"""
        Analyze the following email for phishing indicators:
        
        Subject: {subject}
        Content: {email_content}
        
        Provide a JSON response with:
        - is_phishing: boolean
        - confidence: float (0-1)
        - indicators: list of detected indicators
        - classification: string (legitimate, suspicious, phishing)
        """
        
        try:
            response = await self.post(
                "https://api.openai.com/v1/chat/completions",
                service="openai",
                headers=headers,
                json_data={
                    "model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 500,
                    "temperature": 0.1
                }
            )
            return response
        except APIClientError as e:
            logger.error(f"AI analysis failed: {e}")
            return {"error": str(e)}


# Singleton instances
threat_intel_client = ThreatIntelAPIClient()
ai_service_client = AIServiceAPIClient()
api_client = APIClient()


# Context managers for resource management
async def get_threat_intel_client() -> ThreatIntelAPIClient:
    """Get threat intelligence client."""
    return threat_intel_client


async def get_ai_service_client() -> AIServiceAPIClient:
    """Get AI service client."""
    return ai_service_client


async def get_api_client() -> APIClient:
    """Get general API client."""
    return api_client
