"""
External API Health Checker

Checks connectivity and status of external APIs used by PhishNet.
"""

import asyncio
import aiohttp
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from .base import HealthChecker, HealthResult, HealthStatus
from app.config.settings import get_settings


class ExternalAPIHealthChecker(HealthChecker):
    """Health checker for external APIs."""
    
    def __init__(self, timeout: float = 10.0):
        super().__init__("external_apis", timeout)
        self.settings = get_settings()
    
    async def check_health(self) -> HealthResult:
        """Check all external API health."""
        api_results = await self._check_all_apis()
        
        # Determine overall status
        healthy_count = sum(1 for r in api_results.values() if r['status'] == 'healthy')
        total_apis = len(api_results)
        
        if healthy_count == total_apis:
            status = HealthStatus.HEALTHY
            message = f"All {total_apis} external APIs are healthy"
        elif healthy_count > total_apis * 0.5:
            status = HealthStatus.DEGRADED
            message = f"{healthy_count}/{total_apis} external APIs are healthy"
        else:
            status = HealthStatus.UNHEALTHY
            message = f"Only {healthy_count}/{total_apis} external APIs are healthy"
        
        return HealthResult(
            component=self.component_name,
            status=status,
            message=message,
            details={'apis': api_results, 'summary': {'healthy': healthy_count, 'total': total_apis}}
        )
    
    async def _check_all_apis(self) -> Dict[str, Dict[str, Any]]:
        """Check all configured external APIs."""
        results = {}
        
        # Skip API checks if mocking is enabled
        if self.settings.MOCK_EXTERNAL_APIS:
            return {
                'mocked_apis': {
                    'status': 'healthy',
                    'message': 'External APIs are mocked',
                    'response_time_ms': 0
                }
            }
        
        # Check each API concurrently
        tasks = []
        api_configs = [
            ('virustotal', self._check_virustotal),
            ('abuseipdb', self._check_abuseipdb),
            ('gemini', self._check_gemini),
            ('gmail', self._check_gmail_oauth),
        ]
        
        for api_name, check_func in api_configs:
            tasks.append(self._safe_api_check(api_name, check_func))
        
        api_results_list = await asyncio.gather(*tasks)
        
        # Combine results
        for api_name, result in api_results_list:
            results[api_name] = result
        
        return results
    
    async def _safe_api_check(self, api_name: str, check_func) -> tuple:
        """Safely run an API check function."""
        try:
            result = await check_func()
            return api_name, result
        except Exception as e:
            return api_name, {
                'status': 'unhealthy',
                'message': f"Check failed: {str(e)}",
                'error': str(e),
                'error_type': type(e).__name__
            }
    
    async def _check_virustotal(self) -> Dict[str, Any]:
        """Check VirusTotal API connectivity."""
        if not self.settings.VIRUSTOTAL_API_KEY:
            return {
                'status': 'degraded',
                'message': 'API key not configured',
                'configured': False
            }
        
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            'apikey': self.settings.VIRUSTOTAL_API_KEY,
            'resource': 'test'  # Dummy resource
        }
        
        return await self._make_api_request('VirusTotal', url, method='GET', params=params)
    
    async def _check_abuseipdb(self) -> Dict[str, Any]:
        """Check AbuseIPDB API connectivity."""
        if not self.settings.ABUSEIPDB_API_KEY:
            return {
                'status': 'degraded', 
                'message': 'API key not configured',
                'configured': False
            }
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': self.settings.ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': '8.8.8.8',  # Test with Google DNS
            'maxAgeInDays': 90
        }
        
        return await self._make_api_request('AbuseIPDB', url, method='GET', headers=headers, params=params)
    
    async def _check_gemini(self) -> Dict[str, Any]:
        """Check Google Gemini API connectivity."""
        api_key = self.settings.GEMINI_API_KEY or self.settings.GOOGLE_GEMINI_API_KEY
        if not api_key:
            return {
                'status': 'degraded',
                'message': 'API key not configured',
                'configured': False
            }
        
        # Simple request to Gemini API
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
        
        return await self._make_api_request('Gemini', url, method='GET')
    
    async def _check_gmail_oauth(self) -> Dict[str, Any]:
        """Check Gmail OAuth configuration."""
        if not self.settings.GMAIL_CLIENT_ID or not self.settings.GMAIL_CLIENT_SECRET:
            return {
                'status': 'degraded',
                'message': 'OAuth credentials not configured',
                'configured': False
            }
        
        # Check if OAuth endpoint is accessible
        url = "https://oauth2.googleapis.com/token"
        
        # Just check connectivity, not actual OAuth flow
        return await self._make_api_request('Gmail OAuth', url, method='HEAD', expect_status=[200, 400, 405])
    
    async def _make_api_request(self, 
                              api_name: str, 
                              url: str, 
                              method: str = 'GET',
                              headers: Optional[Dict] = None,
                              params: Optional[Dict] = None,
                              expect_status: Optional[List[int]] = None) -> Dict[str, Any]:
        """Make an API request and return health status."""
        if expect_status is None:
            expect_status = [200]
        
        import time
        start_time = time.time()
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params
                ) as response:
                    response_time = (time.time() - start_time) * 1000
                    
                    if response.status in expect_status:
                        return {
                            'status': 'healthy',
                            'message': f'{api_name} API is accessible',
                            'response_time_ms': response_time,
                            'status_code': response.status,
                            'configured': True
                        }
                    else:
                        return {
                            'status': 'unhealthy',
                            'message': f'{api_name} API returned status {response.status}',
                            'response_time_ms': response_time,
                            'status_code': response.status,
                            'configured': True
                        }
                        
        except asyncio.TimeoutError:
            return {
                'status': 'unhealthy',
                'message': f'{api_name} API request timed out',
                'response_time_ms': self.timeout * 1000,
                'configured': True,
                'error': 'timeout'
            }
        except aiohttp.ClientError as e:
            response_time = (time.time() - start_time) * 1000
            return {
                'status': 'unhealthy', 
                'message': f'{api_name} API connection failed: {str(e)}',
                'response_time_ms': response_time,
                'configured': True,
                'error': str(e),
                'error_type': 'ClientError'
            }
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return {
                'status': 'unhealthy',
                'message': f'{api_name} API check failed: {str(e)}',
                'response_time_ms': response_time,
                'configured': True,
                'error': str(e),
                'error_type': type(e).__name__
            }
