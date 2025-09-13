"""
Privacy-preserving service adapter layer.
Handles sandbox IP routing and user data redaction for external API calls.
"""

import asyncio
import aiohttp
import random
import hashlib
import time
from typing import Dict, Any, List, Optional, Union
from urllib.parse import urlparse
import ipaddress
import socket

from app.config.settings import settings
from app.config.logging import get_logger

logger = get_logger(__name__)


class PrivacyPreservingAdapter:
    """
    Adapter layer that adds privacy protection to external API calls.
    Handles IP anonymization, request routing, and data redaction.
    """
    
    def __init__(self):
        self.sandbox_ip_pool = self._initialize_sandbox_ips()
        self.proxy_rotation_index = 0
        self.request_cache = {}
        
        # Privacy configuration
        self.privacy_config = {
            'use_proxy_rotation': True,
            'enable_ip_masking': True,
            'request_delay_range': (1, 3),  # seconds
            'max_retries': 2,
            'timeout': 30,
            'user_agent_rotation': True
        }
        
        # Pool of legitimate user agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
    
    def _initialize_sandbox_ips(self) -> List[str]:
        """Initialize sandbox IP pool for external requests."""
        # In production, this would be configured with dedicated sandbox IPs
        # For development/testing, use empty list (will use default routing)
        sandbox_ips = []
        
        # Check for configured sandbox IPs
        if hasattr(settings, 'SANDBOX_IP_POOL'):
            sandbox_ips = settings.SANDBOX_IP_POOL
        
        if not sandbox_ips:
            logger.info("No sandbox IP pool configured, using default routing")
        else:
            logger.info(f"Initialized sandbox IP pool with {len(sandbox_ips)} addresses")
        
        return sandbox_ips
    
    async def make_protected_request(
        self,
        method: str,
        url: str,
        service_name: str,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Make HTTP request with privacy protection and IP masking.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            service_name: Name of the service being called
            **kwargs: Additional arguments for aiohttp request
            
        Returns:
            Response object with privacy protection applied
        """
        
        # Generate request ID for tracking
        request_id = hashlib.md5(f"{method}{url}{time.time()}".encode()).hexdigest()[:8]
        logger.debug(f"Making protected request {request_id} to {service_name}")
        
        try:
            # Apply privacy protection to request
            protected_kwargs = await self._apply_privacy_protection(kwargs, service_name)
            
            # Add request delay for privacy
            if self.privacy_config['request_delay_range']:
                delay = random.uniform(*self.privacy_config['request_delay_range'])
                await asyncio.sleep(delay)
            
            # Create session with privacy settings
            connector = await self._create_privacy_connector()
            
            async with aiohttp.ClientSession(connector=connector) as session:
                
                # Make request with retries
                for attempt in range(self.privacy_config['max_retries'] + 1):
                    try:
                        async with session.request(method, url, **protected_kwargs) as response:
                            logger.debug(f"Request {request_id} completed: {response.status}")
                            return response
                            
                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        if attempt < self.privacy_config['max_retries']:
                            logger.warning(f"Request {request_id} attempt {attempt + 1} failed: {e}")
                            await asyncio.sleep(2 ** attempt)  # Exponential backoff
                            continue
                        else:
                            logger.error(f"Request {request_id} failed after {attempt + 1} attempts: {e}")
                            raise
                            
        except Exception as e:
            logger.error(f"Protected request {request_id} failed: {e}")
            raise
    
    async def _apply_privacy_protection(
        self, 
        kwargs: Dict[str, Any], 
        service_name: str
    ) -> Dict[str, Any]:
        """Apply privacy protection settings to request kwargs."""
        
        protected_kwargs = kwargs.copy()
        
        # Set timeout
        if 'timeout' not in protected_kwargs:
            protected_kwargs['timeout'] = aiohttp.ClientTimeout(
                total=self.privacy_config['timeout']
            )
        
        # Set headers with privacy protection
        headers = protected_kwargs.get('headers', {})
        
        # Rotate user agent
        if self.privacy_config['user_agent_rotation']:
            headers['User-Agent'] = random.choice(self.user_agents)
        
        # Add privacy headers
        headers.update({
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        })
        
        # Service-specific header adjustments
        if service_name == 'virustotal':
            headers['x-tool'] = 'PhishNet-Security'
        elif service_name == 'abuseipdb':
            headers['Accept'] = 'application/json'
        elif service_name == 'gemini':
            headers['Content-Type'] = 'application/json'
        
        protected_kwargs['headers'] = headers
        
        # Redact sensitive data from request body
        if 'json' in protected_kwargs:
            protected_kwargs['json'] = self._redact_request_data(
                protected_kwargs['json'], service_name
            )
        
        if 'data' in protected_kwargs:
            protected_kwargs['data'] = self._redact_request_data(
                protected_kwargs['data'], service_name
            )
        
        return protected_kwargs
    
    async def _create_privacy_connector(self) -> aiohttp.TCPConnector:
        """Create TCP connector with privacy settings."""
        
        connector_kwargs = {
            'limit': 10,
            'limit_per_host': 2,
            'ttl_dns_cache': 300,
            'use_dns_cache': True,
            'ssl': False,  # We handle SSL verification separately
            'enable_cleanup_closed': True
        }
        
        # Apply IP binding if sandbox pool is available
        if self.sandbox_ip_pool and self.privacy_config['enable_ip_masking']:
            # Rotate through sandbox IPs
            sandbox_ip = self.sandbox_ip_pool[
                self.proxy_rotation_index % len(self.sandbox_ip_pool)
            ]
            self.proxy_rotation_index += 1
            
            try:
                # Bind to specific IP
                connector_kwargs['local_addr'] = (sandbox_ip, 0)
                logger.debug(f"Binding request to sandbox IP: {sandbox_ip}")
            except Exception as e:
                logger.warning(f"Failed to bind to sandbox IP {sandbox_ip}: {e}")
        
        return aiohttp.TCPConnector(**connector_kwargs)
    
    def _redact_request_data(
        self, 
        data: Union[Dict[str, Any], str], 
        service_name: str
    ) -> Union[Dict[str, Any], str]:
        """Redact sensitive data from request payload."""
        
        if isinstance(data, dict):
            redacted_data = {}
            
            for key, value in data.items():
                if isinstance(value, str):
                    redacted_data[key] = self._redact_text_content(value, service_name)
                elif isinstance(value, dict):
                    redacted_data[key] = self._redact_request_data(value, service_name)
                elif isinstance(value, list):
                    redacted_data[key] = [
                        self._redact_text_content(item, service_name) if isinstance(item, str) else item
                        for item in value
                    ]
                else:
                    redacted_data[key] = value
            
            return redacted_data
            
        elif isinstance(data, str):
            return self._redact_text_content(data, service_name)
        
        return data
    
    def _redact_text_content(self, text: str, service_name: str) -> str:
        """Redact sensitive content from text before sending to external service."""
        if not text:
            return text
        
        import re
        
        # Create redacted version
        redacted_text = text
        
        # General redactions (apply to all services)
        
        # Redact email addresses but preserve domains for analysis
        redacted_text = re.sub(
            r'\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})', 
            r'[REDACTED_USER]@\\1', 
            redacted_text
        )
        
        # Redact phone numbers
        redacted_text = re.sub(r'\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b', '[PHONE_REDACTED]', redacted_text)
        
        # Redact credit card numbers
        redacted_text = re.sub(r'\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b', '[CARD_REDACTED]', redacted_text)
        
        # Redact SSN patterns
        redacted_text = re.sub(r'\\b\\d{3}-\\d{2}-\\d{4}\\b', '[SSN_REDACTED]', redacted_text)
        
        # Redact potential API keys/tokens
        redacted_text = re.sub(r'\\b[A-Za-z0-9+/]{32,}\\b', '[TOKEN_REDACTED]', redacted_text)
        
        # Service-specific redactions
        if service_name == 'gemini':
            # For LLM analysis, preserve more context but redact specific PII
            redacted_text = re.sub(r'\\b\\d{9,}\\b', '[NUMBER_REDACTED]', redacted_text)
            
        elif service_name in ['virustotal', 'abuseipdb']:
            # For security analysis, preserve suspicious patterns
            pass
        
        # Limit content length to prevent data leakage
        max_length = 2000  # Configurable limit
        if len(redacted_text) > max_length:
            redacted_text = redacted_text[:max_length] + "...[CONTENT_TRUNCATED]"
        
        return redacted_text
    
    async def validate_external_request(
        self, 
        url: str, 
        service_name: str
    ) -> Dict[str, Any]:
        """
        Validate external request for privacy and security compliance.
        
        Args:
            url: Target URL
            service_name: Service being called
            
        Returns:
            Validation result with approval status and warnings
        """
        
        validation_result = {
            'approved': True,
            'warnings': [],
            'blocked_reasons': [],
            'privacy_score': 1.0
        }
        
        try:
            parsed_url = urlparse(url)
            
            # Check domain allowlist (if configured)
            if hasattr(settings, 'ALLOWED_EXTERNAL_DOMAINS'):
                allowed_domains = settings.ALLOWED_EXTERNAL_DOMAINS
                if parsed_url.netloc not in allowed_domains:
                    validation_result['approved'] = False
                    validation_result['blocked_reasons'].append(f"Domain not in allowlist: {parsed_url.netloc}")
            
            # Check for private/internal IPs
            try:
                # Resolve hostname to IP
                ip = socket.gethostbyname(parsed_url.netloc)
                ip_obj = ipaddress.ip_address(ip)
                
                if ip_obj.is_private or ip_obj.is_loopback:
                    validation_result['approved'] = False
                    validation_result['blocked_reasons'].append(f"Request to private IP blocked: {ip}")
                    
            except (socket.gaierror, ValueError) as e:
                validation_result['warnings'].append(f"Could not resolve hostname: {e}")
                validation_result['privacy_score'] *= 0.8
            
            # Service-specific validations
            service_validations = {
                'virustotal': self._validate_virustotal_request,
                'abuseipdb': self._validate_abuseipdb_request,
                'gemini': self._validate_gemini_request
            }
            
            if service_name in service_validations:
                service_result = service_validations[service_name](url)
                validation_result['warnings'].extend(service_result.get('warnings', []))
                if not service_result.get('approved', True):
                    validation_result['approved'] = False
                    validation_result['blocked_reasons'].extend(service_result.get('blocked_reasons', []))
            
            # Calculate final privacy score
            if validation_result['blocked_reasons']:
                validation_result['privacy_score'] = 0.0
            elif validation_result['warnings']:
                validation_result['privacy_score'] *= 0.7
            
        except Exception as e:
            logger.error(f"Request validation failed: {e}")
            validation_result.update({
                'approved': False,
                'blocked_reasons': [f"Validation error: {e}"],
                'privacy_score': 0.0
            })
        
        return validation_result
    
    def _validate_virustotal_request(self, url: str) -> Dict[str, Any]:
        """Validate VirusTotal-specific request."""
        return {
            'approved': True,
            'warnings': [],
            'notes': 'VirusTotal requests are generally safe for security analysis'
        }
    
    def _validate_abuseipdb_request(self, url: str) -> Dict[str, Any]:
        """Validate AbuseIPDB-specific request."""
        return {
            'approved': True,
            'warnings': [],
            'notes': 'AbuseIPDB requests are safe for IP reputation checking'
        }
    
    def _validate_gemini_request(self, url: str) -> Dict[str, Any]:
        """Validate Gemini LLM-specific request."""
        warnings = []
        
        # Check for Google AI API endpoint
        parsed = urlparse(url)
        if 'googleapis.com' not in parsed.netloc:
            warnings.append('Non-standard Gemini API endpoint detected')
        
        return {
            'approved': True,
            'warnings': warnings,
            'notes': 'Gemini requests require content redaction'
        }
    
    async def log_privacy_event(
        self,
        event_type: str,
        service_name: str,
        details: Dict[str, Any]
    ) -> None:
        """Log privacy-related events for audit purposes."""
        
        privacy_event = {
            'timestamp': time.time(),
            'event_type': event_type,
            'service_name': service_name,
            'details': details,
            'redacted': True
        }
        
        # Remove sensitive details before logging
        safe_details = {}
        for key, value in details.items():
            if key in ['ip_address', 'user_agent', 'headers']:
                safe_details[key] = '[REDACTED]'
            elif isinstance(value, str) and len(value) > 100:
                safe_details[key] = value[:100] + '...[TRUNCATED]'
            else:
                safe_details[key] = value
        
        privacy_event['details'] = safe_details
        
        # Log event (in production, this might go to a secure audit log)
        logger.info(f"Privacy event: {privacy_event}")
    
    def get_privacy_statistics(self) -> Dict[str, Any]:
        """Get privacy protection statistics."""
        return {
            'sandbox_ips_configured': len(self.sandbox_ip_pool),
            'user_agents_available': len(self.user_agents),
            'privacy_protection_enabled': True,
            'request_delay_enabled': self.privacy_config['request_delay_range'] is not None,
            'ip_masking_enabled': self.privacy_config['enable_ip_masking'],
            'user_agent_rotation_enabled': self.privacy_config['user_agent_rotation']
        }


# Global instance
privacy_adapter = PrivacyPreservingAdapter()


def get_privacy_adapter() -> PrivacyPreservingAdapter:
    """Get the global privacy adapter instance."""
    return privacy_adapter
