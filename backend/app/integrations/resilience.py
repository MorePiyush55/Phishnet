"""
Circuit breaker and resilience patterns for third-party API integrations.

This module implements circuit breaker, retry, timeout, and fallback patterns
to ensure system resilience when external services are unavailable or degraded.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, Optional, TypeVar, Union
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, blocking requests  
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    failure_threshold: int = 5          # Failures before opening
    recovery_timeout: int = 60          # Seconds before trying half-open
    success_threshold: int = 3          # Successes in half-open to close
    timeout_seconds: float = 30.0       # Request timeout
    expected_exception: tuple = (Exception,)  # Exceptions that count as failures


@dataclass
class CircuitBreakerStats:
    """Circuit breaker statistics."""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    total_requests: int = 0
    total_failures: int = 0
    total_successes: int = 0
    opened_at: Optional[datetime] = None
    
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate as percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.total_failures / self.total_requests) * 100
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        return 100.0 - self.failure_rate


class CircuitBreaker:
    """Circuit breaker implementation for API resilience."""
    
    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config
        self.stats = CircuitBreakerStats()
        self.logger = logging.getLogger(f"{__name__}.{name}")
        self._lock = asyncio.Lock()
    
    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with circuit breaker protection."""
        async with self._lock:
            # Check if circuit should transition states
            await self._check_state_transitions()
            
            # Block requests if circuit is open
            if self.stats.state == CircuitState.OPEN:
                self.logger.warning(f"Circuit breaker {self.name} is OPEN - blocking request")
                raise CircuitOpenError(f"Circuit breaker {self.name} is open")
            
            self.stats.total_requests += 1
        
        # Execute the function with timeout
        try:
            result = await asyncio.wait_for(
                func(*args, **kwargs),
                timeout=self.config.timeout_seconds
            )
            await self._record_success()
            return result
            
        except asyncio.TimeoutError:
            await self._record_failure()
            self.logger.warning(f"Circuit breaker {self.name} - request timed out")
            raise TimeoutError(f"Request timed out after {self.config.timeout_seconds}s")
            
        except self.config.expected_exception as e:
            await self._record_failure()
            self.logger.warning(f"Circuit breaker {self.name} - request failed: {str(e)}")
            raise
    
    async def _check_state_transitions(self):
        """Check and handle state transitions."""
        now = datetime.utcnow()
        
        if self.stats.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if (self.stats.opened_at and 
                now - self.stats.opened_at >= timedelta(seconds=self.config.recovery_timeout)):
                self.stats.state = CircuitState.HALF_OPEN
                self.stats.success_count = 0
                self.stats.failure_count = 0
                self.logger.info(f"Circuit breaker {self.name} transitioning to HALF_OPEN")
        
        elif self.stats.state == CircuitState.HALF_OPEN:
            # Check if enough successes to close
            if self.stats.success_count >= self.config.success_threshold:
                self.stats.state = CircuitState.CLOSED
                self.stats.failure_count = 0
                self.logger.info(f"Circuit breaker {self.name} transitioning to CLOSED")
    
    async def _record_success(self):
        """Record successful request."""
        async with self._lock:
            self.stats.success_count += 1
            self.stats.total_successes += 1
            self.stats.last_success_time = datetime.utcnow()
            
            # Reset failure count on success in closed state
            if self.stats.state == CircuitState.CLOSED:
                self.stats.failure_count = 0
    
    async def _record_failure(self):
        """Record failed request."""
        async with self._lock:
            self.stats.failure_count += 1
            self.stats.total_failures += 1
            self.stats.last_failure_time = datetime.utcnow()
            
            # Check if should open circuit
            if (self.stats.state == CircuitState.CLOSED and 
                self.stats.failure_count >= self.config.failure_threshold):
                self.stats.state = CircuitState.OPEN
                self.stats.opened_at = datetime.utcnow()
                self.logger.warning(f"Circuit breaker {self.name} transitioning to OPEN")
            
            # In half-open, any failure reopens the circuit
            elif self.stats.state == CircuitState.HALF_OPEN:
                self.stats.state = CircuitState.OPEN
                self.stats.opened_at = datetime.utcnow()
                self.logger.warning(f"Circuit breaker {self.name} reopening due to failure in HALF_OPEN")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get circuit breaker statistics."""
        return {
            "name": self.name,
            "state": self.stats.state.value,
            "failure_count": self.stats.failure_count,
            "success_count": self.stats.success_count,
            "total_requests": self.stats.total_requests,
            "total_failures": self.stats.total_failures,
            "total_successes": self.stats.total_successes,
            "failure_rate": self.stats.failure_rate,
            "success_rate": self.stats.success_rate,
            "last_failure": self.stats.last_failure_time.isoformat() if self.stats.last_failure_time else None,
            "last_success": self.stats.last_success_time.isoformat() if self.stats.last_success_time else None,
            "opened_at": self.stats.opened_at.isoformat() if self.stats.opened_at else None
        }


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    base_delay: float = 1.0      # Base delay in seconds
    max_delay: float = 60.0      # Maximum delay in seconds
    exponential_base: float = 2.0  # Exponential backoff multiplier
    jitter: bool = True          # Add random jitter to delays


class RetryableError(Exception):
    """Exception that should trigger a retry."""
    pass


class NonRetryableError(Exception):
    """Exception that should not trigger a retry."""
    pass


async def retry_with_backoff(
    func: Callable[..., T],
    config: RetryConfig,
    *args,
    **kwargs
) -> T:
    """Execute function with exponential backoff retry."""
    import random
    
    last_exception = None
    
    for attempt in range(config.max_attempts):
        try:
            result = await func(*args, **kwargs)
            if attempt > 0:
                logger.info(f"Retry succeeded on attempt {attempt + 1}")
            return result
            
        except NonRetryableError:
            # Don't retry non-retryable errors
            raise
            
        except Exception as e:
            last_exception = e
            
            if attempt == config.max_attempts - 1:
                # Last attempt, don't delay
                break
            
            # Calculate delay with exponential backoff
            delay = min(
                config.base_delay * (config.exponential_base ** attempt),
                config.max_delay
            )
            
            # Add jitter to prevent thundering herd
            if config.jitter:
                delay *= (0.5 + random.random() * 0.5)
            
            logger.warning(
                f"Attempt {attempt + 1} failed: {str(e)}. "
                f"Retrying in {delay:.2f}s"
            )
            
            await asyncio.sleep(delay)
    
    # All attempts failed
    logger.error(f"All {config.max_attempts} retry attempts failed")
    raise last_exception


class FallbackHandler:
    """Handles fallback responses when primary services fail."""
    
    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.fallback.{name}")
    
    async def handle_virustotal_fallback(self, resource: str, resource_type: str) -> Dict[str, Any]:
        """Fallback for VirusTotal when service is unavailable."""
        self.logger.info(f"Using VirusTotal fallback for {resource_type}: {resource[:50]}...")
        
        # Simple heuristic-based analysis as fallback
        threat_score = 0.0
        threat_level = "unknown"
        detected_threats = []
        
        if resource_type == "url":
            # Check for suspicious URL patterns
            suspicious_patterns = [
                'bit.ly', 'tinyurl', 'short.link', 'link.ly',  # URL shorteners
                'phish', 'secure-', 'verify-', 'update-',     # Common phishing terms
                '.tk', '.ml', '.ga', '.cf',                   # Suspicious TLDs
                'account-', 'login-', 'signin-'               # Account-related terms
            ]
            
            resource_lower = resource.lower()
            matches = [pattern for pattern in suspicious_patterns if pattern in resource_lower]
            
            if len(matches) >= 3:
                threat_score = 0.8
                threat_level = "high"
                detected_threats = [f"suspicious_pattern_{pattern}" for pattern in matches[:3]]
            elif len(matches) >= 1:
                threat_score = 0.4
                threat_level = "medium"
                detected_threats = [f"suspicious_pattern_{matches[0]}"]
            else:
                threat_score = 0.1
                threat_level = "low"
        
        return {
            "success": True,
            "fallback": True,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "detected_threats": detected_threats,
            "confidence": 0.3,  # Low confidence for fallback
            "source": "virustotal_fallback",
            "metadata": {
                "fallback_reason": "primary_service_unavailable",
                "fallback_method": "heuristic_patterns"
            }
        }
    
    async def handle_abuseipdb_fallback(self, ip_address: str) -> Dict[str, Any]:
        """Fallback for AbuseIPDB when service is unavailable."""
        self.logger.info(f"Using AbuseIPDB fallback for IP: {ip_address}")
        
        # Basic IP reputation checks
        threat_score = 0.0
        threat_level = "unknown"
        
        # Check for private/local IPs (generally safe)
        import ipaddress
        try:
            ip = ipaddress.ip_address(ip_address)
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                threat_score = 0.0
                threat_level = "safe"
            else:
                # Public IP - assign medium confidence unknown
                threat_score = 0.2
                threat_level = "unknown"
        except ValueError:
            threat_score = 0.3
            threat_level = "medium"  # Invalid IP format is suspicious
        
        return {
            "success": True,
            "fallback": True,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "detected_threats": [],
            "confidence": 0.4,
            "source": "abuseipdb_fallback",
            "metadata": {
                "fallback_reason": "primary_service_unavailable",
                "fallback_method": "basic_ip_classification"
            }
        }
    
    async def handle_gemini_fallback(self, content: str) -> Dict[str, Any]:
        """Fallback for Gemini when service is unavailable."""
        self.logger.info(f"Using Gemini fallback for content analysis")
        
        # Simple keyword-based content analysis
        content_lower = content.lower()
        
        # High-risk keywords
        high_risk_keywords = [
            'urgent', 'immediate', 'expire', 'suspend', 'locked',
            'verify', 'confirm', 'update', 'click here', 'act now',
            'security alert', 'account closure', 'limited time'
        ]
        
        # Medium-risk keywords  
        medium_risk_keywords = [
            'prize', 'winner', 'congratulations', 'free', 'offer',
            'deal', 'discount', 'bonus', 'reward', 'promotion'
        ]
        
        high_matches = sum(1 for keyword in high_risk_keywords if keyword in content_lower)
        medium_matches = sum(1 for keyword in medium_risk_keywords if keyword in content_lower)
        
        # Calculate threat score
        if high_matches >= 3:
            threat_score = 0.8
            threat_level = "high"
        elif high_matches >= 1 or medium_matches >= 3:
            threat_score = 0.5
            threat_level = "medium"
        elif medium_matches >= 1:
            threat_score = 0.2
            threat_level = "low"
        else:
            threat_score = 0.1
            threat_level = "safe"
        
        detected_threats = []
        if high_matches > 0:
            detected_threats.append(f"high_risk_keywords_{high_matches}")
        if medium_matches > 0:
            detected_threats.append(f"medium_risk_keywords_{medium_matches}")
        
        return {
            "success": True,
            "fallback": True,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "detected_threats": detected_threats,
            "confidence": 0.5,  # Medium confidence for keyword analysis
            "source": "gemini_fallback",
            "metadata": {
                "fallback_reason": "primary_service_unavailable",
                "fallback_method": "keyword_analysis",
                "high_risk_matches": high_matches,
                "medium_risk_matches": medium_matches
            }
        }


# Custom exceptions for circuit breaker
class CircuitOpenError(Exception):
    """Exception raised when circuit breaker is open."""
    pass


class TimeoutError(Exception):
    """Exception raised when request times out."""
    pass


# Resilient API client wrapper
class ResilientAPIClient:
    """Wrapper that adds resilience patterns to any API client."""
    
    def __init__(self, client, name: str):
        self.client = client
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.resilient.{name}")
        
        # Circuit breaker configuration per service
        cb_configs = {
            "virustotal": CircuitBreakerConfig(
                failure_threshold=5,
                recovery_timeout=120,  # 2 minutes
                timeout_seconds=30.0
            ),
            "abuseipdb": CircuitBreakerConfig(
                failure_threshold=3,
                recovery_timeout=60,   # 1 minute
                timeout_seconds=20.0
            ),
            "gemini": CircuitBreakerConfig(
                failure_threshold=3,
                recovery_timeout=90,   # 1.5 minutes
                timeout_seconds=60.0   # Longer timeout for AI
            )
        }
        
        self.circuit_breaker = CircuitBreaker(
            name, 
            cb_configs.get(name, CircuitBreakerConfig())
        )
        
        # Retry configuration
        self.retry_config = RetryConfig(
            max_attempts=3,
            base_delay=1.0,
            max_delay=30.0
        )
        
        self.fallback_handler = FallbackHandler(name)
    
    async def resilient_call(self, method_name: str, *args, **kwargs):
        """Make resilient API call with circuit breaker, retry, and fallback."""
        try:
            method = getattr(self.client, method_name)
            
            # Wrap with circuit breaker and retry
            result = await self.circuit_breaker.call(
                lambda: retry_with_backoff(method, self.retry_config, *args, **kwargs)
            )
            
            return result
            
        except (CircuitOpenError, TimeoutError, Exception) as e:
            self.logger.warning(f"Primary service failed: {str(e)}. Using fallback.")
            
            # Use fallback based on service type and method
            if method_name in ["analyze_url", "analyze_domain"] and self.name == "virustotal":
                resource = args[0] if args else kwargs.get('url') or kwargs.get('domain')
                resource_type = "url" if method_name == "analyze_url" else "domain"
                return await self.fallback_handler.handle_virustotal_fallback(resource, resource_type)
            
            elif method_name == "analyze_ip" and self.name == "abuseipdb":
                ip_address = args[0] if args else kwargs.get('ip_address')
                return await self.fallback_handler.handle_abuseipdb_fallback(ip_address)
            
            elif method_name == "analyze_content" and self.name == "gemini":
                content = args[0] if args else kwargs.get('content')
                return await self.fallback_handler.handle_gemini_fallback(content)
            
            else:
                # No fallback available, re-raise exception
                raise
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status including circuit breaker stats."""
        return {
            "service": self.name,
            "circuit_breaker": self.circuit_breaker.get_stats(),
            "quota": self.client.get_quota_status() if hasattr(self.client, 'get_quota_status') else None
        }