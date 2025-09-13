"""
Circuit breaker and resilience patterns for external API calls.
Provides circuit breakers, bulkheads, retries with exponential backoff, and fallback modes.
"""

import asyncio
import time
import random
from enum import Enum
from typing import Any, Callable, Dict, Optional, Union, List
from dataclasses import dataclass, field
from functools import wraps

from app.config.logging import get_logger
from app.observability.tracing import record_circuit_breaker_state, record_external_api_failure
from app.observability.correlation import get_structured_logger

logger = get_structured_logger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = 0      # Normal operation
    HALF_OPEN = 1   # Testing if service recovered
    OPEN = 2        # Failing fast


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5          # Number of failures to open circuit
    recovery_timeout: float = 60.0      # Seconds to wait before trying half-open
    success_threshold: int = 3          # Successful calls to close circuit from half-open
    timeout: float = 30.0               # Request timeout in seconds
    
    # Retry configuration
    max_retries: int = 3
    initial_backoff: float = 1.0        # Initial backoff in seconds
    max_backoff: float = 60.0           # Maximum backoff in seconds
    backoff_multiplier: float = 2.0     # Exponential backoff multiplier
    jitter: bool = True                 # Add jitter to backoff
    
    # Bulkhead configuration
    max_concurrent_calls: int = 10      # Maximum concurrent calls
    queue_size: int = 50                # Queue size for pending calls


@dataclass
class CircuitBreakerStats:
    """Circuit breaker statistics."""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    
    # Performance metrics
    avg_response_time: float = 0.0
    last_response_time: float = 0.0
    
    # Timestamps
    last_state_change: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)


class CircuitBreaker:
    """
    Circuit breaker implementation with retries, exponential backoff, and bulkheads.
    """
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.stats = CircuitBreakerStats()
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent_calls)
        self._lock = asyncio.Lock()
        
        logger.info(f"Circuit breaker '{name}' initialized", extra={
            "circuit_breaker": name,
            "config": self.config.__dict__
        })
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection.
        """
        # Check if circuit is open
        if await self._should_fail_fast():
            raise CircuitBreakerOpenError(f"Circuit breaker '{self.name}' is open")
        
        # Acquire semaphore for bulkhead pattern
        async with self.semaphore:
            return await self._execute_with_retries(func, *args, **kwargs)
    
    async def _should_fail_fast(self) -> bool:
        """Check if we should fail fast due to open circuit."""
        async with self._lock:
            if self.stats.state == CircuitState.OPEN:
                # Check if recovery timeout has passed
                if time.time() - self.stats.last_failure_time >= self.config.recovery_timeout:
                    await self._transition_to_half_open()
                    return False
                return True
            return False
    
    async def _execute_with_retries(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic and exponential backoff."""
        last_exception = None
        backoff = self.config.initial_backoff
        
        for attempt in range(self.config.max_retries + 1):
            try:
                start_time = time.time()
                
                # Execute function with timeout
                result = await asyncio.wait_for(
                    func(*args, **kwargs), 
                    timeout=self.config.timeout
                )
                
                # Record successful call
                response_time = time.time() - start_time
                await self._record_success(response_time)
                
                return result
                
            except Exception as e:
                last_exception = e
                await self._record_failure(e)
                
                # Don't retry on last attempt
                if attempt == self.config.max_retries:
                    break
                
                # Wait with exponential backoff
                await self._backoff_delay(backoff, attempt)
                backoff = min(
                    backoff * self.config.backoff_multiplier,
                    self.config.max_backoff
                )
        
        # All retries failed
        record_external_api_failure(self.name, type(last_exception).__name__)
        raise last_exception
    
    async def _backoff_delay(self, backoff: float, attempt: int) -> None:
        """Apply exponential backoff with optional jitter."""
        delay = backoff
        
        if self.config.jitter:
            # Add jitter (±25% of backoff time)
            jitter = backoff * 0.25 * (2 * random.random() - 1)
            delay = max(0, backoff + jitter)
        
        logger.debug(f"Circuit breaker '{self.name}' backoff delay", extra={
            "circuit_breaker": self.name,
            "attempt": attempt + 1,
            "delay_seconds": delay
        })
        
        await asyncio.sleep(delay)
    
    async def _record_success(self, response_time: float) -> None:
        """Record successful call and update circuit state."""
        async with self._lock:
            self.stats.total_calls += 1
            self.stats.successful_calls += 1
            self.stats.last_response_time = response_time
            
            # Update average response time
            if self.stats.successful_calls == 1:
                self.stats.avg_response_time = response_time
            else:
                # Exponential moving average
                self.stats.avg_response_time = (
                    0.9 * self.stats.avg_response_time + 0.1 * response_time
                )
            
            if self.stats.state == CircuitState.HALF_OPEN:
                self.stats.success_count += 1
                if self.stats.success_count >= self.config.success_threshold:
                    await self._transition_to_closed()
            
            elif self.stats.state == CircuitState.OPEN:
                # Shouldn't happen, but reset if it does
                await self._transition_to_closed()
    
    async def _record_failure(self, exception: Exception) -> None:
        """Record failed call and update circuit state."""
        async with self._lock:
            self.stats.total_calls += 1
            self.stats.failed_calls += 1
            self.stats.failure_count += 1
            self.stats.last_failure_time = time.time()
            
            logger.warning(f"Circuit breaker '{self.name}' recorded failure", extra={
                "circuit_breaker": self.name,
                "error_type": type(exception).__name__,
                "error_message": str(exception),
                "failure_count": self.stats.failure_count
            })
            
            # Check if we should open the circuit
            if (self.stats.state == CircuitState.CLOSED and 
                self.stats.failure_count >= self.config.failure_threshold):
                await self._transition_to_open()
            
            elif self.stats.state == CircuitState.HALF_OPEN:
                # Any failure in half-open goes back to open
                await self._transition_to_open()
    
    async def _transition_to_closed(self) -> None:
        """Transition circuit to closed state."""
        if self.stats.state != CircuitState.CLOSED:
            self.stats.state = CircuitState.CLOSED
            self.stats.failure_count = 0
            self.stats.success_count = 0
            self.stats.last_state_change = time.time()
            
            record_circuit_breaker_state(self.name, CircuitState.CLOSED.value)
            
            logger.info(f"Circuit breaker '{self.name}' transitioned to CLOSED", extra={
                "circuit_breaker": self.name,
                "state": "CLOSED"
            })
    
    async def _transition_to_half_open(self) -> None:
        """Transition circuit to half-open state."""
        self.stats.state = CircuitState.HALF_OPEN
        self.stats.success_count = 0
        self.stats.last_state_change = time.time()
        
        record_circuit_breaker_state(self.name, CircuitState.HALF_OPEN.value)
        
        logger.info(f"Circuit breaker '{self.name}' transitioned to HALF_OPEN", extra={
            "circuit_breaker": self.name,
            "state": "HALF_OPEN"
        })
    
    async def _transition_to_open(self) -> None:
        """Transition circuit to open state."""
        self.stats.state = CircuitState.OPEN
        self.stats.success_count = 0
        self.stats.last_state_change = time.time()
        
        record_circuit_breaker_state(self.name, CircuitState.OPEN.value)
        
        logger.error(f"Circuit breaker '{self.name}' transitioned to OPEN", extra={
            "circuit_breaker": self.name,
            "state": "OPEN",
            "failure_count": self.stats.failure_count,
            "threshold": self.config.failure_threshold
        })
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current circuit breaker statistics."""
        return {
            "name": self.name,
            "state": self.stats.state.name,
            "failure_count": self.stats.failure_count,
            "success_count": self.stats.success_count,
            "total_calls": self.stats.total_calls,
            "successful_calls": self.stats.successful_calls,
            "failed_calls": self.stats.failed_calls,
            "success_rate": (
                self.stats.successful_calls / self.stats.total_calls 
                if self.stats.total_calls > 0 else 0.0
            ),
            "avg_response_time": self.stats.avg_response_time,
            "last_response_time": self.stats.last_response_time,
            "last_state_change": self.stats.last_state_change,
            "uptime_seconds": time.time() - self.stats.created_at
        }


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open."""
    pass


# Global circuit breaker registry
_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get or create a circuit breaker instance."""
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(name, config)
    return _circuit_breakers[name]


def circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None):
    """Decorator to add circuit breaker protection to async functions."""
    def decorator(func):
        breaker = get_circuit_breaker(name, config)
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await breaker.call(func, *args, **kwargs)
        
        return wrapper
    return decorator


# Predefined circuit breaker configurations
VIRUSTOTAL_CONFIG = CircuitBreakerConfig(
    failure_threshold=3,
    recovery_timeout=120.0,
    success_threshold=2,
    timeout=30.0,
    max_retries=2,
    max_concurrent_calls=5
)

GEMINI_CONFIG = CircuitBreakerConfig(
    failure_threshold=5,
    recovery_timeout=60.0,
    success_threshold=3,
    timeout=45.0,
    max_retries=3,
    max_concurrent_calls=10
)

GMAIL_CONFIG = CircuitBreakerConfig(
    failure_threshold=3,
    recovery_timeout=180.0,
    success_threshold=2,
    timeout=60.0,
    max_retries=2,
    max_concurrent_calls=3
)

ABUSEIPDB_CONFIG = CircuitBreakerConfig(
    failure_threshold=3,
    recovery_timeout=90.0,
    success_threshold=2,
    timeout=20.0,
    max_retries=2,
    max_concurrent_calls=5
)


# Fallback response generators
class FallbackMode:
    """Fallback response modes for when external services are unavailable."""
    
    @staticmethod
    def safe_fallback() -> Dict[str, Any]:
        """Conservative fallback - assume content is safe."""
        return {
            "status": "fallback",
            "verdict": "clean",
            "confidence": 0.1,
            "reason": "External service unavailable - defaulting to safe",
            "fallback_mode": True
        }
    
    @staticmethod
    def suspicious_fallback() -> Dict[str, Any]:
        """Conservative fallback - assume content is suspicious."""
        return {
            "status": "fallback",
            "verdict": "suspicious", 
            "confidence": 0.3,
            "reason": "External service unavailable - flagging for manual review",
            "fallback_mode": True
        }
    
    @staticmethod
    def cached_fallback(cache_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Use cached data if available."""
        if cache_data:
            return {
                **cache_data,
                "status": "cached_fallback",
                "fallback_mode": True
            }
        return FallbackMode.suspicious_fallback()


def get_all_circuit_breaker_stats() -> List[Dict[str, Any]]:
    """Get statistics for all circuit breakers."""
    return [breaker.get_stats() for breaker in _circuit_breakers.values()]


def reset_circuit_breaker(name: str) -> bool:
    """Reset a circuit breaker to closed state."""
    if name in _circuit_breakers:
        breaker = _circuit_breakers[name]
        asyncio.create_task(breaker._transition_to_closed())
        logger.info(f"Circuit breaker '{name}' manually reset", extra={
            "circuit_breaker": name,
            "action": "manual_reset"
        })
        return True
    return False


def reset_all_circuit_breakers() -> None:
    """Reset all circuit breakers to closed state."""
    for name in _circuit_breakers:
        reset_circuit_breaker(name)
