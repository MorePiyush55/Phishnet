"""
Circuit Breaker Pattern Implementation for External API Calls

Prevents cascading failures by temporarily stopping calls to failing services.
"""

import time
import asyncio
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
from app.config.logging import get_logger

logger = get_logger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject all calls
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreaker:
    """
    Circuit Breaker for protecting external API calls.
    
    Usage:
        breaker = CircuitBreaker(name="virustotal")
        
        if breaker.can_execute():
            try:
                result = await call_virustotal()
                breaker.record_success()
            except Exception:
                breaker.record_failure()
    """
    name: str
    failure_threshold: int = 5          # Failures before opening
    recovery_timeout: int = 60          # Seconds to wait before half-open
    half_open_max_calls: int = 3        # Calls allowed in half-open state
    
    # State tracking
    state: CircuitState = field(default=CircuitState.CLOSED)
    failure_count: int = field(default=0)
    success_count: int = field(default=0)
    last_failure_time: Optional[float] = field(default=None)
    half_open_calls: int = field(default=0)
    
    def can_execute(self) -> bool:
        """Check if a call should be allowed."""
        if self.state == CircuitState.CLOSED:
            return True
        
        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if self.last_failure_time and (time.time() - self.last_failure_time) >= self.recovery_timeout:
                self._transition_to_half_open()
                return True
            return False
        
        if self.state == CircuitState.HALF_OPEN:
            if self.half_open_calls < self.half_open_max_calls:
                self.half_open_calls += 1
                return True
            return False
        
        return False
    
    def record_success(self) -> None:
        """Record a successful call."""
        self.success_count += 1
        
        if self.state == CircuitState.HALF_OPEN:
            # Recovered! Close the circuit
            self._transition_to_closed()
            logger.info(f"🟢 Circuit Breaker [{self.name}]: RECOVERED - circuit closed")
        
        # Reset failure count on success
        self.failure_count = 0
    
    def record_failure(self) -> None:
        """Record a failed call."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitState.CLOSED:
            if self.failure_count >= self.failure_threshold:
                self._transition_to_open()
                logger.warning(
                    f"🔴 Circuit Breaker [{self.name}]: OPEN after {self.failure_count} failures. "
                    f"Blocking calls for {self.recovery_timeout}s"
                )
        
        elif self.state == CircuitState.HALF_OPEN:
            # Failed during recovery test, reopen
            self._transition_to_open()
            logger.warning(f"🔴 Circuit Breaker [{self.name}]: Back to OPEN - recovery failed")
    
    def _transition_to_open(self) -> None:
        self.state = CircuitState.OPEN
        self.half_open_calls = 0
    
    def _transition_to_half_open(self) -> None:
        self.state = CircuitState.HALF_OPEN
        self.half_open_calls = 0
        logger.info(f"🟡 Circuit Breaker [{self.name}]: HALF_OPEN - testing recovery")
    
    def _transition_to_closed(self) -> None:
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.half_open_calls = 0
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status for monitoring."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure": self.last_failure_time,
            "can_execute": self.can_execute()
        }


# ============================================================================
# Global Circuit Breakers for External Services
# ============================================================================

_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(name: str, **kwargs) -> CircuitBreaker:
    """Get or create a circuit breaker for a service."""
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(name=name, **kwargs)
    return _circuit_breakers[name]


def get_all_circuit_breakers() -> Dict[str, Dict[str, Any]]:
    """Get status of all circuit breakers."""
    return {name: cb.get_status() for name, cb in _circuit_breakers.items()}


# Pre-configured circuit breakers for common services
VIRUSTOTAL_BREAKER = get_circuit_breaker(
    "virustotal",
    failure_threshold=3,
    recovery_timeout=120  # 2 minutes
)

ABUSEIPDB_BREAKER = get_circuit_breaker(
    "abuseipdb", 
    failure_threshold=3,
    recovery_timeout=120
)

GEMINI_BREAKER = get_circuit_breaker(
    "gemini",
    failure_threshold=5,
    recovery_timeout=60  # 1 minute
)


# ============================================================================
# Decorator for automatic circuit breaker protection
# ============================================================================

def with_circuit_breaker(breaker: CircuitBreaker):
    """
    Decorator to protect async functions with circuit breaker.
    
    Usage:
        @with_circuit_breaker(VIRUSTOTAL_BREAKER)
        async def call_virustotal(url: str):
            ...
    """
    def decorator(func: Callable):
        async def wrapper(*args, **kwargs):
            if not breaker.can_execute():
                logger.warning(f"Circuit breaker [{breaker.name}] is OPEN, skipping call")
                return None
            
            try:
                result = await func(*args, **kwargs)
                breaker.record_success()
                return result
            except Exception as e:
                breaker.record_failure()
                raise
        
        return wrapper
    return decorator
