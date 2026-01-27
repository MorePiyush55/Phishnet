"""
Enterprise Worker Resilience
============================
Protects the Mode 1 pipeline from:
1. Volume spikes (backpressure)
2. External API failures (circuit breakers)
3. Rate limits (adaptive throttling)
4. Cascading failures (bulkhead isolation)

Design Patterns:
- Circuit Breaker: Fail fast when downstream is unhealthy
- Bulkhead: Isolate tenant workloads
- Backpressure: Slow down when overwhelmed
- Retry with Exponential Backoff: Graceful recovery
"""

import asyncio
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Callable, Awaitable, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import functools

from app.config.logging import get_logger

logger = get_logger(__name__)

T = TypeVar('T')


class CircuitState(str, Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5        # Failures before opening
    success_threshold: int = 3        # Successes to close from half-open
    timeout_seconds: float = 30.0     # Time in open state before half-open
    half_open_max_calls: int = 3      # Max calls in half-open state


@dataclass
class CircuitBreakerState:
    """State tracking for circuit breaker"""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_state_change: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    half_open_calls: int = 0


class CircuitBreaker:
    """
    Circuit Breaker implementation.
    
    Usage:
        cb = CircuitBreaker("virustotal", config)
        result = await cb.execute(vt_client.scan_url, url)
    """
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitBreakerState()
        self._lock = asyncio.Lock()
    
    @property
    def state(self) -> CircuitState:
        return self._state.state
    
    @property
    def is_closed(self) -> bool:
        return self._state.state == CircuitState.CLOSED
    
    @property
    def is_open(self) -> bool:
        return self._state.state == CircuitState.OPEN
    
    async def _should_allow_request(self) -> bool:
        """Check if request should be allowed"""
        async with self._lock:
            if self._state.state == CircuitState.CLOSED:
                return True
            
            if self._state.state == CircuitState.OPEN:
                # Check if timeout has passed
                elapsed = (datetime.now(timezone.utc) - self._state.last_state_change).total_seconds()
                if elapsed >= self.config.timeout_seconds:
                    # Transition to half-open
                    self._state.state = CircuitState.HALF_OPEN
                    self._state.half_open_calls = 0
                    self._state.success_count = 0
                    self._state.last_state_change = datetime.now(timezone.utc)
                    logger.info(f"Circuit {self.name}: OPEN → HALF_OPEN after {elapsed:.1f}s")
                    return True
                return False
            
            if self._state.state == CircuitState.HALF_OPEN:
                # Allow limited calls in half-open
                if self._state.half_open_calls < self.config.half_open_max_calls:
                    self._state.half_open_calls += 1
                    return True
                return False
            
            return False
    
    async def _record_success(self):
        """Record successful call"""
        async with self._lock:
            if self._state.state == CircuitState.HALF_OPEN:
                self._state.success_count += 1
                if self._state.success_count >= self.config.success_threshold:
                    # Transition to closed
                    self._state.state = CircuitState.CLOSED
                    self._state.failure_count = 0
                    self._state.success_count = 0
                    self._state.last_state_change = datetime.now(timezone.utc)
                    logger.info(f"Circuit {self.name}: HALF_OPEN → CLOSED (recovered)")
            
            elif self._state.state == CircuitState.CLOSED:
                # Reset failure count on success
                self._state.failure_count = 0
    
    async def _record_failure(self, error: Exception):
        """Record failed call"""
        async with self._lock:
            self._state.failure_count += 1
            self._state.last_failure_time = datetime.now(timezone.utc)
            
            if self._state.state == CircuitState.HALF_OPEN:
                # Any failure in half-open goes back to open
                self._state.state = CircuitState.OPEN
                self._state.last_state_change = datetime.now(timezone.utc)
                logger.warning(f"Circuit {self.name}: HALF_OPEN → OPEN (failure: {error})")
            
            elif self._state.state == CircuitState.CLOSED:
                if self._state.failure_count >= self.config.failure_threshold:
                    # Open the circuit
                    self._state.state = CircuitState.OPEN
                    self._state.last_state_change = datetime.now(timezone.utc)
                    logger.warning(
                        f"Circuit {self.name}: CLOSED → OPEN "
                        f"(failures: {self._state.failure_count})"
                    )
    
    async def execute(
        self, 
        func: Callable[..., Awaitable[T]], 
        *args, 
        **kwargs
    ) -> T:
        """
        Execute function with circuit breaker protection.
        
        Raises:
            CircuitBreakerOpen: If circuit is open
            Exception: Original exception if call fails
        """
        if not await self._should_allow_request():
            raise CircuitBreakerOpen(f"Circuit {self.name} is open")
        
        try:
            result = await func(*args, **kwargs)
            await self._record_success()
            return result
        except Exception as e:
            await self._record_failure(e)
            raise
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status"""
        return {
            "name": self.name,
            "state": self._state.state.value,
            "failure_count": self._state.failure_count,
            "success_count": self._state.success_count,
            "last_failure": self._state.last_failure_time.isoformat() if self._state.last_failure_time else None,
            "last_state_change": self._state.last_state_change.isoformat()
        }


class CircuitBreakerOpen(Exception):
    """Raised when circuit breaker is open"""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    requests_per_second: float = 10.0
    requests_per_minute: float = 100.0
    requests_per_hour: float = 1000.0
    burst_size: int = 20  # Max burst


class TokenBucketRateLimiter:
    """
    Token bucket rate limiter with adaptive throttling.
    
    Usage:
        limiter = TokenBucketRateLimiter("gemini", RateLimitConfig(rps=5))
        await limiter.acquire()  # Blocks until token available
        await limiter.acquire(timeout=1.0)  # Raises if can't acquire in 1s
    """
    
    def __init__(self, name: str, config: Optional[RateLimitConfig] = None):
        self.name = name
        self.config = config or RateLimitConfig()
        
        # Token bucket state
        self._tokens = float(self.config.burst_size)
        self._last_update = time.monotonic()
        self._lock = asyncio.Lock()
        
        # Metrics
        self._total_requests = 0
        self._rejected_requests = 0
        self._wait_time_total = 0.0
    
    async def acquire(self, timeout: Optional[float] = None) -> bool:
        """
        Acquire a token from the bucket.
        
        Args:
            timeout: Max seconds to wait. None = wait forever.
        
        Returns:
            True if acquired, False if timeout
        
        Raises:
            RateLimitExceeded: If timeout and can't acquire
        """
        start_time = time.monotonic()
        deadline = start_time + timeout if timeout else float('inf')
        
        while True:
            async with self._lock:
                # Refill tokens based on elapsed time
                now = time.monotonic()
                elapsed = now - self._last_update
                self._tokens = min(
                    self.config.burst_size,
                    self._tokens + elapsed * self.config.requests_per_second
                )
                self._last_update = now
                
                # Try to consume a token
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self._total_requests += 1
                    self._wait_time_total += (now - start_time)
                    return True
            
            # Check timeout
            if time.monotonic() >= deadline:
                self._rejected_requests += 1
                raise RateLimitExceeded(f"Rate limit exceeded for {self.name}")
            
            # Calculate wait time until next token
            tokens_needed = 1.0 - self._tokens
            wait_time = tokens_needed / self.config.requests_per_second
            wait_time = min(wait_time, 0.1)  # Max 100ms wait between checks
            
            await asyncio.sleep(wait_time)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        return {
            "name": self.name,
            "tokens_available": self._tokens,
            "total_requests": self._total_requests,
            "rejected_requests": self._rejected_requests,
            "avg_wait_ms": (self._wait_time_total / max(1, self._total_requests)) * 1000
        }


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded"""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# BACKPRESSURE CONTROLLER
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class BackpressureConfig:
    """Backpressure configuration"""
    max_queue_size: int = 1000        # Max pending jobs
    high_watermark: float = 0.8       # Start slowing at 80%
    low_watermark: float = 0.5        # Resume normal at 50%
    min_delay_ms: float = 0           # Min delay between jobs
    max_delay_ms: float = 5000        # Max delay when at capacity


class BackpressureController:
    """
    Backpressure controller for managing processing load.
    
    When queue fills up:
    1. Start adding delays between processing
    2. Reject new items if at max capacity
    3. Resume normal operation when queue drains
    """
    
    def __init__(self, name: str, config: Optional[BackpressureConfig] = None):
        self.name = name
        self.config = config or BackpressureConfig()
        
        self._queue_size = 0
        self._in_backpressure = False
        self._lock = asyncio.Lock()
        
        # Metrics
        self._total_accepted = 0
        self._total_rejected = 0
        self._delays_applied = 0
    
    @property
    def queue_utilization(self) -> float:
        """Current queue utilization (0-1)"""
        return self._queue_size / max(1, self.config.max_queue_size)
    
    async def try_acquire(self) -> bool:
        """
        Try to acquire a slot for processing.
        
        Returns:
            True if slot acquired, False if rejected
        """
        async with self._lock:
            if self._queue_size >= self.config.max_queue_size:
                self._total_rejected += 1
                logger.warning(f"Backpressure {self.name}: Rejected (queue full)")
                return False
            
            self._queue_size += 1
            self._total_accepted += 1
            
            # Check if entering backpressure
            if self.queue_utilization >= self.config.high_watermark:
                if not self._in_backpressure:
                    self._in_backpressure = True
                    logger.warning(f"Backpressure {self.name}: ACTIVE (util={self.queue_utilization:.1%})")
            
            return True
    
    async def release(self):
        """Release a processing slot"""
        async with self._lock:
            self._queue_size = max(0, self._queue_size - 1)
            
            # Check if exiting backpressure
            if self.queue_utilization <= self.config.low_watermark:
                if self._in_backpressure:
                    self._in_backpressure = False
                    logger.info(f"Backpressure {self.name}: RELEASED (util={self.queue_utilization:.1%})")
    
    def get_delay(self) -> float:
        """
        Get delay to apply between jobs.
        
        Returns:
            Delay in seconds
        """
        if not self._in_backpressure:
            return self.config.min_delay_ms / 1000
        
        # Linear interpolation between high watermark and 100%
        utilization = self.queue_utilization
        high = self.config.high_watermark
        
        if utilization >= 1.0:
            delay_ms = self.config.max_delay_ms
        else:
            # Scale delay based on how far above high watermark
            scale = (utilization - high) / (1.0 - high)
            delay_ms = self.config.min_delay_ms + scale * (
                self.config.max_delay_ms - self.config.min_delay_ms
            )
        
        return delay_ms / 1000
    
    def get_stats(self) -> Dict[str, Any]:
        """Get backpressure statistics"""
        return {
            "name": self.name,
            "queue_size": self._queue_size,
            "max_queue_size": self.config.max_queue_size,
            "utilization": self.queue_utilization,
            "in_backpressure": self._in_backpressure,
            "total_accepted": self._total_accepted,
            "total_rejected": self._total_rejected,
            "current_delay_ms": self.get_delay() * 1000
        }


class BackpressureFull(Exception):
    """Raised when backpressure queue is full"""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# TENANT BULKHEAD
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class BulkheadConfig:
    """Bulkhead configuration per tenant"""
    max_concurrent: int = 10          # Max concurrent jobs
    max_queue: int = 100              # Max queued jobs
    timeout_seconds: float = 300      # Max job duration


class TenantBulkhead:
    """
    Bulkhead isolates tenant workloads.
    
    Prevents one tenant from consuming all resources
    and affecting other tenants.
    """
    
    def __init__(self, config: Optional[BulkheadConfig] = None):
        self.config = config or BulkheadConfig()
        self._tenant_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._tenant_queue_sizes: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()
    
    async def _get_semaphore(self, tenant_id: str) -> asyncio.Semaphore:
        """Get or create semaphore for tenant"""
        async with self._lock:
            if tenant_id not in self._tenant_semaphores:
                self._tenant_semaphores[tenant_id] = asyncio.Semaphore(
                    self.config.max_concurrent
                )
            return self._tenant_semaphores[tenant_id]
    
    async def acquire(self, tenant_id: str, timeout: Optional[float] = None) -> bool:
        """
        Acquire a slot for tenant processing.
        
        Args:
            tenant_id: Tenant identifier
            timeout: Max seconds to wait
        
        Returns:
            True if acquired
        
        Raises:
            BulkheadFull: If tenant queue is full
        """
        # Check queue limit
        async with self._lock:
            if self._tenant_queue_sizes[tenant_id] >= self.config.max_queue:
                raise BulkheadFull(f"Tenant {tenant_id} queue full")
            self._tenant_queue_sizes[tenant_id] += 1
        
        # Acquire semaphore
        semaphore = await self._get_semaphore(tenant_id)
        
        try:
            if timeout:
                await asyncio.wait_for(semaphore.acquire(), timeout)
            else:
                await semaphore.acquire()
            return True
        except asyncio.TimeoutError:
            async with self._lock:
                self._tenant_queue_sizes[tenant_id] -= 1
            raise
    
    async def release(self, tenant_id: str):
        """Release a tenant processing slot"""
        semaphore = await self._get_semaphore(tenant_id)
        semaphore.release()
        
        async with self._lock:
            self._tenant_queue_sizes[tenant_id] = max(
                0, self._tenant_queue_sizes[tenant_id] - 1
            )
    
    def get_tenant_stats(self, tenant_id: str) -> Dict[str, Any]:
        """Get stats for a specific tenant"""
        semaphore = self._tenant_semaphores.get(tenant_id)
        return {
            "tenant_id": tenant_id,
            "queue_size": self._tenant_queue_sizes[tenant_id],
            "max_queue": self.config.max_queue,
            "concurrent_slots": self.config.max_concurrent,
            "available_slots": semaphore._value if semaphore else self.config.max_concurrent
        }
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get stats for all tenants"""
        return {
            tenant_id: self.get_tenant_stats(tenant_id)
            for tenant_id in self._tenant_semaphores.keys()
        }


class BulkheadFull(Exception):
    """Raised when bulkhead capacity is reached"""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# RETRY WITH BACKOFF
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class RetryConfig:
    """Retry configuration"""
    max_retries: int = 3
    initial_delay_ms: float = 100
    max_delay_ms: float = 10000
    exponential_base: float = 2.0
    jitter: bool = True


async def retry_with_backoff(
    func: Callable[..., Awaitable[T]],
    *args,
    config: Optional[RetryConfig] = None,
    retryable_exceptions: tuple = (Exception,),
    **kwargs
) -> T:
    """
    Retry function with exponential backoff.
    
    Usage:
        result = await retry_with_backoff(
            api_call,
            url,
            config=RetryConfig(max_retries=3),
            retryable_exceptions=(HTTPError, TimeoutError)
        )
    """
    config = config or RetryConfig()
    last_exception = None
    
    for attempt in range(config.max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except retryable_exceptions as e:
            last_exception = e
            
            if attempt >= config.max_retries:
                logger.error(f"Retry exhausted after {attempt + 1} attempts: {e}")
                raise
            
            # Calculate delay with exponential backoff
            delay_ms = min(
                config.initial_delay_ms * (config.exponential_base ** attempt),
                config.max_delay_ms
            )
            
            # Add jitter (±25%)
            if config.jitter:
                import random
                jitter_factor = 0.75 + random.random() * 0.5
                delay_ms *= jitter_factor
            
            delay_s = delay_ms / 1000
            logger.warning(f"Retry {attempt + 1}/{config.max_retries} after {delay_s:.2f}s: {e}")
            
            await asyncio.sleep(delay_s)
    
    raise last_exception


# ═══════════════════════════════════════════════════════════════════════════
# RESILIENCE MANAGER (FACADE)
# ═══════════════════════════════════════════════════════════════════════════

class ResilienceManager:
    """
    Facade for all resilience components.
    
    Provides unified access to:
    - Circuit breakers (per external service)
    - Rate limiters (per API)
    - Backpressure controller
    - Tenant bulkheads
    """
    
    def __init__(self):
        # Circuit breakers for external services
        self.circuit_breakers: Dict[str, CircuitBreaker] = {
            "virustotal": CircuitBreaker("virustotal", CircuitBreakerConfig(
                failure_threshold=3,
                timeout_seconds=60
            )),
            "abuseipdb": CircuitBreaker("abuseipdb", CircuitBreakerConfig(
                failure_threshold=3,
                timeout_seconds=60
            )),
            "gemini": CircuitBreaker("gemini", CircuitBreakerConfig(
                failure_threshold=5,
                timeout_seconds=30
            )),
            "imap": CircuitBreaker("imap", CircuitBreakerConfig(
                failure_threshold=5,
                timeout_seconds=120
            ))
        }
        
        # Rate limiters
        self.rate_limiters: Dict[str, TokenBucketRateLimiter] = {
            "virustotal": TokenBucketRateLimiter("virustotal", RateLimitConfig(
                requests_per_second=4,  # VT free tier: 4 req/min
                burst_size=4
            )),
            "gemini": TokenBucketRateLimiter("gemini", RateLimitConfig(
                requests_per_second=10,
                burst_size=20
            )),
            "email_send": TokenBucketRateLimiter("email_send", RateLimitConfig(
                requests_per_second=5,
                burst_size=10
            ))
        }
        
        # Backpressure
        self.backpressure = BackpressureController("mode1_pipeline", BackpressureConfig(
            max_queue_size=1000,
            high_watermark=0.8,
            low_watermark=0.5
        ))
        
        # Tenant bulkheads
        self.bulkhead = TenantBulkhead(BulkheadConfig(
            max_concurrent=10,
            max_queue=100
        ))
    
    def get_circuit_breaker(self, service: str) -> CircuitBreaker:
        """Get circuit breaker for a service"""
        if service not in self.circuit_breakers:
            self.circuit_breakers[service] = CircuitBreaker(service)
        return self.circuit_breakers[service]
    
    def get_rate_limiter(self, service: str) -> TokenBucketRateLimiter:
        """Get rate limiter for a service"""
        if service not in self.rate_limiters:
            self.rate_limiters[service] = TokenBucketRateLimiter(service)
        return self.rate_limiters[service]
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of all resilience components"""
        return {
            "circuit_breakers": {
                name: cb.get_status() 
                for name, cb in self.circuit_breakers.items()
            },
            "rate_limiters": {
                name: rl.get_stats()
                for name, rl in self.rate_limiters.items()
            },
            "backpressure": self.backpressure.get_stats(),
            "bulkheads": self.bulkhead.get_all_stats()
        }


# Singleton
_resilience_manager: Optional[ResilienceManager] = None


def get_resilience_manager() -> ResilienceManager:
    """Get singleton resilience manager"""
    global _resilience_manager
    if _resilience_manager is None:
        _resilience_manager = ResilienceManager()
    return _resilience_manager
