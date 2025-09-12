"""
Resilience Patterns - Circuit Breakers, Retries, Timeouts, Bulkheads
Handles external API failures, database timeouts, and service degradation gracefully
"""

import asyncio
import logging
import time
import random
from typing import Dict, Any, Optional, Callable, TypeVar, Union, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
import inspect
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

T = TypeVar('T')

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, calls rejected
    HALF_OPEN = "half_open"  # Testing recovery

class RetryStrategy(Enum):
    FIXED_DELAY = "fixed_delay"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    JITTERED_BACKOFF = "jittered_backoff"

@dataclass
class RetryConfig:
    """Retry configuration"""
    max_attempts: int = 3
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    base_delay: float = 1.0  # seconds
    max_delay: float = 60.0  # seconds
    backoff_factor: float = 2.0
    jitter: bool = True
    retry_on: List[type] = field(default_factory=lambda: [Exception])
    stop_on: List[type] = field(default_factory=list)

@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0  # seconds
    expected_exception: type = Exception
    success_threshold: int = 3  # for half-open state
    timeout: float = 30.0  # call timeout

@dataclass
class TimeoutConfig:
    """Timeout configuration"""
    connect_timeout: float = 5.0
    read_timeout: float = 30.0
    total_timeout: float = 60.0

@dataclass
class BulkheadConfig:
    """Bulkhead configuration for resource isolation"""
    max_concurrent: int = 10
    queue_size: int = 100
    timeout: float = 30.0

class ResilienceException(Exception):
    """Base exception for resilience patterns"""
    pass

class CircuitOpenException(ResilienceException):
    """Raised when circuit breaker is open"""
    pass

class TimeoutException(ResilienceException):
    """Raised when operation times out"""
    pass

class BulkheadFullException(ResilienceException):
    """Raised when bulkhead is at capacity"""
    pass

class RetryExhaustedException(ResilienceException):
    """Raised when all retry attempts are exhausted"""
    pass

class CircuitBreaker:
    """
    Circuit breaker implementation
    
    States:
    - CLOSED: Normal operation, failures counted
    - OPEN: Calls rejected immediately, timeout starts
    - HALF_OPEN: Limited calls allowed to test recovery
    """
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        self.state_change_time = time.time()
        
        self._lock = asyncio.Lock()
    
    async def __aenter__(self):
        await self._check_state()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            await self._on_success()
        elif issubclass(exc_type, self.config.expected_exception):
            await self._on_failure()
        # Let other exceptions propagate
        return False
    
    async def _check_state(self):
        """Check and update circuit breaker state"""
        async with self._lock:
            now = time.time()
            
            if self.state == CircuitState.OPEN:
                if now - self.state_change_time >= self.config.recovery_timeout:
                    self.state = CircuitState.HALF_OPEN
                    self.state_change_time = now
                    self.success_count = 0
                    logger.info(f"Circuit breaker {self.name}: OPEN -> HALF_OPEN")
                else:
                    raise CircuitOpenException(f"Circuit breaker {self.name} is OPEN")
            
            elif self.state == CircuitState.HALF_OPEN:
                # Allow limited calls in half-open state
                pass
    
    async def _on_success(self):
        """Handle successful operation"""
        async with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.config.success_threshold:
                    self.state = CircuitState.CLOSED
                    self.state_change_time = time.time()
                    self.failure_count = 0
                    logger.info(f"Circuit breaker {self.name}: HALF_OPEN -> CLOSED")
            
            elif self.state == CircuitState.CLOSED:
                # Reset failure count on success
                self.failure_count = 0
    
    async def _on_failure(self):
        """Handle failed operation"""
        async with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.state == CircuitState.CLOSED:
                if self.failure_count >= self.config.failure_threshold:
                    self.state = CircuitState.OPEN
                    self.state_change_time = time.time()
                    logger.warning(f"Circuit breaker {self.name}: CLOSED -> OPEN")
            
            elif self.state == CircuitState.HALF_OPEN:
                # Failure in half-open immediately goes back to open
                self.state = CircuitState.OPEN
                self.state_change_time = time.time()
                logger.warning(f"Circuit breaker {self.name}: HALF_OPEN -> OPEN")
    
    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state"""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure_time": self.last_failure_time,
            "state_change_time": self.state_change_time
        }

class RetryHandler:
    """
    Retry handler with various backoff strategies
    """
    
    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
    
    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt"""
        if self.config.strategy == RetryStrategy.FIXED_DELAY:
            delay = self.config.base_delay
        
        elif self.config.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = self.config.base_delay * (self.config.backoff_factor ** (attempt - 1))
        
        elif self.config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = self.config.base_delay * attempt
        
        elif self.config.strategy == RetryStrategy.JITTERED_BACKOFF:
            base_delay = self.config.base_delay * (self.config.backoff_factor ** (attempt - 1))
            jitter = random.uniform(0, base_delay * 0.1)  # 10% jitter
            delay = base_delay + jitter
        
        else:
            delay = self.config.base_delay
        
        return min(delay, self.config.max_delay)
    
    def _should_retry(self, attempt: int, exception: Exception) -> bool:
        """Determine if we should retry"""
        if attempt >= self.config.max_attempts:
            return False
        
        # Check stop conditions
        for stop_exc in self.config.stop_on:
            if isinstance(exception, stop_exc):
                return False
        
        # Check retry conditions
        for retry_exc in self.config.retry_on:
            if isinstance(exception, retry_exc):
                return True
        
        return False
    
    async def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with retry logic"""
        last_exception = None
        
        for attempt in range(1, self.config.max_attempts + 1):
            try:
                if inspect.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            
            except Exception as e:
                last_exception = e
                
                if not self._should_retry(attempt, e):
                    break
                
                delay = self._calculate_delay(attempt)
                logger.warning(
                    f"Attempt {attempt}/{self.config.max_attempts} failed: {e}. "
                    f"Retrying in {delay:.2f}s"
                )
                
                await asyncio.sleep(delay)
        
        raise RetryExhaustedException(
            f"All {self.config.max_attempts} attempts failed. Last error: {last_exception}"
        ) from last_exception

class TimeoutHandler:
    """
    Timeout handler for operations
    """
    
    def __init__(self, config: Optional[TimeoutConfig] = None):
        self.config = config or TimeoutConfig()
    
    @asynccontextmanager
    async def timeout(self, timeout_seconds: Optional[float] = None):
        """Context manager for timeout handling"""
        timeout = timeout_seconds or self.config.total_timeout
        
        try:
            async with asyncio.timeout(timeout):
                yield
        except asyncio.TimeoutError:
            raise TimeoutException(f"Operation timed out after {timeout}s")

class Bulkhead:
    """
    Bulkhead pattern for resource isolation
    Limits concurrent operations and provides queueing
    """
    
    def __init__(self, name: str, config: Optional[BulkheadConfig] = None):
        self.name = name
        self.config = config or BulkheadConfig()
        
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)
        self._queue = asyncio.Queue(maxsize=self.config.queue_size)
        self._active_tasks = 0
        self._total_requests = 0
        self._rejected_requests = 0
    
    @asynccontextmanager
    async def acquire(self):
        """Acquire bulkhead resource"""
        self._total_requests += 1
        
        # Check if we can queue the request
        if self._queue.qsize() >= self.config.queue_size:
            self._rejected_requests += 1
            raise BulkheadFullException(f"Bulkhead {self.name} is at capacity")
        
        # Add to queue
        await self._queue.put(None)
        
        try:
            # Wait for semaphore with timeout
            await asyncio.wait_for(
                self._semaphore.acquire(),
                timeout=self.config.timeout
            )
            
            self._active_tasks += 1
            yield
            
        except asyncio.TimeoutError:
            # Remove from queue if timeout
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            raise TimeoutException(f"Bulkhead {self.name} acquire timeout")
        
        finally:
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            
            self._active_tasks -= 1
            self._semaphore.release()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get bulkhead statistics"""
        return {
            "name": self.name,
            "active_tasks": self._active_tasks,
            "queue_size": self._queue.qsize(),
            "max_concurrent": self.config.max_concurrent,
            "max_queue_size": self.config.queue_size,
            "total_requests": self._total_requests,
            "rejected_requests": self._rejected_requests,
            "rejection_rate": f"{(self._rejected_requests / max(self._total_requests, 1) * 100):.2f}%"
        }

class ResilienceManager:
    """
    Central manager for all resilience patterns
    """
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.bulkheads: Dict[str, Bulkhead] = {}
        self.default_retry_config = RetryConfig()
        self.default_timeout_config = TimeoutConfig()
    
    def get_circuit_breaker(self, name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """Get or create circuit breaker"""
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker(name, config)
        return self.circuit_breakers[name]
    
    def get_bulkhead(self, name: str, config: Optional[BulkheadConfig] = None) -> Bulkhead:
        """Get or create bulkhead"""
        if name not in self.bulkheads:
            self.bulkheads[name] = Bulkhead(name, config)
        return self.bulkheads[name]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get all resilience statistics"""
        return {
            "circuit_breakers": {
                name: cb.get_state() 
                for name, cb in self.circuit_breakers.items()
            },
            "bulkheads": {
                name: bh.get_stats() 
                for name, bh in self.bulkheads.items()
            }
        }

# Global resilience manager
_resilience_manager = ResilienceManager()

def get_resilience_manager() -> ResilienceManager:
    """Get global resilience manager"""
    return _resilience_manager

# Decorators for resilience patterns

def circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None):
    """Circuit breaker decorator"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            cb = get_resilience_manager().get_circuit_breaker(name, config)
            async with cb:
                return await func(*args, **kwargs)
        return wrapper
    return decorator

def retry(config: Optional[RetryConfig] = None):
    """Retry decorator"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            handler = RetryHandler(config)
            return await handler.execute(func, *args, **kwargs)
        return wrapper
    return decorator

def timeout(seconds: float):
    """Timeout decorator"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                async with asyncio.timeout(seconds):
                    return await func(*args, **kwargs)
            except asyncio.TimeoutError:
                raise TimeoutException(f"Function {func.__name__} timed out after {seconds}s")
        return wrapper
    return decorator

def bulkhead(name: str, config: Optional[BulkheadConfig] = None):
    """Bulkhead decorator"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            bh = get_resilience_manager().get_bulkhead(name, config)
            async with bh.acquire():
                return await func(*args, **kwargs)
        return wrapper
    return decorator

def resilient(
    circuit_breaker_name: Optional[str] = None,
    retry_config: Optional[RetryConfig] = None,
    timeout_seconds: Optional[float] = None,
    bulkhead_name: Optional[str] = None
):
    """
    Combined resilience decorator
    Applies circuit breaker, retry, timeout, and bulkhead patterns
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            manager = get_resilience_manager()
            
            # Apply bulkhead if specified
            if bulkhead_name:
                bh = manager.get_bulkhead(bulkhead_name)
                async with bh.acquire():
                    return await _execute_with_patterns(
                        func, circuit_breaker_name, retry_config, 
                        timeout_seconds, *args, **kwargs
                    )
            else:
                return await _execute_with_patterns(
                    func, circuit_breaker_name, retry_config, 
                    timeout_seconds, *args, **kwargs
                )
        return wrapper
    return decorator

async def _execute_with_patterns(
    func, circuit_breaker_name, retry_config, timeout_seconds, *args, **kwargs
):
    """Helper function to execute with resilience patterns"""
    
    async def execute_func():
        # Apply circuit breaker if specified
        if circuit_breaker_name:
            cb = get_resilience_manager().get_circuit_breaker(circuit_breaker_name)
            async with cb:
                return await func(*args, **kwargs)
        else:
            return await func(*args, **kwargs)
    
    # Apply timeout if specified
    if timeout_seconds:
        async def timeout_func():
            try:
                async with asyncio.timeout(timeout_seconds):
                    return await execute_func()
            except asyncio.TimeoutError:
                raise TimeoutException(f"Function {func.__name__} timed out after {timeout_seconds}s")
        execute_func = timeout_func
    
    # Apply retry if specified
    if retry_config:
        handler = RetryHandler(retry_config)
        return await handler.execute(execute_func)
    else:
        return await execute_func()

# PhishNet-specific resilience configurations

PHISHNET_RESILIENCE_CONFIGS = {
    "virustotal_api": {
        "circuit_breaker": CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=300.0,  # 5 minutes
            timeout=30.0
        ),
        "retry": RetryConfig(
            max_attempts=3,
            strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            base_delay=2.0,
            retry_on=[Exception],
            stop_on=[KeyError, ValueError]  # Don't retry on config errors
        ),
        "bulkhead": BulkheadConfig(
            max_concurrent=5,  # VirusTotal rate limits
            queue_size=50,
            timeout=60.0
        )
    },
    
    "abuseipdb_api": {
        "circuit_breaker": CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=300.0,
            timeout=30.0
        ),
        "retry": RetryConfig(
            max_attempts=3,
            strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            base_delay=1.0
        ),
        "bulkhead": BulkheadConfig(
            max_concurrent=3,
            queue_size=30,
            timeout=45.0
        )
    },
    
    "gmail_api": {
        "circuit_breaker": CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=180.0,  # 3 minutes
            timeout=60.0
        ),
        "retry": RetryConfig(
            max_attempts=5,
            strategy=RetryStrategy.JITTERED_BACKOFF,
            base_delay=1.0,
            max_delay=30.0
        ),
        "bulkhead": BulkheadConfig(
            max_concurrent=10,
            queue_size=100,
            timeout=120.0
        )
    },
    
    "database": {
        "circuit_breaker": CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60.0,
            timeout=10.0
        ),
        "retry": RetryConfig(
            max_attempts=3,
            strategy=RetryStrategy.FIXED_DELAY,
            base_delay=0.5
        ),
        "bulkhead": BulkheadConfig(
            max_concurrent=20,
            queue_size=200,
            timeout=30.0
        )
    }
}

# PhishNet-specific decorated functions

@resilient(
    circuit_breaker_name="virustotal_api",
    retry_config=PHISHNET_RESILIENCE_CONFIGS["virustotal_api"]["retry"],
    timeout_seconds=30.0,
    bulkhead_name="virustotal_api"
)
async def get_virustotal_report(domain: str) -> Dict[str, Any]:
    """Get VirusTotal report with full resilience"""
    # Simulate API call
    await asyncio.sleep(random.uniform(0.1, 2.0))
    
    # Simulate occasional failures
    if random.random() < 0.1:  # 10% failure rate
        raise Exception("VirusTotal API error")
    
    return {
        "domain": domain,
        "reputation": random.choice(["clean", "suspicious", "malicious"]),
        "scan_date": datetime.utcnow().isoformat()
    }

@resilient(
    circuit_breaker_name="gmail_api",
    retry_config=PHISHNET_RESILIENCE_CONFIGS["gmail_api"]["retry"],
    timeout_seconds=60.0,
    bulkhead_name="gmail_api"
)
async def fetch_gmail_messages(query: str) -> List[Dict[str, Any]]:
    """Fetch Gmail messages with full resilience"""
    # Simulate API call
    await asyncio.sleep(random.uniform(0.5, 3.0))
    
    # Simulate occasional failures
    if random.random() < 0.05:  # 5% failure rate
        raise Exception("Gmail API quota exceeded")
    
    return [
        {
            "id": f"msg_{i}",
            "subject": f"Test message {i}",
            "sender": f"test{i}@example.com"
        }
        for i in range(random.randint(1, 10))
    ]

# Health check and monitoring

async def check_resilience_health() -> Dict[str, Any]:
    """Check health of all resilience components"""
    manager = get_resilience_manager()
    stats = manager.get_stats()
    
    health = {
        "status": "healthy",
        "circuit_breakers": {},
        "bulkheads": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Check circuit breakers
    for name, cb_stats in stats["circuit_breakers"].items():
        is_healthy = cb_stats["state"] != "open"
        health["circuit_breakers"][name] = {
            "healthy": is_healthy,
            "state": cb_stats["state"],
            "failure_count": cb_stats["failure_count"]
        }
        
        if not is_healthy:
            health["status"] = "degraded"
    
    # Check bulkheads
    for name, bh_stats in stats["bulkheads"].items():
        rejection_rate = float(bh_stats["rejection_rate"].rstrip('%'))
        is_healthy = rejection_rate < 10.0  # Less than 10% rejection rate
        
        health["bulkheads"][name] = {
            "healthy": is_healthy,
            "rejection_rate": bh_stats["rejection_rate"],
            "active_tasks": bh_stats["active_tasks"]
        }
        
        if not is_healthy:
            health["status"] = "degraded"
    
    return health

# Testing and demonstration functions

async def demonstrate_resilience():
    """Demonstrate resilience patterns"""
    print("PhishNet Resilience Patterns Demonstration")
    print("=" * 50)
    
    # Test circuit breaker
    print("\n1. Testing Circuit Breaker...")
    for i in range(10):
        try:
            result = await get_virustotal_report(f"test{i}.com")
            print(f"  Call {i+1}: Success - {result['reputation']}")
        except Exception as e:
            print(f"  Call {i+1}: Failed - {e}")
        
        await asyncio.sleep(0.1)
    
    # Test bulkhead
    print("\n2. Testing Bulkhead (concurrent requests)...")
    tasks = []
    for i in range(15):  # More than bulkhead limit
        task = asyncio.create_task(fetch_gmail_messages(f"query_{i}"))
        tasks.append(task)
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    successes = sum(1 for r in results if not isinstance(r, Exception))
    failures = len(results) - successes
    print(f"  Concurrent requests: {len(tasks)}")
    print(f"  Successes: {successes}")
    print(f"  Failures: {failures}")
    
    # Show resilience stats
    print("\n3. Resilience Statistics:")
    health = await check_resilience_health()
    print(f"  Overall status: {health['status']}")
    
    for name, cb in health["circuit_breakers"].items():
        print(f"  Circuit Breaker {name}: {cb['state']} (failures: {cb['failure_count']})")
    
    for name, bh in health["bulkheads"].items():
        print(f"  Bulkhead {name}: {bh['rejection_rate']} rejection rate")

if __name__ == "__main__":
    asyncio.run(demonstrate_resilience())
