"""
Rate limiting system for external API calls.
Implements per-tenant and global rate limits to prevent quota exhaustion.
"""

import asyncio
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import uuid

from app.core.redis_client import get_redis_client

logger = logging.getLogger(__name__)

class RateLimitType(Enum):
    """Types of rate limits"""
    PER_SECOND = "per_second"
    PER_MINUTE = "per_minute" 
    PER_HOUR = "per_hour"
    PER_DAY = "per_day"
    PER_MONTH = "per_month"

@dataclass
class RateLimitConfig:
    """Configuration for a rate limit"""
    service: str
    limit_type: RateLimitType
    max_requests: int
    window_seconds: int
    burst_allowance: int = 0  # Extra requests allowed in burst
    cooldown_seconds: int = 0  # Cooldown after limit hit
    priority_bypass: bool = False  # Allow priority requests to bypass
    
    def __post_init__(self):
        """Calculate window seconds from limit type if not provided"""
        if self.window_seconds == 0:
            window_mapping = {
                RateLimitType.PER_SECOND: 1,
                RateLimitType.PER_MINUTE: 60,
                RateLimitType.PER_HOUR: 3600,
                RateLimitType.PER_DAY: 86400,
                RateLimitType.PER_MONTH: 2592000  # 30 days
            }
            self.window_seconds = window_mapping.get(self.limit_type, 60)

@dataclass
class RateLimitResult:
    """Result of rate limit check"""
    allowed: bool
    remaining: int
    reset_time: float
    retry_after: Optional[int] = None
    reason: str = ""
    burst_used: int = 0

class RateLimitError(Exception):
    """Raised when rate limit is exceeded"""
    def __init__(self, message: str, retry_after: int = None, 
                 remaining: int = 0, reset_time: float = None):
        super().__init__(message)
        self.retry_after = retry_after
        self.remaining = remaining
        self.reset_time = reset_time

class RateLimiter:
    """
    Redis-based rate limiter with sliding window algorithm.
    Supports multiple rate limit types and burst allowances.
    """
    
    def __init__(self, redis_client=None):
        self.redis_client = redis_client or get_redis_client()
        self._lua_scripts = self._load_lua_scripts()
        
        # Default rate limit configurations
        self._default_configs = self._get_default_rate_limits()
        
    def _load_lua_scripts(self) -> Dict[str, str]:
        """Load Lua scripts for atomic rate limiting operations"""
        
        # Sliding window rate limit script
        sliding_window_script = """
        local key = KEYS[1]
        local window = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local current_time = tonumber(ARGV[3])
        local identifier = ARGV[4]
        local burst = tonumber(ARGV[5]) or 0
        
        -- Clean old entries outside window
        redis.call('ZREMRANGEBYSCORE', key, 0, current_time - window)
        
        -- Count current requests in window
        local current_requests = redis.call('ZCARD', key)
        local total_limit = limit + burst
        
        if current_requests < total_limit then
            -- Add current request
            redis.call('ZADD', key, current_time, identifier)
            redis.call('EXPIRE', key, window + 1)
            
            local remaining = total_limit - current_requests - 1
            local reset_time = current_time + window
            
            return {1, remaining, reset_time, current_requests >= limit and 1 or 0}
        else
            -- Rate limit exceeded
            local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
            local reset_time = oldest[2] and (tonumber(oldest[2]) + window) or (current_time + window)
            
            return {0, 0, reset_time, current_requests - limit}
        end
        """
        
        # Token bucket script
        token_bucket_script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local current_time = tonumber(ARGV[3])
        local requested_tokens = tonumber(ARGV[4]) or 1
        
        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1]) or capacity
        local last_refill = tonumber(bucket[2]) or current_time
        
        -- Calculate tokens to add based on time passed
        local time_passed = current_time - last_refill
        local tokens_to_add = math.floor(time_passed * refill_rate)
        tokens = math.min(capacity, tokens + tokens_to_add)
        
        if tokens >= requested_tokens then
            -- Grant request
            tokens = tokens - requested_tokens
            redis.call('HMSET', key, 'tokens', tokens, 'last_refill', current_time)
            redis.call('EXPIRE', key, 3600)  -- 1 hour TTL
            
            return {1, tokens, 0}
        else
            -- Deny request
            local wait_time = math.ceil((requested_tokens - tokens) / refill_rate)
            redis.call('HMSET', key, 'tokens', tokens, 'last_refill', current_time)
            redis.call('EXPIRE', key, 3600)
            
            return {0, tokens, wait_time}
        end
        """
        
        return {
            'sliding_window': sliding_window_script,
            'token_bucket': token_bucket_script
        }
    
    def _get_default_rate_limits(self) -> Dict[str, List[RateLimitConfig]]:
        """Get default rate limit configurations for common APIs"""
        return {
            'virustotal': [
                RateLimitConfig(
                    service='virustotal',
                    limit_type=RateLimitType.PER_MINUTE,
                    max_requests=4,
                    window_seconds=60,
                    burst_allowance=2,
                    cooldown_seconds=15
                ),
                RateLimitConfig(
                    service='virustotal',
                    limit_type=RateLimitType.PER_DAY,
                    max_requests=1000,
                    window_seconds=86400,
                    burst_allowance=100
                )
            ],
            'abuseipdb': [
                RateLimitConfig(
                    service='abuseipdb',
                    limit_type=RateLimitType.PER_MINUTE,
                    max_requests=10,
                    window_seconds=60,
                    burst_allowance=5
                ),
                RateLimitConfig(
                    service='abuseipdb',
                    limit_type=RateLimitType.PER_DAY,
                    max_requests=1000,
                    window_seconds=86400
                )
            ],
            'urlscan': [
                RateLimitConfig(
                    service='urlscan',
                    limit_type=RateLimitType.PER_MINUTE,
                    max_requests=2,
                    window_seconds=60,
                    burst_allowance=1,
                    cooldown_seconds=30
                ),
                RateLimitConfig(
                    service='urlscan',
                    limit_type=RateLimitType.PER_HOUR,
                    max_requests=100,
                    window_seconds=3600
                )
            ],
            'shodan': [
                RateLimitConfig(
                    service='shodan',
                    limit_type=RateLimitType.PER_SECOND,
                    max_requests=1,
                    window_seconds=1,
                    burst_allowance=0
                ),
                RateLimitConfig(
                    service='shodan',
                    limit_type=RateLimitType.PER_MONTH,
                    max_requests=1000,
                    window_seconds=2592000
                )
            ],
            'global': [
                RateLimitConfig(
                    service='global',
                    limit_type=RateLimitType.PER_SECOND,
                    max_requests=50,
                    window_seconds=1,
                    burst_allowance=20
                ),
                RateLimitConfig(
                    service='global',
                    limit_type=RateLimitType.PER_MINUTE,
                    max_requests=1000,
                    window_seconds=60,
                    burst_allowance=200
                )
            ]
        }
    
    async def check_rate_limit(self, service: str, identifier: str = "default",
                             tenant_id: str = None, priority: bool = False) -> RateLimitResult:
        """
        Check if request is allowed under rate limits.
        
        Args:
            service: Service name (e.g., 'virustotal', 'abuseipdb')
            identifier: Unique identifier for the request (IP, user_id, etc.)
            tenant_id: Tenant identifier for multi-tenant rate limiting
            priority: Whether this is a priority request
            
        Returns:
            RateLimitResult with decision and metadata
        """
        
        # Get rate limit configs for service
        configs = self._default_configs.get(service, [])
        if not configs:
            logger.warning(f"No rate limit config found for service {service}")
            return RateLimitResult(
                allowed=True,
                remaining=999,
                reset_time=time.time() + 3600,
                reason="No rate limit configured"
            )
        
        # Check each rate limit configuration
        for config in configs:
            # Skip if priority request and config allows bypass
            if priority and config.priority_bypass:
                continue
                
            result = await self._check_single_limit(
                config, service, identifier, tenant_id
            )
            
            if not result.allowed:
                return result
        
        # If all limits passed, return the most restrictive remaining count
        min_remaining = min(
            await self._get_remaining_requests(config, service, identifier, tenant_id)
            for config in configs
        )
        
        return RateLimitResult(
            allowed=True,
            remaining=min_remaining,
            reset_time=time.time() + min(c.window_seconds for c in configs),
            reason="All limits passed"
        )
    
    async def _check_single_limit(self, config: RateLimitConfig, service: str,
                                identifier: str, tenant_id: str = None) -> RateLimitResult:
        """Check a single rate limit configuration"""
        
        # Build rate limit key
        key_parts = ['rate_limit', service, config.limit_type.value]
        if tenant_id:
            key_parts.append(f"tenant:{tenant_id}")
        key_parts.append(identifier)
        key = ':'.join(key_parts)
        
        current_time = time.time()
        request_id = str(uuid.uuid4())
        
        # Execute sliding window rate limit
        try:
            result = await self.redis_client.eval(
                self._lua_scripts['sliding_window'],
                1,  # Number of keys
                key,
                config.window_seconds,
                config.max_requests,
                current_time,
                request_id,
                config.burst_allowance
            )
            
            allowed, remaining, reset_time, burst_used = result
            
            if not allowed:
                retry_after = max(1, int(reset_time - current_time))
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after,
                    reason=f"Rate limit exceeded for {service} ({config.limit_type.value})",
                    burst_used=burst_used
                )
            
            return RateLimitResult(
                allowed=True,
                remaining=remaining,
                reset_time=reset_time,
                burst_used=burst_used
            )
            
        except Exception as e:
            logger.error(f"Rate limit check failed for {service}: {e}")
            # Fail open - allow request but log error
            return RateLimitResult(
                allowed=True,
                remaining=0,
                reset_time=current_time + config.window_seconds,
                reason=f"Rate limit check failed: {e}"
            )
    
    async def _get_remaining_requests(self, config: RateLimitConfig, service: str,
                                    identifier: str, tenant_id: str = None) -> int:
        """Get remaining requests for a rate limit"""
        key_parts = ['rate_limit', service, config.limit_type.value]
        if tenant_id:
            key_parts.append(f"tenant:{tenant_id}")
        key_parts.append(identifier)
        key = ':'.join(key_parts)
        
        try:
            current_time = time.time()
            
            # Clean old entries and count current
            await self.redis_client.zremrangebyscore(
                key, 0, current_time - config.window_seconds
            )
            current_requests = await self.redis_client.zcard(key)
            
            total_limit = config.max_requests + config.burst_allowance
            return max(0, total_limit - current_requests)
            
        except Exception as e:
            logger.error(f"Failed to get remaining requests: {e}")
            return 0
    
    async def acquire(self, service: str, identifier: str = "default",
                     tenant_id: str = None, priority: bool = False,
                     timeout: float = 60.0) -> RateLimitResult:
        """
        Acquire rate limit permission, waiting if necessary.
        
        Args:
            service: Service name
            identifier: Request identifier  
            tenant_id: Tenant identifier
            priority: Priority request flag
            timeout: Maximum wait time in seconds
            
        Returns:
            RateLimitResult when permission granted
            
        Raises:
            RateLimitError: If timeout exceeded or permanent failure
        """
        
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            result = await self.check_rate_limit(
                service, identifier, tenant_id, priority
            )
            
            if result.allowed:
                return result
            
            if result.retry_after:
                wait_time = min(result.retry_after, timeout - (time.time() - start_time))
                if wait_time > 0:
                    logger.info(f"Rate limited for {service}, waiting {wait_time}s")
                    await asyncio.sleep(wait_time)
                else:
                    break
            else:
                # No retry info, use exponential backoff
                wait_time = min(2.0, timeout - (time.time() - start_time))
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                else:
                    break
        
        # Timeout exceeded
        raise RateLimitError(
            f"Rate limit timeout for {service}",
            retry_after=result.retry_after,
            remaining=result.remaining,
            reset_time=result.reset_time
        )
    
    async def release(self, service: str, identifier: str = "default",
                     tenant_id: str = None) -> None:
        """
        Release a rate limit slot (for failed requests).
        This removes the most recent request from the sliding window.
        """
        
        configs = self._default_configs.get(service, [])
        
        for config in configs:
            key_parts = ['rate_limit', service, config.limit_type.value]
            if tenant_id:
                key_parts.append(f"tenant:{tenant_id}")
            key_parts.append(identifier)
            key = ':'.join(key_parts)
            
            try:
                # Remove the most recent entry
                await self.redis_client.zremrangebyrank(key, -1, -1)
                
            except Exception as e:
                logger.error(f"Failed to release rate limit for {service}: {e}")
    
    async def get_rate_limit_status(self, service: str = None, 
                                  identifier: str = "default",
                                  tenant_id: str = None) -> Dict[str, Any]:
        """Get current rate limit status for service(s)"""
        
        if service:
            services = [service]
        else:
            services = list(self._default_configs.keys())
        
        status = {
            'timestamp': time.time(),
            'services': {}
        }
        
        for svc in services:
            configs = self._default_configs.get(svc, [])
            svc_status = {
                'limits': [],
                'overall_status': 'ok'
            }
            
            for config in configs:
                remaining = await self._get_remaining_requests(
                    config, svc, identifier, tenant_id
                )
                
                total_limit = config.max_requests + config.burst_allowance
                usage_percent = ((total_limit - remaining) / total_limit) * 100
                
                limit_status = {
                    'type': config.limit_type.value,
                    'limit': config.max_requests,
                    'burst': config.burst_allowance,
                    'remaining': remaining,
                    'usage_percent': usage_percent,
                    'window_seconds': config.window_seconds,
                    'status': 'ok' if usage_percent < 80 else 'warning' if usage_percent < 95 else 'critical'
                }
                
                svc_status['limits'].append(limit_status)
                
                # Update overall status to worst individual status
                if limit_status['status'] == 'critical':
                    svc_status['overall_status'] = 'critical'
                elif limit_status['status'] == 'warning' and svc_status['overall_status'] == 'ok':
                    svc_status['overall_status'] = 'warning'
            
            status['services'][svc] = svc_status
        
        return status
    
    async def reset_rate_limits(self, service: str = None, identifier: str = None,
                              tenant_id: str = None) -> bool:
        """Reset rate limits (admin function)"""
        
        try:
            if service and identifier:
                # Reset specific service/identifier
                configs = self._default_configs.get(service, [])
                for config in configs:
                    key_parts = ['rate_limit', service, config.limit_type.value]
                    if tenant_id:
                        key_parts.append(f"tenant:{tenant_id}")
                    key_parts.append(identifier)
                    key = ':'.join(key_parts)
                    
                    await self.redis_client.delete(key)
                    
                logger.info(f"Reset rate limits for {service}:{identifier}")
                
            elif service:
                # Reset all identifiers for service
                pattern = f"rate_limit:{service}:*"
                if tenant_id:
                    pattern = f"rate_limit:{service}:*:tenant:{tenant_id}:*"
                
                keys = await self.redis_client.keys(pattern)
                if keys:
                    await self.redis_client.delete(*keys)
                    
                logger.info(f"Reset all rate limits for {service}")
                
            else:
                # Reset all rate limits (nuclear option)
                keys = await self.redis_client.keys("rate_limit:*")
                if keys:
                    await self.redis_client.delete(*keys)
                    
                logger.warning("Reset ALL rate limits")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to reset rate limits: {e}")
            return False
    
    def add_custom_rate_limit(self, service: str, config: RateLimitConfig) -> None:
        """Add or update a custom rate limit configuration"""
        
        if service not in self._default_configs:
            self._default_configs[service] = []
        
        # Remove existing config of same type
        self._default_configs[service] = [
            c for c in self._default_configs[service] 
            if c.limit_type != config.limit_type
        ]
        
        # Add new config
        self._default_configs[service].append(config)
        
        logger.info(f"Added custom rate limit for {service}: "
                   f"{config.max_requests}/{config.limit_type.value}")

# Decorator for automatic rate limiting
def rate_limited(service: str, identifier_func: callable = None, 
                tenant_func: callable = None, priority_func: callable = None):
    """
    Decorator to automatically apply rate limiting to functions.
    
    Args:
        service: Service name for rate limiting
        identifier_func: Function to extract identifier from args/kwargs
        tenant_func: Function to extract tenant_id from args/kwargs  
        priority_func: Function to determine if request is priority
    """
    
    def decorator(func):
        async def wrapper(*args, **kwargs):
            rate_limiter = get_rate_limiter()
            
            # Extract parameters
            identifier = "default"
            if identifier_func:
                try:
                    identifier = identifier_func(*args, **kwargs)
                except Exception as e:
                    logger.warning(f"Failed to extract identifier: {e}")
            
            tenant_id = None
            if tenant_func:
                try:
                    tenant_id = tenant_func(*args, **kwargs)
                except Exception as e:
                    logger.warning(f"Failed to extract tenant_id: {e}")
            
            priority = False
            if priority_func:
                try:
                    priority = priority_func(*args, **kwargs)
                except Exception as e:
                    logger.warning(f"Failed to extract priority: {e}")
            
            # Acquire rate limit
            try:
                await rate_limiter.acquire(service, identifier, tenant_id, priority)
                return await func(*args, **kwargs)
                
            except RateLimitError as e:
                logger.error(f"Rate limit exceeded for {service}: {e}")
                raise
            except Exception as e:
                # Release rate limit on failure
                await rate_limiter.release(service, identifier, tenant_id)
                raise
        
        return wrapper
    return decorator

# Global rate limiter instance
_rate_limiter = None

def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance"""
    global _rate_limiter
    if not _rate_limiter:
        _rate_limiter = RateLimiter()
    return _rate_limiter

# Convenience functions for common services
async def virustotal_rate_limit(identifier: str = "default", tenant_id: str = None) -> RateLimitResult:
    """Check VirusTotal rate limit"""
    limiter = get_rate_limiter()
    return await limiter.check_rate_limit("virustotal", identifier, tenant_id)

async def abuseipdb_rate_limit(identifier: str = "default", tenant_id: str = None) -> RateLimitResult:
    """Check AbuseIPDB rate limit"""
    limiter = get_rate_limiter()
    return await limiter.check_rate_limit("abuseipdb", identifier, tenant_id)

async def urlscan_rate_limit(identifier: str = "default", tenant_id: str = None) -> RateLimitResult:
    """Check URLScan rate limit"""
    limiter = get_rate_limiter()
    return await limiter.check_rate_limit("urlscan", identifier, tenant_id)

# Rate limit monitoring functions
async def get_all_rate_limit_stats() -> Dict[str, Any]:
    """Get comprehensive rate limit statistics"""
    limiter = get_rate_limiter()
    return await limiter.get_rate_limit_status()

async def check_service_health(service: str) -> Dict[str, Any]:
    """Check if a service is healthy from rate limiting perspective"""
    limiter = get_rate_limiter()
    status = await limiter.get_rate_limit_status(service)
    
    service_status = status['services'].get(service, {})
    overall_status = service_status.get('overall_status', 'unknown')
    
    return {
        'service': service,
        'healthy': overall_status in ['ok', 'warning'],
        'status': overall_status,
        'limits': service_status.get('limits', []),
        'timestamp': status['timestamp']
    }
