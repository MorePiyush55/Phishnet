"""
Caching decorators for expensive API calls in PhishNet.
Provides intelligent caching with TTL, invalidation, and performance monitoring.
"""

import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
import inspect

from app.core.async_cache import get_async_cache, AsyncCacheKey, async_cached
from app.config.settings import get_settings

logger = logging.getLogger(__name__)

F = TypeVar('F', bound=Callable[..., Any])


class CacheStats:
    """Cache performance statistics tracking."""
    
    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.errors = 0
        self.total_time_saved = 0.0  # seconds
        self.cache_operations = 0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate percentage."""
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0.0
    
    def record_hit(self, time_saved: float = 0.0):
        """Record a cache hit."""
        self.hits += 1
        self.cache_operations += 1
        self.total_time_saved += time_saved
    
    def record_miss(self):
        """Record a cache miss."""
        self.misses += 1
        self.cache_operations += 1
    
    def record_error(self):
        """Record a cache error."""
        self.errors += 1
        self.cache_operations += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            'hits': self.hits,
            'misses': self.misses,
            'errors': self.errors,
            'hit_rate': self.hit_rate,
            'total_time_saved': self.total_time_saved,
            'cache_operations': self.cache_operations
        }


# Global cache statistics
_cache_stats: Dict[str, CacheStats] = {}


def get_cache_stats(service: str = None) -> Dict[str, Any]:
    """Get cache statistics for a service or all services."""
    if service:
        return _cache_stats.get(service, CacheStats()).to_dict()
    
    return {
        service: stats.to_dict() 
        for service, stats in _cache_stats.items()
    }


def _get_or_create_stats(service: str) -> CacheStats:
    """Get or create cache stats for a service."""
    if service not in _cache_stats:
        _cache_stats[service] = CacheStats()
    return _cache_stats[service]


def _create_cache_key(
    func: Callable,
    service: str,
    args: tuple,
    kwargs: dict,
    key_generator: Optional[Callable] = None
) -> str:
    """Create a standardized cache key for function calls."""
    if key_generator:
        return key_generator(*args, **kwargs)
    
    # Default key generation
    func_signature = f"{func.__module__}.{func.__name__}"
    
    # Create hash of arguments for consistent keys
    key_data = {
        'args': args,
        'kwargs': {k: v for k, v in kwargs.items() if not k.startswith('_')}
    }
    
    key_json = json.dumps(key_data, sort_keys=True, default=str)
    key_hash = hashlib.sha256(key_json.encode()).hexdigest()[:16]
    
    return AsyncCacheKey.build(service, func_signature, key_hash)


def cached_api_call(
    service: str,
    ttl: int = 3600,
    key_generator: Optional[Callable] = None,
    cache_failures: bool = False,
    failure_ttl: int = 300,
    tags: Optional[List[str]] = None,
    invalidate_on: Optional[List[str]] = None,
    skip_cache_condition: Optional[Callable] = None
) -> Callable[[F], F]:
    """
    Advanced caching decorator for API calls with comprehensive features.
    
    Args:
        service: Service name (e.g., 'virustotal', 'abuseipdb', 'gemini')
        ttl: Cache time-to-live in seconds
        key_generator: Custom function to generate cache keys
        cache_failures: Whether to cache failed API calls
        failure_ttl: TTL for cached failures (shorter than success TTL)
        tags: Cache tags for bulk invalidation
        invalidate_on: List of events that should invalidate this cache
        skip_cache_condition: Function to determine if cache should be skipped
    """
    
    def decorator(func: F) -> F:
        stats = _get_or_create_stats(service)
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Check if we should skip caching
            if skip_cache_condition and skip_cache_condition(*args, **kwargs):
                logger.debug(f"Skipping cache for {service}.{func.__name__} due to condition")
                return await func(*args, **kwargs)
            
            # Generate cache key
            cache_key = _create_cache_key(func, service, args, kwargs, key_generator)
            
            try:
                cache = await get_async_cache()
                
                # Try to get from cache
                start_time = time.time()
                cached_result = await cache.get(cache_key)
                
                if cached_result is not None:
                    # Cache hit
                    time_saved = time.time() - start_time
                    stats.record_hit(time_saved)
                    
                    logger.debug(f"Cache hit for {service}.{func.__name__}: {cache_key}")
                    
                    # Check if it's a cached failure
                    if isinstance(cached_result, dict) and cached_result.get('_cached_error'):
                        error_msg = cached_result.get('error', 'Cached API failure')
                        raise Exception(f"Cached failure: {error_msg}")
                    
                    return cached_result
                
                # Cache miss - execute the function
                stats.record_miss()
                logger.debug(f"Cache miss for {service}.{func.__name__}: {cache_key}")
                
                # Record execution time for performance monitoring
                execution_start = time.time()
                
                try:
                    result = await func(*args, **kwargs)
                    execution_time = time.time() - execution_start
                    
                    # Cache successful result
                    cache_tags = (tags or []) + [service, 'api_success']
                    await cache.set(
                        cache_key, 
                        result, 
                        ttl=ttl, 
                        cache_type=service,
                        tags=cache_tags
                    )
                    
                    logger.debug(
                        f"Cached successful result for {service}.{func.__name__} "
                        f"(execution: {execution_time:.2f}s, ttl: {ttl}s)"
                    )
                    
                    return result
                    
                except Exception as e:
                    execution_time = time.time() - execution_start
                    
                    if cache_failures:
                        # Cache the failure for a shorter period
                        failure_result = {
                            '_cached_error': True,
                            'error': str(e),
                            'timestamp': datetime.utcnow().isoformat(),
                            'execution_time': execution_time
                        }
                        
                        failure_tags = (tags or []) + [service, 'api_failure']
                        await cache.set(
                            cache_key,
                            failure_result,
                            ttl=failure_ttl,
                            cache_type=f"{service}_failure",
                            tags=failure_tags
                        )
                        
                        logger.debug(
                            f"Cached failure for {service}.{func.__name__} "
                            f"(execution: {execution_time:.2f}s, ttl: {failure_ttl}s)"
                        )
                    
                    # Re-raise the original exception
                    raise
                    
            except Exception as e:
                stats.record_error()
                logger.error(f"Cache operation failed for {service}.{func.__name__}: {e}")
                
                # Execute function without caching on cache errors
                return await func(*args, **kwargs)
        
        # Add cache management methods to the decorated function
        wrapper._cache_service = service
        wrapper._cache_ttl = ttl
        wrapper._original_func = func
        
        return wrapper
    
    return decorator


# Specialized decorators for different services
def cache_virustotal(
    ttl: int = 7200,  # 2 hours - VT results are stable
    cache_failures: bool = True,
    failure_ttl: int = 600  # 10 minutes for failures
):
    """Cache decorator specifically for VirusTotal API calls."""
    return cached_api_call(
        service="virustotal",
        ttl=ttl,
        cache_failures=cache_failures,
        failure_ttl=failure_ttl,
        tags=["virustotal", "threat_intel"],
        key_generator=lambda *args, **kwargs: AsyncCacheKey.build(
            "virustotal",
            hashlib.sha256(str(args).encode()).hexdigest()[:16]
        )
    )


def cache_abuseipdb(
    ttl: int = 3600,  # 1 hour - IP reputation can change
    cache_failures: bool = True,
    failure_ttl: int = 300  # 5 minutes for failures
):
    """Cache decorator specifically for AbuseIPDB API calls."""
    return cached_api_call(
        service="abuseipdb",
        ttl=ttl,
        cache_failures=cache_failures,
        failure_ttl=failure_ttl,
        tags=["abuseipdb", "ip_reputation"],
        key_generator=lambda ip, **kwargs: AsyncCacheKey.build(
            "abuseipdb",
            ip,
            str(kwargs.get('days', 30))
        )
    )


def cache_gemini_analysis(
    ttl: int = 1800,  # 30 minutes - AI analysis may vary slightly
    cache_failures: bool = False  # Don't cache AI failures as they might be transient
):
    """Cache decorator specifically for Gemini AI analysis."""
    def should_skip_cache(*args, **kwargs) -> bool:
        # Skip cache for real-time analysis requests
        return kwargs.get('real_time', False)
    
    return cached_api_call(
        service="gemini",
        ttl=ttl,
        cache_failures=cache_failures,
        tags=["gemini", "ai_analysis"],
        skip_cache_condition=should_skip_cache,
        key_generator=lambda text, **kwargs: AsyncCacheKey.build(
            "gemini",
            hashlib.sha256(text.encode()).hexdigest(),
            str(kwargs.get('model', 'default'))
        )
    )


def cache_url_analysis(
    ttl: int = 3600,  # 1 hour for URL analysis
    cache_failures: bool = True,
    failure_ttl: int = 600
):
    """Cache decorator for URL analysis results."""
    return cached_api_call(
        service="url_analysis",
        ttl=ttl,
        cache_failures=cache_failures,
        failure_ttl=failure_ttl,
        tags=["url_analysis", "security"],
        key_generator=lambda url, **kwargs: AsyncCacheKey.build(
            "url_analysis",
            hashlib.sha256(url.encode()).hexdigest()
        )
    )


def cache_email_features(
    ttl: int = 7200,  # 2 hours - email features are stable
):
    """Cache decorator for email feature extraction."""
    return cached_api_call(
        service="email_features",
        ttl=ttl,
        cache_failures=False,
        tags=["email_features", "ml"],
        key_generator=lambda email_content, **kwargs: AsyncCacheKey.build(
            "email_features",
            hashlib.sha256(str(email_content).encode()).hexdigest()
        )
    )


# Cache invalidation utilities
async def invalidate_service_cache(service: str) -> int:
    """Invalidate all cached results for a specific service."""
    try:
        cache = await get_async_cache()
        return await cache.invalidate_by_tag(service)
    except Exception as e:
        logger.error(f"Failed to invalidate cache for service {service}: {e}")
        return 0


async def invalidate_threat_intel_cache() -> int:
    """Invalidate all threat intelligence caches."""
    try:
        cache = await get_async_cache()
        count = 0
        for tag in ["virustotal", "abuseipdb", "threat_intel"]:
            count += await cache.invalidate_by_tag(tag)
        return count
    except Exception as e:
        logger.error(f"Failed to invalidate threat intel cache: {e}")
        return 0


async def warm_cache_for_common_queries():
    """Pre-warm cache with common queries (can be run periodically)."""
    logger.info("Starting cache warming process")
    
    # This would be implemented to pre-populate cache with common
    # threat intel queries, popular URLs, etc.
    # For now, just log the intent
    
    logger.info("Cache warming completed")


# Cache monitoring and metrics
async def get_comprehensive_cache_stats() -> Dict[str, Any]:
    """Get comprehensive cache statistics across all services."""
    try:
        cache = await get_async_cache()
        redis_stats = await cache.get_cache_stats()
        
        service_stats = get_cache_stats()
        
        return {
            'redis_stats': redis_stats,
            'service_stats': service_stats,
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get cache stats: {e}")
        return {'error': str(e)}


# Periodic maintenance tasks
async def cleanup_expired_cache_stats():
    """Clean up old cache statistics (run periodically)."""
    # Reset stats that are too old or have no recent activity
    current_time = time.time()
    
    for service, stats in list(_cache_stats.items()):
        # If no operations in the last hour, reset stats
        if hasattr(stats, '_last_operation'):
            if current_time - stats._last_operation > 3600:
                del _cache_stats[service]
                logger.debug(f"Cleaned up old stats for service: {service}")


# Export commonly used decorators
__all__ = [
    'cached_api_call',
    'cache_virustotal',
    'cache_abuseipdb', 
    'cache_gemini_analysis',
    'cache_url_analysis',
    'cache_email_features',
    'invalidate_service_cache',
    'invalidate_threat_intel_cache',
    'get_cache_stats',
    'get_comprehensive_cache_stats',
    'warm_cache_for_common_queries'
]
