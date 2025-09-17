"""
Caching layer with decorators for API calls.
Provides Redis-backed caching with TTL support and normalized resource keys.
"""

import functools
import hashlib
import inspect
import logging
from typing import Any, Callable, Dict, Optional, Union, TypeVar, ParamSpec
from datetime import datetime, timedelta
import json
import asyncio
from urllib.parse import urlparse

from app.core.redis_client import get_cache_manager, CacheManager

logger = logging.getLogger(__name__)

# Type hints for decorator
P = ParamSpec('P')
T = TypeVar('T')

# Cache TTL configurations (in seconds)
CACHE_TTL_CONFIG = {
    'virustotal': 24 * 60 * 60,      # 24 hours - VT data is relatively stable
    'abuseipdb': 1 * 60 * 60,        # 1 hour - IP reputation can change
    'gemini': 1 * 60 * 60,           # 1 hour - LLM analysis might change with model updates
    'urlvoid': 6 * 60 * 60,          # 6 hours - URL reputation service
    'whois': 24 * 60 * 60,           # 24 hours - Domain info changes rarely
    'screenshot': 30 * 60,           # 30 minutes - Screenshots may change
    'redirect_analysis': 2 * 60 * 60, # 2 hours - Redirect chains can change
    'reputation_check': 4 * 60 * 60, # 4 hours - General reputation data
    'dns_resolution': 30 * 60,       # 30 minutes - DNS can change frequently
    'default': 15 * 60               # 15 minutes - Default fallback
}

class ResourceNormalizer:
    """
    Normalizes resource identifiers for consistent caching.
    Handles URLs, domains, IPs, hashes, etc.
    """
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL for caching"""
        try:
            parsed = urlparse(url.lower().strip())
            
            # Remove fragment and common tracking parameters
            query_params = []
            if parsed.query:
                # Filter out common tracking parameters
                tracking_params = {
                    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
                    'fbclid', 'gclid', 'ref', 'source', '_ga', '_gl'
                }
                
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, _ = param.split('=', 1)
                        if key.lower() not in tracking_params:
                            query_params.append(param)
                    else:
                        query_params.append(param)
            
            # Reconstruct normalized URL
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if query_params:
                normalized += "?" + "&".join(sorted(query_params))
            
            return normalized
        except Exception:
            # If parsing fails, return original URL cleaned
            return url.lower().strip()
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain for caching"""
        domain = domain.lower().strip()
        # Remove protocol if present
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        # Remove path if present
        if '/' in domain:
            domain = domain.split('/', 1)[0]
        # Remove port if present (keep for non-standard ports)
        if ':' in domain and not domain.endswith((':80', ':443')):
            pass  # Keep non-standard ports
        elif domain.endswith((':80', ':443')):
            domain = domain.rsplit(':', 1)[0]
        
        return domain
    
    @staticmethod
    def normalize_ip(ip: str) -> str:
        """Normalize IP address for caching"""
        return ip.strip()
    
    @staticmethod
    def normalize_hash(hash_value: str) -> str:
        """Normalize hash for caching"""
        return hash_value.lower().strip()
    
    @staticmethod
    def normalize_email(email: str) -> str:
        """Normalize email for caching"""
        return email.lower().strip()
    
    @classmethod
    def normalize_resource(cls, resource: str, resource_type: str = 'auto') -> str:
        """Auto-detect and normalize resource"""
        resource = resource.strip()
        
        if resource_type == 'auto':
            # Auto-detect resource type
            if resource.startswith(('http://', 'https://')):
                resource_type = 'url'
            elif '@' in resource:
                resource_type = 'email'
            elif len(resource) in [32, 40, 64, 128] and all(c in '0123456789abcdefABCDEF' for c in resource):
                resource_type = 'hash'
            elif resource.replace('.', '').replace(':', '').isdigit() or ':' in resource:
                resource_type = 'ip'
            else:
                resource_type = 'domain'
        
        # Apply appropriate normalization
        if resource_type == 'url':
            return cls.normalize_url(resource)
        elif resource_type == 'domain':
            return cls.normalize_domain(resource)
        elif resource_type == 'ip':
            return cls.normalize_ip(resource)
        elif resource_type == 'hash':
            return cls.normalize_hash(resource)
        elif resource_type == 'email':
            return cls.normalize_email(resource)
        else:
            return resource.lower().strip()

class CacheKeyBuilder:
    """
    Builds cache keys for different API calls and resource types.
    """
    
    @staticmethod
    def build_key(service: str, resource: str, resource_type: str = 'auto',
                  additional_params: Dict[str, Any] = None) -> str:
        """Build a cache key for the given parameters"""
        
        # Normalize the resource
        normalized_resource = ResourceNormalizer.normalize_resource(resource, resource_type)
        
        # Create base key components
        key_parts = [
            service.lower(),
            resource_type.lower() if resource_type != 'auto' else 'resource',
            hashlib.md5(normalized_resource.encode()).hexdigest()[:16]  # Short hash
        ]
        
        # Add additional parameters if provided
        if additional_params:
            params_str = json.dumps(additional_params, sort_keys=True, default=str)
            params_hash = hashlib.md5(params_str.encode()).hexdigest()[:8]
            key_parts.append(params_hash)
        
        return ":".join(key_parts)
    
    @staticmethod
    def build_function_key(func_name: str, args: tuple, kwargs: dict) -> str:
        """Build cache key based on function name and arguments"""
        
        # Create a string representation of arguments
        args_str = ",".join(str(arg) for arg in args)
        kwargs_str = ",".join(f"{k}={v}" for k, v in sorted(kwargs.items()))
        
        # Combine all parts
        signature = f"{func_name}({args_str},{kwargs_str})"
        
        # Hash the signature to create a fixed-length key
        key_hash = hashlib.md5(signature.encode()).hexdigest()
        
        return f"func:{func_name}:{key_hash[:16]}"

def cached(
    ttl_seconds: Optional[int] = None,
    service: str = None,
    ttl: Optional[int] = None,
    resource_type: str = 'auto',
    key_builder: Callable = None,
    cache_on_error: bool = False,
    invalidate_on: Optional[Callable] = None
):
    """
    Decorator for caching function results with Redis.
    
    Args:
        ttl_seconds: Cache TTL in seconds. If None, uses service-based default
        service: Service name for TTL lookup (e.g., 'virustotal', 'gemini')
        resource_type: Type of resource being cached ('url', 'domain', 'ip', 'hash', 'auto')
        key_builder: Custom function to build cache key
        cache_on_error: Whether to cache error results
        invalidate_on: Function that determines when to invalidate cache
    """
    
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        cache_manager = get_cache_manager()
        
        # Determine TTL (accept legacy 'ttl' kw)
        # Allow callers to pass ttl=... as shorthand or ttl_seconds
        if ttl is not None:
            ttl_value = ttl
        elif ttl_seconds is not None:
            ttl_value = ttl_seconds
        elif service and service in CACHE_TTL_CONFIG:
            ttl_value = CACHE_TTL_CONFIG[service]
        else:
            ttl_value = CACHE_TTL_CONFIG['default']
        
        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            try:
                # Build cache key
                if key_builder:
                    cache_key = key_builder(*args, **kwargs)
                elif service and len(args) > 0:
                    # Use first argument as resource
                    cache_key = CacheKeyBuilder.build_key(
                        service, str(args[0]), resource_type, kwargs
                    )
                else:
                    # Fallback to function-based key
                    cache_key = CacheKeyBuilder.build_function_key(
                        func.__name__, args, kwargs
                    )
                
                # Check for invalidation condition
                if invalidate_on and invalidate_on(*args, **kwargs):
                    cache_manager.delete(cache_key)
                
                # Try to get from cache
                cached_result = cache_manager.get(cache_key)
                if cached_result is not None:
                    logger.debug(f"Cache hit for {func.__name__}: {cache_key}")
                    return cached_result
                
                # Call the function
                logger.debug(f"Cache miss for {func.__name__}: {cache_key}")
                result = func(*args, **kwargs)
                
                # Cache the result (if not an error or if cache_on_error is True)
                should_cache = True
                if hasattr(result, 'get') and isinstance(result, dict):
                    # Check if result indicates an error
                    if result.get('error') and not cache_on_error:
                        should_cache = False
                
                if should_cache:
                    cache_manager.set(cache_key, result, ttl)
                    logger.debug(f"Cached result for {func.__name__}: {cache_key} (TTL: {ttl}s)")
                
                return result
                
            except Exception as e:
                logger.error(f"Cache error in {func.__name__}: {e}")
                # If cache fails, still call the function
                return func(*args, **kwargs)
        
        @functools.wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            try:
                # Build cache key
                if key_builder:
                    cache_key = key_builder(*args, **kwargs)
                elif service and len(args) > 0:
                    cache_key = CacheKeyBuilder.build_key(
                        service, str(args[0]), resource_type, kwargs
                    )
                else:
                    cache_key = CacheKeyBuilder.build_function_key(
                        func.__name__, args, kwargs
                    )
                
                # Check for invalidation condition
                if invalidate_on and invalidate_on(*args, **kwargs):
                    await cache_manager.async_delete(cache_key)
                
                # Try to get from cache
                cached_result = await cache_manager.async_get(cache_key)
                if cached_result is not None:
                    logger.debug(f"Async cache hit for {func.__name__}: {cache_key}")
                    return cached_result
                
                # Call the function
                logger.debug(f"Async cache miss for {func.__name__}: {cache_key}")
                result = await func(*args, **kwargs)
                
                # Cache the result
                should_cache = True
                if hasattr(result, 'get') and isinstance(result, dict):
                    if result.get('error') and not cache_on_error:
                        should_cache = False
                
                if should_cache:
                    await cache_manager.async_set(cache_key, result, ttl)
                    logger.debug(f"Async cached result for {func.__name__}: {cache_key} (TTL: {ttl}s)")
                
                return result
                
            except Exception as e:
                logger.error(f"Async cache error in {func.__name__}: {e}")
                return await func(*args, **kwargs)
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

def cache_invalidate(pattern: str = None, service: str = None, 
                    resource: str = None, resource_type: str = 'auto') -> int:
    """
    Invalidate cache entries matching the given criteria.
    
    Args:
        pattern: Cache key pattern to match
        service: Service name to invalidate
        resource: Specific resource to invalidate
        resource_type: Type of resource
    
    Returns:
        Number of keys invalidated
    """
    cache_manager = get_cache_manager()
    
    if pattern:
        return cache_manager.clear_pattern(pattern)
    elif service and resource:
        cache_key = CacheKeyBuilder.build_key(service, resource, resource_type)
        return 1 if cache_manager.delete(cache_key) else 0
    elif service:
        return cache_manager.clear_pattern(f"*{service}*")
    else:
        logger.warning("No invalidation criteria provided")
        return 0

def get_cache_stats(service: str = None) -> Dict[str, Any]:
    """
    Get cache statistics for monitoring.
    
    Args:
        service: Specific service to get stats for
    
    Returns:
        Dictionary with cache statistics
    """
    cache_manager = get_cache_manager()
    redis_client = cache_manager.redis.connect()
    
    try:
        info = redis_client.info('memory')
        stats = {
            'memory_used': info.get('used_memory_human', 'Unknown'),
            'memory_peak': info.get('used_memory_peak_human', 'Unknown'),
            'keyspace_hits': redis_client.info('stats').get('keyspace_hits', 0),
            'keyspace_misses': redis_client.info('stats').get('keyspace_misses', 0),
        }
        
        # Calculate hit rate
        hits = stats['keyspace_hits']
        misses = stats['keyspace_misses']
        total = hits + misses
        stats['hit_rate'] = hits / total if total > 0 else 0.0
        
        if service:
            # Get service-specific key count
            pattern = f"{cache_manager.key_prefix}:*{service}*"
            keys = redis_client.keys(pattern)
            stats['service_keys'] = len(keys)
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return {'error': str(e)}

# Predefined decorators for common services
virustotal_cached = functools.partial(cached, service='virustotal', resource_type='auto')
abuseipdb_cached = functools.partial(cached, service='abuseipdb', resource_type='ip')
gemini_cached = functools.partial(cached, service='gemini', resource_type='auto')
screenshot_cached = functools.partial(cached, service='screenshot', resource_type='url')
redirect_cached = functools.partial(cached, service='redirect_analysis', resource_type='url')
reputation_cached = functools.partial(cached, service='reputation_check', resource_type='auto')

# Example usage:
"""
@virustotal_cached()
def check_url_virustotal(url: str) -> Dict[str, Any]:
    # VT API call here
    pass

@abuseipdb_cached()
async def check_ip_abuseipdb(ip: str) -> Dict[str, Any]:
    # AbuseIPDB API call here
    pass

@gemini_cached(ttl_seconds=30*60)  # Custom TTL
def analyze_with_gemini(content: str, prompt: str) -> Dict[str, Any]:
    # Gemini API call here
    pass
"""
