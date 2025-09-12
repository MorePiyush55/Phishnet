"""
Enhanced async Redis caching layer for PhishNet Postgres migration.
Integrates with the existing cache system while adding async support.
"""

import json
import logging
import pickle
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable, TypeVar
from functools import wraps
import hashlib

import aioredis
from aioredis import Redis
from pydantic import BaseModel

from app.config.settings import get_settings

logger = logging.getLogger(__name__)

T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])


class AsyncCacheKey:
    """Async cache key builder with namespacing."""
    
    PREFIX = "phishnet:async:"
    
    @staticmethod
    def build(*parts: Union[str, int]) -> str:
        """Build a cache key from parts."""
        return AsyncCacheKey.PREFIX + ":".join(str(part) for part in parts)
    
    @staticmethod
    def user(user_id: str) -> str:
        """User-specific cache key."""
        return AsyncCacheKey.build("user", user_id)
    
    @staticmethod
    def email_analysis(email_hash: str, source: str) -> str:
        """Email analysis cache key."""
        return AsyncCacheKey.build("analysis", source, email_hash)
    
    @staticmethod
    def threat_result(source: str, indicator: str) -> str:
        """Threat analysis result cache key."""
        indicator_hash = hashlib.md5(indicator.encode()).hexdigest()
        return AsyncCacheKey.build("threat", source, indicator_hash)
    
    @staticmethod
    def api_response(service: str, endpoint: str, params_hash: str) -> str:
        """API response cache key."""
        return AsyncCacheKey.build("api", service, endpoint, params_hash)
    
    @staticmethod
    def feature_flag(flag_name: str) -> str:
        """Feature flag cache key."""
        return AsyncCacheKey.build("feature", flag_name)
    
    @staticmethod
    def user_session(session_id: str) -> str:
        """User session cache key."""
        return AsyncCacheKey.build("session", session_id)


class AsyncCacheManager:
    """Enhanced async Redis cache manager for persistent infrastructure."""
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis: Optional[Redis] = None
        self.default_ttl = 3600  # 1 hour
        
        # Cache TTL configurations
        self.ttl_config = {
            'virustotal': 7200,      # 2 hours - VT results are stable
            'abuseipdb': 3600,       # 1 hour - IP reputation changes
            'gemini': 1800,          # 30 minutes - AI analysis may vary
            'email_analysis': 3600,   # 1 hour - Email analysis results
            'feature_flags': 300,     # 5 minutes - Feature flags can change quickly
            'user_session': 86400,    # 24 hours - User sessions
            'threat_intel': 7200,     # 2 hours - Threat intelligence
        }
        
    async def initialize(self) -> None:
        """Initialize Redis connection with optimal settings."""
        logger.info("Initializing async Redis cache connection")
        
        self.redis = await aioredis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=False,
            retry_on_timeout=True,
            socket_keepalive=True,
            socket_keepalive_options={
                1: 1,  # TCP_KEEPIDLE
                2: 3,  # TCP_KEEPINTVL  
                3: 5,  # TCP_KEEPCNT
            },
            health_check_interval=30,
            connection_pool=aioredis.ConnectionPool.from_url(
                self.redis_url,
                max_connections=20,
                retry_on_timeout=True,
            )
        )
        
        # Test connection and set Redis configuration
        await self.redis.ping()
        
        # Configure Redis for optimal caching
        try:
            await self.redis.config_set('maxmemory-policy', 'allkeys-lru')
            await self.redis.config_set('maxmemory', '512mb')
        except Exception as e:
            logger.warning(f"Could not set Redis config: {e}")
        
        logger.info("Async Redis cache connection established")
    
    async def close(self) -> None:
        """Close Redis connection."""
        if self.redis:
            await self.redis.close()
            logger.info("Async Redis connection closed")
    
    def _serialize(self, data: Any) -> bytes:
        """Serialize data for caching with compression support."""
        if isinstance(data, (str, int, float, bool, type(None))):
            return json.dumps(data).encode()
        elif isinstance(data, BaseModel):
            return data.model_dump_json().encode()
        elif isinstance(data, (dict, list)):
            return json.dumps(data, default=str).encode()
        else:
            # Use pickle for complex objects
            return pickle.dumps(data, protocol=pickle.HIGHEST_PROTOCOL)
    
    def _deserialize(self, data: bytes, data_type: type = None) -> Any:
        """Deserialize cached data with type support."""
        try:
            # Try JSON first (most common)
            text_data = data.decode()
            json_data = json.loads(text_data)
            
            # If we have a Pydantic model type, construct it
            if data_type and hasattr(data_type, 'model_validate'):
                return data_type.model_validate(json_data)
            
            return json_data
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Fallback to pickle
            return pickle.loads(data)
    
    def _get_ttl(self, cache_type: str, custom_ttl: Optional[int] = None) -> int:
        """Get TTL for cache type."""
        if custom_ttl:
            return custom_ttl
        return self.ttl_config.get(cache_type, self.default_ttl)
    
    async def set(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None,
        cache_type: str = "default",
        tags: Optional[List[str]] = None
    ) -> bool:
        """Set cache entry with smart TTL and tagging."""
        if not self.redis:
            logger.warning("Redis not available, skipping cache set")
            return False
        
        try:
            serialized_data = self._serialize(value)
            effective_ttl = self._get_ttl(cache_type, ttl)
            
            # Use pipeline for atomic operations
            pipe = self.redis.pipeline()
            
            # Set the main cache entry
            pipe.setex(key, effective_ttl, serialized_data)
            
            # Handle cache tags for invalidation
            if tags:
                for tag in tags:
                    tag_key = f"tag:{tag}"
                    pipe.sadd(tag_key, key)
                    pipe.expire(tag_key, effective_ttl + 300)  # Keep tags a bit longer
            
            # Add to cache metadata for monitoring
            metadata_key = f"meta:{key}"
            metadata = {
                'created_at': datetime.utcnow().isoformat(),
                'cache_type': cache_type,
                'ttl': effective_ttl,
                'size': len(serialized_data)
            }
            pipe.setex(metadata_key, effective_ttl, json.dumps(metadata))
            
            await pipe.execute()
            
            logger.debug(f"Cached {key} ({cache_type}) with TTL {effective_ttl}")
            return True
            
        except Exception as e:
            logger.error(f"Cache set failed for {key}: {e}")
            return False
    
    async def get(self, key: str, data_type: type = None) -> Optional[Any]:
        """Get cache entry with optional type casting."""
        if not self.redis:
            return None
        
        try:
            data = await self.redis.get(key)
            if data is None:
                logger.debug(f"Cache miss for {key}")
                return None
                
            result = self._deserialize(data, data_type)
            logger.debug(f"Cache hit for {key}")
            return result
            
        except Exception as e:
            logger.error(f"Cache get failed for {key}: {e}")
            return None
    
    async def get_or_set(
        self,
        key: str,
        factory: Callable[[], Any],
        ttl: Optional[int] = None,
        cache_type: str = "default"
    ) -> Any:
        """Get from cache or set using factory function."""
        cached = await self.get(key)
        if cached is not None:
            return cached
        
        # Generate value and cache it
        value = await factory() if asyncio.iscoroutinefunction(factory) else factory()
        await self.set(key, value, ttl, cache_type)
        return value
    
    async def delete(self, key: str) -> bool:
        """Delete cache entry and its metadata."""
        if not self.redis:
            return False
        
        try:
            pipe = self.redis.pipeline()
            pipe.delete(key)
            pipe.delete(f"meta:{key}")
            results = await pipe.execute()
            
            deleted = sum(results)
            if deleted > 0:
                logger.debug(f"Deleted cache key {key}")
            return bool(deleted)
        except Exception as e:
            logger.error(f"Cache delete failed for {key}: {e}")
            return False
    
    async def invalidate_by_tag(self, tag: str) -> int:
        """Invalidate all cache entries with a specific tag."""
        if not self.redis:
            return 0
        
        try:
            tag_key = f"tag:{tag}"
            keys = await self.redis.smembers(tag_key)
            
            if keys:
                # Delete all tagged keys and their metadata
                pipe = self.redis.pipeline()
                for key in keys:
                    pipe.delete(key.decode() if isinstance(key, bytes) else key)
                    pipe.delete(f"meta:{key.decode() if isinstance(key, bytes) else key}")
                pipe.delete(tag_key)
                
                results = await pipe.execute()
                deleted = sum(1 for r in results if r)
                
                logger.info(f"Invalidated {deleted} cache entries with tag '{tag}'")
                return deleted
            
            return 0
            
        except Exception as e:
            logger.error(f"Cache invalidation failed for tag {tag}: {e}")
            return 0
    
    async def exists(self, key: str) -> bool:
        """Check if cache key exists."""
        if not self.redis:
            return False
        
        try:
            return bool(await self.redis.exists(key))
        except Exception as e:
            logger.error(f"Cache exists check failed for {key}: {e}")
            return False
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        if not self.redis:
            return {}
        
        try:
            info = await self.redis.info()
            return {
                'used_memory': info.get('used_memory_human'),
                'connected_clients': info.get('connected_clients'),
                'total_commands_processed': info.get('total_commands_processed'),
                'keyspace_hits': info.get('keyspace_hits'),
                'keyspace_misses': info.get('keyspace_misses'),
                'hit_rate': (
                    info.get('keyspace_hits', 0) / 
                    max(info.get('keyspace_hits', 0) + info.get('keyspace_misses', 0), 1)
                ) * 100
            }
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {}


# Global async cache manager instance
async_cache_manager: Optional[AsyncCacheManager] = None


async def init_async_cache() -> AsyncCacheManager:
    """Initialize the global async cache manager."""
    global async_cache_manager
    
    settings = get_settings()
    async_cache_manager = AsyncCacheManager(settings.REDIS_URL)
    await async_cache_manager.initialize()
    
    return async_cache_manager


async def get_async_cache() -> AsyncCacheManager:
    """Get the global async cache manager instance."""
    if not async_cache_manager:
        raise RuntimeError("Async cache not initialized. Call init_async_cache() first.")
    return async_cache_manager


def cache_key_hash(*args, **kwargs) -> str:
    """Generate a hash for cache key from function arguments."""
    # Create a stable hash from arguments
    key_data = []
    for arg in args:
        if hasattr(arg, 'dict'):  # Pydantic model
            key_data.append(str(arg.dict()))
        else:
            key_data.append(str(arg))
    
    for k, v in sorted(kwargs.items()):
        if hasattr(v, 'dict'):
            key_data.append(f"{k}:{v.dict()}")
        else:
            key_data.append(f"{k}:{v}")
    
    combined = "|".join(key_data)
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def async_cached(
    ttl: Optional[int] = None,
    cache_type: str = "default",
    key_prefix: str = "",
    tags: Optional[List[str]] = None,
    skip_cache_on_error: bool = True
) -> Callable[[F], F]:
    """Decorator for caching async function results."""
    
    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            func_name = f"{func.__module__}.{func.__name__}"
            args_hash = cache_key_hash(*args, **kwargs)
            cache_key = AsyncCacheKey.build(key_prefix or func_name, args_hash)
            
            try:
                cache = await get_async_cache()
                
                # Try to get from cache first
                cached_result = await cache.get(cache_key)
                if cached_result is not None:
                    logger.debug(f"Async cache hit for {func_name}")
                    return cached_result
                
                # Cache miss - execute function
                logger.debug(f"Async cache miss for {func_name}, executing function")
                result = await func(*args, **kwargs)
                
                # Cache the result
                await cache.set(cache_key, result, ttl, cache_type, tags)
                return result
                
            except Exception as e:
                logger.error(f"Async cache decorator error for {func_name}: {e}")
                if skip_cache_on_error:
                    return await func(*args, **kwargs)
                else:
                    raise
        
        return wrapper
    return decorator


# Specialized async cache decorators
def cache_threat_analysis(ttl: Optional[int] = None):
    """Async cache decorator for threat analysis results."""
    return async_cached(
        ttl=ttl, 
        cache_type="threat_intel", 
        key_prefix="threat_analysis", 
        tags=["threat", "analysis"]
    )


def cache_api_response(service: str, ttl: Optional[int] = None):
    """Async cache decorator for external API responses."""
    return async_cached(
        ttl=ttl, 
        cache_type=service, 
        key_prefix=f"api_{service}", 
        tags=["api", service]
    )


def cache_email_analysis(ttl: Optional[int] = None):
    """Async cache decorator for email analysis results."""
    return async_cached(
        ttl=ttl, 
        cache_type="email_analysis", 
        key_prefix="email_analysis", 
        tags=["email", "analysis"]
    )


# Health check
async def check_async_cache_health() -> bool:
    """Check if async Redis cache is healthy."""
    try:
        cache = await get_async_cache()
        await cache.redis.ping()
        return True
    except Exception as e:
        logger.error(f"Async cache health check failed: {e}")
        return False


# Cleanup function
async def cleanup_async_cache():
    """Cleanup async cache connections on application shutdown."""
    global async_cache_manager
    if async_cache_manager:
        await async_cache_manager.close()
        async_cache_manager = None
        logger.info("Async cache cleanup completed")
