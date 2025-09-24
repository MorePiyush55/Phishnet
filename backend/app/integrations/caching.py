"""
Redis-based caching layer for third-party API results.

This module provides intelligent caching of threat intelligence data with TTL management,
cache invalidation, and performance optimization for external API calls.
"""

import asyncio
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
import logging

import redis.asyncio as redis
from redis.exceptions import ConnectionError, TimeoutError as RedisTimeoutError

from .threat_intel.base import (
    ThreatIntelligence, APIResponse, APIStatus, ResourceType, ThreatLevel
)

logger = logging.getLogger(__name__)


class CacheConfig:
    """Configuration for Redis caching behavior."""
    
    def __init__(self):
        # TTL settings (in seconds)
        self.ttl_by_threat_level = {
            ThreatLevel.CRITICAL: 3600,      # 1 hour - check frequently
            ThreatLevel.HIGH: 7200,          # 2 hours
            ThreatLevel.MEDIUM: 14400,       # 4 hours  
            ThreatLevel.LOW: 43200,          # 12 hours
            ThreatLevel.SAFE: 86400,         # 24 hours - safe resources stay cached longer
            ThreatLevel.UNKNOWN: 1800        # 30 minutes - recheck unknown quickly
        }
        
        # Service-specific TTL overrides
        self.service_ttl = {
            "virustotal": 14400,    # 4 hours default
            "abuseipdb": 7200,      # 2 hours default
            "gemini": 3600          # 1 hour default (content can change frequently)
        }
        
        # Cache key prefixes
        self.key_prefix = "phishnet:threat_intel"
        self.stats_prefix = "phishnet:cache_stats"
        self.invalidation_prefix = "phishnet:cache_invalidation"
        
        # Performance settings
        self.max_key_length = 250
        self.compression_threshold = 1024  # Compress responses larger than 1KB
        self.batch_size = 100             # Batch operations for performance


class ThreatIntelligenceCache:
    """Redis-based cache for threat intelligence data."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", config: Optional[CacheConfig] = None):
        self.redis_url = redis_url
        self.config = config or CacheConfig()
        self.redis_client: Optional[redis.Redis] = None
        self.logger = logging.getLogger(f"{__name__}.cache")
        
        # Cache statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "errors": 0
        }
    
    async def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection."""
        if self.redis_client is None:
            self.redis_client = redis.from_url(
                self.redis_url,
                encoding='utf-8',
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                max_connections=20
            )
            
            # Test connection
            try:
                await self.redis_client.ping()
                self.logger.info("Redis connection established")
            except Exception as e:
                self.logger.error(f"Redis connection failed: {str(e)}")
                raise
        
        return self.redis_client
    
    def _generate_cache_key(self, resource: str, resource_type: ResourceType, service: str) -> str:
        """Generate deterministic cache key for resource."""
        # Normalize resource for consistent caching
        normalized_resource = self._normalize_resource(resource, resource_type)
        
        # Create hash for long resources
        resource_hash = hashlib.sha256(normalized_resource.encode()).hexdigest()[:16]
        
        # Build key
        key = f"{self.config.key_prefix}:{service}:{resource_type.value}:{resource_hash}"
        
        # Ensure key length limit
        if len(key) > self.config.max_key_length:
            key = f"{self.config.key_prefix}:{hashlib.sha256(key.encode()).hexdigest()}"
        
        return key
    
    def _normalize_resource(self, resource: str, resource_type: ResourceType) -> str:
        """Normalize resource for consistent caching."""
        if resource_type == ResourceType.URL:
            # Normalize URLs
            from .threat_intel.base import normalize_url
            return normalize_url(resource)
        elif resource_type == ResourceType.DOMAIN:
            return resource.lower().strip()
        elif resource_type == ResourceType.IP_ADDRESS:
            return resource.strip()
        elif resource_type == ResourceType.FILE_HASH:
            return resource.lower().strip()
        else:
            return resource.strip()
    
    def _calculate_ttl(self, threat_intel: ThreatIntelligence, service: str) -> int:
        """Calculate TTL based on threat level and service."""
        # Start with threat-level based TTL
        base_ttl = self.config.ttl_by_threat_level.get(
            threat_intel.threat_level, 
            self.config.service_ttl.get(service, 3600)
        )
        
        # Adjust based on confidence
        confidence_multiplier = 0.5 + (threat_intel.confidence * 0.5)  # 0.5 to 1.0
        adjusted_ttl = int(base_ttl * confidence_multiplier)
        
        # Ensure minimum TTL
        return max(300, adjusted_ttl)  # Minimum 5 minutes
    
    def _serialize_data(self, data: Union[ThreatIntelligence, APIResponse]) -> str:
        """Serialize data for cache storage."""
        if isinstance(data, ThreatIntelligence):
            # Convert dataclass to dict
            from dataclasses import asdict
            serializable_data = asdict(data)
            
            # Handle datetime serialization
            if serializable_data.get('first_seen'):
                serializable_data['first_seen'] = data.first_seen.isoformat()
            if serializable_data.get('last_seen'):
                serializable_data['last_seen'] = data.last_seen.isoformat()
            
            # Convert enums to values
            serializable_data['threat_level'] = data.threat_level.value
            serializable_data['resource_type'] = data.resource_type.value
            
        elif isinstance(data, APIResponse):
            from dataclasses import asdict
            serializable_data = asdict(data)
            serializable_data['status'] = data.status.value
            
            if data.data:
                serializable_data['data'] = asdict(data.data)
                if serializable_data['data'].get('first_seen'):
                    serializable_data['data']['first_seen'] = data.data.first_seen.isoformat()
                if serializable_data['data'].get('last_seen'):
                    serializable_data['data']['last_seen'] = data.data.last_seen.isoformat()
                serializable_data['data']['threat_level'] = data.data.threat_level.value
                serializable_data['data']['resource_type'] = data.data.resource_type.value
        else:
            serializable_data = data
        
        # Add cache metadata
        cache_data = {
            "data": serializable_data,
            "cached_at": datetime.utcnow().isoformat(),
            "cache_version": "1.0"
        }
        
        return json.dumps(cache_data, separators=(',', ':'))  # Compact JSON
    
    def _deserialize_data(self, cached_data: str) -> Optional[Union[ThreatIntelligence, APIResponse]]:
        """Deserialize data from cache."""
        try:
            cache_obj = json.loads(cached_data)
            data = cache_obj.get("data")
            
            if not data:
                return None
            
            # Reconstruct datetime objects
            if data.get('first_seen'):
                data['first_seen'] = datetime.fromisoformat(data['first_seen'])
            if data.get('last_seen'):
                data['last_seen'] = datetime.fromisoformat(data['last_seen'])
            
            # Reconstruct enums
            if 'threat_level' in data:
                data['threat_level'] = ThreatLevel(data['threat_level'])
            if 'resource_type' in data:
                data['resource_type'] = ResourceType(data['resource_type'])
            
            # Check if this is ThreatIntelligence or APIResponse
            if 'success' in data:  # APIResponse
                if data.get('data'):
                    # Handle nested ThreatIntelligence in APIResponse
                    nested_data = data['data']
                    if nested_data.get('first_seen'):
                        nested_data['first_seen'] = datetime.fromisoformat(nested_data['first_seen'])
                    if nested_data.get('last_seen'):
                        nested_data['last_seen'] = datetime.fromisoformat(nested_data['last_seen'])
                    nested_data['threat_level'] = ThreatLevel(nested_data['threat_level'])
                    nested_data['resource_type'] = ResourceType(nested_data['resource_type'])
                    data['data'] = ThreatIntelligence(**nested_data)
                
                data['status'] = APIStatus(data['status'])
                return APIResponse(**data)
            else:  # ThreatIntelligence
                return ThreatIntelligence(**data)
                
        except Exception as e:
            self.logger.error(f"Failed to deserialize cached data: {str(e)}")
            return None
    
    async def get(self, resource: str, resource_type: ResourceType, service: str) -> Optional[APIResponse]:
        """Get cached threat intelligence data."""
        try:
            redis_client = await self._get_redis()
            cache_key = self._generate_cache_key(resource, resource_type, service)
            
            cached_data = await redis_client.get(cache_key)
            
            if cached_data:
                self.stats["hits"] += 1
                deserialized = self._deserialize_data(cached_data)
                
                if isinstance(deserialized, APIResponse):
                    # Mark as cached
                    deserialized.cached = True
                    deserialized.status = APIStatus.CACHED
                    self.logger.debug(f"Cache HIT for {service}:{resource_type.value}:{resource[:50]}")
                    return deserialized
                elif isinstance(deserialized, ThreatIntelligence):
                    # Wrap in APIResponse
                    response = APIResponse(
                        success=True,
                        status=APIStatus.CACHED,
                        data=deserialized,
                        cached=True
                    )
                    return response
            
            self.stats["misses"] += 1
            self.logger.debug(f"Cache MISS for {service}:{resource_type.value}:{resource[:50]}")
            return None
            
        except (ConnectionError, RedisTimeoutError) as e:
            self.stats["errors"] += 1
            self.logger.warning(f"Redis connection error during get: {str(e)}")
            return None
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Unexpected error during cache get: {str(e)}")
            return None
    
    async def set(self, resource: str, resource_type: ResourceType, service: str, 
                  data: Union[ThreatIntelligence, APIResponse], ttl: Optional[int] = None) -> bool:
        """Cache threat intelligence data."""
        try:
            redis_client = await self._get_redis()
            cache_key = self._generate_cache_key(resource, resource_type, service)
            
            # Calculate TTL
            if ttl is None:
                if isinstance(data, APIResponse) and data.data:
                    ttl = self._calculate_ttl(data.data, service)
                elif isinstance(data, ThreatIntelligence):
                    ttl = self._calculate_ttl(data, service)
                else:
                    ttl = self.config.service_ttl.get(service, 3600)
            
            # Serialize data
            serialized_data = self._serialize_data(data)
            
            # Store in Redis with TTL
            await redis_client.setex(cache_key, ttl, serialized_data)
            
            self.stats["sets"] += 1
            self.logger.debug(f"Cached {service}:{resource_type.value}:{resource[:50]} for {ttl}s")
            
            # Update cache statistics
            await self._update_cache_stats(service, resource_type)
            
            return True
            
        except (ConnectionError, RedisTimeoutError) as e:
            self.stats["errors"] += 1
            self.logger.warning(f"Redis connection error during set: {str(e)}")
            return False
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Unexpected error during cache set: {str(e)}")
            return False
    
    async def delete(self, resource: str, resource_type: ResourceType, service: str) -> bool:
        """Delete cached data for a resource."""
        try:
            redis_client = await self._get_redis()
            cache_key = self._generate_cache_key(resource, resource_type, service)
            
            result = await redis_client.delete(cache_key)
            
            if result > 0:
                self.stats["deletes"] += 1
                self.logger.debug(f"Deleted cache for {service}:{resource_type.value}:{resource[:50]}")
                return True
            
            return False
            
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Error deleting cache entry: {str(e)}")
            return False
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all cache entries matching a pattern."""
        try:
            redis_client = await self._get_redis()
            
            # Find matching keys
            keys = await redis_client.keys(f"{self.config.key_prefix}:{pattern}")
            
            if keys:
                deleted = await redis_client.delete(*keys)
                self.logger.info(f"Invalidated {deleted} cache entries matching pattern: {pattern}")
                return deleted
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Error invalidating cache pattern {pattern}: {str(e)}")
            return 0
    
    async def _update_cache_stats(self, service: str, resource_type: ResourceType):
        """Update cache statistics in Redis."""
        try:
            redis_client = await self._get_redis()
            stats_key = f"{self.config.stats_prefix}:{service}:{resource_type.value}"
            
            # Increment counters
            await redis_client.hincrby(stats_key, "total_cached", 1)
            await redis_client.hset(stats_key, "last_cached", datetime.utcnow().isoformat())
            
            # Set expiry for stats (keep for 7 days)
            await redis_client.expire(stats_key, 604800)
            
        except Exception as e:
            self.logger.warning(f"Failed to update cache stats: {str(e)}")
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        try:
            redis_client = await self._get_redis()
            
            # Get Redis info
            redis_info = await redis_client.info("memory")
            
            # Get service-specific stats
            service_stats = {}
            stats_keys = await redis_client.keys(f"{self.config.stats_prefix}:*")
            
            for key in stats_keys:
                stats_data = await redis_client.hgetall(key)
                service_name = key.split(":")[-2]
                resource_type = key.split(":")[-1]
                
                if service_name not in service_stats:
                    service_stats[service_name] = {}
                
                service_stats[service_name][resource_type] = {
                    "total_cached": int(stats_data.get("total_cached", 0)),
                    "last_cached": stats_data.get("last_cached")
                }
            
            return {
                "local_stats": self.stats,
                "service_stats": service_stats,
                "redis_memory_usage": redis_info.get("used_memory_human"),
                "redis_connected_clients": redis_info.get("connected_clients"),
                "cache_hit_rate": (
                    self.stats["hits"] / (self.stats["hits"] + self.stats["misses"]) * 100
                    if (self.stats["hits"] + self.stats["misses"]) > 0 else 0
                )
            }
            
        except Exception as e:
            self.logger.error(f"Error getting cache stats: {str(e)}")
            return {"error": str(e), "local_stats": self.stats}
    
    async def health_check(self) -> Dict[str, Any]:
        """Check cache health and connectivity."""
        try:
            redis_client = await self._get_redis()
            
            # Test basic operations
            start_time = time.time()
            await redis_client.ping()
            ping_time = (time.time() - start_time) * 1000  # ms
            
            # Test set/get
            test_key = f"{self.config.key_prefix}:health_check"
            test_value = str(time.time())
            
            await redis_client.setex(test_key, 60, test_value)
            retrieved_value = await redis_client.get(test_key)
            await redis_client.delete(test_key)
            
            operations_working = (retrieved_value == test_value)
            
            return {
                "status": "healthy" if operations_working else "degraded",
                "ping_time_ms": round(ping_time, 2),
                "operations_working": operations_working,
                "connection_pool_size": len(redis_client.connection_pool._available_connections),
                "redis_url": self.redis_url
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "redis_url": self.redis_url
            }
    
    async def close(self):
        """Close Redis connection."""
        if self.redis_client:
            await self.redis_client.aclose()
            self.redis_client = None
            self.logger.info("Redis connection closed")


# Example usage and testing
async def test_cache():
    """Test cache functionality."""
    cache = ThreatIntelligenceCache()
    
    # Test data
    test_threat_intel = ThreatIntelligence(
        resource="https://example.com",
        resource_type=ResourceType.URL,
        threat_level=ThreatLevel.HIGH,
        confidence=0.9,
        source="test",
        detected_threats=["test_threat"],
        categories=["test_category"]
    )
    
    # Test set
    success = await cache.set(
        "https://example.com", 
        ResourceType.URL, 
        "virustotal", 
        test_threat_intel
    )
    print(f"Cache set: {success}")
    
    # Test get
    cached_result = await cache.get(
        "https://example.com",
        ResourceType.URL,
        "virustotal"
    )
    print(f"Cache get: {cached_result is not None}")
    print(f"Cached data: {cached_result.data.threat_level if cached_result and cached_result.data else 'None'}")
    
    # Test stats
    stats = await cache.get_cache_stats()
    print(f"Cache stats: {stats}")
    
    # Test health
    health = await cache.health_check()
    print(f"Cache health: {health}")
    
    await cache.close()


if __name__ == "__main__":
    asyncio.run(test_cache())