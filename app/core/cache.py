"""
Cache Strategy - VT/AbuseIPDB and link chains cached with TTL
Revalidate on demand for threat intelligence and analysis results
"""

import json
import logging
import hashlib
import time
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import redis
import asyncio
from functools import wraps
import pickle

logger = logging.getLogger(__name__)

class CacheStrategy(Enum):
    TTL = "ttl"  # Time-to-live
    LRU = "lru"  # Least recently used
    LFU = "lfu"  # Least frequently used
    WRITE_THROUGH = "write_through"
    WRITE_BACK = "write_back"

@dataclass
class CacheConfig:
    """Cache configuration"""
    redis_url: str = "redis://localhost:6379/0"
    default_ttl: int = 3600  # 1 hour
    threat_intel_ttl: int = 7200  # 2 hours
    link_analysis_ttl: int = 1800  # 30 minutes
    email_analysis_ttl: int = 600  # 10 minutes
    max_memory: str = "256mb"
    eviction_policy: str = "allkeys-lru"
    enable_compression: bool = True
    key_prefix: str = "phishnet:"

class CacheKey:
    """Cache key generators"""
    
    @staticmethod
    def threat_intel(source: str, indicator: str) -> str:
        """Generate cache key for threat intelligence"""
        hash_input = f"{source}:{indicator}".encode()
        hash_hex = hashlib.md5(hash_input).hexdigest()
        return f"phishnet:threat_intel:{source}:{hash_hex}"
    
    @staticmethod
    def link_analysis(url: str) -> str:
        """Generate cache key for link analysis"""
        hash_input = url.encode()
        hash_hex = hashlib.sha256(hash_input).hexdigest()
        return f"phishnet:link_analysis:{hash_hex}"
    
    @staticmethod
    def email_analysis(email_id: int) -> str:
        """Generate cache key for email analysis"""
        return f"phishnet:email_analysis:{email_id}"
    
    @staticmethod
    def user_session(user_id: str) -> str:
        """Generate cache key for user session"""
        return f"phishnet:session:{user_id}"
    
    @staticmethod
    def api_response(endpoint: str, params: str) -> str:
        """Generate cache key for API response"""
        hash_input = f"{endpoint}:{params}".encode()
        hash_hex = hashlib.md5(hash_input).hexdigest()
        return f"phishnet:api:{hash_hex}"

class PhishNetCache:
    """
    Advanced caching system for PhishNet
    
    Features:
    - Redis-based distributed caching
    - TTL-based expiration
    - Compression for large values
    - Cache warming and preloading
    - Hit/miss statistics
    - Cache invalidation patterns
    - Async/await support
    """
    
    def __init__(self, config: Optional[CacheConfig] = None):
        self.config = config or CacheConfig()
        self._redis: Optional[redis.Redis] = None
        self._stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0
        }
        self._connect()
    
    def _connect(self):
        """Connect to Redis"""
        try:
            self._redis = redis.from_url(
                self.config.redis_url,
                decode_responses=False,  # We handle encoding ourselves
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            
            # Test connection
            self._redis.ping()
            
            # Configure memory policy
            self._redis.config_set('maxmemory', self.config.max_memory)
            self._redis.config_set('maxmemory-policy', self.config.eviction_policy)
            
            logger.info(f"Connected to Redis: {self.config.redis_url}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._redis = None
    
    def _serialize(self, value: Any) -> bytes:
        """Serialize value for storage"""
        try:
            if self.config.enable_compression:
                import gzip
                serialized = pickle.dumps(value)
                return gzip.compress(serialized)
            else:
                return pickle.dumps(value)
        except Exception as e:
            logger.error(f"Serialization failed: {e}")
            raise
    
    def _deserialize(self, data: bytes) -> Any:
        """Deserialize value from storage"""
        try:
            if self.config.enable_compression:
                import gzip
                decompressed = gzip.decompress(data)
                return pickle.loads(decompressed)
            else:
                return pickle.loads(data)
        except Exception as e:
            logger.error(f"Deserialization failed: {e}")
            raise
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self._redis:
            return None
        
        try:
            data = self._redis.get(key)
            if data is None:
                self._stats["misses"] += 1
                return None
            
            value = self._deserialize(data)
            self._stats["hits"] += 1
            
            logger.debug(f"Cache hit: {key}")
            return value
            
        except Exception as e:
            logger.error(f"Cache get failed for key {key}: {e}")
            self._stats["misses"] += 1
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        if not self._redis:
            return False
        
        try:
            data = self._serialize(value)
            expire_time = ttl or self.config.default_ttl
            
            result = self._redis.setex(key, expire_time, data)
            self._stats["sets"] += 1
            
            logger.debug(f"Cache set: {key} (TTL: {expire_time}s)")
            return bool(result)
            
        except Exception as e:
            logger.error(f"Cache set failed for key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        if not self._redis:
            return False
        
        try:
            result = self._redis.delete(key)
            self._stats["deletes"] += 1
            
            logger.debug(f"Cache delete: {key}")
            return bool(result)
            
        except Exception as e:
            logger.error(f"Cache delete failed for key {key}: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        if not self._redis:
            return False
        
        try:
            return bool(self._redis.exists(key))
        except Exception as e:
            logger.error(f"Cache exists check failed for key {key}: {e}")
            return False
    
    async def ttl(self, key: str) -> int:
        """Get TTL for key"""
        if not self._redis:
            return -1
        
        try:
            return self._redis.ttl(key)
        except Exception as e:
            logger.error(f"Cache TTL check failed for key {key}: {e}")
            return -1
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching pattern"""
        if not self._redis:
            return 0
        
        try:
            keys = self._redis.keys(pattern)
            if keys:
                deleted = self._redis.delete(*keys)
                self._stats["deletes"] += deleted
                logger.info(f"Invalidated {deleted} keys matching pattern: {pattern}")
                return deleted
            return 0
            
        except Exception as e:
            logger.error(f"Cache pattern invalidation failed for {pattern}: {e}")
            return 0
    
    # Specialized cache methods for PhishNet
    
    async def cache_threat_intel(self, source: str, indicator: str, data: Dict[str, Any]) -> bool:
        """Cache threat intelligence data"""
        key = CacheKey.threat_intel(source, indicator)
        return await self.set(key, data, self.config.threat_intel_ttl)
    
    async def get_threat_intel(self, source: str, indicator: str) -> Optional[Dict[str, Any]]:
        """Get cached threat intelligence data"""
        key = CacheKey.threat_intel(source, indicator)
        return await self.get(key)
    
    async def cache_link_analysis(self, url: str, analysis: Dict[str, Any]) -> bool:
        """Cache link analysis results"""
        key = CacheKey.link_analysis(url)
        return await self.set(key, analysis, self.config.link_analysis_ttl)
    
    async def get_link_analysis(self, url: str) -> Optional[Dict[str, Any]]:
        """Get cached link analysis results"""
        key = CacheKey.link_analysis(url)
        return await self.get(key)
    
    async def cache_email_analysis(self, email_id: int, analysis: Dict[str, Any]) -> bool:
        """Cache email analysis results"""
        key = CacheKey.email_analysis(email_id)
        return await self.set(key, analysis, self.config.email_analysis_ttl)
    
    async def get_email_analysis(self, email_id: int) -> Optional[Dict[str, Any]]:
        """Get cached email analysis results"""
        key = CacheKey.email_analysis(email_id)
        return await self.get(key)
    
    async def invalidate_email_cache(self, email_id: int) -> bool:
        """Invalidate all cache entries for an email"""
        pattern = f"phishnet:*email*{email_id}*"
        deleted = await self.invalidate_pattern(pattern)
        return deleted > 0
    
    async def warm_cache(self, warm_funcs: List[Callable]) -> Dict[str, bool]:
        """Warm cache with common data"""
        results = {}
        
        for func in warm_funcs:
            try:
                await func()
                results[func.__name__] = True
                logger.info(f"Cache warmed successfully: {func.__name__}")
            except Exception as e:
                results[func.__name__] = False
                logger.error(f"Cache warming failed for {func.__name__}: {e}")
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_operations = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / total_operations * 100) if total_operations > 0 else 0
        
        stats = {
            **self._stats,
            "hit_rate": f"{hit_rate:.2f}%",
            "total_operations": total_operations,
            "connected": self._redis is not None
        }
        
        if self._redis:
            try:
                info = self._redis.info()
                stats.update({
                    "redis_memory_used": info.get("used_memory_human", "Unknown"),
                    "redis_connected_clients": info.get("connected_clients", 0),
                    "redis_total_commands": info.get("total_commands_processed", 0)
                })
            except Exception:
                pass
        
        return stats
    
    async def health_check(self) -> Dict[str, Any]:
        """Check cache health"""
        health = {
            "status": "unhealthy",
            "connected": False,
            "latency_ms": None,
            "memory_usage": None
        }
        
        if not self._redis:
            return health
        
        try:
            # Test latency
            start_time = time.time()
            self._redis.ping()
            latency = (time.time() - start_time) * 1000
            
            # Get memory info
            info = self._redis.info()
            
            health.update({
                "status": "healthy",
                "connected": True,
                "latency_ms": round(latency, 2),
                "memory_usage": info.get("used_memory_human", "Unknown"),
                "uptime_seconds": info.get("uptime_in_seconds", 0)
            })
            
        except Exception as e:
            health["error"] = str(e)
        
        return health

# Cache decorators
def cached(ttl: Optional[int] = None, key_func: Optional[Callable] = None):
    """
    Decorator to cache function results
    
    Args:
        ttl: Time to live in seconds
        key_func: Function to generate cache key
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            cache = get_cache()
            
            # Generate cache key
            if key_func:
                key = key_func(*args, **kwargs)
            else:
                # Default key generation
                args_str = "_".join(str(arg) for arg in args)
                kwargs_str = "_".join(f"{k}={v}" for k, v in kwargs.items())
                key = f"phishnet:func:{func.__name__}:{args_str}:{kwargs_str}"
            
            # Try to get from cache
            cached_result = await cache.get(key)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            result = await func(*args, **kwargs)
            await cache.set(key, result, ttl)
            
            return result
        return wrapper
    return decorator

def cache_threat_intel(source: str, ttl: Optional[int] = None):
    """Decorator specifically for threat intelligence caching"""
    def decorator(func):
        @wraps(func)
        async def wrapper(indicator: str, *args, **kwargs):
            cache = get_cache()
            
            # Check cache first
            cached_data = await cache.get_threat_intel(source, indicator)
            if cached_data is not None:
                return cached_data
            
            # Get fresh data
            result = await func(indicator, *args, **kwargs)
            
            # Cache the result
            if result:
                await cache.cache_threat_intel(source, indicator, result)
            
            return result
        return wrapper
    return decorator

# Cache warming functions
async def warm_common_threat_intel(cache: PhishNetCache):
    """Warm cache with common threat indicators"""
    common_indicators = [
        "google.com",  # Known safe domain
        "phishing.example.com",  # Test phishing domain
        "malware.example.net"  # Test malware domain
    ]
    
    for indicator in common_indicators:
        # This would normally call actual threat intel APIs
        fake_data = {
            "indicator": indicator,
            "reputation": "unknown",
            "last_analyzed": datetime.utcnow().isoformat(),
            "sources": ["cache_warm"]
        }
        await cache.cache_threat_intel("virustotal", indicator, fake_data)

async def warm_link_analysis_cache(cache: PhishNetCache):
    """Warm cache with common link analysis"""
    common_urls = [
        "https://google.com",
        "https://github.com",
        "https://stackoverflow.com"
    ]
    
    for url in common_urls:
        fake_analysis = {
            "url": url,
            "final_url": url,
            "redirect_chain": [url],
            "risk_score": 0.1,
            "analyzed_at": datetime.utcnow().isoformat()
        }
        await cache.cache_link_analysis(url, fake_analysis)

# Global cache instance
_cache_instance = None

def get_cache() -> PhishNetCache:
    """Get global cache instance"""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = PhishNetCache()
    return _cache_instance

# Example usage functions
@cached(ttl=3600, key_func=lambda url: f"url_analysis:{hashlib.md5(url.encode()).hexdigest()}")
async def analyze_url_cached(url: str) -> Dict[str, Any]:
    """Example cached URL analysis function"""
    # Simulate expensive analysis
    await asyncio.sleep(1)
    
    return {
        "url": url,
        "risk_score": 0.3,
        "analyzed_at": datetime.utcnow().isoformat(),
        "threats_found": 0
    }

@cache_threat_intel("virustotal", ttl=7200)
async def get_virustotal_data(domain: str) -> Dict[str, Any]:
    """Example cached VirusTotal lookup"""
    # Simulate API call
    await asyncio.sleep(0.5)
    
    return {
        "domain": domain,
        "reputation": "clean",
        "scans": {"positives": 0, "total": 67},
        "last_scanned": datetime.utcnow().isoformat()
    }

# CLI functions
async def test_cache_performance():
    """Test cache performance"""
    cache = get_cache()
    
    print("Testing cache performance...")
    
    # Test set/get performance
    start_time = time.time()
    for i in range(1000):
        await cache.set(f"test_key_{i}", {"data": f"value_{i}"}, 60)
    set_time = time.time() - start_time
    
    start_time = time.time()
    for i in range(1000):
        await cache.get(f"test_key_{i}")
    get_time = time.time() - start_time
    
    print(f"Set 1000 keys: {set_time:.3f}s ({1000/set_time:.0f} ops/sec)")
    print(f"Get 1000 keys: {get_time:.3f}s ({1000/get_time:.0f} ops/sec)")
    
    # Clean up
    await cache.invalidate_pattern("test_key_*")
    
    # Show stats
    stats = cache.get_stats()
    print(f"Cache stats: {stats}")

async def demonstrate_caching():
    """Demonstrate caching functionality"""
    cache = get_cache()
    
    print("PhishNet Cache Demonstration")
    print("=" * 40)
    
    # Cache threat intel
    print("\n1. Caching threat intelligence...")
    await cache.cache_threat_intel("virustotal", "example.com", {
        "reputation": "clean",
        "last_scan": datetime.utcnow().isoformat()
    })
    
    # Retrieve threat intel
    data = await cache.get_threat_intel("virustotal", "example.com")
    print(f"Retrieved: {data}")
    
    # Cache link analysis
    print("\n2. Caching link analysis...")
    await cache.cache_link_analysis("https://example.com", {
        "risk_score": 0.1,
        "final_url": "https://example.com"
    })
    
    # Test cached function
    print("\n3. Testing cached function...")
    result1 = await analyze_url_cached("https://test.com")
    result2 = await analyze_url_cached("https://test.com")  # Should be cached
    print(f"First call: {result1['analyzed_at']}")
    print(f"Second call: {result2['analyzed_at']}")
    print(f"Results match: {result1 == result2}")
    
    # Show statistics
    print("\n4. Cache statistics:")
    stats = cache.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Health check
    print("\n5. Health check:")
    health = await cache.health_check()
    for key, value in health.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    asyncio.run(demonstrate_caching())
