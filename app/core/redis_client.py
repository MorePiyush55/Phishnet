"""
Redis Client Configuration

Comprehensive Redis client for caching, queuing, and session management.
Supports connection pooling, async operations, and error handling.
"""

import redis
import redis.asyncio as aioredis
import logging
from typing import Optional, Any, Dict, Union
from contextlib import asynccontextmanager
import json
import pickle
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class RedisConfig:
    """Redis configuration settings"""
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    socket_timeout: int = 5
    socket_connect_timeout: int = 5
    retry_on_timeout: bool = True
    health_check_interval: int = 30
    max_connections: int = 50
    decode_responses: bool = True

class RedisClient:
    """
    Redis client wrapper with connection pooling, error handling, and reconnection logic.
    Supports both sync and async operations.
    """
    
    def __init__(self, config: Optional[RedisConfig] = None, host: str = "localhost", port: int = 6379, db: int = 0):
        # Support both new config and legacy parameters
        if config:
            self.config = config
        else:
            self.config = RedisConfig(host=host, port=port, db=db)
        
        self._client: Optional[redis.Redis] = None
        self._async_client: Optional[aioredis.Redis] = None
        self._connection_pool: Optional[redis.ConnectionPool] = None
        self._async_connection_pool: Optional[aioredis.ConnectionPool] = None
    
        """Get or create Redis connection with connection pooling."""
        if self._client is None:
            try:
                if not self._connection_pool:
                    self._connection_pool = redis.ConnectionPool(
                        host=self.config.host,
                        port=self.config.port,
                        db=self.config.db,
                        password=self.config.password,
                        socket_timeout=self.config.socket_timeout,
                        socket_connect_timeout=self.config.socket_connect_timeout,
                        retry_on_timeout=self.config.retry_on_timeout,
                        health_check_interval=self.config.health_check_interval,
                        max_connections=self.config.max_connections,
                        decode_responses=self.config.decode_responses
                    )
                
                self._client = redis.Redis(connection_pool=self._connection_pool)
                # Test connection
                self._client.ping()
                logger.info("Redis connection established")
            except redis.ConnectionError:
                logger.warning("Redis not available, using mock client")
                self._client = MockRedisClient()
        
        return self._client
    
    def _create_async_client(self) -> aioredis.Redis:
        """Create asynchronous Redis client with connection pooling"""
        if not self._async_connection_pool:
            self._async_connection_pool = aioredis.ConnectionPool(
                host=self.config.host,
                port=self.config.port,
                db=self.config.db,
                password=self.config.password,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.socket_connect_timeout,
                retry_on_timeout=self.config.retry_on_timeout,
                health_check_interval=self.config.health_check_interval,
                max_connections=self.config.max_connections,
                decode_responses=self.config.decode_responses
            )
        
        return aioredis.Redis(connection_pool=self._async_connection_pool)
    
    @property
    def async_client(self) -> aioredis.Redis:
        """Get asynchronous Redis client"""
        if not self._async_client:
            self._async_client = self._create_async_client()
        return self._async_client
    
    def ping(self) -> bool:
        """Test Redis connection"""
        try:
            return self.connect().ping()
        except Exception as e:
            logger.error(f"Redis ping failed: {e}")
            return False
    
    async def async_ping(self) -> bool:
        """Test async Redis connection"""
        try:
            return await self.async_client.ping()
        except Exception as e:
            logger.error(f"Async Redis ping failed: {e}")
            return False
    
    def close(self):
        """Close Redis connections"""
        if self._client:
            self._client.close()
        if self._connection_pool:
            self._connection_pool.disconnect()
    
    async def async_close(self):
        """Close async Redis connections"""
        if self._async_client:
            await self._async_client.close()
        if self._async_connection_pool:
            await self._async_connection_pool.disconnect()

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        """Set key with expiration."""
        try:
            client = self.connect()
            return bool(client.setex(key, ttl, value))
        except Exception as e:
            logger.error(f"Redis setex failed: {e}")
            return False
    
    async def get(self, key: str) -> Optional[str]:
        """Get value by key."""
        try:
            client = self.connect()
            return client.get(key)
        except Exception as e:
            logger.error(f"Redis get failed: {e}")
            return None


class CacheManager:
    """
    Redis-based cache manager with TTL support and serialization.
    Handles caching for API responses and computed results.
    """
    
    def __init__(self, redis_client: RedisClient, key_prefix: str = "phishnet:cache"):
        self.redis = redis_client
        self.key_prefix = key_prefix
    
    def _make_key(self, key: str) -> str:
        """Create prefixed cache key"""
        return f"{self.key_prefix}:{key}"
    
    def _serialize_value(self, value: Any) -> bytes:
        """Serialize value for Redis storage"""
        if isinstance(value, (dict, list)):
            return json.dumps(value, default=str).encode('utf-8')
        elif isinstance(value, (str, int, float, bool)):
            return json.dumps(value).encode('utf-8')
        else:
            return pickle.dumps(value)
    
    def _deserialize_value(self, data: bytes) -> Any:
        """Deserialize value from Redis"""
        try:
            # Try JSON first (more common)
            return json.loads(data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Fall back to pickle
            return pickle.loads(data)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            cache_key = self._make_key(key)
            data = self.redis.connect().get(cache_key)
            if data is None:
                return None
            return self._deserialize_value(data)
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            return None
    
    async def async_get(self, key: str) -> Optional[Any]:
        """Async get value from cache"""
        try:
            cache_key = self._make_key(key)
            data = await self.redis.async_client.get(cache_key)
            if data is None:
                return None
            return self._deserialize_value(data)
        except Exception as e:
            logger.error(f"Async cache get error for key {key}: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> bool:
        """Set value in cache with optional TTL"""
        try:
            cache_key = self._make_key(key)
            serialized_value = self._serialize_value(value)
            
            if ttl_seconds:
                return self.redis.connect().setex(cache_key, ttl_seconds, serialized_value)
            else:
                return self.redis.connect().set(cache_key, serialized_value)
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False
    
    async def async_set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> bool:
        """Async set value in cache with optional TTL"""
        try:
            cache_key = self._make_key(key)
            serialized_value = self._serialize_value(value)
            
            if ttl_seconds:
                return await self.redis.async_client.setex(cache_key, ttl_seconds, serialized_value)
            else:
                return await self.redis.async_client.set(cache_key, serialized_value)
        except Exception as e:
            logger.error(f"Async cache set error for key {key}: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        try:
            cache_key = self._make_key(key)
            return bool(self.redis.connect().delete(cache_key))
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            cache_key = self._make_key(key)
            return bool(self.redis.connect().exists(cache_key))
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False
    
    def get_ttl(self, key: str) -> int:
        """Get TTL for key (-1 if no expiry, -2 if key doesn't exist)"""
        try:
            cache_key = self._make_key(key)
            return self.redis.connect().ttl(cache_key)
        except Exception as e:
            logger.error(f"Cache TTL error for key {key}: {e}")
            return -2
    
    def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern"""
        try:
            pattern_key = self._make_key(pattern)
            keys = self.redis.connect().keys(pattern_key)
            if keys:
                return self.redis.connect().delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Cache clear pattern error for {pattern}: {e}")
            return 0


class QueueManager:
    """
    Redis-based queue manager for job processing.
    Supports priority queues, dead letter queues, and job status tracking.
    """
    
    def __init__(self, redis_client: RedisClient, queue_prefix: str = "phishnet:queue"):
        self.redis = redis_client
        self.queue_prefix = queue_prefix
    
    def _make_queue_key(self, queue_name: str) -> str:
        """Create prefixed queue key"""
        return f"{self.queue_prefix}:{queue_name}"
    
    def enqueue(self, queue_name: str, job_data: Dict[str, Any], priority: int = 0) -> bool:
        """Add job to queue with priority (lower number = higher priority)"""
        try:
            queue_key = self._make_queue_key(queue_name)
            job_json = json.dumps(job_data, default=str)
            
            # Use sorted set for priority queue (score = priority)
            return bool(self.redis.connect().zadd(queue_key, {job_json: priority}))
        except Exception as e:
            logger.error(f"Queue enqueue error for {queue_name}: {e}")
            return False
    
    async def async_enqueue(self, queue_name: str, job_data: Dict[str, Any], priority: int = 0) -> bool:
        """Async add job to queue with priority"""
        try:
            queue_key = self._make_queue_key(queue_name)
            job_json = json.dumps(job_data, default=str)
            
            return bool(await self.redis.async_client.zadd(queue_key, {job_json: priority}))
        except Exception as e:
            logger.error(f"Async queue enqueue error for {queue_name}: {e}")
            return False
    
    def dequeue(self, queue_name: str, timeout: int = 0) -> Optional[Dict[str, Any]]:
        """Remove and return highest priority job from queue"""
        try:
            queue_key = self._make_queue_key(queue_name)
            
            if timeout > 0:
                # Blocking pop with timeout
                result = self.redis.connect().bzpopmin(queue_key, timeout=timeout)
                if result:
                    _, job_json, _ = result
                    return json.loads(job_json)
            else:
                # Non-blocking pop
                result = self.redis.connect().zpopmin(queue_key, count=1)
                if result:
                    job_json, _ = result[0]
                    return json.loads(job_json)
            
            return None
        except Exception as e:
            logger.error(f"Queue dequeue error for {queue_name}: {e}")
            return None
    
    async def async_dequeue(self, queue_name: str, timeout: int = 0) -> Optional[Dict[str, Any]]:
        """Async remove and return highest priority job from queue"""
        try:
            queue_key = self._make_queue_key(queue_name)
            
            if timeout > 0:
                # Blocking pop with timeout
                result = await self.redis.async_client.bzpopmin(queue_key, timeout=timeout)
                if result:
                    _, job_json, _ = result
                    return json.loads(job_json)
            else:
                # Non-blocking pop
                result = await self.redis.async_client.zpopmin(queue_key, count=1)
                if result:
                    job_json, _ = result[0]
                    return json.loads(job_json)
            
            return None
        except Exception as e:
            logger.error(f"Async queue dequeue error for {queue_name}: {e}")
            return None
    
    def queue_length(self, queue_name: str) -> int:
        """Get number of jobs in queue"""
        try:
            queue_key = self._make_queue_key(queue_name)
            return self.redis.connect().zcard(queue_key)
        except Exception as e:
            logger.error(f"Queue length error for {queue_name}: {e}")
            return 0
    
    def clear_queue(self, queue_name: str) -> bool:
        """Clear all jobs from queue"""
        try:
            queue_key = self._make_queue_key(queue_name)
            return bool(self.redis.connect().delete(queue_key))
        except Exception as e:
            logger.error(f"Queue clear error for {queue_name}: {e}")
            return False


class MockRedisClient:
    """Mock Redis client for when Redis is not available."""
    
    def __init__(self):
        """Initialize mock client."""
        self._data = {}
    
    def ping(self):
        """Mock ping."""
        return True
    
    def setex(self, key: str, ttl: int, value: str) -> bool:
        """Mock setex."""
        self._data[key] = value
        return True
    
    def get(self, key: str) -> Optional[str]:
        """Mock get."""
        return self._data.get(key)


# Global Redis client instance
_redis_client: Optional[RedisClient] = None


def get_redis_client() -> RedisClient:
    """Get or create global Redis client."""
    global _redis_client
    if _redis_client is None:
        _redis_client = RedisClient()
    return _redis_client


class MockRedisClient:
    """Mock Redis client for testing environments"""
    
    def __init__(self):
        self._data = {}
    
    def get(self, key: str):
        """Mock get."""
        return self._data.get(key)
    
    def set(self, key: str, value: str) -> bool:
        """Mock set."""
        self._data[key] = value
        return True
    
    def delete(self, key: str) -> bool:
        """Mock delete."""
        if key in self._data:
            del self._data[key]
            return True
        return False
    
    def exists(self, key: str) -> bool:
        """Mock exists."""
        return key in self._data
    
    def ttl(self, key: str) -> int:
        """Mock TTL."""
        return -1 if key in self._data else -2
    
    def keys(self, pattern: str) -> list:
        """Mock keys."""
        return list(self._data.keys())
    
    def zadd(self, key: str, mapping: dict) -> int:
        """Mock zadd."""
        if key not in self._data:
            self._data[key] = []
        for item, score in mapping.items():
            self._data[key].append((item, score))
        return len(mapping)
    
    def zpopmin(self, key: str, count: int = 1) -> list:
        """Mock zpopmin."""
        if key not in self._data or not self._data[key]:
            return []
        
        # Sort by score and return lowest
        self._data[key].sort(key=lambda x: x[1])
        result = []
        for _ in range(min(count, len(self._data[key]))):
            if self._data[key]:
                item, score = self._data[key].pop(0)
                result.append((item, score))
        return result
    
    def bzpopmin(self, key: str, timeout: int = 0) -> Optional[tuple]:
        """Mock bzpopmin."""
        result = self.zpopmin(key, 1)
        if result:
            item, score = result[0]
            return (key, item, score)
        return None
    
    def zcard(self, key: str) -> int:
        """Mock zcard."""
        return len(self._data.get(key, []))


# Global instances
_redis_client = None
_cache_manager = None
_queue_manager = None

def get_redis_client() -> RedisClient:
    """Get global Redis client instance"""
    global _redis_client
    
    if _redis_client is None:
        _redis_client = RedisClient()
    
    return _redis_client

def get_cache_manager() -> CacheManager:
    """Get global cache manager instance"""
    global _cache_manager
    
    if _cache_manager is None:
        _cache_manager = CacheManager(get_redis_client())
    
    return _cache_manager

def get_queue_manager() -> QueueManager:
    """Get global queue manager instance"""
    global _queue_manager
    
    if _queue_manager is None:
        _queue_manager = QueueManager(get_redis_client())
    
    return _queue_manager

@asynccontextmanager
async def redis_lifespan():
    """Context manager for Redis connection lifecycle"""
    try:
        client = get_redis_client()
        # Test connections
        if not client.ping():
            raise ConnectionError("Failed to connect to Redis")
        
        logger.info("Redis connection established")
        yield client
        
    except Exception as e:
        logger.error(f"Redis connection error: {e}")
        raise
    finally:
        client.close()
        await client.async_close()
        logger.info("Redis connections closed")

# For compatibility with existing imports - lazy initialization
redis_client = None

def get_redis_connection():
    """Get Redis connection, initializing lazily"""
    global redis_client
    if redis_client is None:
        redis_client = get_redis_client().connect()
    return redis_client
