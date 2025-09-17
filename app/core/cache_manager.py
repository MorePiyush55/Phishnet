"""Compatibility shim providing CacheManager and CacheKey.

Many modules import `app.core.cache_manager.CacheManager` and `CacheKey`.
This file re-exports the implementations from `app.core.cache` to keep a
single canonical implementation.
"""

import json
from app.core.cache import PhishNetCache as _PhishNetCache, CacheKey as _OriginalCacheKey
from app.core.redis_client import get_redis_client, get_redis_connection


# Provide a thin subclass that will attempt to use an injected / patched
# redis client from this module. Tests frequently patch
# 'app.core.cache_manager.get_redis_client' and then instantiate
# CacheManager() directly, so ensuring the constructor consults the
# patched function guarantees the mock is used instead of attempting
# a real redis connection.
class CacheManager(_PhishNetCache):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            client = get_redis_client()
            if client is not None:
                # Best-effort inject the provided client
                self._redis = client
        except Exception:
            # Don't fail if injection isn't possible
            pass

    # Backwards-compatible API expected by older code/tests
    async def get(self, key: str):
        if self._redis is None:
            return None
        try:
            raw = self._redis.get(key)
            if raw is None:
                return None
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8')
            return json.loads(raw)
        except Exception:
            return None

    async def set(self, key: str, value, ttl: int | None = None):
        if self._redis is None:
            return False
        try:
            payload = json.dumps(value, default=str)
            if ttl:
                return bool(self._redis.set(key, payload, ex=ttl))
            else:
                return bool(self._redis.set(key, payload))
        except Exception:
            return False

    async def delete(self, key: str) -> bool:
        if self._redis is None:
            return False
        try:
            return bool(self._redis.delete(key))
        except Exception:
            return False

    async def delete_pattern(self, pattern: str) -> int:
        # Return number of deleted keys
        if self._redis is None:
            return 0
        try:
            keys = self._redis.keys(pattern)
            if not keys:
                return 0
            deleted = self._redis.delete(*keys)
            return int(deleted or 0)
        except Exception:
            return 0

    def generate_key(self, key_type, identifier: str) -> str:
        # Provide the small set of legacy key formats tests expect.
        try:
            name = getattr(key_type, 'name', None) or str(key_type)
            if name == 'URL_SCAN' or name == 'url_scan':
                return f"phishnet:url_scan:{identifier}"
            if name == 'THREAT_ANALYSIS' or name == 'threat_analysis':
                return f"phishnet:threat_analysis:{identifier}"
            if name == 'REDIRECT_ANALYSIS' or name == 'redirect_analysis':
                return f"phishnet:redirect_analysis:{identifier}"
            if name == 'USER_CONSENT' or name == 'user_consent':
                return f"phishnet:user_consent:{identifier}"
        except Exception:
            pass
        # Fallback to a generic namespaced key
        return f"phishnet:{str(key_type).lower()}:{identifier}"

_CACHE: CacheManager | None = None

def get_cache() -> CacheManager:
    """Return a singleton cache manager instance."""
    global _CACHE
    if _CACHE is None:
        _CACHE = CacheManager()
        # Allow tests or other callers to inject a redis client by
        # patching `app.core.cache_manager.get_redis_client`.
        try:
            client = get_redis_client()
            if client is not None:
                # Inject the provided client into the cache instance so
                # all cache operations use the mocked/stubbed client.
                try:
                    _CACHE._redis = client
                except Exception:
                    # Best-effort injection; don't raise during import/test setup
                    pass
        except Exception:
            # If getting a client fails, leave the cache to use its
            # normal connection behavior.
            pass
    return _CACHE

# Create a lightweight compatibility CacheKey that provides the symbols
# tests import (URL_SCAN, THREAT_ANALYSIS, REDIRECT_ANALYSIS, USER_CONSENT)
class CacheKey:
    URL_SCAN = 'url_scan'
    THREAT_ANALYSIS = 'threat_analysis'
    REDIRECT_ANALYSIS = 'redirect_analysis'
    USER_CONSENT = 'user_consent'

__all__ = ["CacheManager", "CacheKey", "get_cache"]

# Backwards-compatible redis accessors used in tests
def get_redis_client_proxy():
    return get_redis_client()

def get_redis_connection_proxy():
    return get_redis_connection()

__all__ += ["get_redis_client_proxy", "get_redis_connection_proxy", "get_redis_client", "get_redis_connection"]


# Backwards-compatible name used in tests
def get_cache_manager() -> CacheManager:
    return get_cache()

__all__.append("get_cache_manager")
