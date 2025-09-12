import { useState, useCallback, useRef, useEffect } from 'react';

export interface CacheConfig {
  maxSize: number; // Maximum number of items
  maxMemory: number; // Maximum memory in bytes
  ttl: number; // Time to live in milliseconds
  gcInterval: number; // Garbage collection interval in milliseconds
}

export interface CacheItem<T> {
  data: T;
  timestamp: number;
  size: number;
  accessCount: number;
  lastAccessed: number;
}

export interface CacheStats {
  itemCount: number;
  memoryUsed: number;
  hitRate: number;
  totalHits: number;
  totalMisses: number;
}

const DEFAULT_CONFIG: CacheConfig = {
  maxSize: 500,
  maxMemory: 100 * 1024 * 1024, // 100MB
  ttl: 5 * 60 * 1000, // 5 minutes
  gcInterval: 60 * 1000, // 1 minute
};

class ClientCache<T = any> {
  private cache = new Map<string, CacheItem<T>>();
  private config: CacheConfig;
  private stats = {
    totalHits: 0,
    totalMisses: 0,
    memoryUsed: 0,
  };
  private gcTimer: NodeJS.Timeout | null = null;

  constructor(config: Partial<CacheConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.startGarbageCollection();
  }

  private calculateSize(data: T): number {
    try {
      return JSON.stringify(data).length * 2; // Rough estimate (Unicode = 2 bytes per char)
    } catch {
      return 1024; // Default size if calculation fails
    }
  }

  private startGarbageCollection() {
    if (this.gcTimer) {
      clearInterval(this.gcTimer);
    }
    
    this.gcTimer = setInterval(() => {
      this.cleanup();
    }, this.config.gcInterval);
  }

  private cleanup() {
    const now = Date.now();
    const expiredKeys: string[] = [];
    
    // Find expired items
    for (const [key, item] of this.cache.entries()) {
      if (now - item.timestamp > this.config.ttl) {
        expiredKeys.push(key);
      }
    }
    
    // Remove expired items
    expiredKeys.forEach(key => this.delete(key));
    
    // If still over limits, remove least recently used items
    this.evictIfNeeded();
  }

  private evictIfNeeded() {
    // Check size limit
    while (this.cache.size > this.config.maxSize) {
      this.evictLRU();
    }
    
    // Check memory limit
    while (this.stats.memoryUsed > this.config.maxMemory) {
      this.evictLRU();
    }
  }

  private evictLRU() {
    let oldestKey: string | null = null;
    let oldestTime = Date.now();
    
    for (const [key, item] of this.cache.entries()) {
      if (item.lastAccessed < oldestTime) {
        oldestTime = item.lastAccessed;
        oldestKey = key;
      }
    }
    
    if (oldestKey) {
      this.delete(oldestKey);
    }
  }

  set(key: string, data: T): void {
    const size = this.calculateSize(data);
    const now = Date.now();
    
    // Remove existing item if it exists
    if (this.cache.has(key)) {
      this.delete(key);
    }
    
    const item: CacheItem<T> = {
      data,
      timestamp: now,
      size,
      accessCount: 0,
      lastAccessed: now,
    };
    
    this.cache.set(key, item);
    this.stats.memoryUsed += size;
    
    // Evict if needed
    this.evictIfNeeded();
  }

  get(key: string): T | null {
    const item = this.cache.get(key);
    
    if (!item) {
      this.stats.totalMisses++;
      return null;
    }
    
    const now = Date.now();
    
    // Check if expired
    if (now - item.timestamp > this.config.ttl) {
      this.delete(key);
      this.stats.totalMisses++;
      return null;
    }
    
    // Update access statistics
    item.accessCount++;
    item.lastAccessed = now;
    this.stats.totalHits++;
    
    return item.data;
  }

  has(key: string): boolean {
    const item = this.cache.get(key);
    if (!item) return false;
    
    const now = Date.now();
    if (now - item.timestamp > this.config.ttl) {
      this.delete(key);
      return false;
    }
    
    return true;
  }

  delete(key: string): boolean {
    const item = this.cache.get(key);
    if (item) {
      this.stats.memoryUsed -= item.size;
      return this.cache.delete(key);
    }
    return false;
  }

  clear(): void {
    this.cache.clear();
    this.stats.memoryUsed = 0;
    this.stats.totalHits = 0;
    this.stats.totalMisses = 0;
  }

  getStats(): CacheStats {
    const total = this.stats.totalHits + this.stats.totalMisses;
    return {
      itemCount: this.cache.size,
      memoryUsed: this.stats.memoryUsed,
      hitRate: total > 0 ? this.stats.totalHits / total : 0,
      totalHits: this.stats.totalHits,
      totalMisses: this.stats.totalMisses,
    };
  }

  getKeys(): string[] {
    return Array.from(this.cache.keys());
  }

  destroy(): void {
    if (this.gcTimer) {
      clearInterval(this.gcTimer);
      this.gcTimer = null;
    }
    this.clear();
  }
}

// Global cache instances for different data types
const emailCache = new ClientCache({
  maxSize: 200,
  maxMemory: 50 * 1024 * 1024, // 50MB
  ttl: 10 * 60 * 1000, // 10 minutes
});

const emailBodyCache = new ClientCache({
  maxSize: 50,
  maxMemory: 30 * 1024 * 1024, // 30MB
  ttl: 5 * 60 * 1000, // 5 minutes
});

const auditCache = new ClientCache({
  maxSize: 100,
  maxMemory: 10 * 1024 * 1024, // 10MB
  ttl: 2 * 60 * 1000, // 2 minutes
});

const redirectChainCache = new ClientCache({
  maxSize: 100,
  maxMemory: 20 * 1024 * 1024, // 20MB
  ttl: 15 * 60 * 1000, // 15 minutes
});

// Hook for using client-side cache
export const useClientCache = <T = any>(cacheKey: string, cacheInstance?: ClientCache<T>) => {
  const cache = cacheInstance || new ClientCache<T>();
  const [, forceUpdate] = useState({});

  const set = useCallback((key: string, data: T) => {
    cache.set(key, data);
    forceUpdate({});
  }, [cache]);

  const get = useCallback((key: string): T | null => {
    return cache.get(key);
  }, [cache]);

  const has = useCallback((key: string): boolean => {
    return cache.has(key);
  }, [cache]);

  const remove = useCallback((key: string): boolean => {
    const result = cache.delete(key);
    forceUpdate({});
    return result;
  }, [cache]);

  const clear = useCallback(() => {
    cache.clear();
    forceUpdate({});
  }, [cache]);

  const getStats = useCallback((): CacheStats => {
    return cache.getStats();
  }, [cache]);

  return {
    set,
    get,
    has,
    remove,
    clear,
    getStats,
  };
};

// Hook for caching API responses with automatic key generation
export const useApiCache = <T = any>(
  baseKey: string,
  cacheInstance?: ClientCache<T>
) => {
  const cache = useClientCache(baseKey, cacheInstance);

  const cacheApiResponse = useCallback(async <R = T>(
    key: string,
    apiCall: () => Promise<R>,
    ttlOverride?: number
  ): Promise<R> => {
    const cached = cache.get(key);
    if (cached) {
      return cached as R;
    }

    try {
      const response = await apiCall();
      cache.set(key, response as any);
      return response;
    } catch (error) {
      throw error;
    }
  }, [cache]);

  const invalidatePattern = useCallback((pattern: string) => {
    const stats = cache.getStats();
    // Since we can't easily iterate over keys in our cache,
    // we'll need to implement this if needed
    console.warn('Pattern invalidation not implemented yet');
  }, [cache]);

  return {
    ...cache,
    cacheApiResponse,
    invalidatePattern,
  };
};

// Specialized hooks for different data types
export const useEmailCache = () => useClientCache('emails', emailCache);
export const useEmailBodyCache = () => useClientCache('emailBodies', emailBodyCache);
export const useAuditCache = () => useClientCache('audits', auditCache);
export const useRedirectChainCache = () => useClientCache('redirectChains', redirectChainCache);

// Hook for preloading data
export const usePreloader = <T = any>(cacheInstance: ClientCache<T>) => {
  const preload = useCallback(async <R = T>(
    key: string,
    dataLoader: () => Promise<R>
  ): Promise<void> => {
    if (cacheInstance.has(key)) {
      return; // Already cached
    }

    try {
      const data = await dataLoader();
      cacheInstance.set(key, data as any);
    } catch (error) {
      console.error(`Failed to preload data for key ${key}:`, error);
    }
  }, [cacheInstance]);

  const preloadMultiple = useCallback(async <R = T>(
    items: Array<{ key: string; loader: () => Promise<R> }>
  ): Promise<void> => {
    const promises = items
      .filter(item => !cacheInstance.has(item.key))
      .map(item => preload(item.key, item.loader));

    await Promise.allSettled(promises);
  }, [cacheInstance, preload]);

  return {
    preload,
    preloadMultiple,
  };
};

// Cache management utilities
export const getCacheStats = () => ({
  emails: emailCache.getStats(),
  emailBodies: emailBodyCache.getStats(),
  audits: auditCache.getStats(),
  redirectChains: redirectChainCache.getStats(),
});

export const clearAllCaches = () => {
  emailCache.clear();
  emailBodyCache.clear();
  auditCache.clear();
  redirectChainCache.clear();
};

export const destroyAllCaches = () => {
  emailCache.destroy();
  emailBodyCache.destroy();
  auditCache.destroy();
  redirectChainCache.destroy();
};

// Performance monitoring hook
export const useCachePerformance = () => {
  const [performanceData, setPerformanceData] = useState(getCacheStats());

  useEffect(() => {
    const interval = setInterval(() => {
      setPerformanceData(getCacheStats());
    }, 5000); // Update every 5 seconds

    return () => clearInterval(interval);
  }, []);

  const getTotalStats = useCallback(() => {
    const stats = getCacheStats();
    return {
      totalItems: Object.values(stats).reduce((sum, stat) => sum + stat.itemCount, 0),
      totalMemory: Object.values(stats).reduce((sum, stat) => sum + stat.memoryUsed, 0),
      averageHitRate: Object.values(stats).reduce((sum, stat) => sum + stat.hitRate, 0) / Object.keys(stats).length,
      totalHits: Object.values(stats).reduce((sum, stat) => sum + stat.totalHits, 0),
      totalMisses: Object.values(stats).reduce((sum, stat) => sum + stat.totalMisses, 0),
    };
  }, []);

  return {
    performanceData,
    getTotalStats,
    clearAllCaches,
    destroyAllCaches,
  };
};

export default ClientCache;
