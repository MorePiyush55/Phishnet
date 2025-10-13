"""
Enhanced caching utilities for playbook integration.

Extends the existing caching layer with:
- Playbook-specific cache keys
- Cache warming for common indicators
- Batch cache operations
- Cache analytics and monitoring
"""

import asyncio
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict

from app.config.logging import get_logger
from app.integrations.caching import ThreatIntelligenceCache, ResourceType
from app.integrations.threat_intel.base import ThreatIntelligence, ThreatLevel

logger = get_logger(__name__)


class PlaybookCacheExtension:
    """Extended caching functionality for playbook execution."""
    
    def __init__(self, base_cache: ThreatIntelligenceCache):
        """
        Initialize playbook cache extension.
        
        Args:
            base_cache: Base threat intelligence cache instance
        """
        self.cache = base_cache
        self.logger = logger
        
        # Cache warming configuration
        self.warm_cache_enabled = True
        self.warm_cache_indicators: Set[str] = set()
        
        # Statistics
        self.stats = {
            "batch_gets": 0,
            "batch_sets": 0,
            "warm_cache_hits": 0,
            "playbook_cache_hits": 0
        }
    
    async def batch_get(
        self,
        resources: List[str],
        resource_type: ResourceType,
        service: str
    ) -> Dict[str, Optional[Any]]:
        """
        Get multiple resources from cache in a single operation.
        
        Args:
            resources: List of resources to fetch
            resource_type: Type of resources
            service: Service name
        
        Returns:
            Dictionary mapping resource to cached data (None if not cached)
        """
        self.stats["batch_gets"] += 1
        
        results = {}
        tasks = []
        
        # Create tasks for all cache lookups
        for resource in resources:
            task = self.cache.get(resource, resource_type, service)
            tasks.append((resource, task))
        
        # Execute all lookups concurrently
        for resource, task in tasks:
            try:
                result = await task
                results[resource] = result
            except Exception as e:
                self.logger.error(f"Batch get failed for {resource}: {e}")
                results[resource] = None
        
        # Count hits
        hits = sum(1 for v in results.values() if v is not None)
        self.logger.debug(f"Batch get: {hits}/{len(resources)} hits for {service}")
        
        return results
    
    async def batch_set(
        self,
        items: List[tuple[str, ResourceType, str, ThreatIntelligence]],
        ttl: Optional[int] = None
    ) -> int:
        """
        Set multiple items in cache concurrently.
        
        Args:
            items: List of (resource, resource_type, service, data) tuples
            ttl: Optional TTL override
        
        Returns:
            Number of successfully cached items
        """
        self.stats["batch_sets"] += 1
        
        tasks = []
        for resource, resource_type, service, data in items:
            task = self.cache.set(resource, resource_type, service, data, ttl)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = sum(1 for r in results if r is True)
        
        self.logger.info(f"Batch set: {success_count}/{len(items)} items cached")
        return success_count
    
    async def warm_cache_for_playbook(
        self,
        playbook_name: str,
        common_indicators: Dict[ResourceType, List[str]],
        service: str
    ) -> int:
        """
        Pre-warm cache with common indicators for a playbook.
        
        Args:
            playbook_name: Name of playbook
            common_indicators: Dictionary of resource type to list of indicators
            service: Service name
        
        Returns:
            Number of indicators warmed
        """
        if not self.warm_cache_enabled:
            return 0
        
        self.logger.info(f"Warming cache for playbook: {playbook_name}")
        
        warmed_count = 0
        
        for resource_type, indicators in common_indicators.items():
            # Check which indicators are not cached
            uncached = []
            for indicator in indicators:
                cached = await self.cache.get(indicator, resource_type, service)
                if cached is None:
                    uncached.append(indicator)
                else:
                    self.stats["warm_cache_hits"] += 1
            
            if uncached:
                self.logger.info(
                    f"Warming {len(uncached)} {resource_type.value} indicators "
                    f"for {playbook_name}"
                )
                # Here you would fetch and cache uncached indicators
                # For now, just track the count
                warmed_count += len(uncached)
        
        return warmed_count
    
    async def get_playbook_cache_stats(
        self,
        playbook_name: str,
        time_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get cache statistics specific to a playbook.
        
        Args:
            playbook_name: Name of playbook
            time_window_hours: Time window for statistics
        
        Returns:
            Dictionary of cache statistics
        """
        # This would query Redis for playbook-specific cache stats
        # For now, return aggregated stats
        return {
            "playbook": playbook_name,
            "time_window_hours": time_window_hours,
            "cache_hits": self.stats["playbook_cache_hits"],
            "batch_operations": self.stats["batch_gets"] + self.stats["batch_sets"],
            "warm_cache_hits": self.stats["warm_cache_hits"]
        }
    
    async def invalidate_playbook_cache(
        self,
        playbook_name: str,
        resource_types: Optional[List[ResourceType]] = None
    ) -> int:
        """
        Invalidate cache entries related to a specific playbook.
        
        Args:
            playbook_name: Name of playbook
            resource_types: Optional list of resource types to invalidate
        
        Returns:
            Number of cache entries invalidated
        """
        pattern = f"*playbook:{playbook_name}*"
        
        try:
            invalidated = await self.cache.invalidate_pattern(pattern)
            self.logger.info(f"Invalidated {invalidated} cache entries for {playbook_name}")
            return invalidated
        except Exception as e:
            self.logger.error(f"Cache invalidation failed: {e}")
            return 0
    
    def register_warm_cache_indicator(
        self,
        indicator: str,
        resource_type: ResourceType
    ) -> None:
        """
        Register an indicator for cache warming.
        
        Args:
            indicator: The indicator to warm
            resource_type: Type of indicator
        """
        key = f"{resource_type.value}:{indicator}"
        self.warm_cache_indicators.add(key)
    
    async def execute_warm_cache_cycle(self, service: str) -> int:
        """
        Execute a cache warming cycle for all registered indicators.
        
        Args:
            service: Service to warm cache for
        
        Returns:
            Number of indicators warmed
        """
        self.logger.info(f"Starting cache warming cycle for {len(self.warm_cache_indicators)} indicators")
        
        warmed_count = 0
        
        for indicator_key in self.warm_cache_indicators:
            try:
                resource_type_str, indicator = indicator_key.split(":", 1)
                resource_type = ResourceType(resource_type_str)
                
                # Check if already cached
                cached = await self.cache.get(indicator, resource_type, service)
                if cached is None:
                    # Would fetch and cache here
                    warmed_count += 1
            except Exception as e:
                self.logger.error(f"Failed to warm cache for {indicator_key}: {e}")
        
        self.logger.info(f"Cache warming cycle complete: {warmed_count} indicators warmed")
        return warmed_count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache extension statistics."""
        return {
            **self.stats,
            "warm_cache_indicators": len(self.warm_cache_indicators),
            "warm_cache_enabled": self.warm_cache_enabled
        }


class CacheAnalytics:
    """Analytics and monitoring for cache performance."""
    
    def __init__(self, cache: ThreatIntelligenceCache):
        self.cache = cache
        self.logger = logger
        self.metrics = defaultdict(lambda: defaultdict(int))
    
    def record_hit(self, service: str, resource_type: ResourceType) -> None:
        """Record a cache hit."""
        self.metrics[service][f"{resource_type.value}_hits"] += 1
    
    def record_miss(self, service: str, resource_type: ResourceType) -> None:
        """Record a cache miss."""
        self.metrics[service][f"{resource_type.value}_misses"] += 1
    
    def get_hit_rate(self, service: str, resource_type: ResourceType) -> float:
        """Calculate cache hit rate for a service and resource type."""
        hits = self.metrics[service][f"{resource_type.value}_hits"]
        misses = self.metrics[service][f"{resource_type.value}_misses"]
        total = hits + misses
        
        if total == 0:
            return 0.0
        
        return hits / total
    
    def get_service_stats(self, service: str) -> Dict[str, Any]:
        """Get cache statistics for a specific service."""
        service_metrics = self.metrics[service]
        
        stats = {
            "service": service,
            "total_hits": sum(v for k, v in service_metrics.items() if k.endswith("_hits")),
            "total_misses": sum(v for k, v in service_metrics.items() if k.endswith("_misses")),
            "by_resource_type": {}
        }
        
        # Calculate per-resource-type stats
        for resource_type in ResourceType:
            hits = service_metrics[f"{resource_type.value}_hits"]
            misses = service_metrics[f"{resource_type.value}_misses"]
            total = hits + misses
            
            if total > 0:
                stats["by_resource_type"][resource_type.value] = {
                    "hits": hits,
                    "misses": misses,
                    "hit_rate": hits / total
                }
        
        return stats
    
    def get_overall_stats(self) -> Dict[str, Any]:
        """Get overall cache statistics across all services."""
        total_hits = 0
        total_misses = 0
        
        for service_metrics in self.metrics.values():
            total_hits += sum(v for k, v in service_metrics.items() if k.endswith("_hits"))
            total_misses += sum(v for k, v in service_metrics.items() if k.endswith("_misses"))
        
        total = total_hits + total_misses
        
        return {
            "total_hits": total_hits,
            "total_misses": total_misses,
            "total_requests": total,
            "overall_hit_rate": total_hits / total if total > 0 else 0.0,
            "services": list(self.metrics.keys())
        }
    
    def reset_metrics(self) -> None:
        """Reset all metrics."""
        self.metrics.clear()


class CacheOptimizer:
    """Optimizes cache usage based on access patterns."""
    
    def __init__(self, cache: ThreatIntelligenceCache, analytics: CacheAnalytics):
        self.cache = cache
        self.analytics = analytics
        self.logger = logger
    
    async def optimize_ttl(self, service: str, resource_type: ResourceType) -> int:
        """
        Optimize TTL based on access patterns.
        
        Args:
            service: Service name
            resource_type: Resource type
        
        Returns:
            Recommended TTL in seconds
        """
        hit_rate = self.analytics.get_hit_rate(service, resource_type)
        
        # High hit rate = longer TTL
        if hit_rate > 0.8:
            return 7200  # 2 hours
        elif hit_rate > 0.5:
            return 3600  # 1 hour
        elif hit_rate > 0.2:
            return 1800  # 30 minutes
        else:
            return 900   # 15 minutes
    
    async def identify_hot_indicators(
        self,
        service: str,
        limit: int = 100
    ) -> List[tuple[str, int]]:
        """
        Identify frequently accessed indicators for cache warming.
        
        Args:
            service: Service name
            limit: Maximum number to return
        
        Returns:
            List of (indicator, access_count) tuples
        """
        # This would query Redis for access counts
        # For now, return empty list
        return []
    
    async def suggest_cache_warming_targets(self) -> Dict[str, List[str]]:
        """
        Suggest indicators that should be warmed in cache.
        
        Returns:
            Dictionary mapping resource type to list of indicators
        """
        suggestions = defaultdict(list)
        
        # Analyze access patterns and suggest warming targets
        for service in self.analytics.metrics.keys():
            hot_indicators = await self.identify_hot_indicators(service)
            for indicator, count in hot_indicators[:20]:  # Top 20
                # Determine resource type (simplified)
                if "." in indicator:
                    suggestions["url"].append(indicator)
                elif ":" in indicator:
                    suggestions["ip"].append(indicator)
        
        return dict(suggestions)
