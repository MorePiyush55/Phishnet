"""
Batch Processor - Optimizes external API calls through batching and concurrency.

This module provides intelligent batching of API requests to external services
(VirusTotal, PhishTank, AbuseIPDB, etc.) to improve performance and reduce
API call overhead.

Key features:
- Batch similar requests together
- Rate limiting and throttling
- Concurrent execution with semaphores
- Automatic retry with exponential backoff
- Result caching integration
"""

import asyncio
from typing import List, Dict, Any, Optional, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import time

from app.config.logging import get_logger
from app.integrations.caching import ThreatIntelligenceCache, ResourceType

logger = get_logger(__name__)


@dataclass
class BatchRequest:
    """Individual request in a batch."""
    resource: str  # URL, IP, hash, domain
    resource_type: ResourceType
    service: str  # virustotal, phishtank, abuseipdb
    priority: int = 1  # Higher = more urgent
    callback: Optional[Callable] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BatchResult:
    """Result of a batch request."""
    resource: str
    resource_type: ResourceType
    service: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    cached: bool = False
    response_time_ms: float = 0.0


class RateLimiter:
    """Token bucket rate limiter for API calls."""
    
    def __init__(self, requests_per_second: float, burst_size: int):
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, waiting if necessary."""
        async with self.lock:
            while True:
                now = time.time()
                elapsed = now - self.last_update
                
                # Refill tokens
                self.tokens = min(
                    self.burst_size,
                    self.tokens + elapsed * self.requests_per_second
                )
                self.last_update = now
                
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                
                # Wait for tokens to refill
                wait_time = (tokens - self.tokens) / self.requests_per_second
                await asyncio.sleep(wait_time)


class BatchProcessor:
    """
    Intelligent batch processor for external API calls.
    
    Features:
    - Automatic batching of similar requests
    - Rate limiting per service
    - Concurrent execution with configurable limits
    - Cache-aware processing
    - Retry logic with exponential backoff
    """
    
    def __init__(
        self,
        cache: Optional[ThreatIntelligenceCache] = None,
        max_concurrent_requests: int = 10,
        batch_size: int = 25,
        batch_timeout_seconds: float = 2.0
    ):
        """
        Initialize batch processor.
        
        Args:
            cache: Cache instance for checking cached results
            max_concurrent_requests: Maximum concurrent API calls
            batch_size: Maximum items per batch
            batch_timeout_seconds: Max time to wait before processing partial batch
        """
        self.cache = cache
        self.max_concurrent_requests = max_concurrent_requests
        self.batch_size = batch_size
        self.batch_timeout_seconds = batch_timeout_seconds
        
        # Request queues by service
        self.pending_requests: Dict[str, List[BatchRequest]] = defaultdict(list)
        
        # Rate limiters by service
        self.rate_limiters: Dict[str, RateLimiter] = {
            "virustotal": RateLimiter(requests_per_second=4.0, burst_size=10),  # 4/sec API limit
            "phishtank": RateLimiter(requests_per_second=10.0, burst_size=20),
            "abuseipdb": RateLimiter(requests_per_second=5.0, burst_size=10),
            "gemini": RateLimiter(requests_per_second=2.0, burst_size=5),
            "default": RateLimiter(requests_per_second=10.0, burst_size=20)
        }
        
        # Semaphore for concurrent requests
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        
        # Statistics
        self.stats = {
            "total_requests": 0,
            "batched_requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "failed_requests": 0,
            "total_api_calls": 0,
            "batch_count": 0
        }
        
        self.logger = logger
    
    async def process_batch(
        self,
        requests: List[BatchRequest],
        executor: Callable
    ) -> List[BatchResult]:
        """
        Process a batch of requests.
        
        Args:
            requests: List of batch requests to process
            executor: Async function to execute requests (service-specific)
        
        Returns:
            List of batch results
        """
        if not requests:
            return []
        
        self.stats["total_requests"] += len(requests)
        self.stats["batch_count"] += 1
        
        # Deduplicate requests
        unique_requests = self._deduplicate_requests(requests)
        self.logger.info(
            f"Processing batch of {len(unique_requests)} unique requests "
            f"(deduplicated from {len(requests)})"
        )
        
        # Check cache first
        cached_results, uncached_requests = await self._check_cache(unique_requests)
        self.stats["cache_hits"] += len(cached_results)
        self.stats["cache_misses"] += len(uncached_requests)
        
        if not uncached_requests:
            self.logger.info(f"All {len(requests)} requests served from cache")
            return cached_results
        
        # Group by service for rate limiting
        grouped_requests = self._group_by_service(uncached_requests)
        
        # Process each service group concurrently
        api_results = []
        tasks = []
        
        for service, service_requests in grouped_requests.items():
            task = self._process_service_batch(service, service_requests, executor)
            tasks.append(task)
        
        # Wait for all service batches to complete
        service_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten results
        for result in service_results:
            if isinstance(result, list):
                api_results.extend(result)
            elif isinstance(result, Exception):
                self.logger.error(f"Service batch failed: {result}")
        
        # Combine cached and API results
        all_results = cached_results + api_results
        
        self.logger.info(
            f"Batch complete: {len(cached_results)} cached, "
            f"{len(api_results)} from API, {len(all_results)} total"
        )
        
        return all_results
    
    def _deduplicate_requests(self, requests: List[BatchRequest]) -> List[BatchRequest]:
        """Remove duplicate requests."""
        seen = set()
        unique = []
        
        for req in requests:
            key = (req.resource.lower(), req.resource_type, req.service)
            if key not in seen:
                seen.add(key)
                unique.append(req)
        
        return unique
    
    async def _check_cache(
        self,
        requests: List[BatchRequest]
    ) -> tuple[List[BatchResult], List[BatchRequest]]:
        """Check cache for existing results."""
        cached_results = []
        uncached_requests = []
        
        if not self.cache:
            return cached_results, requests
        
        for request in requests:
            try:
                cached_data = await self.cache.get(
                    request.resource,
                    request.resource_type,
                    request.service
                )
                
                if cached_data and cached_data.success:
                    cached_results.append(BatchResult(
                        resource=request.resource,
                        resource_type=request.resource_type,
                        service=request.service,
                        success=True,
                        data=cached_data.data.__dict__ if hasattr(cached_data.data, '__dict__') else cached_data.data,
                        cached=True,
                        response_time_ms=0.0
                    ))
                else:
                    uncached_requests.append(request)
            except Exception as e:
                self.logger.warning(f"Cache check failed for {request.resource}: {e}")
                uncached_requests.append(request)
        
        return cached_results, uncached_requests
    
    def _group_by_service(self, requests: List[BatchRequest]) -> Dict[str, List[BatchRequest]]:
        """Group requests by service."""
        grouped = defaultdict(list)
        for request in requests:
            grouped[request.service].append(request)
        return dict(grouped)
    
    async def _process_service_batch(
        self,
        service: str,
        requests: List[BatchRequest],
        executor: Callable
    ) -> List[BatchResult]:
        """Process a batch for a specific service with rate limiting."""
        results = []
        
        # Get rate limiter for this service
        rate_limiter = self.rate_limiters.get(service, self.rate_limiters["default"])
        
        # Split into sub-batches if needed
        for i in range(0, len(requests), self.batch_size):
            sub_batch = requests[i:i + self.batch_size]
            
            # Apply rate limiting
            await rate_limiter.acquire(len(sub_batch))
            
            # Process sub-batch concurrently
            sub_batch_results = await self._process_concurrent(sub_batch, executor)
            results.extend(sub_batch_results)
            
            self.stats["total_api_calls"] += 1
        
        return results
    
    async def _process_concurrent(
        self,
        requests: List[BatchRequest],
        executor: Callable
    ) -> List[BatchResult]:
        """Process requests concurrently with semaphore."""
        tasks = []
        
        for request in requests:
            task = self._process_single_request(request, executor)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Request failed: {result}")
                self.stats["failed_requests"] += 1
                processed_results.append(BatchResult(
                    resource=requests[i].resource,
                    resource_type=requests[i].resource_type,
                    service=requests[i].service,
                    success=False,
                    error=str(result)
                ))
            else:
                processed_results.append(result)
        
        return processed_results
    
    async def _process_single_request(
        self,
        request: BatchRequest,
        executor: Callable
    ) -> BatchResult:
        """Process a single request with retry logic."""
        async with self.semaphore:
            start_time = time.time()
            
            try:
                # Execute request
                result = await self._execute_with_retry(request, executor)
                
                response_time = (time.time() - start_time) * 1000
                
                # Cache successful results
                if result.success and self.cache:
                    try:
                        await self._cache_result(request, result)
                    except Exception as e:
                        self.logger.warning(f"Failed to cache result: {e}")
                
                result.response_time_ms = response_time
                return result
                
            except Exception as e:
                self.logger.error(f"Request execution failed: {e}")
                return BatchResult(
                    resource=request.resource,
                    resource_type=request.resource_type,
                    service=request.service,
                    success=False,
                    error=str(e),
                    response_time_ms=(time.time() - start_time) * 1000
                )
    
    async def _execute_with_retry(
        self,
        request: BatchRequest,
        executor: Callable,
        max_retries: int = 3
    ) -> BatchResult:
        """Execute request with exponential backoff retry."""
        last_error = None
        
        for attempt in range(max_retries):
            try:
                # Execute the actual API call
                result = await executor(request)
                return result
                
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 0.5  # Exponential backoff
                    self.logger.warning(
                        f"Request failed (attempt {attempt + 1}/{max_retries}), "
                        f"retrying in {wait_time}s: {e}"
                    )
                    await asyncio.sleep(wait_time)
        
        # All retries failed
        raise last_error
    
    async def _cache_result(self, request: BatchRequest, result: BatchResult) -> None:
        """Cache a successful result."""
        if not result.data:
            return
        
        try:
            # Convert result data to ThreatIntelligence format
            from app.integrations.threat_intel.base import ThreatIntelligence, ThreatLevel
            
            threat_intel = ThreatIntelligence(
                resource=request.resource,
                resource_type=request.resource_type,
                threat_level=ThreatLevel.UNKNOWN,
                confidence=0.5,
                last_seen=datetime.now(),
                tags=[],
                indicators=result.data
            )
            
            await self.cache.set(
                request.resource,
                request.resource_type,
                request.service,
                threat_intel
            )
        except Exception as e:
            self.logger.error(f"Cache set failed: {e}")
    
    async def process_urls(
        self,
        urls: List[str],
        service: str,
        executor: Callable
    ) -> List[BatchResult]:
        """Convenience method for processing URL batch."""
        requests = [
            BatchRequest(
                resource=url,
                resource_type=ResourceType.URL,
                service=service
            )
            for url in urls
        ]
        return await self.process_batch(requests, executor)
    
    async def process_ips(
        self,
        ips: List[str],
        service: str,
        executor: Callable
    ) -> List[BatchResult]:
        """Convenience method for processing IP batch."""
        requests = [
            BatchRequest(
                resource=ip,
                resource_type=ResourceType.IP,
                service=service
            )
            for ip in ips
        ]
        return await self.process_batch(requests, executor)
    
    async def process_hashes(
        self,
        hashes: List[str],
        service: str,
        executor: Callable
    ) -> List[BatchResult]:
        """Convenience method for processing file hash batch."""
        requests = [
            BatchRequest(
                resource=file_hash,
                resource_type=ResourceType.FILE_HASH,
                service=service
            )
            for file_hash in hashes
        ]
        return await self.process_batch(requests, executor)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get batch processing statistics."""
        total_requests = self.stats["total_requests"]
        if total_requests == 0:
            cache_hit_rate = 0.0
            failure_rate = 0.0
        else:
            cache_hit_rate = self.stats["cache_hits"] / total_requests
            failure_rate = self.stats["failed_requests"] / total_requests
        
        return {
            **self.stats,
            "cache_hit_rate": cache_hit_rate,
            "failure_rate": failure_rate,
            "avg_batch_size": (
                total_requests / max(self.stats["batch_count"], 1)
            )
        }
    
    def reset_stats(self) -> None:
        """Reset statistics counters."""
        self.stats = {
            "total_requests": 0,
            "batched_requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "failed_requests": 0,
            "total_api_calls": 0,
            "batch_count": 0
        }


# Example executor functions for different services
async def virustotal_executor(request: BatchRequest) -> BatchResult:
    """Example executor for VirusTotal API."""
    # This would call the actual VirusTotal API
    await asyncio.sleep(0.1)  # Simulate API call
    
    return BatchResult(
        resource=request.resource,
        resource_type=request.resource_type,
        service=request.service,
        success=True,
        data={"status": "analyzed", "score": 0.5}
    )


async def phishtank_executor(request: BatchRequest) -> BatchResult:
    """Example executor for PhishTank API."""
    await asyncio.sleep(0.1)  # Simulate API call
    
    return BatchResult(
        resource=request.resource,
        resource_type=request.resource_type,
        service=request.service,
        success=True,
        data={"in_database": True, "verified": True}
    )
