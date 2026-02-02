"""
Performance Optimization Utilities

Database query optimization, caching strategies, and performance monitoring.
"""

from typing import Optional, Any, Dict, List
from functools import wraps
import time
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


# ==================== Database Query Optimization ====================

# Projection for email list view (exclude large fields)
EMAIL_LIST_PROJECTION = {
    "message_id": 1,
    "thread_id": 1,
    "sender": 1,
    "subject": 1,
    "snippet": 1,
    "is_read": 1,
    "is_starred": 1,
    "has_attachment": 1,
    "threat_score": 1,
    "risk_level": 1,
    "received_at": 1,
    "labels": 1,
    "folder": 1,
    # Exclude body_text and body_html (large fields)
    "body_text": 0,
    "body_html": 0,
}

# Projection for email detail view (include all fields)
EMAIL_DETAIL_PROJECTION = None  # None means include all fields


def get_optimized_projection(include_body: bool = False) -> Optional[Dict]:
    """
    Get optimized projection based on use case.
    
    Args:
        include_body: Whether to include email body fields
    
    Returns:
        Projection dict or None for all fields
    """
    if include_body:
        return EMAIL_DETAIL_PROJECTION
    return EMAIL_LIST_PROJECTION


# ==================== Caching Strategies ====================

class CacheStrategy:
    """Cache TTL strategies for different data types."""
    
    # Email data
    EMAIL_LIST_TTL = 300  # 5 minutes
    EMAIL_DETAIL_TTL = 1800  # 30 minutes
    
    # Folder/Label data
    FOLDER_COUNTS_TTL = 60  # 1 minute
    LABELS_TTL = 3600  # 1 hour
    
    # Search results
    SEARCH_RESULTS_TTL = 600  # 10 minutes
    
    # User preferences
    USER_PREFERENCES_TTL = 86400  # 24 hours


def get_cache_key(prefix: str, *args) -> str:
    """
    Generate cache key from prefix and arguments.
    
    Args:
        prefix: Cache key prefix (e.g., 'email', 'folder')
        *args: Additional arguments to include in key
    
    Returns:
        Cache key string
    """
    parts = [prefix] + [str(arg) for arg in args]
    return ":".join(parts)


# ==================== Performance Monitoring ====================

def measure_time(func):
    """
    Decorator to measure function execution time.
    
    Usage:
        @measure_time
        async def slow_function():
            ...
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start = time.time()
        result = await func(*args, **kwargs)
        elapsed = time.time() - start
        
        # Log slow queries (> 100ms)
        if elapsed > 0.1:
            logger.warning(
                f"Slow operation: {func.__name__} took {elapsed:.3f}s",
                extra={"function": func.__name__, "duration": elapsed}
            )
        
        return result
    
    return wrapper


class PerformanceMonitor:
    """Monitor and log performance metrics."""
    
    def __init__(self):
        self.metrics: Dict[str, List[float]] = {}
    
    def record(self, operation: str, duration: float):
        """Record operation duration."""
        if operation not in self.metrics:
            self.metrics[operation] = []
        
        self.metrics[operation].append(duration)
        
        # Keep only last 100 measurements
        if len(self.metrics[operation]) > 100:
            self.metrics[operation] = self.metrics[operation][-100:]
    
    def get_stats(self, operation: str) -> Dict[str, float]:
        """Get statistics for operation."""
        if operation not in self.metrics or not self.metrics[operation]:
            return {}
        
        durations = self.metrics[operation]
        return {
            "count": len(durations),
            "avg": sum(durations) / len(durations),
            "min": min(durations),
            "max": max(durations),
            "p95": sorted(durations)[int(len(durations) * 0.95)],
        }


# Global performance monitor
perf_monitor = PerformanceMonitor()


# ==================== Batch Operations ====================

async def batch_fetch(
    fetch_func,
    ids: List[str],
    batch_size: int = 100
) -> List[Any]:
    """
    Fetch items in batches to avoid overwhelming database.
    
    Args:
        fetch_func: Async function to fetch items
        ids: List of IDs to fetch
        batch_size: Number of items per batch
    
    Returns:
        List of fetched items
    """
    results = []
    
    for i in range(0, len(ids), batch_size):
        batch_ids = ids[i:i + batch_size]
        batch_results = await fetch_func(batch_ids)
        results.extend(batch_results)
    
    return results


# ==================== Index Recommendations ====================

RECOMMENDED_INDEXES = [
    # Email indexes
    {
        "collection": "inbox_emails",
        "keys": [("user_id", 1), ("folder", 1), ("received_at", -1)],
        "name": "user_folder_received_idx",
    },
    {
        "collection": "inbox_emails",
        "keys": [("user_id", 1), ("is_read", 1)],
        "name": "user_read_idx",
    },
    {
        "collection": "inbox_emails",
        "keys": [("user_id", 1), ("is_starred", 1)],
        "name": "user_starred_idx",
    },
    {
        "collection": "inbox_emails",
        "keys": [("thread_id", 1), ("received_at", -1)],
        "name": "thread_received_idx",
    },
    {
        "collection": "inbox_emails",
        "keys": [("user_id", 1), ("labels", 1)],
        "name": "user_labels_idx",
    },
    
    # Label indexes
    {
        "collection": "email_labels",
        "keys": [("user_id", 1), ("name", 1)],
        "name": "user_label_name_idx",
        "unique": True,
    },
]


async def create_indexes(db):
    """
    Create recommended indexes for optimal performance.
    
    Args:
        db: MongoDB database instance
    """
    for index_spec in RECOMMENDED_INDEXES:
        collection = db[index_spec["collection"]]
        
        await collection.create_index(
            index_spec["keys"],
            name=index_spec["name"],
            unique=index_spec.get("unique", False),
        )
        
        logger.info(f"Created index: {index_spec['name']}")


# ==================== Query Optimization Tips ====================

"""
Performance Optimization Best Practices:

1. **Use Projections**:
   - Only fetch fields you need
   - Exclude large fields (body_text, body_html) for list views
   
2. **Proper Indexing**:
   - Index fields used in queries (user_id, folder, received_at)
   - Compound indexes for common query patterns
   
3. **Pagination**:
   - Use cursor-based pagination (not offset/limit)
   - Limit page size to 50-100 items
   
4. **Caching**:
   - Cache frequently accessed data (folder counts, labels)
   - Use appropriate TTL based on data volatility
   
5. **Batch Operations**:
   - Process multiple items in single query
   - Limit batch size to avoid timeouts
   
6. **Monitoring**:
   - Log slow queries (> 100ms)
   - Track p95 latency
   - Set up alerts for degradation

Example Optimized Query:
```python
# Bad: Fetches all fields, no index
emails = await InboxEmail.find({"user_id": user_id}).to_list()

# Good: Uses projection, leverages index
emails = await InboxEmail.find(
    {"user_id": user_id, "folder": "inbox"},
    projection=EMAIL_LIST_PROJECTION
).sort([("received_at", -1)]).limit(50).to_list()
```
"""
