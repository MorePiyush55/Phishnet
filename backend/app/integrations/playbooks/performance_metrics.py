"""
Performance Metrics and Monitoring for Playbook Integration.

Tracks and reports on:
- Playbook execution times
- Batch processing efficiency
- Cache hit rates and performance
- Overall throughput improvements
- Resource utilization
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import time

from app.config.logging import get_logger

logger = get_logger(__name__)


@dataclass
class PlaybookMetrics:
    """Metrics for playbook execution."""
    playbook_name: str
    execution_count: int = 0
    total_execution_time_ms: float = 0.0
    avg_execution_time_ms: float = 0.0
    min_execution_time_ms: float = float('inf')
    max_execution_time_ms: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    success_rate: float = 0.0
    findings_generated: int = 0
    actions_executed: int = 0


@dataclass
class BatchProcessingMetrics:
    """Metrics for batch processing operations."""
    total_batches: int = 0
    total_requests: int = 0
    avg_batch_size: float = 0.0
    total_api_calls: int = 0
    api_call_savings_pct: float = 0.0  # % saved through batching
    total_processing_time_ms: float = 0.0
    avg_processing_time_per_request_ms: float = 0.0
    concurrent_efficiency: float = 0.0  # Ratio of parallel to sequential time


@dataclass
class CachePerformanceMetrics:
    """Metrics for cache performance."""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    hit_rate: float = 0.0
    avg_hit_time_ms: float = 0.0
    avg_miss_time_ms: float = 0.0
    total_time_saved_ms: float = 0.0  # Time saved by cache hits
    memory_usage_mb: float = 0.0
    eviction_count: int = 0
    warm_cache_hits: int = 0


@dataclass
class ThroughputMetrics:
    """Overall throughput and performance metrics."""
    emails_analyzed: int = 0
    total_analysis_time_ms: float = 0.0
    avg_analysis_time_ms: float = 0.0
    emails_per_second: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0


class PerformanceMonitor:
    """
    Centralized performance monitoring for playbook integration.
    
    Collects and aggregates metrics from:
    - Playbook engine
    - Batch processor
    - Cache extensions
    - Orchestrator
    """
    
    def __init__(self):
        self.logger = logger
        self.start_time = time.time()
        
        # Metrics storage
        self.playbook_metrics: Dict[str, PlaybookMetrics] = {}
        self.batch_metrics = BatchProcessingMetrics()
        self.cache_metrics = CachePerformanceMetrics()
        self.throughput_metrics = ThroughputMetrics()
        
        # Time-series data for latency percentiles
        self.latency_samples: List[float] = []
        self.max_samples = 10000  # Keep last 10k samples
        
        # Resource usage tracking
        self.resource_metrics = {
            "cpu_usage_pct": 0.0,
            "memory_usage_mb": 0.0,
            "active_connections": 0
        }
    
    def record_playbook_execution(
        self,
        playbook_name: str,
        execution_time_ms: float,
        success: bool,
        findings_count: int,
        actions_count: int
    ) -> None:
        """Record a playbook execution."""
        if playbook_name not in self.playbook_metrics:
            self.playbook_metrics[playbook_name] = PlaybookMetrics(playbook_name=playbook_name)
        
        metrics = self.playbook_metrics[playbook_name]
        metrics.execution_count += 1
        metrics.total_execution_time_ms += execution_time_ms
        metrics.findings_generated += findings_count
        metrics.actions_executed += actions_count
        
        if success:
            metrics.success_count += 1
        else:
            metrics.failure_count += 1
        
        # Update min/max
        metrics.min_execution_time_ms = min(metrics.min_execution_time_ms, execution_time_ms)
        metrics.max_execution_time_ms = max(metrics.max_execution_time_ms, execution_time_ms)
        
        # Calculate running averages
        metrics.avg_execution_time_ms = metrics.total_execution_time_ms / metrics.execution_count
        metrics.success_rate = metrics.success_count / metrics.execution_count
    
    def record_batch_operation(
        self,
        batch_size: int,
        api_calls_made: int,
        processing_time_ms: float
    ) -> None:
        """Record a batch processing operation."""
        self.batch_metrics.total_batches += 1
        self.batch_metrics.total_requests += batch_size
        self.batch_metrics.total_api_calls += api_calls_made
        self.batch_metrics.total_processing_time_ms += processing_time_ms
        
        # Calculate averages
        self.batch_metrics.avg_batch_size = (
            self.batch_metrics.total_requests / self.batch_metrics.total_batches
        )
        self.batch_metrics.avg_processing_time_per_request_ms = (
            self.batch_metrics.total_processing_time_ms / max(self.batch_metrics.total_requests, 1)
        )
        
        # Calculate API call savings (assumes 1 call per request without batching)
        self.batch_metrics.api_call_savings_pct = (
            (1 - api_calls_made / max(batch_size, 1)) * 100
        )
    
    def record_cache_access(
        self,
        hit: bool,
        access_time_ms: float,
        warm_cache: bool = False
    ) -> None:
        """Record a cache access."""
        self.cache_metrics.total_requests += 1
        
        if hit:
            self.cache_metrics.cache_hits += 1
            self.cache_metrics.avg_hit_time_ms = (
                (self.cache_metrics.avg_hit_time_ms * (self.cache_metrics.cache_hits - 1) + access_time_ms) /
                self.cache_metrics.cache_hits
            )
            
            if warm_cache:
                self.cache_metrics.warm_cache_hits += 1
            
            # Estimate time saved (assume API call would take 100-500ms)
            estimated_api_time = 300.0  # ms
            self.cache_metrics.total_time_saved_ms += (estimated_api_time - access_time_ms)
        else:
            self.cache_metrics.cache_misses += 1
            self.cache_metrics.avg_miss_time_ms = (
                (self.cache_metrics.avg_miss_time_ms * (self.cache_metrics.cache_misses - 1) + access_time_ms) /
                self.cache_metrics.cache_misses
            )
        
        # Update hit rate
        self.cache_metrics.hit_rate = (
            self.cache_metrics.cache_hits / self.cache_metrics.total_requests
        )
    
    def record_email_analysis(
        self,
        analysis_time_ms: float
    ) -> None:
        """Record an email analysis for throughput tracking."""
        self.throughput_metrics.emails_analyzed += 1
        self.throughput_metrics.total_analysis_time_ms += analysis_time_ms
        
        # Add to latency samples
        self.latency_samples.append(analysis_time_ms)
        if len(self.latency_samples) > self.max_samples:
            self.latency_samples.pop(0)
        
        # Calculate averages
        self.throughput_metrics.avg_analysis_time_ms = (
            self.throughput_metrics.total_analysis_time_ms / 
            self.throughput_metrics.emails_analyzed
        )
        
        # Calculate emails per second
        elapsed_seconds = time.time() - self.start_time
        self.throughput_metrics.emails_per_second = (
            self.throughput_metrics.emails_analyzed / max(elapsed_seconds, 1)
        )
        
        # Update percentiles
        if len(self.latency_samples) >= 10:
            sorted_samples = sorted(self.latency_samples)
            self.throughput_metrics.p50_latency_ms = sorted_samples[int(len(sorted_samples) * 0.50)]
            self.throughput_metrics.p95_latency_ms = sorted_samples[int(len(sorted_samples) * 0.95)]
            self.throughput_metrics.p99_latency_ms = sorted_samples[int(len(sorted_samples) * 0.99)]
    
    def get_playbook_summary(self) -> Dict[str, Any]:
        """Get summary of playbook performance."""
        if not self.playbook_metrics:
            return {"message": "No playbook executions recorded"}
        
        total_executions = sum(m.execution_count for m in self.playbook_metrics.values())
        total_time = sum(m.total_execution_time_ms for m in self.playbook_metrics.values())
        total_success = sum(m.success_count for m in self.playbook_metrics.values())
        
        return {
            "total_playbooks": len(self.playbook_metrics),
            "total_executions": total_executions,
            "overall_success_rate": total_success / max(total_executions, 1),
            "total_execution_time_ms": total_time,
            "avg_execution_time_ms": total_time / max(total_executions, 1),
            "playbooks": {
                name: {
                    "executions": m.execution_count,
                    "avg_time_ms": m.avg_execution_time_ms,
                    "success_rate": m.success_rate,
                    "findings": m.findings_generated,
                    "actions": m.actions_executed
                }
                for name, m in self.playbook_metrics.items()
            }
        }
    
    def get_batch_processing_summary(self) -> Dict[str, Any]:
        """Get summary of batch processing performance."""
        return {
            "total_batches": self.batch_metrics.total_batches,
            "total_requests": self.batch_metrics.total_requests,
            "avg_batch_size": round(self.batch_metrics.avg_batch_size, 2),
            "total_api_calls": self.batch_metrics.total_api_calls,
            "api_call_savings_pct": round(self.batch_metrics.api_call_savings_pct, 2),
            "avg_processing_time_per_request_ms": round(
                self.batch_metrics.avg_processing_time_per_request_ms, 2
            )
        }
    
    def get_cache_performance_summary(self) -> Dict[str, Any]:
        """Get summary of cache performance."""
        return {
            "total_requests": self.cache_metrics.total_requests,
            "cache_hits": self.cache_metrics.cache_hits,
            "cache_misses": self.cache_metrics.cache_misses,
            "hit_rate": round(self.cache_metrics.hit_rate * 100, 2),
            "avg_hit_time_ms": round(self.cache_metrics.avg_hit_time_ms, 2),
            "avg_miss_time_ms": round(self.cache_metrics.avg_miss_time_ms, 2),
            "total_time_saved_ms": round(self.cache_metrics.total_time_saved_ms, 2),
            "time_saved_seconds": round(self.cache_metrics.total_time_saved_ms / 1000, 2),
            "warm_cache_hits": self.cache_metrics.warm_cache_hits
        }
    
    def get_throughput_summary(self) -> Dict[str, Any]:
        """Get summary of overall throughput."""
        return {
            "emails_analyzed": self.throughput_metrics.emails_analyzed,
            "avg_analysis_time_ms": round(self.throughput_metrics.avg_analysis_time_ms, 2),
            "emails_per_second": round(self.throughput_metrics.emails_per_second, 2),
            "latency_percentiles": {
                "p50_ms": round(self.throughput_metrics.p50_latency_ms, 2),
                "p95_ms": round(self.throughput_metrics.p95_latency_ms, 2),
                "p99_ms": round(self.throughput_metrics.p99_latency_ms, 2)
            }
        }
    
    def get_full_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report."""
        uptime_seconds = time.time() - self.start_time
        
        return {
            "timestamp": datetime.now().isoformat(),
            "uptime_seconds": round(uptime_seconds, 2),
            "playbook_performance": self.get_playbook_summary(),
            "batch_processing": self.get_batch_processing_summary(),
            "cache_performance": self.get_cache_performance_summary(),
            "throughput": self.get_throughput_summary(),
            "resource_usage": self.resource_metrics
        }
    
    def export_metrics_for_prometheus(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        
        # Playbook metrics
        for name, metrics in self.playbook_metrics.items():
            lines.append(f'playbook_executions_total{{playbook="{name}"}} {metrics.execution_count}')
            lines.append(f'playbook_success_rate{{playbook="{name}"}} {metrics.success_rate}')
            lines.append(f'playbook_avg_time_ms{{playbook="{name}"}} {metrics.avg_execution_time_ms}')
        
        # Cache metrics
        lines.append(f'cache_hit_rate {self.cache_metrics.hit_rate}')
        lines.append(f'cache_total_requests {self.cache_metrics.total_requests}')
        
        # Throughput metrics
        lines.append(f'emails_analyzed_total {self.throughput_metrics.emails_analyzed}')
        lines.append(f'emails_per_second {self.throughput_metrics.emails_per_second}')
        
        return '\n'.join(lines)
    
    def reset_metrics(self) -> None:
        """Reset all metrics counters."""
        self.playbook_metrics.clear()
        self.batch_metrics = BatchProcessingMetrics()
        self.cache_metrics = CachePerformanceMetrics()
        self.throughput_metrics = ThroughputMetrics()
        self.latency_samples.clear()
        self.start_time = time.time()
        
        logger.info("Performance metrics reset")


# Global performance monitor instance
_performance_monitor: Optional[PerformanceMonitor] = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get or create the global performance monitor."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor


def reset_performance_monitor() -> None:
    """Reset the global performance monitor."""
    global _performance_monitor
    if _performance_monitor:
        _performance_monitor.reset_metrics()
