"""
Base Health Checker Classes

Defines the foundation for all health check implementations.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import asyncio
import logging

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health check status enumeration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthResult:
    """Health check result."""
    component: str
    status: HealthStatus
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = None
    duration_ms: Optional[float] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'component': self.component,
            'status': self.status.value,
            'message': self.message,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
        }
        
        if self.details:
            result['details'] = self.details
        if self.duration_ms is not None:
            result['duration_ms'] = self.duration_ms
            
        return result
    
    @property
    def is_healthy(self) -> bool:
        """Check if the result indicates healthy status."""
        return self.status == HealthStatus.HEALTHY
    
    @property
    def is_degraded(self) -> bool:
        """Check if the result indicates degraded status."""
        return self.status == HealthStatus.DEGRADED
    
    @property
    def is_unhealthy(self) -> bool:
        """Check if the result indicates unhealthy status."""
        return self.status == HealthStatus.UNHEALTHY


class HealthChecker(ABC):
    """Abstract base class for health checkers."""
    
    def __init__(self, component_name: str, timeout: float = 10.0):
        self.component_name = component_name
        self.timeout = timeout
        self.last_result: Optional[HealthResult] = None
        self.last_check_time: Optional[datetime] = None
    
    @abstractmethod
    async def check_health(self) -> HealthResult:
        """Perform health check and return result."""
        pass
    
    async def check_with_timeout(self) -> HealthResult:
        """Check health with timeout protection."""
        start_time = time.time()
        
        try:
            # Run with timeout
            result = await asyncio.wait_for(
                self.check_health(), 
                timeout=self.timeout
            )
            
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            result.duration_ms = duration_ms
            
            self.last_result = result
            self.last_check_time = datetime.utcnow()
            
            return result
            
        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            result = HealthResult(
                component=self.component_name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check timed out after {self.timeout}s",
                duration_ms=duration_ms
            )
            self.last_result = result
            self.last_check_time = datetime.utcnow()
            return result
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            result = HealthResult(
                component=self.component_name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                details={'error': str(e), 'error_type': type(e).__name__},
                duration_ms=duration_ms
            )
            self.last_result = result
            self.last_check_time = datetime.utcnow()
            return result
    
    def is_stale(self, max_age: timedelta = timedelta(minutes=5)) -> bool:
        """Check if the last health check result is stale."""
        if not self.last_check_time:
            return True
        return datetime.utcnow() - self.last_check_time > max_age
    
    def get_cached_result(self) -> Optional[HealthResult]:
        """Get the cached result if not stale."""
        if self.last_result and not self.is_stale():
            return self.last_result
        return None


class CompositeHealthChecker:
    """Composite health checker that runs multiple checkers."""
    
    def __init__(self, checkers: List[HealthChecker]):
        self.checkers = checkers
    
    async def check_all(self, parallel: bool = True) -> List[HealthResult]:
        """Run all health checks."""
        if parallel:
            # Run checks in parallel
            tasks = [checker.check_with_timeout() for checker in self.checkers]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Convert exceptions to unhealthy results
            final_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    final_results.append(HealthResult(
                        component=self.checkers[i].component_name,
                        status=HealthStatus.UNHEALTHY,
                        message=f"Health check failed: {str(result)}",
                        details={'error': str(result), 'error_type': type(result).__name__}
                    ))
                else:
                    final_results.append(result)
            
            return final_results
        else:
            # Run checks sequentially
            results = []
            for checker in self.checkers:
                result = await checker.check_with_timeout()
                results.append(result)
            return results
    
    def get_overall_status(self, results: List[HealthResult]) -> HealthStatus:
        """Determine overall system health from individual results."""
        if not results:
            return HealthStatus.UNKNOWN
        
        # Count status types
        status_counts = {status: 0 for status in HealthStatus}
        for result in results:
            status_counts[result.status] += 1
        
        # Determine overall status
        if status_counts[HealthStatus.UNHEALTHY] > 0:
            return HealthStatus.UNHEALTHY
        elif status_counts[HealthStatus.DEGRADED] > 0:
            return HealthStatus.DEGRADED
        elif status_counts[HealthStatus.HEALTHY] == len(results):
            return HealthStatus.HEALTHY
        else:
            return HealthStatus.UNKNOWN
    
    def create_summary(self, results: List[HealthResult]) -> Dict[str, Any]:
        """Create health check summary."""
        overall_status = self.get_overall_status(results)
        
        # Component status breakdown
        component_status = {}
        for result in results:
            component_status[result.component] = {
                'status': result.status.value,
                'message': result.message,
                'duration_ms': result.duration_ms,
                'timestamp': result.timestamp.isoformat() if result.timestamp else None
            }
        
        # Statistics
        total_duration = sum(r.duration_ms for r in results if r.duration_ms is not None)
        avg_duration = total_duration / len(results) if results else 0
        
        return {
            'overall_status': overall_status.value,
            'timestamp': datetime.utcnow().isoformat(),
            'total_checks': len(results),
            'healthy_count': sum(1 for r in results if r.status == HealthStatus.HEALTHY),
            'degraded_count': sum(1 for r in results if r.status == HealthStatus.DEGRADED),
            'unhealthy_count': sum(1 for r in results if r.status == HealthStatus.UNHEALTHY),
            'total_duration_ms': total_duration,
            'avg_duration_ms': avg_duration,
            'components': component_status
        }
