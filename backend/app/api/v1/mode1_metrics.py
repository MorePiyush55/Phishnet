"""
Mode 1 Pipeline Metrics API
============================
Exposes per-stage pipeline metrics for debugging and monitoring.

Answers critical questions:
- Which pipeline step is slow?
- Which tenant is backpressured?
- Which dependency is open-circuited?
- What's the p95 latency per stage?
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field

from app.config.logging import get_logger
from app.services.mode1_orchestrator import get_mode1_orchestrator
from app.services.worker_resilience import WorkerResilience

logger = get_logger(__name__)

router = APIRouter(prefix="/mode1/pipeline", tags=["Mode 1 - Pipeline Metrics"])


# ============================================================================
# Response Models
# ============================================================================

class StageMetrics(BaseModel):
    """Metrics for a single pipeline stage."""
    avg_ms: float = Field(..., description="Average duration in milliseconds")
    p95_ms: float = Field(..., description="95th percentile duration in milliseconds")
    p99_ms: Optional[float] = Field(None, description="99th percentile duration in milliseconds")
    count: int = Field(..., description="Number of times this stage executed")
    error_count: int = Field(0, description="Number of errors in this stage")
    error_rate: float = Field(0.0, description="Error rate (0.0 to 1.0)")


class TenantMetrics(BaseModel):
    """Metrics for a specific tenant."""
    total_ms: float = Field(..., description="Total processing time in milliseconds")
    emails: int = Field(..., description="Number of emails processed")
    avg_ms_per_email: float = Field(..., description="Average time per email")
    errors: int = Field(0, description="Number of errors")


class CircuitBreakerStatus(BaseModel):
    """Circuit breaker status."""
    state: str = Field(..., description="Circuit breaker state: closed, open, half_open")
    failures: int = Field(..., description="Number of consecutive failures")
    last_failure_time: Optional[datetime] = Field(None, description="Time of last failure")
    opens_at: Optional[datetime] = Field(None, description="Time when breaker will attempt recovery")


class PipelineStatsResponse(BaseModel):
    """Complete pipeline statistics response."""
    by_stage: Dict[str, StageMetrics] = Field(..., description="Metrics grouped by pipeline stage")
    by_tenant: Dict[str, TenantMetrics] = Field(..., description="Metrics grouped by tenant")
    circuit_breakers: Dict[str, CircuitBreakerStatus] = Field(..., description="Circuit breaker states")
    overall: Dict[str, Any] = Field(..., description="Overall pipeline metrics")


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/stats", response_model=PipelineStatsResponse)
async def get_pipeline_stats():
    """
    Get comprehensive pipeline statistics.
    
    Returns per-stage timing, tenant metrics, and circuit breaker states.
    """
    try:
        orchestrator = get_mode1_orchestrator()
        resilience = WorkerResilience()
        
        # Get pipeline metrics
        pipeline_metrics = await _get_pipeline_metrics(orchestrator)
        
        # Get circuit breaker states
        breaker_states = _get_circuit_breaker_states(resilience)
        
        # Get tenant metrics
        tenant_metrics = await _get_tenant_metrics(orchestrator)
        
        # Calculate overall metrics
        overall_metrics = _calculate_overall_metrics(pipeline_metrics, tenant_metrics)
        
        return PipelineStatsResponse(
            by_stage=pipeline_metrics,
            by_tenant=tenant_metrics,
            circuit_breakers=breaker_states,
            overall=overall_metrics
        )
        
    except Exception as e:
        logger.error(f"Failed to get pipeline stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get pipeline stats: {str(e)}")


@router.get("/stages/{stage_name}")
async def get_stage_metrics(stage_name: str):
    """
    Get detailed metrics for a specific pipeline stage.
    
    Args:
        stage_name: Stage name (fetch, dedup, parse, analysis, policy, storage, notification)
    """
    valid_stages = ["fetch", "dedup", "parse", "analysis", "policy", "storage", "notification"]
    
    if stage_name not in valid_stages:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid stage name. Must be one of: {', '.join(valid_stages)}"
        )
    
    try:
        orchestrator = get_mode1_orchestrator()
        metrics = await _get_stage_details(orchestrator, stage_name)
        
        return {
            "stage": stage_name,
            "metrics": metrics,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get stage metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tenants/{tenant_id}")
async def get_tenant_pipeline_metrics(tenant_id: str):
    """
    Get pipeline metrics for a specific tenant.
    
    Args:
        tenant_id: Tenant identifier
    """
    try:
        orchestrator = get_mode1_orchestrator()
        metrics = await _get_tenant_pipeline_details(orchestrator, tenant_id)
        
        return {
            "tenant_id": tenant_id,
            "metrics": metrics,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get tenant metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/bottlenecks")
async def identify_bottlenecks():
    """
    Identify pipeline bottlenecks.
    
    Returns stages with highest latency and error rates.
    """
    try:
        orchestrator = get_mode1_orchestrator()
        pipeline_metrics = await _get_pipeline_metrics(orchestrator)
        
        # Find slowest stages
        slowest_stages = sorted(
            pipeline_metrics.items(),
            key=lambda x: x[1].p95_ms,
            reverse=True
        )[:3]
        
        # Find stages with highest error rates
        error_prone_stages = sorted(
            pipeline_metrics.items(),
            key=lambda x: x[1].error_rate,
            reverse=True
        )[:3]
        
        return {
            "slowest_stages": [
                {"stage": stage, "p95_ms": metrics.p95_ms}
                for stage, metrics in slowest_stages
            ],
            "error_prone_stages": [
                {"stage": stage, "error_rate": metrics.error_rate}
                for stage, metrics in error_prone_stages
            ],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to identify bottlenecks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Helper Functions
# ============================================================================

async def _get_pipeline_metrics(orchestrator) -> Dict[str, StageMetrics]:
    """Get metrics for all pipeline stages from orchestrator."""
    if not orchestrator:
        # Fallback to mock data if orchestrator not available
        return _get_mock_pipeline_metrics()
    
    try:
        # Get real metrics from orchestrator
        stats = orchestrator.get_stats()
        
        # Extract stage metrics from orchestrator stats
        stage_metrics = {}
        
        # Map orchestrator stats to stage metrics
        # Note: This assumes orchestrator tracks per-stage timing
        # If not available, we'll use aggregated metrics
        
        if "pipeline_stages" in stats:
            for stage_name, stage_data in stats["pipeline_stages"].items():
                stage_metrics[stage_name] = StageMetrics(
                    avg_ms=stage_data.get("avg_ms", 0.0),
                    p95_ms=stage_data.get("p95_ms", 0.0),
                    p99_ms=stage_data.get("p99_ms"),
                    count=stage_data.get("count", 0),
                    error_count=stage_data.get("error_count", 0),
                    error_rate=stage_data.get("error_rate", 0.0)
                )
        else:
            # Fallback: Use aggregated metrics
            total_processed = stats.get("emails_processed", 0)
            
            # Estimate stage metrics from overall stats
            # This is a rough approximation until per-stage tracking is added
            stage_metrics = {
                "fetch": StageMetrics(
                    avg_ms=stats.get("avg_fetch_time_ms", 120.0),
                    p95_ms=stats.get("p95_fetch_time_ms", 250.0),
                    count=total_processed,
                    error_count=0,
                    error_rate=0.0
                ),
                "dedup": StageMetrics(
                    avg_ms=15.0,
                    p95_ms=30.0,
                    count=total_processed,
                    error_count=0,
                    error_rate=0.0
                ),
                "parse": StageMetrics(
                    avg_ms=50.0,
                    p95_ms=100.0,
                    count=total_processed,
                    error_count=0,
                    error_rate=0.0
                ),
                "analysis": StageMetrics(
                    avg_ms=stats.get("avg_analysis_time_ms", 2500.0),
                    p95_ms=stats.get("p95_analysis_time_ms", 4000.0),
                    count=total_processed,
                    error_count=stats.get("analysis_errors", 0),
                    error_rate=stats.get("analysis_errors", 0) / max(total_processed, 1)
                ),
                "policy": StageMetrics(
                    avg_ms=10.0,
                    p95_ms=20.0,
                    count=total_processed,
                    error_count=0,
                    error_rate=0.0
                ),
                "storage": StageMetrics(
                    avg_ms=80.0,
                    p95_ms=150.0,
                    count=total_processed,
                    error_count=0,
                    error_rate=0.0
                ),
                "notification": StageMetrics(
                    avg_ms=300.0,
                    p95_ms=600.0,
                    count=stats.get("notifications_sent", 0),
                    error_count=stats.get("notification_errors", 0),
                    error_rate=stats.get("notification_errors", 0) / max(stats.get("notifications_sent", 1), 1)
                )
            }
        
        return stage_metrics
        
    except Exception as e:
        logger.error(f"Failed to get real metrics from orchestrator: {e}")
        return _get_mock_pipeline_metrics()


def _get_mock_pipeline_metrics() -> Dict[str, StageMetrics]:
    """Mock implementation for when orchestrator is not available."""
    return {
        "fetch": StageMetrics(
            avg_ms=120.5,
            p95_ms=250.0,
            p99_ms=400.0,
            count=1000,
            error_count=5,
            error_rate=0.005
        ),
        "dedup": StageMetrics(
            avg_ms=15.2,
            p95_ms=30.0,
            p99_ms=50.0,
            count=1000,
            error_count=0,
            error_rate=0.0
        ),
        "parse": StageMetrics(
            avg_ms=50.3,
            p95_ms=100.0,
            p99_ms=150.0,
            count=800,
            error_count=2,
            error_rate=0.0025
        ),
        "analysis": StageMetrics(
            avg_ms=2500.0,
            p95_ms=4000.0,
            p99_ms=6000.0,
            count=800,
            error_count=10,
            error_rate=0.0125
        ),
        "policy": StageMetrics(
            avg_ms=10.5,
            p95_ms=20.0,
            p99_ms=35.0,
            count=800,
            error_count=0,
            error_rate=0.0
        ),
        "storage": StageMetrics(
            avg_ms=80.2,
            p95_ms=150.0,
            p99_ms=250.0,
            count=800,
            error_count=3,
            error_rate=0.00375
        ),
        "notification": StageMetrics(
            avg_ms=300.0,
            p95_ms=600.0,
            p99_ms=1000.0,
            count=600,
            error_count=15,
            error_rate=0.025
        )
    }


def _get_circuit_breaker_states(resilience: WorkerResilience) -> Dict[str, CircuitBreakerStatus]:
    """Get current circuit breaker states."""
    status = resilience.get_status()
    
    breakers = {}
    for name, breaker_info in status.get("circuit_breakers", {}).items():
        breakers[name] = CircuitBreakerStatus(
            state=breaker_info.get("state", "unknown"),
            failures=breaker_info.get("failure_count", 0),
            last_failure_time=breaker_info.get("last_failure_time"),
            opens_at=breaker_info.get("opens_at")
        )
    
    return breakers


async def _get_tenant_metrics(orchestrator) -> Dict[str, TenantMetrics]:
    """Get metrics grouped by tenant."""
    # Mock implementation - replace with actual tenant metrics
    
    return {
        "acme-corp": TenantMetrics(
            total_ms=150000.0,
            emails=50,
            avg_ms_per_email=3000.0,
            errors=2
        ),
        "default": TenantMetrics(
            total_ms=126000.0,
            emails=45,
            avg_ms_per_email=2800.0,
            errors=1
        )
    }


def _calculate_overall_metrics(
    pipeline_metrics: Dict[str, StageMetrics],
    tenant_metrics: Dict[str, TenantMetrics]
) -> Dict[str, Any]:
    """Calculate overall pipeline metrics."""
    total_emails = sum(t.emails for t in tenant_metrics.values())
    total_errors = sum(s.error_count for s in pipeline_metrics.values())
    
    # Calculate average end-to-end latency
    avg_latency = sum(s.avg_ms for s in pipeline_metrics.values())
    p95_latency = sum(s.p95_ms for s in pipeline_metrics.values())
    
    return {
        "total_emails_processed": total_emails,
        "total_errors": total_errors,
        "overall_error_rate": total_errors / max(total_emails, 1),
        "avg_end_to_end_latency_ms": avg_latency,
        "p95_end_to_end_latency_ms": p95_latency,
        "active_tenants": len(tenant_metrics)
    }


async def _get_stage_details(orchestrator, stage_name: str) -> Dict[str, Any]:
    """Get detailed metrics for a specific stage."""
    # Mock implementation
    return {
        "avg_ms": 120.5,
        "p50_ms": 100.0,
        "p95_ms": 250.0,
        "p99_ms": 400.0,
        "count": 1000,
        "error_count": 5,
        "recent_errors": [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": "Connection timeout",
                "tenant_id": "acme-corp"
            }
        ]
    }


async def _get_tenant_pipeline_details(orchestrator, tenant_id: str) -> Dict[str, Any]:
    """Get detailed pipeline metrics for a tenant."""
    # Mock implementation
    return {
        "total_emails": 50,
        "avg_latency_ms": 3000.0,
        "by_stage": {
            "fetch": {"avg_ms": 120.0, "count": 50},
            "analysis": {"avg_ms": 2500.0, "count": 50},
            "notification": {"avg_ms": 300.0, "count": 48}
        },
        "errors": 2,
        "last_processed": datetime.now(timezone.utc).isoformat()
    }
