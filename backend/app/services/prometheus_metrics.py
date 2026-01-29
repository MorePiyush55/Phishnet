"""
Prometheus Metrics Integration for Mode 1
==========================================
Exposes Mode 1 pipeline metrics in Prometheus format.
"""

from prometheus_client import Counter, Histogram, Gauge, Info
from typing import Dict, Any

from app.config.logging import get_logger

logger = get_logger(__name__)


# ============================================================================
# Pipeline Stage Metrics
# ============================================================================

# Email processing counters
emails_processed_total = Counter(
    'mode1_emails_processed_total',
    'Total number of emails processed by Mode 1',
    ['tenant_id', 'verdict']
)

emails_deduplicated_total = Counter(
    'mode1_emails_deduplicated_total',
    'Total number of deduplicated emails',
    ['tenant_id', 'dedup_type']
)

# Stage timing histograms
stage_duration_seconds = Histogram(
    'mode1_stage_duration_seconds',
    'Duration of pipeline stages in seconds',
    ['stage', 'tenant_id'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
)

# Circuit breaker metrics
circuit_breaker_state = Gauge(
    'mode1_circuit_breaker_state',
    'Circuit breaker state (0=closed, 1=open, 2=half_open)',
    ['breaker_name']
)

circuit_breaker_failures = Counter(
    'mode1_circuit_breaker_failures_total',
    'Total circuit breaker failures',
    ['breaker_name']
)

# Active jobs gauge
active_jobs = Gauge(
    'mode1_active_jobs',
    'Number of currently active processing jobs'
)

# Rate limiter metrics
rate_limit_wait_seconds = Histogram(
    'mode1_rate_limit_wait_seconds',
    'Time spent waiting due to rate limiting',
    buckets=[0.01, 0.1, 0.5, 1.0, 5.0, 10.0]
)

# Error counters
pipeline_errors_total = Counter(
    'mode1_pipeline_errors_total',
    'Total pipeline errors',
    ['stage', 'error_type']
)


# ============================================================================
# Helper Functions
# ============================================================================

def record_email_processed(tenant_id: str, verdict: str):
    """Record an email processed."""
    emails_processed_total.labels(tenant_id=tenant_id, verdict=verdict).inc()


def record_email_deduplicated(tenant_id: str, dedup_type: str):
    """Record an email deduplicated."""
    emails_deduplicated_total.labels(tenant_id=tenant_id, dedup_type=dedup_type).inc()


def record_stage_duration(stage: str, tenant_id: str, duration_seconds: float):
    """Record stage duration."""
    stage_duration_seconds.labels(stage=stage, tenant_id=tenant_id).observe(duration_seconds)


def update_circuit_breaker_state(breaker_name: str, state: int):
    """
    Update circuit breaker state.
    
    Args:
        breaker_name: Name of the circuit breaker
        state: 0=closed, 1=open, 2=half_open
    """
    circuit_breaker_state.labels(breaker_name=breaker_name).set(state)


def record_circuit_breaker_failure(breaker_name: str):
    """Record circuit breaker failure."""
    circuit_breaker_failures.labels(breaker_name=breaker_name).inc()


def update_active_jobs(count: int):
    """Update active jobs count."""
    active_jobs.set(count)


def record_rate_limit_wait(wait_seconds: float):
    """Record rate limit wait time."""
    rate_limit_wait_seconds.observe(wait_seconds)


def record_pipeline_error(stage: str, error_type: str):
    """Record pipeline error."""
    pipeline_errors_total.labels(stage=stage, error_type=error_type).inc()


# ============================================================================
# Metrics Export
# ============================================================================

def get_metrics_summary() -> Dict[str, Any]:
    """
    Get summary of current metrics.
    
    Returns:
        Dictionary with metric summaries
    """
    return {
        "emails_processed": emails_processed_total._value.sum(),
        "emails_deduplicated": emails_deduplicated_total._value.sum(),
        "active_jobs": active_jobs._value.get(),
        "circuit_breakers": {
            "imap": circuit_breaker_state.labels(breaker_name="imap")._value.get(),
            "virustotal": circuit_breaker_state.labels(breaker_name="virustotal")._value.get(),
            "gemini": circuit_breaker_state.labels(breaker_name="gemini")._value.get()
        }
    }
