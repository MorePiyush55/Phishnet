"""
Metrics endpoint for Prometheus scraping.
Exposes PhishNet application metrics in Prometheus format.
"""

from fastapi import APIRouter, Response
from backend.app.observability.metrics import metrics

router = APIRouter()

@router.get("/metrics")
async def get_metrics():
    """
    Expose Prometheus metrics endpoint.
    
    Returns metrics in Prometheus text format for scraping.
    """
    # Update system metrics before serving
    metrics.update_system_metrics()
    
    # Get metrics in Prometheus format
    metrics_data = metrics.get_metrics()
    
    # Return with proper content type
    return Response(
        content=metrics_data,
        media_type="text/plain; version=0.0.4; charset=utf-8"
    )