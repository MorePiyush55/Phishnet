"""
API endpoints for threat intelligence service status and monitoring.

Provides endpoints for frontend dashboard to monitor service health,
cache performance, and privacy protection status.
"""

from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse

from app.integrations.unified_service import UnifiedThreatIntelligenceService, ThreatIntelligenceConfig
from app.core.dependencies import get_current_user
from app.core.config import settings

router = APIRouter(prefix="/api/threat-intelligence", tags=["threat-intelligence"])

# Global service instance (in production, this would be dependency injected)
_threat_intelligence_service: Optional[UnifiedThreatIntelligenceService] = None


async def get_threat_intelligence_service() -> UnifiedThreatIntelligenceService:
    """Get or initialize the threat intelligence service."""
    global _threat_intelligence_service
    
    if _threat_intelligence_service is None:
        config = ThreatIntelligenceConfig(
            virustotal_api_key=settings.VIRUSTOTAL_API_KEY,
            abuseipdb_api_key=settings.ABUSEIPDB_API_KEY,
            gemini_api_key=settings.GEMINI_API_KEY,
            redis_url=settings.REDIS_URL,
            cache_enabled=settings.CACHE_ENABLED,
            pii_sanitization_enabled=settings.PII_SANITIZATION_ENABLED,
            audit_logging_enabled=settings.AUDIT_LOGGING_ENABLED
        )
        
        _threat_intelligence_service = UnifiedThreatIntelligenceService(config)
        await _threat_intelligence_service.initialize()
    
    return _threat_intelligence_service


@router.get("/health")
async def get_service_health():
    """Get health status of all threat intelligence services."""
    try:
        service = await get_threat_intelligence_service()
        health_status = await service.get_service_health()
        
        # Convert to API-friendly format
        api_response = {}
        for service_name, health in health_status.items():
            api_response[service_name] = {
                "service_name": health.service_name,
                "is_healthy": health.is_healthy,
                "circuit_breaker_state": health.circuit_breaker_state,
                "last_success": health.last_success.isoformat() if health.last_success else None,
                "last_failure": health.last_failure.isoformat() if health.last_failure else None,
                "quota_remaining": health.quota_remaining,
                "error_message": health.error_message
            }
        
        return JSONResponse(content=api_response)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get service health: {str(e)}")


@router.get("/cache-stats")
async def get_cache_stats():
    """Get cache performance statistics."""
    try:
        service = await get_threat_intelligence_service()
        cache_stats = await service.get_cache_stats()
        
        if cache_stats.get("cache_disabled"):
            return JSONResponse(content={
                "cache_hits": 0,
                "cache_misses": 0,
                "hit_rate": 0.0,
                "total_keys": 0,
                "memory_usage": "N/A",
                "status": "disabled"
            })
        
        return JSONResponse(content={
            "cache_hits": cache_stats.get("hits", 0),
            "cache_misses": cache_stats.get("misses", 0),
            "hit_rate": cache_stats.get("hit_rate", 0.0),
            "total_keys": cache_stats.get("total_keys", 0),
            "memory_usage": cache_stats.get("memory_usage", "Unknown"),
            "status": cache_stats.get("status", "unknown")
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get cache stats: {str(e)}")


@router.get("/privacy-summary")
async def get_privacy_summary():
    """Get privacy protection summary."""
    try:
        service = await get_threat_intelligence_service()
        privacy_summary = await service.get_privacy_summary()
        
        if privacy_summary.get("privacy_protection_disabled"):
            return JSONResponse(content={
                "privacy_protection_enabled": False,
                "services": {}
            })
        
        return JSONResponse(content={
            "privacy_protection_enabled": True,
            "services": privacy_summary
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get privacy summary: {str(e)}")


@router.post("/analyze/url")
async def analyze_url(
    url: str,
    current_user = Depends(get_current_user)
):
    """Analyze a URL for threat intelligence."""
    try:
        service = await get_threat_intelligence_service()
        result = await service.analyze_url(url)
        
        return JSONResponse(content={
            "resource": result.resource,
            "resource_type": result.resource_type.value,
            "aggregated_score": result.aggregated_score,
            "confidence": result.confidence,
            "sources_used": result.sources_used,
            "cache_hit": result.cache_hit,
            "privacy_protected": result.privacy_protected,
            "processing_time": result.processing_time,
            "errors": result.errors,
            "threat_level": result.primary_result.threat_level.value if result.primary_result else "unknown",
            "analysis_timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL analysis failed: {str(e)}")


@router.post("/analyze/ip")
async def analyze_ip(
    ip_address: str,
    current_user = Depends(get_current_user)
):
    """Analyze an IP address for threat intelligence."""
    try:
        service = await get_threat_intelligence_service()
        result = await service.analyze_ip(ip_address)
        
        return JSONResponse(content={
            "resource": result.resource,
            "resource_type": result.resource_type.value,
            "aggregated_score": result.aggregated_score,
            "confidence": result.confidence,
            "sources_used": result.sources_used,
            "cache_hit": result.cache_hit,
            "privacy_protected": result.privacy_protected,
            "processing_time": result.processing_time,
            "errors": result.errors,
            "threat_level": result.primary_result.threat_level.value if result.primary_result else "unknown",
            "analysis_timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IP analysis failed: {str(e)}")


@router.post("/analyze/content")
async def analyze_content(
    content: str,
    current_user = Depends(get_current_user)
):
    """Analyze content for threat intelligence."""
    try:
        service = await get_threat_intelligence_service()
        result = await service.analyze_content(content)
        
        return JSONResponse(content={
            "resource": result.resource,
            "resource_type": result.resource_type.value,
            "aggregated_score": result.aggregated_score,
            "confidence": result.confidence,
            "sources_used": result.sources_used,
            "cache_hit": result.cache_hit,
            "privacy_protected": result.privacy_protected,
            "processing_time": result.processing_time,
            "errors": result.errors,
            "threat_level": result.primary_result.threat_level.value if result.primary_result else "unknown",
            "analysis_timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Content analysis failed: {str(e)}")


@router.get("/status")
async def get_overall_status():
    """Get overall system status with key metrics."""
    try:
        service = await get_threat_intelligence_service()
        
        # Get all metrics
        health_status = await service.get_service_health()
        cache_stats = await service.get_cache_stats()
        privacy_summary = await service.get_privacy_summary()
        
        # Calculate overall health
        healthy_services = sum(1 for h in health_status.values() if h.is_healthy)
        total_services = len(health_status)
        overall_health = "healthy" if healthy_services == total_services else "degraded" if healthy_services > 0 else "unhealthy"
        
        return JSONResponse(content={
            "overall_health": overall_health,
            "services": {
                "healthy": healthy_services,
                "total": total_services,
                "details": {name: h.is_healthy for name, h in health_status.items()}
            },
            "cache": {
                "enabled": not cache_stats.get("cache_disabled", False),
                "hit_rate": cache_stats.get("hit_rate", 0.0),
                "status": cache_stats.get("status", "unknown")
            },
            "privacy": {
                "enabled": not privacy_summary.get("privacy_protection_disabled", False),
                "services_protected": len(privacy_summary) if not privacy_summary.get("privacy_protection_disabled") else 0
            },
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get system status: {str(e)}")


@router.post("/clear-cache")
async def clear_cache(
    current_user = Depends(get_current_user)
):
    """Clear the threat intelligence cache (admin only)."""
    try:
        service = await get_threat_intelligence_service()
        
        if service.cache:
            # Clear all cache keys
            await service.cache.clear_all()
            return JSONResponse(content={
                "message": "Cache cleared successfully",
                "timestamp": datetime.utcnow().isoformat()
            })
        else:
            return JSONResponse(content={
                "message": "Cache is not enabled",
                "timestamp": datetime.utcnow().isoformat()
            })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear cache: {str(e)}")


@router.get("/metrics")
async def get_metrics():
    """Get detailed metrics for monitoring systems."""
    try:
        service = await get_threat_intelligence_service()
        
        health_status = await service.get_service_health()
        cache_stats = await service.get_cache_stats()
        
        # Format metrics for Prometheus/monitoring systems
        metrics = []
        
        # Service health metrics
        for service_name, health in health_status.items():
            metrics.append(f'threat_intel_service_healthy{{service="{service_name}"}} {1 if health.is_healthy else 0}')
            if health.quota_remaining is not None:
                metrics.append(f'threat_intel_quota_remaining{{service="{service_name}"}} {health.quota_remaining}')
        
        # Cache metrics
        if not cache_stats.get("cache_disabled"):
            metrics.append(f'threat_intel_cache_hits {cache_stats.get("hits", 0)}')
            metrics.append(f'threat_intel_cache_misses {cache_stats.get("misses", 0)}')
            metrics.append(f'threat_intel_cache_hit_rate {cache_stats.get("hit_rate", 0.0)}')
            metrics.append(f'threat_intel_cache_keys {cache_stats.get("total_keys", 0)}')
        
        return JSONResponse(content={
            "metrics": metrics,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}")


# Health check endpoint for load balancers
@router.get("/ping")
async def ping():
    """Simple health check endpoint."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}