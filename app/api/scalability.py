"""
API endpoints for PhishNet scalability features
Provides REST API access to horizontal scaling, threat hunting, and feature flags
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query
from fastapi.responses import JSONResponse, FileResponse
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import asyncio

from app.core.horizontal_scaling import horizontal_scaler, ScalingStrategy
from app.services.threat_hunting import threat_hunting_engine, ThreatIndicator, SearchFilter
from app.core.feature_flags import feature_flag_manager, FeatureFlag, TargetingRule
from app.core.scaling_demo import run_scaling_demo, ArchitectureDiagramGenerator
from app.core.auth import get_current_user, require_permissions
from app.core.rate_limiting import rate_limit
from app.config.logging import get_logger

logger = get_logger(__name__)

# Create router for scalability features
scalability_router = APIRouter(prefix="/api/v1/scalability", tags=["scalability"])

# Request/Response Models
class ScalingRequest(BaseModel):
    """Request model for manual scaling operations"""
    worker_count: int = Field(gt=0, le=20, description="Number of workers to scale to")
    reason: str = Field(default="manual", description="Reason for scaling")

class ScalingConfigRequest(BaseModel):
    """Request model for scaling configuration"""
    strategy: ScalingStrategy = Field(description="Scaling strategy")
    min_workers: int = Field(ge=1, le=5, description="Minimum workers")
    max_workers: int = Field(ge=2, le=20, description="Maximum workers")
    target_cpu_usage: float = Field(ge=10, le=90, description="Target CPU usage percentage")
    target_queue_size: int = Field(ge=10, le=200, description="Target queue size")

class ThreatHuntRequest(BaseModel):
    """Request model for threat hunting"""
    query: str = Field(description="Search query or pattern")
    search_type: str = Field(default="regex", description="Type of search")
    time_range_hours: int = Field(default=24, ge=1, le=168, description="Time range in hours")
    limit: int = Field(default=100, ge=1, le=1000, description="Maximum results")

class FeatureFlagRequest(BaseModel):
    """Request model for feature flag operations"""
    flag_key: str = Field(description="Feature flag key")
    enabled: bool = Field(description="Whether flag is enabled")
    targeting_rules: Optional[List[Dict[str, Any]]] = Field(default=None, description="Targeting rules")
    rollout_percentage: Optional[float] = Field(default=None, ge=0, le=100, description="Rollout percentage")

# Scaling Management Endpoints
@scalability_router.get("/scaling/status")
@rate_limit(max_calls=100, time_window=60)
async def get_scaling_status(current_user = Depends(get_current_user)):
    """Get comprehensive scaling status and metrics"""
    try:
        status = await horizontal_scaler.get_scaling_status()
        return JSONResponse(content={
            "success": True,
            "data": status,
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get scaling status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@scalability_router.post("/scaling/scale-up")
@require_permissions(["scaling:write"])
async def scale_up_workers(
    request: ScalingRequest,
    current_user = Depends(get_current_user)
):
    """Manually scale up workers"""
    try:
        current_status = await horizontal_scaler.get_scaling_status()
        current_workers = current_status["workers"]["total"]
        workers_to_add = request.worker_count - current_workers
        
        if workers_to_add <= 0:
            raise HTTPException(status_code=400, detail="Worker count must be greater than current")
        
        new_workers = await horizontal_scaler.scale_up(workers_to_add, request.reason)
        
        return JSONResponse(content={
            "success": True,
            "message": f"Scaled up by {len(new_workers)} workers",
            "data": {
                "new_workers": new_workers,
                "total_workers": current_workers + len(new_workers)
            }
        })
    except Exception as e:
        logger.error(f"Failed to scale up: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@scalability_router.post("/scaling/scale-down")
@require_permissions(["scaling:write"])
async def scale_down_workers(
    request: ScalingRequest,
    current_user = Depends(get_current_user)
):
    """Manually scale down workers"""
    try:
        current_status = await horizontal_scaler.get_scaling_status()
        current_workers = current_status["workers"]["total"]
        workers_to_remove = current_workers - request.worker_count
        
        if workers_to_remove <= 0:
            raise HTTPException(status_code=400, detail="Worker count must be less than current")
        
        removed_workers = await horizontal_scaler.scale_down(workers_to_remove, request.reason)
        
        return JSONResponse(content={
            "success": True,
            "message": f"Scaled down by {len(removed_workers)} workers",
            "data": {
                "removed_workers": removed_workers,
                "total_workers": current_workers - len(removed_workers)
            }
        })
    except Exception as e:
        logger.error(f"Failed to scale down: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@scalability_router.put("/scaling/config")
@require_permissions(["scaling:admin"])
async def update_scaling_config(
    request: ScalingConfigRequest,
    current_user = Depends(get_current_user)
):
    """Update scaling configuration"""
    try:
        # Update horizontal scaler configuration
        horizontal_scaler.strategy = request.strategy
        horizontal_scaler.min_workers = request.min_workers
        horizontal_scaler.max_workers = request.max_workers
        horizontal_scaler.target_cpu_usage = request.target_cpu_usage
        horizontal_scaler.target_queue_size = request.target_queue_size
        
        # Ensure worker count is within new limits
        current_status = await horizontal_scaler.get_scaling_status()
        current_workers = current_status["workers"]["total"]
        
        if current_workers < request.min_workers:
            await horizontal_scaler.scale_up(request.min_workers - current_workers, "config_update")
        elif current_workers > request.max_workers:
            await horizontal_scaler.scale_down(current_workers - request.max_workers, "config_update")
        
        return JSONResponse(content={
            "success": True,
            "message": "Scaling configuration updated",
            "data": {
                "strategy": request.strategy.value,
                "min_workers": request.min_workers,
                "max_workers": request.max_workers,
                "target_cpu_usage": request.target_cpu_usage,
                "target_queue_size": request.target_queue_size
            }
        })
    except Exception as e:
        logger.error(f"Failed to update scaling config: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Threat Hunting Endpoints
@scalability_router.post("/threat-hunting/search")
@require_permissions(["threat_hunting:read"])
async def search_threats(
    request: ThreatHuntRequest,
    current_user = Depends(get_current_user)
):
    """Search for threats using various hunting techniques"""
    try:
        # Create search filter
        search_filter = SearchFilter(
            time_range_start=datetime.utcnow() - timedelta(hours=request.time_range_hours),
            time_range_end=datetime.utcnow(),
            limit=request.limit
        )
        
        # Perform search based on type
        if request.search_type == "regex":
            results = await threat_hunting_engine.search_by_regex(request.query, search_filter)
        elif request.search_type == "domain":
            results = await threat_hunting_engine.hunt_domains([request.query], search_filter)
        elif request.search_type == "ip":
            results = await threat_hunting_engine.hunt_ips([request.query], search_filter)
        elif request.search_type == "pattern":
            results = await threat_hunting_engine.analyze_patterns(search_filter)
        else:
            raise HTTPException(status_code=400, detail="Invalid search type")
        
        return JSONResponse(content={
            "success": True,
            "data": {
                "query": request.query,
                "search_type": request.search_type,
                "results_count": len(results),
                "results": [result.dict() for result in results]
            },
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Threat hunting search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@scalability_router.get("/threat-hunting/indicators")
@require_permissions(["threat_hunting:read"])
async def get_threat_indicators(
    limit: int = Query(100, ge=1, le=1000),
    current_user = Depends(get_current_user)
):
    """Get recent threat indicators"""
    try:
        search_filter = SearchFilter(
            time_range_start=datetime.utcnow() - timedelta(hours=24),
            time_range_end=datetime.utcnow(),
            limit=limit
        )
        
        indicators = await threat_hunting_engine.extract_indicators(search_filter)
        
        return JSONResponse(content={
            "success": True,
            "data": {
                "indicators_count": len(indicators),
                "indicators": [indicator.dict() for indicator in indicators]
            },
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get threat indicators: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@scalability_router.get("/threat-hunting/timeline")
@require_permissions(["threat_hunting:read"])
async def get_threat_timeline(
    hours: int = Query(24, ge=1, le=168),
    current_user = Depends(get_current_user)
):
    """Get threat activity timeline"""
    try:
        search_filter = SearchFilter(
            time_range_start=datetime.utcnow() - timedelta(hours=hours),
            time_range_end=datetime.utcnow(),
            limit=1000
        )
        
        timeline = await threat_hunting_engine.create_threat_timeline(search_filter)
        
        return JSONResponse(content={
            "success": True,
            "data": {
                "timeline_events": len(timeline),
                "timeline": timeline
            },
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get threat timeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Feature Flags Endpoints
@scalability_router.get("/feature-flags")
@require_permissions(["feature_flags:read"])
async def list_feature_flags(current_user = Depends(get_current_user)):
    """List all feature flags"""
    try:
        flags = await feature_flag_manager.list_flags()
        
        return JSONResponse(content={
            "success": True,
            "data": {
                "flags_count": len(flags),
                "flags": [flag.dict() for flag in flags]
            },
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to list feature flags: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@scalability_router.post("/feature-flags")
@require_permissions(["feature_flags:write"])
async def create_feature_flag(
    request: FeatureFlagRequest,
    current_user = Depends(get_current_user)
):
    """Create or update a feature flag"""
    try:
        # Create targeting rules if provided
        targeting_rules = []
        if request.targeting_rules:
            for rule_data in request.targeting_rules:
                targeting_rules.append(TargetingRule(**rule_data))
        
        # Create feature flag
        flag = FeatureFlag(
            key=request.flag_key,
            enabled=request.enabled,
            targeting_rules=targeting_rules,
            rollout_percentage=request.rollout_percentage
        )
        
        success = await feature_flag_manager.set_flag(flag)
        
        if success:
            return JSONResponse(content={
                "success": True,
                "message": f"Feature flag '{request.flag_key}' created/updated",
                "data": flag.dict()
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to create feature flag")
    except Exception as e:
        logger.error(f"Failed to create feature flag: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@scalability_router.get("/feature-flags/{flag_key}")
@require_permissions(["feature_flags:read"])
async def get_feature_flag(
    flag_key: str,
    current_user = Depends(get_current_user)
):
    """Get specific feature flag"""
    try:
        flag = await feature_flag_manager.get_flag(flag_key)
        
        if flag:
            return JSONResponse(content={
                "success": True,
                "data": flag.dict(),
                "timestamp": datetime.utcnow().isoformat()
            })
        else:
            raise HTTPException(status_code=404, detail="Feature flag not found")
    except Exception as e:
        logger.error(f"Failed to get feature flag: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@scalability_router.delete("/feature-flags/{flag_key}")
@require_permissions(["feature_flags:write"])
async def delete_feature_flag(
    flag_key: str,
    current_user = Depends(get_current_user)
):
    """Delete a feature flag"""
    try:
        success = await feature_flag_manager.delete_flag(flag_key)
        
        if success:
            return JSONResponse(content={
                "success": True,
                "message": f"Feature flag '{flag_key}' deleted"
            })
        else:
            raise HTTPException(status_code=404, detail="Feature flag not found")
    except Exception as e:
        logger.error(f"Failed to delete feature flag: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Demo and Documentation Endpoints
@scalability_router.post("/demo/run")
@require_permissions(["scaling:admin"])
async def run_scaling_demonstration(
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_user)
):
    """Run horizontal scaling demonstration"""
    try:
        # Run demo in background
        background_tasks.add_task(run_scaling_demo)
        
        return JSONResponse(content={
            "success": True,
            "message": "Scaling demonstration started",
            "note": "Demo is running in background. Check status for updates."
        })
    except Exception as e:
        logger.error(f"Failed to start scaling demo: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@scalability_router.get("/architecture/diagram")
async def get_architecture_diagram(current_user = Depends(get_current_user)):
    """Get architecture diagram"""
    try:
        diagram_path = "docs/architecture_scalable.png"
        
        # Generate diagram if it doesn't exist
        try:
            generator = ArchitectureDiagramGenerator()
            generator.generate_scalable_architecture_diagram(diagram_path)
        except Exception as e:
            logger.warning(f"Failed to generate diagram: {e}")
        
        return FileResponse(
            path=diagram_path,
            media_type="image/png",
            filename="phishnet_architecture.png"
        )
    except Exception as e:
        logger.error(f"Failed to get architecture diagram: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@scalability_router.get("/metrics/performance")
@rate_limit(max_calls=50, time_window=60)
async def get_performance_metrics(
    hours: int = Query(1, ge=1, le=24),
    current_user = Depends(get_current_user)
):
    """Get comprehensive performance metrics"""
    try:
        # Get scaling metrics
        scaling_status = await horizontal_scaler.get_scaling_status()
        
        # Get threat hunting metrics
        search_filter = SearchFilter(
            time_range_start=datetime.utcnow() - timedelta(hours=hours),
            time_range_end=datetime.utcnow(),
            limit=100
        )
        threat_indicators = await threat_hunting_engine.extract_indicators(search_filter)
        
        # Get feature flag usage
        flags = await feature_flag_manager.list_flags()
        
        return JSONResponse(content={
            "success": True,
            "data": {
                "scaling": {
                    "workers": scaling_status["workers"],
                    "queue": scaling_status["queue"],
                    "performance": scaling_status["performance"]
                },
                "threat_hunting": {
                    "indicators_found": len(threat_indicators),
                    "high_risk_indicators": len([i for i in threat_indicators if i.risk_level == "HIGH"])
                },
                "feature_flags": {
                    "total_flags": len(flags),
                    "enabled_flags": len([f for f in flags if f.enabled])
                }
            },
            "time_range_hours": hours,
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Health Check for Scalability Features
@scalability_router.get("/health")
async def scalability_health_check():
    """Health check for all scalability features"""
    try:
        health_status = {
            "horizontal_scaling": "healthy",
            "threat_hunting": "healthy", 
            "feature_flags": "healthy",
            "message_queue": "healthy"
        }
        
        # Check horizontal scaler
        try:
            await horizontal_scaler.get_scaling_status()
        except Exception:
            health_status["horizontal_scaling"] = "unhealthy"
        
        # Check threat hunting
        try:
            search_filter = SearchFilter(
                time_range_start=datetime.utcnow() - timedelta(minutes=5),
                time_range_end=datetime.utcnow(),
                limit=1
            )
            await threat_hunting_engine.extract_indicators(search_filter)
        except Exception:
            health_status["threat_hunting"] = "unhealthy"
        
        # Check feature flags
        try:
            await feature_flag_manager.list_flags()
        except Exception:
            health_status["feature_flags"] = "unhealthy"
        
        overall_health = "healthy" if all(status == "healthy" for status in health_status.values()) else "degraded"
        
        return JSONResponse(content={
            "success": True,
            "overall_health": overall_health,
            "components": health_status,
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "overall_health": "unhealthy",
                "error": str(e)
            }
        )
