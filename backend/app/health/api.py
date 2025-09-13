"""
Health Check API Endpoints

Provides REST API endpoints for health, readiness, and liveness checks.
"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List, Optional

from app.health.service import get_health_service, check_health, check_readiness, check_liveness


router = APIRouter(prefix="/health", tags=["health"])


@router.get("/")
async def get_health_status(
    components: Optional[str] = None,
    include_details: bool = True
) -> Dict[str, Any]:
    """
    Get comprehensive health status.
    
    Args:
        components: Comma-separated list of components to check (optional)
        include_details: Include detailed results in response
        
    Returns:
        Health check report
    """
    try:
        service = get_health_service()
        
        if components:
            component_list = [c.strip() for c in components.split(",")]
            report = await service.check_specific(component_list)
        else:
            report = await service.check_all(include_details=include_details)
        
        return report
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


@router.get("/ready")
async def readiness_check() -> Dict[str, Any]:
    """
    Kubernetes-style readiness check.
    
    Returns 200 if the service is ready to handle requests,
    503 if not ready.
    """
    try:
        result = await check_readiness()
        
        if not result.get('ready', False):
            raise HTTPException(
                status_code=503,
                detail={
                    "ready": False,
                    "message": "Service is not ready",
                    "details": result
                }
            )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail={
                "ready": False,
                "message": f"Readiness check failed: {str(e)}",
                "error": str(e)
            }
        )


@router.get("/live")
async def liveness_check() -> Dict[str, Any]:
    """
    Kubernetes-style liveness check.
    
    Returns 200 if the service is alive and running,
    503 if the service should be restarted.
    """
    try:
        result = await check_liveness()
        
        if not result.get('alive', False):
            raise HTTPException(
                status_code=503,
                detail={
                    "alive": False,
                    "message": "Service is not alive",
                    "details": result
                }
            )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail={
                "alive": False,
                "message": f"Liveness check failed: {str(e)}",
                "error": str(e)
            }
        )


@router.get("/components")
async def get_available_components() -> Dict[str, List[str]]:
    """Get list of available health check components."""
    try:
        service = get_health_service()
        components = service.get_available_checks()
        
        return {
            "components": components,
            "count": len(components)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get components: {str(e)}")


@router.get("/database")
async def database_health() -> Dict[str, Any]:
    """Get detailed database health information."""
    try:
        service = get_health_service()
        report = await service.check_specific(['database'])
        
        return report
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database health check failed: {str(e)}")


@router.get("/external-apis")
async def external_apis_health() -> Dict[str, Any]:
    """Get detailed external APIs health information."""
    try:
        service = get_health_service()
        report = await service.check_specific(['external_apis'])
        
        return report
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"External APIs health check failed: {str(e)}")


@router.get("/system")
async def system_health() -> Dict[str, Any]:
    """Get detailed system health information."""
    try:
        service = get_health_service()
        report = await service.check_specific(['system'])
        
        return report
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"System health check failed: {str(e)}")
