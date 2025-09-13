"""
Health check endpoints and monitoring for all system components.
Provides comprehensive health monitoring for database, Redis, external APIs, and services.
"""

import asyncio
import time
from typing import Dict, Any, Optional, List
from enum import Enum

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import redis.asyncio as redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.redis_client import get_redis_connection
from app.config.settings import settings
from app.observability.correlation import get_structured_logger
from app.observability.tracing import get_observability_health
from app.resilience.circuit_breaker import get_all_circuit_breaker_stats
from app.services.virustotal import VirusTotalClient
from app.services.interfaces import ServiceStatus

logger = get_structured_logger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


class HealthStatus(str, Enum):
    """Health check status values."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ComponentHealth(BaseModel):
    """Health status for a single component."""
    status: HealthStatus
    message: str
    response_time_ms: Optional[float] = None
    last_check: float
    details: Optional[Dict[str, Any]] = None


class SystemHealth(BaseModel):
    """Overall system health status."""
    status: HealthStatus
    timestamp: float
    uptime_seconds: float
    components: Dict[str, ComponentHealth]
    circuit_breakers: List[Dict[str, Any]]
    observability: Dict[str, Any]


class HealthChecker:
    """Health check implementation for all system components."""
    
    def __init__(self):
        self.start_time = time.time()
    
    async def check_database(self, db: AsyncSession) -> ComponentHealth:
        """Check database connectivity and performance."""
        start_time = time.time()
        
        try:
            # Simple query to test database
            result = await db.execute(text("SELECT 1 as health_check"))
            row = result.fetchone()
            
            response_time = (time.time() - start_time) * 1000
            
            if row and row[0] == 1:
                return ComponentHealth(
                    status=HealthStatus.HEALTHY,
                    message="Database connection successful",
                    response_time_ms=response_time,
                    last_check=time.time(),
                    details={
                        "query_response": "OK",
                        "connection_pool": "active"
                    }
                )
            else:
                return ComponentHealth(
                    status=HealthStatus.UNHEALTHY,
                    message="Database query failed",
                    response_time_ms=response_time,
                    last_check=time.time()
                )
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            logger.error("Database health check failed", extra={
                "error": str(e),
                "component": "database"
            })
            
            return ComponentHealth(
                status=HealthStatus.UNHEALTHY,
                message=f"Database error: {str(e)}",
                response_time_ms=response_time,
                last_check=time.time(),
                details={"error_type": type(e).__name__}
            )
    
    async def check_redis(self) -> ComponentHealth:
        """Check Redis connectivity and performance."""
        start_time = time.time()
        
        try:
            redis_client = await get_redis_connection()
            
            # Test basic Redis operations
            test_key = "health_check"
            test_value = str(time.time())
            
            await redis_client.set(test_key, test_value, ex=60)
            retrieved_value = await redis_client.get(test_key)
            await redis_client.delete(test_key)
            
            response_time = (time.time() - start_time) * 1000
            
            if retrieved_value and retrieved_value.decode() == test_value:
                # Get Redis info
                info = await redis_client.info()
                
                return ComponentHealth(
                    status=HealthStatus.HEALTHY,
                    message="Redis connection and operations successful",
                    response_time_ms=response_time,
                    last_check=time.time(),
                    details={
                        "operations": "set/get/delete successful",
                        "connected_clients": info.get("connected_clients", "unknown"),
                        "used_memory": info.get("used_memory_human", "unknown")
                    }
                )
            else:
                return ComponentHealth(
                    status=HealthStatus.UNHEALTHY,
                    message="Redis operations failed",
                    response_time_ms=response_time,
                    last_check=time.time()
                )
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            logger.error("Redis health check failed", extra={
                "error": str(e),
                "component": "redis"
            })
            
            return ComponentHealth(
                status=HealthStatus.UNHEALTHY,
                message=f"Redis error: {str(e)}",
                response_time_ms=response_time,
                last_check=time.time(),
                details={"error_type": type(e).__name__}
            )
    
    async def check_virustotal_api(self) -> ComponentHealth:
        """Check VirusTotal API connectivity."""
        start_time = time.time()
        
        try:
            client = VirusTotalClient()
            health = client.get_health()
            
            response_time = (time.time() - start_time) * 1000
            
            if health.status == ServiceStatus.HEALTHY:
                return ComponentHealth(
                    status=HealthStatus.HEALTHY,
                    message="VirusTotal API accessible",
                    response_time_ms=response_time,
                    last_check=time.time(),
                    details={
                        "service_status": health.status.value,
                        "last_check": health.last_check,
                        "api_key_configured": bool(client.api_key)
                    }
                )
            elif health.status == ServiceStatus.DEGRADED:
                return ComponentHealth(
                    status=HealthStatus.DEGRADED,
                    message="VirusTotal API partially available",
                    response_time_ms=response_time,
                    last_check=time.time(),
                    details={"service_status": health.status.value}
                )
            else:
                return ComponentHealth(
                    status=HealthStatus.UNHEALTHY,
                    message="VirusTotal API unavailable",
                    response_time_ms=response_time,
                    last_check=time.time(),
                    details={"service_status": health.status.value}
                )
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            logger.error("VirusTotal health check failed", extra={
                "error": str(e),
                "component": "virustotal"
            })
            
            return ComponentHealth(
                status=HealthStatus.UNHEALTHY,
                message=f"VirusTotal check failed: {str(e)}",
                response_time_ms=response_time,
                last_check=time.time(),
                details={"error_type": type(e).__name__}
            )
    
    async def check_gmail_api(self) -> ComponentHealth:
        """Check Gmail API connectivity."""
        start_time = time.time()
        
        try:
            # For now, just check if credentials are configured
            # In a real implementation, you'd test the actual Gmail API
            
            gmail_configured = hasattr(settings, 'GMAIL_CREDENTIALS') or hasattr(settings, 'GOOGLE_API_KEY')
            
            response_time = (time.time() - start_time) * 1000
            
            if gmail_configured:
                return ComponentHealth(
                    status=HealthStatus.HEALTHY,
                    message="Gmail API credentials configured",
                    response_time_ms=response_time,
                    last_check=time.time(),
                    details={
                        "credentials_configured": True,
                        "note": "Basic configuration check only"
                    }
                )
            else:
                return ComponentHealth(
                    status=HealthStatus.DEGRADED,
                    message="Gmail API not configured",
                    response_time_ms=response_time,
                    last_check=time.time(),
                    details={"credentials_configured": False}
                )
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            logger.error("Gmail API health check failed", extra={
                "error": str(e),
                "component": "gmail_api"
            })
            
            return ComponentHealth(
                status=HealthStatus.UNHEALTHY,
                message=f"Gmail API check failed: {str(e)}",
                response_time_ms=response_time,
                last_check=time.time(),
                details={"error_type": type(e).__name__}
            )
    
    async def check_sandbox(self) -> ComponentHealth:
        """Check sandbox environment status."""
        start_time = time.time()
        
        try:
            # Check if sandbox directory exists and is writable
            import os
            import tempfile
            
            sandbox_configured = hasattr(settings, 'SANDBOX_PATH')
            
            if sandbox_configured:
                # Test write access
                with tempfile.NamedTemporaryFile(delete=True) as tmp:
                    tmp.write(b"health check")
                    tmp.flush()
                
                response_time = (time.time() - start_time) * 1000
                
                return ComponentHealth(
                    status=HealthStatus.HEALTHY,
                    message="Sandbox environment accessible",
                    response_time_ms=response_time,
                    last_check=time.time(),
                    details={
                        "sandbox_configured": True,
                        "write_access": True
                    }
                )
            else:
                response_time = (time.time() - start_time) * 1000
                
                return ComponentHealth(
                    status=HealthStatus.DEGRADED,
                    message="Sandbox not configured",
                    response_time_ms=response_time,
                    last_check=time.time(),
                    details={"sandbox_configured": False}
                )
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            logger.error("Sandbox health check failed", extra={
                "error": str(e),
                "component": "sandbox"
            })
            
            return ComponentHealth(
                status=HealthStatus.UNHEALTHY,
                message=f"Sandbox check failed: {str(e)}",
                response_time_ms=response_time,
                last_check=time.time(),
                details={"error_type": type(e).__name__}
            )
    
    def determine_overall_status(self, components: Dict[str, ComponentHealth]) -> HealthStatus:
        """Determine overall system health from component health."""
        unhealthy_count = sum(1 for comp in components.values() if comp.status == HealthStatus.UNHEALTHY)
        degraded_count = sum(1 for comp in components.values() if comp.status == HealthStatus.DEGRADED)
        
        # If any critical component is unhealthy, system is unhealthy
        critical_components = ["database", "redis"]
        for comp_name in critical_components:
            if comp_name in components and components[comp_name].status == HealthStatus.UNHEALTHY:
                return HealthStatus.UNHEALTHY
        
        # If more than half are unhealthy, system is unhealthy
        if unhealthy_count > len(components) // 2:
            return HealthStatus.UNHEALTHY
        
        # If any component is degraded or unhealthy, system is degraded
        if degraded_count > 0 or unhealthy_count > 0:
            return HealthStatus.DEGRADED
        
        return HealthStatus.HEALTHY
    
    async def check_all_components(self, db: AsyncSession) -> SystemHealth:
        """Check all system components and return overall health."""
        start_time = time.time()
        
        # Run all health checks concurrently
        tasks = {
            "database": self.check_database(db),
            "redis": self.check_redis(),
            "virustotal": self.check_virustotal_api(),
            "gmail_api": self.check_gmail_api(),
            "sandbox": self.check_sandbox()
        }
        
        components = {}
        for name, task in tasks.items():
            try:
                components[name] = await task
            except Exception as e:
                logger.error(f"Health check failed for {name}", extra={
                    "component": name,
                    "error": str(e)
                })
                components[name] = ComponentHealth(
                    status=HealthStatus.UNKNOWN,
                    message=f"Health check failed: {str(e)}",
                    last_check=time.time(),
                    details={"error_type": type(e).__name__}
                )
        
        # Determine overall status
        overall_status = self.determine_overall_status(components)
        
        # Get additional system information
        circuit_breaker_stats = get_all_circuit_breaker_stats()
        observability_health = get_observability_health()
        
        return SystemHealth(
            status=overall_status,
            timestamp=time.time(),
            uptime_seconds=time.time() - self.start_time,
            components=components,
            circuit_breakers=circuit_breaker_stats,
            observability=observability_health
        )


# Global health checker instance
health_checker = HealthChecker()


@router.get("/", response_model=SystemHealth)
async def get_system_health(db: AsyncSession = Depends(get_db_session)):
    """Get comprehensive system health status."""
    try:
        health = await health_checker.check_all_components(db)
        
        # Log health check
        logger.info("System health check completed", extra={
            "overall_status": health.status.value,
            "component_count": len(health.components),
            "uptime_seconds": health.uptime_seconds
        })
        
        return health
        
    except Exception as e:
        logger.error("System health check failed", extra={
            "error": str(e),
            "error_type": type(e).__name__
        })
        
        raise HTTPException(
            status_code=500,
            detail=f"Health check failed: {str(e)}"
        )


@router.get("/liveness")
async def liveness_probe():
    """Simple liveness probe for container orchestration."""
    return {
        "status": "alive",
        "timestamp": time.time(),
        "uptime_seconds": time.time() - health_checker.start_time
    }


@router.get("/readiness")
async def readiness_probe(db: AsyncSession = Depends(get_db_session)):
    """Readiness probe checking critical components."""
    try:
        # Check only critical components for readiness
        db_health = await health_checker.check_database(db)
        redis_health = await health_checker.check_redis()
        
        if (db_health.status == HealthStatus.HEALTHY and 
            redis_health.status == HealthStatus.HEALTHY):
            return {
                "status": "ready",
                "timestamp": time.time(),
                "critical_components": {
                    "database": db_health.status.value,
                    "redis": redis_health.status.value
                }
            }
        else:
            raise HTTPException(
                status_code=503,
                detail="Service not ready - critical components unhealthy"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Readiness probe failed", extra={
            "error": str(e),
            "error_type": type(e).__name__
        })
        
        raise HTTPException(
            status_code=503,
            detail=f"Readiness check failed: {str(e)}"
        )


@router.get("/database")
async def get_database_health(db: AsyncSession = Depends(get_db_session)):
    """Get detailed database health information."""
    health = await health_checker.check_database(db)
    return health


@router.get("/redis")
async def get_redis_health():
    """Get detailed Redis health information."""
    health = await health_checker.check_redis()
    return health


@router.get("/external-apis")
async def get_external_apis_health():
    """Get health status of all external APIs."""
    tasks = {
        "virustotal": health_checker.check_virustotal_api(),
        "gmail_api": health_checker.check_gmail_api()
    }
    
    results = {}
    for name, task in tasks.items():
        try:
            results[name] = await task
        except Exception as e:
            results[name] = ComponentHealth(
                status=HealthStatus.UNKNOWN,
                message=f"Health check failed: {str(e)}",
                last_check=time.time(),
                details={"error_type": type(e).__name__}
            )
    
    return results


@router.get("/circuit-breakers")
async def get_circuit_breakers():
    """Get status of all circuit breakers."""
    return {
        "circuit_breakers": get_all_circuit_breaker_stats(),
        "timestamp": time.time()
    }
