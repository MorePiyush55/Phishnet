"""Health check and observability endpoints."""

import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import text
import redis
import asyncio

from app.core.database import get_db
from app.config.settings import settings
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/health", tags=["health"])


class HealthChecker:
    """Health check service for monitoring system components."""
    
    def __init__(self):
        self.start_time = time.time()
    
    async def check_database(self, db: Session) -> Dict[str, Any]:
        """Check database connectivity and performance."""
        try:
            start_time = time.time()
            
            # Simple query to test connection
            result = db.execute(text("SELECT 1 as health_check"))
            result.fetchone()
            
            # Test write capability
            db.execute(text("SELECT NOW()"))
            
            response_time = (time.time() - start_time) * 1000
            
            return {
                "status": "healthy",
                "response_time_ms": round(response_time, 2),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    async def check_redis(self) -> Dict[str, Any]:
        """Check Redis connectivity and performance."""
        try:
            # Try to connect to Redis
            r = redis.from_url(settings.REDIS_URL)
            
            start_time = time.time()
            
            # Test basic operations
            test_key = f"health_check_{uuid.uuid4()}"
            r.set(test_key, "health_check", ex=10)
            value = r.get(test_key)
            r.delete(test_key)
            
            response_time = (time.time() - start_time) * 1000
            
            if value != b"health_check":
                raise Exception("Redis read/write test failed")
            
            return {
                "status": "healthy",
                "response_time_ms": round(response_time, 2),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Redis health check failed: {str(e)}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    async def check_external_apis(self) -> Dict[str, Any]:
        """Check external API connectivity."""
        import httpx
        
        api_checks = {}
        
        # Check Gemini API
        try:
            if settings.GOOGLE_GEMINI_API_KEY:
                import google.generativeai as genai
                genai.configure(api_key=settings.GOOGLE_GEMINI_API_KEY)
                model = genai.GenerativeModel('gemini-1.5-flash')
                
                start_time = time.time()
                response = model.generate_content("health check")
                response_time = (time.time() - start_time) * 1000
                
                api_checks["gemini"] = {
                    "status": "healthy",
                    "response_time_ms": round(response_time, 2)
                }
            else:
                api_checks["gemini"] = {"status": "disabled", "reason": "No API key"}
                
        except Exception as e:
            api_checks["gemini"] = {"status": "unhealthy", "error": str(e)}
        
        # Check VirusTotal API
        try:
            if settings.VIRUSTOTAL_API_KEY:
                async with httpx.AsyncClient() as client:
                    start_time = time.time()
                    response = await client.get(
                        "https://www.virustotal.com/api/v3/domains/google.com",
                        headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                        timeout=5
                    )
                    response_time = (time.time() - start_time) * 1000
                    
                    if response.status_code == 200:
                        api_checks["virustotal"] = {
                            "status": "healthy",
                            "response_time_ms": round(response_time, 2)
                        }
                    else:
                        api_checks["virustotal"] = {
                            "status": "unhealthy",
                            "error": f"HTTP {response.status_code}"
                        }
            else:
                api_checks["virustotal"] = {"status": "disabled", "reason": "No API key"}
                
        except Exception as e:
            api_checks["virustotal"] = {"status": "unhealthy", "error": str(e)}
        
        # Check AbuseIPDB API
        try:
            if settings.ABUSEIPDB_API_KEY:
                async with httpx.AsyncClient() as client:
                    start_time = time.time()
                    response = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                        params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
                        timeout=5
                    )
                    response_time = (time.time() - start_time) * 1000
                    
                    if response.status_code == 200:
                        api_checks["abuseipdb"] = {
                            "status": "healthy",
                            "response_time_ms": round(response_time, 2)
                        }
                    else:
                        api_checks["abuseipdb"] = {
                            "status": "unhealthy",
                            "error": f"HTTP {response.status_code}"
                        }
            else:
                api_checks["abuseipdb"] = {"status": "disabled", "reason": "No API key"}
                
        except Exception as e:
            api_checks["abuseipdb"] = {"status": "unhealthy", "error": str(e)}
        
        return api_checks
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information and metrics."""
        import psutil
        import sys
        
        uptime = time.time() - self.start_time
        
        return {
            "uptime_seconds": round(uptime, 2),
            "python_version": sys.version,
            "memory_usage": {
                "total_mb": round(psutil.virtual_memory().total / 1024 / 1024, 2),
                "available_mb": round(psutil.virtual_memory().available / 1024 / 1024, 2),
                "percent": psutil.virtual_memory().percent
            },
            "cpu_usage_percent": psutil.cpu_percent(interval=0.1),
            "disk_usage": {
                "total_gb": round(psutil.disk_usage('/').total / 1024 / 1024 / 1024, 2),
                "free_gb": round(psutil.disk_usage('/').free / 1024 / 1024 / 1024, 2),
                "percent": psutil.disk_usage('/').percent
            }
        }


# Global health checker instance
health_checker = HealthChecker()


@router.get("/")
async def health_check(request: Request, db: Session = Depends(get_db)):
    """Basic health check endpoint."""
    correlation_id = str(uuid.uuid4())
    
    try:
        # Add correlation ID to request state
        request.state.correlation_id = correlation_id
        
        # Quick database check
        db_health = await health_checker.check_database(db)
        
        if db_health["status"] == "healthy":
            return {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "correlation_id": correlation_id,
                "service": "phishnet-api",
                "version": settings.APP_VERSION
            }
        else:
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "unhealthy",
                    "reason": "Database connectivity issue",
                    "correlation_id": correlation_id
                }
            )
            
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}", extra={"correlation_id": correlation_id})
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unhealthy",
                "error": str(e),
                "correlation_id": correlation_id
            }
        )


@router.get("/detailed")
async def detailed_health_check(request: Request, db: Session = Depends(get_db)):
    """Detailed health check with all components."""
    correlation_id = str(uuid.uuid4())
    request.state.correlation_id = correlation_id
    
    try:
        # Run all health checks concurrently
        db_task = health_checker.check_database(db)
        redis_task = health_checker.check_redis()
        api_task = health_checker.check_external_apis()
        
        db_health, redis_health, api_health = await asyncio.gather(
            db_task, redis_task, api_task, return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(db_health, Exception):
            db_health = {"status": "unhealthy", "error": str(db_health)}
        if isinstance(redis_health, Exception):
            redis_health = {"status": "unhealthy", "error": str(redis_health)}
        if isinstance(api_health, Exception):
            api_health = {"status": "unhealthy", "error": str(api_health)}
        
        # Get system info
        system_info = health_checker.get_system_info()
        
        # Determine overall status
        overall_status = "healthy"
        if any(
            health.get("status") == "unhealthy" 
            for health in [db_health, redis_health]
        ):
            overall_status = "unhealthy"
        elif any(
            api.get("status") == "unhealthy" 
            for api in api_health.values() if isinstance(api_health, dict)
        ):
            overall_status = "degraded"
        
        return {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
            "service": "phishnet-api",
            "version": settings.APP_VERSION,
            "components": {
                "database": db_health,
                "redis": redis_health,
                "external_apis": api_health
            },
            "system": system_info
        }
        
    except Exception as e:
        logger.error(f"Detailed health check failed: {str(e)}", extra={"correlation_id": correlation_id})
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unhealthy",
                "error": str(e),
                "correlation_id": correlation_id
            }
        )


@router.get("/readiness")
async def readiness_check(db: Session = Depends(get_db)):
    """Kubernetes readiness probe endpoint."""
    try:
        # Check critical dependencies
        db_health = await health_checker.check_database(db)
        
        if db_health["status"] == "healthy":
            return {"status": "ready"}
        else:
            raise HTTPException(status_code=503, detail={"status": "not_ready"})
            
    except Exception:
        raise HTTPException(status_code=503, detail={"status": "not_ready"})


@router.get("/liveness")
async def liveness_check():
    """Kubernetes liveness probe endpoint."""
    return {
        "status": "alive",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": round(time.time() - health_checker.start_time, 2)
    }


@router.get("/startup")
async def startup_check(db: Session = Depends(get_db)):
    """Kubernetes startup probe endpoint."""
    try:
        uptime = time.time() - health_checker.start_time
        
        # Application needs at least 10 seconds to fully initialize
        if uptime < 10:
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "starting",
                    "message": "Application still initializing",
                    "uptime_seconds": round(uptime, 2)
                }
            )
        
        # Check that critical services are available
        db_health = await health_checker.check_database(db)
        redis_health = await health_checker.check_redis()
        
        if db_health["status"] != "healthy":
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "starting",
                    "message": "Database not ready",
                    "database": db_health
                }
            )
        
        if redis_health["status"] != "healthy":
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "starting",
                    "message": "Redis not ready",
                    "redis": redis_health
                }
            )
        
        return {
            "status": "started",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": round(uptime, 2),
            "service": "phishnet-api",
            "version": settings.APP_VERSION
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Startup check failed: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail={
                "status": "starting",
                "error": str(e)
            }
        )


@router.get("/metrics")
async def metrics_endpoint(db: Session = Depends(get_db)):
    """Prometheus metrics endpoint."""
    try:
        # Collect metrics
        db_health = await health_checker.check_database(db)
        redis_health = await health_checker.check_redis()
        system_info = health_checker.get_system_info()
        
        # Format metrics in Prometheus format
        metrics = []
        
        # Uptime metric
        metrics.append(f"phishnet_uptime_seconds {system_info['uptime_seconds']}")
        
        # Database metrics
        if db_health.get("response_time_ms"):
            metrics.append(f"phishnet_database_response_time_ms {db_health['response_time_ms']}")
        metrics.append(f"phishnet_database_healthy {1 if db_health['status'] == 'healthy' else 0}")
        
        # Redis metrics
        if redis_health.get("response_time_ms"):
            metrics.append(f"phishnet_redis_response_time_ms {redis_health['response_time_ms']}")
        metrics.append(f"phishnet_redis_healthy {1 if redis_health['status'] == 'healthy' else 0}")
        
        # System metrics
        metrics.append(f"phishnet_memory_usage_percent {system_info['memory_usage']['percent']}")
        metrics.append(f"phishnet_cpu_usage_percent {system_info['cpu_usage_percent']}")
        metrics.append(f"phishnet_disk_usage_percent {system_info['disk_usage']['percent']}")
        
        # Overall health metric
        overall_healthy = (
            db_health["status"] == "healthy" and 
            redis_health["status"] == "healthy"
        )
        metrics.append(f"phishnet_healthy {1 if overall_healthy else 0}")
        
        return "\n".join(metrics) + "\n"
        
    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        return f"# Error collecting metrics: {str(e)}\n"
