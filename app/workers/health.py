"""
Health endpoints for PhishNet worker processes.
Provides readiness and liveness probes for worker deployments.
"""

import asyncio
import logging
import signal
import time
import os
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
import redis.asyncio as redis
from contextlib import asynccontextmanager

from app.config.settings import settings

logger = logging.getLogger(__name__)

class WorkerHealthChecker:
    """Health checking for PhishNet worker processes."""
    
    def __init__(self, worker_type: str = "generic"):
        self.worker_type = worker_type
        self.startup_time = time.time()
        self.is_healthy = True
        self.is_stopping = False
        self.last_job_time = time.time()
        self.processed_jobs = 0
        
        # Check for stop signal file
        self.stop_file = "/tmp/worker_stop"
        
    def mark_job_processed(self):
        """Mark that a job was just processed."""
        self.last_job_time = time.time()
        self.processed_jobs += 1
    
    def should_stop(self) -> bool:
        """Check if worker should stop accepting new jobs."""
        return os.path.exists(self.stop_file) or self.is_stopping
    
    def set_stopping(self):
        """Mark worker as stopping."""
        self.is_stopping = True
        logger.info(f"{self.worker_type} worker marked as stopping")
    
    async def check_redis_connection(self) -> Dict[str, Any]:
        """Check Redis connection for queue access."""
        try:
            redis_client = redis.from_url(settings.REDIS_URL)
            start_time = time.time()
            
            pong = await redis_client.ping()
            response_time = (time.time() - start_time) * 1000
            
            await redis_client.close()
            
            return {
                "status": "healthy",
                "response_time_ms": round(response_time, 2),
                "ping_result": pong
            }
            
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e)
            }
    
    async def check_queue_connectivity(self) -> Dict[str, Any]:
        """Check ability to connect to job queues."""
        try:
            redis_client = redis.from_url(settings.REDIS_URL)
            
            # Check queue existence and size
            queue_name = f"{self.worker_type}_queue"
            queue_size = await redis_client.llen(queue_name)
            
            await redis_client.close()
            
            return {
                "status": "healthy",
                "queue_name": queue_name,
                "queue_size": queue_size
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }

# Global health checker
health_checker = None

def get_health_checker(worker_type: str = None) -> WorkerHealthChecker:
    """Get or create global health checker."""
    global health_checker
    if health_checker is None:
        worker_type = worker_type or os.getenv("WORKER_TYPE", "generic")
        health_checker = WorkerHealthChecker(worker_type)
    return health_checker

# Create FastAPI app for health endpoints
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Worker application lifespan manager."""
    # Startup
    logger.info(f"Starting {app.state.worker_type} worker health server")
    
    # Register signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, stopping worker...")
        health_checker.set_stopping()
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    yield
    
    # Shutdown
    logger.info(f"Shutting down {app.state.worker_type} worker health server")

def create_worker_health_app(worker_type: str = "generic", port: int = 8001) -> FastAPI:
    """Create FastAPI app for worker health endpoints."""
    
    app = FastAPI(
        title=f"PhishNet {worker_type.title()} Worker Health",
        version="1.0.0",
        description=f"Health endpoints for {worker_type} worker",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan
    )
    
    app.state.worker_type = worker_type
    app.state.port = port
    
    # Get health checker
    checker = get_health_checker(worker_type)
    
    @app.get("/health/startup")
    async def startup_check():
        """Startup probe - check if worker is ready to start processing."""
        try:
            uptime = time.time() - checker.startup_time
            
            # Worker needs time to initialize
            if uptime < 5:
                raise HTTPException(
                    status_code=503,
                    detail={
                        "status": "starting",
                        "message": f"{worker_type} worker still initializing",
                        "uptime_seconds": round(uptime, 2)
                    }
                )
            
            # Check Redis connectivity
            redis_health = await checker.check_redis_connection()
            if redis_health["status"] != "healthy":
                raise HTTPException(
                    status_code=503,
                    detail={
                        "status": "starting",
                        "message": "Redis not available",
                        "redis": redis_health
                    }
                )
            
            return {
                "status": "started",
                "worker_type": worker_type,
                "uptime_seconds": round(uptime, 2),
                "timestamp": time.time()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Worker startup check failed: {e}")
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "starting",
                    "error": str(e)
                }
            )
    
    @app.get("/health/liveness")
    async def liveness_check():
        """Liveness probe - check if worker process is alive."""
        uptime = time.time() - checker.startup_time
        time_since_job = time.time() - checker.last_job_time
        
        # Worker is considered dead if it hasn't processed jobs in a long time
        # and the queue has items waiting
        max_idle_time = 300  # 5 minutes
        
        status = "alive"
        if checker.is_stopping:
            status = "stopping"
        elif time_since_job > max_idle_time:
            # Check if there are jobs waiting
            queue_health = await checker.check_queue_connectivity()
            if queue_health.get("queue_size", 0) > 0:
                status = "stalled"
        
        return {
            "status": status,
            "worker_type": worker_type,
            "uptime_seconds": round(uptime, 2),
            "processed_jobs": checker.processed_jobs,
            "time_since_last_job": round(time_since_job, 2),
            "timestamp": time.time()
        }
    
    @app.get("/health/readiness")
    async def readiness_check():
        """Readiness probe - check if worker is ready to process jobs."""
        try:
            # Check if worker is stopping
            if checker.should_stop():
                raise HTTPException(
                    status_code=503,
                    detail={
                        "status": "not_ready",
                        "message": "Worker is stopping"
                    }
                )
            
            # Check Redis connectivity
            redis_health = await checker.check_redis_connection()
            if redis_health["status"] != "healthy":
                raise HTTPException(
                    status_code=503,
                    detail={
                        "status": "not_ready",
                        "message": "Redis connection failed",
                        "redis": redis_health
                    }
                )
            
            # Check queue connectivity
            queue_health = await checker.check_queue_connectivity()
            if queue_health["status"] != "healthy":
                raise HTTPException(
                    status_code=503,
                    detail={
                        "status": "not_ready",
                        "message": "Queue connection failed",
                        "queue": queue_health
                    }
                )
            
            return {
                "status": "ready",
                "worker_type": worker_type,
                "redis": redis_health,
                "queue": queue_health,
                "timestamp": time.time()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Worker readiness check failed: {e}")
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "not_ready",
                    "error": str(e)
                }
            )
    
    @app.get("/health")
    async def health_check():
        """Basic health check."""
        uptime = time.time() - checker.startup_time
        
        return {
            "status": "healthy",
            "worker_type": worker_type,
            "uptime_seconds": round(uptime, 2),
            "processed_jobs": checker.processed_jobs,
            "is_stopping": checker.is_stopping,
            "timestamp": time.time()
        }
    
    @app.get("/metrics")
    async def metrics_endpoint():
        """Prometheus metrics for worker."""
        try:
            uptime = time.time() - checker.startup_time
            time_since_job = time.time() - checker.last_job_time
            
            # Get queue info
            queue_health = await checker.check_queue_connectivity()
            queue_size = queue_health.get("queue_size", 0)
            
            # Get Redis info
            redis_health = await checker.check_redis_connection()
            
            metrics = []
            
            # Worker metrics
            metrics.append(f"phishnet_worker_uptime_seconds{{worker_type=\"{worker_type}\"}} {uptime}")
            metrics.append(f"phishnet_worker_processed_jobs_total{{worker_type=\"{worker_type}\"}} {checker.processed_jobs}")
            metrics.append(f"phishnet_worker_time_since_last_job_seconds{{worker_type=\"{worker_type}\"}} {time_since_job}")
            metrics.append(f"phishnet_worker_stopping{{worker_type=\"{worker_type}\"}} {1 if checker.is_stopping else 0}")
            
            # Queue metrics
            metrics.append(f"phishnet_worker_queue_size{{worker_type=\"{worker_type}\"}} {queue_size}")
            
            # Health metrics
            metrics.append(f"phishnet_worker_healthy{{worker_type=\"{worker_type}\"}} {1 if not checker.is_stopping else 0}")
            metrics.append(f"phishnet_worker_redis_healthy{{worker_type=\"{worker_type}\"}} {1 if redis_health['status'] == 'healthy' else 0}")
            
            if redis_health.get("response_time_ms"):
                metrics.append(f"phishnet_worker_redis_response_time_ms{{worker_type=\"{worker_type}\"}} {redis_health['response_time_ms']}")
            
            return "\n".join(metrics) + "\n"
            
        except Exception as e:
            logger.error(f"Worker metrics collection failed: {e}")
            return f"# Error collecting worker metrics: {str(e)}\n"
    
    return app

# Helper function to run worker health server
async def run_worker_health_server(worker_type: str = "generic", port: int = 8001):
    """Run the worker health server."""
    import uvicorn
    
    app = create_worker_health_app(worker_type, port)
    
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=False  # Reduce log noise from health checks
    )
    
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    import sys
    
    worker_type = sys.argv[1] if len(sys.argv) > 1 else "generic"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8001
    
    asyncio.run(run_worker_health_server(worker_type, port))
