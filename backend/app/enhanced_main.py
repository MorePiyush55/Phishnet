"""Enhanced main application for production-ready PhishNet."""

from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any
import asyncio
import json
import logging
import signal
import sys

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

from app.config.settings import settings
from app.config.logging import setup_logging, get_logger
from app.core.database import engine, Base
from app.core.redis_client import redis_client
from app.api.v2_enhanced import router as api_v2_router
from app.services.websocket_manager import websocket_manager
from app.services.gmail_secure import gmail_service
from app.services.gdpr_compliance import gdpr_manager
from app.workers.email_processor import EmailProcessor
from app.workers.threat_analyzer import ThreatAnalyzer

# Initialize logging
setup_logging()
logger = get_logger(__name__)

# Global worker references for graceful shutdown
workers: Dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown."""
    logger.info("🚀 PhishNet Enhanced v2.0 Starting Up...")
    
    try:
        # Initialize database
        logger.info("📊 Initializing database...")
        Base.metadata.create_all(bind=engine)
        
        # Initialize Redis
        logger.info("🔴 Connecting to Redis...")
        await redis_client.ping()
        
        # Initialize GDPR manager
        logger.info("🔒 Initializing GDPR compliance manager...")
        await gdpr_manager.initialize()
        
        # Start background workers (only if not in webhook-only mode)
        if not getattr(settings, 'WEBHOOK_ONLY_MODE', False):
            logger.info("👷 Starting background workers...")
            
            # Email processor workers
            for i in range(settings.EMAIL_WORKER_COUNT):
                worker = EmailProcessor(worker_id=f"email-{i}")
                task = asyncio.create_task(worker.start())
                workers[f"email_processor_{i}"] = {
                    "worker": worker,
                    "task": task
                }
            
            # Threat analyzer workers
            for i in range(settings.THREAT_WORKER_COUNT):
                worker = ThreatAnalyzer(worker_id=f"threat-{i}")
                task = asyncio.create_task(worker.start())
                workers[f"threat_analyzer_{i}"] = {
                    "worker": worker,
                    "task": task
                }
            
            logger.info(f"✅ Started {len(workers)} background workers")
        
        # Setup graceful shutdown handlers
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            asyncio.create_task(shutdown_workers())
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        logger.info("🎉 PhishNet Enhanced startup complete!")
        
        yield
        
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise
    
    finally:
        # Graceful shutdown
        logger.info("🛑 PhishNet Enhanced shutting down...")
        await shutdown_workers()
        
        # Close Redis connections
        try:
            await redis_client.close()
            logger.info("✅ Redis connections closed")
        except Exception as e:
            logger.error(f"Error closing Redis: {e}")
        
        logger.info("👋 PhishNet Enhanced shutdown complete")


async def shutdown_workers():
    """Gracefully shutdown all background workers."""
    if not workers:
        return
    
    logger.info(f"Stopping {len(workers)} workers...")
    
    # Stop all workers
    for worker_name, worker_info in workers.items():
        try:
            logger.info(f"Stopping {worker_name}...")
            await worker_info["worker"].stop()
            
            # Cancel the task
            worker_info["task"].cancel()
            try:
                await worker_info["task"]
            except asyncio.CancelledError:
                pass
                
        except Exception as e:
            logger.error(f"Error stopping worker {worker_name}: {e}")
    
    workers.clear()
    logger.info("✅ All workers stopped")


# Create FastAPI application
app = FastAPI(
    title="PhishNet Enhanced API",
    description="Production-ready email threat analysis with privacy-first design",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None
)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", settings.DOMAIN_NAME]
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        f"https://{settings.DOMAIN_NAME}",
        f"http://{settings.DOMAIN_NAME}",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ] if not settings.DEBUG else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"]
)


# Custom middleware for security headers
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' wss: ws:;"
    )
    
    return response


# Request logging middleware
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Log all requests with timing."""
    start_time = datetime.utcnow()
    
    # Log request
    logger.info(
        f"Request: {request.method} {request.url.path} "
        f"from {request.client.host if request.client else 'unknown'}"
    )
    
    try:
        response = await call_next(request)
        
        # Calculate duration
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        # Log response
        logger.info(
            f"Response: {response.status_code} "
            f"in {duration:.3f}s"
        )
        
        return response
        
    except Exception as e:
        duration = (datetime.utcnow() - start_time).total_seconds()
        logger.error(
            f"Request failed: {request.method} {request.url.path} "
            f"after {duration:.3f}s - {str(e)}"
        )
        raise


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with proper logging."""
    logger.warning(
        f"HTTP {exc.status_code}: {exc.detail} "
        f"for {request.method} {request.url.path}"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(
        f"Unhandled exception in {request.method} {request.url.path}: {str(exc)}",
        exc_info=True
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


# Include API routers
app.include_router(api_v2_router)

# Static files (for frontend)
if settings.SERVE_STATIC:
    app.mount("/static", StaticFiles(directory="frontend/dist"), name="static")


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with system information."""
    return {
        "service": "PhishNet Enhanced API",
        "version": "2.0.0",
        "status": "online",
        "timestamp": datetime.utcnow().isoformat(),
        "features": [
            "Gmail OAuth 2.0 Integration",
            "Real-time Threat Analysis",
            "Auto-quarantine System",
            "WebSocket Real-time Updates",
            "GDPR Compliance",
            "Privacy-first Design",
            "Multi-component Analysis",
            "Encrypted Credential Storage"
        ],
        "docs": "/docs" if settings.DEBUG else None
    }


# Health check endpoint
@app.get("/health")
async def health_check():
    """Comprehensive health check."""
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "2.0.0",
            "checks": {}
        }
        
        # Check Redis
        try:
            await redis_client.ping()
            health_status["checks"]["redis"] = "healthy"
        except Exception as e:
            health_status["checks"]["redis"] = f"unhealthy: {str(e)}"
            health_status["status"] = "degraded"
        
        # Check WebSocket manager
        try:
            ws_stats = websocket_manager.get_connection_stats()
            health_status["checks"]["websocket"] = {
                "status": "healthy",
                "active_connections": ws_stats["active_connections"]
            }
        except Exception as e:
            health_status["checks"]["websocket"] = f"unhealthy: {str(e)}"
            health_status["status"] = "degraded"
        
        # Check workers
        if workers:
            healthy_workers = 0
            total_workers = len(workers)
            
            for worker_name, worker_info in workers.items():
                try:
                    if not worker_info["task"].done():
                        healthy_workers += 1
                except:
                    pass
            
            health_status["checks"]["workers"] = {
                "status": "healthy" if healthy_workers == total_workers else "degraded",
                "healthy_workers": healthy_workers,
                "total_workers": total_workers
            }
            
            if healthy_workers < total_workers:
                health_status["status"] = "degraded"
        
        # Check Gmail service
        try:
            gmail_health = await gmail_service.health_check()
            health_status["checks"]["gmail_service"] = gmail_health
        except Exception as e:
            health_status["checks"]["gmail_service"] = f"unhealthy: {str(e)}"
            health_status["status"] = "degraded"
        
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


# Metrics endpoint
@app.get("/metrics")
async def get_metrics():
    """Get system metrics."""
    try:
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "version": "2.0.0",
            "uptime_seconds": 0,  # Would need startup tracking
            "workers": {},
            "queues": {},
            "websockets": {},
            "memory": {}
        }
        
        # WebSocket metrics
        try:
            metrics["websockets"] = websocket_manager.get_connection_stats()
        except Exception as e:
            logger.error(f"Error getting WebSocket metrics: {e}")
        
        # Queue metrics
        try:
            metrics["queues"] = {
                "email_processing": await redis_client.llen("email_processing_queue"),
                "threat_analysis": await redis_client.llen("threat_analysis_queue"),
                "quarantine_actions": await redis_client.llen("quarantine_actions_queue")
            }
        except Exception as e:
            logger.error(f"Error getting queue metrics: {e}")
        
        # Worker metrics
        if workers:
            for worker_name, worker_info in workers.items():
                try:
                    metrics["workers"][worker_name] = {
                        "status": "running" if not worker_info["task"].done() else "stopped",
                        "task_done": worker_info["task"].done()
                    }
                except Exception as e:
                    metrics["workers"][worker_name] = {"error": str(e)}
        
        return metrics
        
    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        return {"error": str(e), "timestamp": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    # Runner moved to single canonical entrypoint `backend/main.py`
    pass
