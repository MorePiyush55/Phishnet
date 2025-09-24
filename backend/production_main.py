"""Production-ready PhishNet application with MongoDB Atlas integration."""

import asyncio
import logging
import signal
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
import uvicorn

# Import production components
from app.config.production_config import production_config, validate_production_config
from app.db.production_persistence import production_db_manager, persistent_session_manager
from app.core.production_oauth_security import production_oauth_security_manager
from app.services.production_gmail_oauth import production_gmail_oauth_service
from app.api.production_endpoints import production_router
from app.repositories.production_repositories import audit_log_repository

# Configure logging
logging.basicConfig(
    level=getattr(logging, production_config.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer(auto_error=False)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown."""
    
    # Startup
    logger.info("🚀 Starting PhishNet Production Application")
    
    try:
        # Validate configuration
        config_validation = validate_production_config(production_config)
        if not config_validation["valid"]:
            logger.error("Configuration validation failed:")
            for issue in config_validation["issues"]:
                logger.error(f"  - {issue}")
            raise RuntimeError("Configuration validation failed")
        
        if config_validation["warnings"]:
            for warning in config_validation["warnings"]:
                logger.warning(f"Configuration warning: {warning}")
        
        # Connect to MongoDB Atlas
        logger.info("📊 Connecting to MongoDB Atlas...")
        await production_db_manager.connect_to_atlas()
        
        if not production_db_manager.is_connected:
            raise RuntimeError("Failed to connect to MongoDB Atlas")
        
        # Initialize persistent session manager
        logger.info("🔐 Initializing persistent session management...")
        await persistent_session_manager.initialize()
        
        # Initialize OAuth security manager
        logger.info("🛡️ Initializing OAuth security manager...")
        await production_oauth_security_manager.initialize()
        
        # Initialize Gmail OAuth service
        logger.info("📧 Initializing Gmail OAuth service...")
        await production_gmail_oauth_service.initialize()
        
        # Health check
        health = await production_db_manager.health_check()
        logger.info(f"✅ Database health: {health}")
        
        # Log startup event
        await audit_log_repository.log_event({
            "event_type": "system_startup",
            "action": "application_started",
            "description": "PhishNet production application started successfully",
            "ip_address": "127.0.0.1",
            "user_agent": "PhishNet Production App",
            "metadata": {
                "environment": production_config.environment,
                "version": production_config.api_version,
                "mongodb_status": health.get("status", "unknown"),
                "collections": health.get("collections", 0)
            }
        })
        
        # Start background tasks
        if production_config.enable_health_checks:
            asyncio.create_task(health_monitor())
        
        if production_config.cleanup_interval_hours > 0:
            asyncio.create_task(data_cleanup_task())
        
        logger.info("🎉 PhishNet production application started successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise
    
    # Shutdown
    logger.info("🛑 Shutting down PhishNet Production Application")
    
    try:
        # Log shutdown event
        await audit_log_repository.log_event({
            "event_type": "system_shutdown",
            "action": "application_stopped",
            "description": "PhishNet production application shutdown initiated",
            "ip_address": "127.0.0.1",
            "user_agent": "PhishNet Production App",
            "metadata": {
                "environment": production_config.environment,
                "shutdown_time": datetime.now(timezone.utc).isoformat()
            }
        })
        
        # Cleanup connections
        await production_db_manager.disconnect()
        await production_oauth_security_manager.cleanup()
        
        logger.info("✅ PhishNet application shutdown completed")
        
    except Exception as e:
        logger.error(f"⚠️ Shutdown error: {e}")

# Create FastAPI application
app = FastAPI(
    title=production_config.api_title,
    version=production_config.api_version,
    description=production_config.api_description,
    lifespan=lifespan,
    docs_url="/docs" if production_config.debug else None,
    redoc_url="/redoc" if production_config.debug else None,
    openapi_url="/openapi.json" if production_config.debug else None
)

# Security Middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if production_config.debug else ["localhost", "127.0.0.1"]
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=production_config.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Security Headers Middleware
@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    if not production_config.debug:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
    
    return response

# Rate Limiting Middleware
rate_limit_storage = {}

@app.middleware("http")
async def rate_limiting(request: Request, call_next):
    """Simple rate limiting middleware."""
    
    client_ip = request.client.host
    current_time = datetime.now()
    
    # Simple sliding window rate limiting
    if client_ip not in rate_limit_storage:
        rate_limit_storage[client_ip] = []
    
    # Clean old requests
    rate_limit_storage[client_ip] = [
        req_time for req_time in rate_limit_storage[client_ip]
        if (current_time - req_time).total_seconds() < 60
    ]
    
    # Check rate limit
    if len(rate_limit_storage[client_ip]) >= production_config.rate_limit_per_minute:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"}
        )
    
    # Add current request
    rate_limit_storage[client_ip].append(current_time)
    
    return await call_next(request)

# Include production API routes
app.include_router(production_router, prefix="/api/v2")

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for load balancers."""
    
    try:
        # Check database health
        db_health = await production_db_manager.health_check()
        
        # Check session manager
        session_health = await persistent_session_manager.health_check()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": production_config.api_version,
            "environment": production_config.environment,
            "database": db_health,
            "sessions": session_health
        }
    
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(e)
            }
        )

# Metrics endpoint (if enabled)
@app.get("/metrics")
async def metrics():
    """Metrics endpoint for monitoring."""
    
    if not production_config.enable_metrics:
        raise HTTPException(status_code=404, detail="Metrics not enabled")
    
    try:
        # Get database metrics
        collection_stats = await production_db_manager.get_collection_stats()
        
        # Get session metrics
        session_stats = await persistent_session_manager.get_session_stats()
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": production_config.environment,
            "collections": collection_stats,
            "sessions": session_stats,
            "rate_limits": {
                "active_ips": len(rate_limit_storage),
                "total_requests": sum(len(reqs) for reqs in rate_limit_storage.values())
            }
        }
    
    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        raise HTTPException(status_code=500, detail="Metrics collection failed")

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "PhishNet Production API",
        "version": production_config.api_version,
        "environment": production_config.environment,
        "status": "running",
        "docs_url": "/docs" if production_config.debug else None
    }

# Background Tasks
async def health_monitor():
    """Background task to monitor system health."""
    
    while True:
        try:
            await asyncio.sleep(300)  # Check every 5 minutes
            
            # Check database health
            health = await production_db_manager.health_check()
            
            if health.get("status") != "healthy":
                logger.warning(f"Database health warning: {health}")
                
                # Log health issue
                await audit_log_repository.log_event({
                    "event_type": "system_health",
                    "action": "health_warning",
                    "description": f"Database health check warning: {health.get('status')}",
                    "ip_address": "127.0.0.1",
                    "user_agent": "Health Monitor",
                    "metadata": {"health_status": health}
                })
        
        except Exception as e:
            logger.error(f"Health monitor error: {e}")

async def data_cleanup_task():
    """Background task for data cleanup."""
    
    while True:
        try:
            # Sleep for cleanup interval
            await asyncio.sleep(production_config.cleanup_interval_hours * 3600)
            
            logger.info("🧹 Starting data cleanup task")
            
            # Cleanup expired sessions
            session_cleanup_count = await persistent_session_manager.cleanup_expired_sessions()
            
            # Cleanup old audit logs (keep last 90 days)
            audit_cleanup_count = await audit_log_repository.cleanup_old_entries(days=90)
            
            # Log cleanup results
            await audit_log_repository.log_event({
                "event_type": "system_maintenance",
                "action": "data_cleanup",
                "description": "Scheduled data cleanup completed",
                "ip_address": "127.0.0.1",
                "user_agent": "Cleanup Task",
                "metadata": {
                    "sessions_cleaned": session_cleanup_count,
                    "audit_logs_cleaned": audit_cleanup_count
                }
            })
            
            logger.info(f"✅ Data cleanup completed: {session_cleanup_count} sessions, {audit_cleanup_count} audit logs")
        
        except Exception as e:
            logger.error(f"Data cleanup error: {e}")

# Signal handlers for graceful shutdown
def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")

if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Production server configuration
    server_config = {
        "host": "0.0.0.0",
        "port": int(os.environ.get("PORT", 8000)),
        "workers": int(os.environ.get("WORKERS", 1)),
        "log_level": production_config.log_level.lower(),
        "access_log": production_config.debug,
        "reload": False,
        "loop": "uvloop" if not os.name == 'nt' else "asyncio"  # Use uvloop on Unix
    }
    
    logger.info(f"🚀 Starting PhishNet production server: {server_config}")
    
    # Run server
    uvicorn.run(
        "production_main:app",
        **server_config
    )