"""Main FastAPI application for PhishNet with comprehensive observability."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import redis.asyncio as redis
from prometheus_client import make_asgi_app

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import init_db
from app.core.middleware import setup_middleware
from app.core.metrics import setup_metrics
from app.core.graceful_shutdown import setup_graceful_shutdown
from app.core.error_tracking import (
    ErrorTrackingMiddleware, 
    CorrelationIDMiddleware, 
    RequestLoggingMiddleware
)
from app.middleware.security import add_security_middleware
from app.observability.tracing import setup_observability
from app.observability.correlation import CorrelationIDMiddleware as NewCorrelationIDMiddleware, StructuredLoggingMiddleware
from app.api import auth, dashboard, email_analysis, analysis, scoring, health
from app.api.v1 import v1_router
from app.api.v1.websocket import router as websocket_router
from app.api.v1.health import router as health_v1_router
from app.core.middleware import setup_middleware
from app.core.database import engine
from app.models import user, email, detection, federated, link_analysis, scoring as scoring_models

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager with observability setup."""
    # Startup
    logger.info("Starting PhishNet application with observability")
    
    # Setup observability first
    setup_observability()
    
    # Initialize database
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    
    # Initialize Redis connection
    try:
        app.state.redis = redis.from_url(settings.REDIS_URL)
        await app.state.redis.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.warning(f"Failed to connect to Redis: {e}")
        app.state.redis = None
    
    yield
    
    # Shutdown
    logger.info("Shutting down PhishNet application")
    if hasattr(app.state, 'redis') and app.state.redis:
        await app.state.redis.close()


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Real-Time Email Phishing Detector with Federated Learning",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan
)

# Setup graceful shutdown handling
shutdown_handler = setup_graceful_shutdown(app)

# Setup observability and metrics
setup_metrics(app)

# Add observability middleware (order matters!)
app.add_middleware(NewCorrelationIDMiddleware)
app.add_middleware(StructuredLoggingMiddleware)
app.add_middleware(ErrorTrackingMiddleware)
app.add_middleware(RequestLoggingMiddleware, log_body=settings.DEBUG)

# Setup other middleware
setup_middleware(app, redis_client=app.state.redis if hasattr(app.state, 'redis') else None)

# Add comprehensive security middleware
security_config = {
    "rate_limit": 100,  # requests per minute
    "allowed_origins": [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://localhost:3000"
    ] if settings.DEBUG else ["https://yourdomain.com"],
    "strict_csp": not settings.DEBUG,  # Strict CSP for production
    "enable_hsts": not settings.DEBUG  # HSTS for production
}
add_security_middleware(app, security_config)

# Include API v1 routes (standardized contracts)
app.include_router(v1_router, tags=["API v1"])

# Include WebSocket router
app.include_router(websocket_router, prefix="/api/v1", tags=["WebSocket"])

# Include health endpoints with comprehensive monitoring
app.include_router(health_v1_router, prefix="/api/v1", tags=["Health v1"])

# Include legacy API routers (for backward compatibility)
app.include_router(health.router, tags=["Health"])
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(email_analysis.router, prefix="/api/email", tags=["Email Analysis"])
from app.api import federated
app.include_router(federated.router, prefix="/api/federated", tags=["Federated Learning"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(analysis.router, prefix="/api", tags=["Advanced Analysis"])
app.include_router(scoring.router, prefix="/api", tags=["Scoring & Response"])

# Prometheus metrics endpoint
if settings.ENABLE_METRICS:
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Welcome to PhishNet",
        "version": settings.APP_VERSION,
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "database": "connected",
        "redis": "connected" if hasattr(app.state, 'redis') and app.state.redis else "disconnected"
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.error(
        "Unhandled exception",
        exc_info=exc,
        path=request.url.path,
        method=request.method
    )
    
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "type": "internal_error"
        }
    )


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )

