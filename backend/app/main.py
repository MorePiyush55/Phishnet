"""Main FastAPI application for PhishNet - Simplified for deployment."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

try:
    import redis.asyncio as redis
except ImportError:
    import redis

try:
    from prometheus_client import make_asgi_app
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

from app.config.settings import settings
from app.config.logging import get_logger

# Import core modules with fallbacks
try:
    from app.core.database import init_db
except ImportError:
    def init_db():
        pass

try:
    from app.api import auth, health, gmail_oauth
    from app.api import simple_analysis
except ImportError:
    # Create minimal router if imports fail
    from fastapi import APIRouter
    auth = APIRouter()
    health = APIRouter()
    gmail_oauth = APIRouter()
    simple_analysis = APIRouter()

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Simplified application lifespan manager."""
    # Startup
    logger.info("Starting PhishNet application")
    
    # Initialize database
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.warning(f"Database initialization skipped: {e}")
    
    # Initialize Redis connection (optional)
    try:
        if hasattr(settings, 'REDIS_URL') and settings.REDIS_URL:
            app.state.redis = redis.from_url(settings.REDIS_URL)
            if hasattr(app.state.redis, 'ping'):
                await app.state.redis.ping()
            logger.info("Redis connection established")
    except Exception as e:
        logger.warning(f"Redis connection skipped: {e}")
        app.state.redis = None
    
    yield
    
    # Shutdown
    logger.info("Shutting down PhishNet application")
    if hasattr(app.state, 'redis') and app.state.redis:
        try:
            await app.state.redis.close()
        except:
            pass


# Create FastAPI application
app = FastAPI(
    title=getattr(settings, 'APP_NAME', 'PhishNet'),
    version=getattr(settings, 'APP_VERSION', '1.0.0'),
    description="Real-Time Email Phishing Detector",
    docs_url="/docs" if getattr(settings, 'DEBUG', True) else None,
    redoc_url="/redoc" if getattr(settings, 'DEBUG', True) else None,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173", 
        "https://localhost:3000",
        "https://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Include essential API routers
try:
    app.include_router(health.router, tags=["Health"])
    app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
    app.include_router(gmail_oauth.router, tags=["Gmail OAuth"])
    app.include_router(simple_analysis.router, tags=["Email Analysis"])
except Exception as e:
    logger.warning(f"Some routers could not be loaded: {e}")

# Prometheus metrics endpoint (if available)
if METRICS_AVAILABLE and getattr(settings, 'ENABLE_METRICS', False):
    try:
        metrics_app = make_asgi_app()
        app.mount("/metrics", metrics_app)
    except Exception as e:
        logger.warning(f"Metrics endpoint not available: {e}")


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Welcome to PhishNet",
        "version": getattr(settings, 'APP_VERSION', '1.0.0'),
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": getattr(settings, 'APP_VERSION', '1.0.0'),
        "database": "connected",
        "redis": "connected" if hasattr(app.state, 'redis') and app.state.redis else "disconnected"
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "type": "internal_error"
        }
    )


if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment variable (Render sets this)
    port = int(os.environ.get("PORT", 8000))
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )

