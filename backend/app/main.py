"""Main FastAPI application for PhishNet with comprehensive observability."""

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

# Observability imports
try:
    from app.observability import (
        get_logger as get_structured_logger,
        tracing_manager,
        error_capture
    )
    from app.observability.middleware import (
        ObservabilityMiddleware,
        HealthCheckMiddleware
    )
    OBSERVABILITY_AVAILABLE = True
except ImportError:
    OBSERVABILITY_AVAILABLE = False
    get_structured_logger = get_logger

# Privacy compliance imports
try:
    from app.privacy.middleware import (
        PrivacyComplianceMiddleware,
        ConsentEnforcementMiddleware,
        DataMinimizationMiddleware
    )
    PRIVACY_AVAILABLE = True
except ImportError:
    PRIVACY_AVAILABLE = False

# MongoDB support
try:
    from app.db.mongodb import MongoDBManager
    from app.models.mongodb_models import DOCUMENT_MODELS
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    MongoDBManager = None
    DOCUMENT_MODELS = []

try:
    from app.api.health import router as health_router  # Direct import to avoid __init__.py
    from app.api.test_oauth import router as oauth_router  # Direct import to avoid conflicts
    # Note: Avoiding "from app.api import" to prevent SQLAlchemy model conflicts
    # Temporarily disabled: gmail_oauth, simple_oauth, simple_analysis, auth_simple, gmail_api
except ImportError:
    # Create minimal router if imports fail
    from fastapi import APIRouter
    health = APIRouter()
    gmail_oauth = APIRouter()
    simple_oauth = APIRouter()
    simple_analysis = APIRouter()
    auth_simple = APIRouter()
    test_oauth = APIRouter()
    gmail_api = APIRouter()

# Use structured logger if available
logger = get_structured_logger(__name__) if OBSERVABILITY_AVAILABLE else get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Simplified application lifespan manager."""
    # Startup
    logger.info("Starting PhishNet application")
    
    # Initialize MongoDB
    if MONGODB_AVAILABLE and settings.get_mongodb_uri():
        try:
            await MongoDBManager.connect_to_mongo()
            await MongoDBManager.initialize_beanie(DOCUMENT_MODELS)
            logger.info("MongoDB initialized successfully")
        except Exception as e:
            logger.error(f"MongoDB initialization failed: {e}")
            raise  # Fail startup if MongoDB is not available
    else:
        logger.error("MongoDB URI not configured or MongoDB not available")
        raise RuntimeError("MongoDB is required for PhishNet to function")
    
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
    
    # Initialize real-time monitoring
    try:
        from app.services.real_time_monitor import real_time_monitor
        import asyncio
        # Start monitoring in background
        asyncio.create_task(real_time_monitor.start_monitoring())
        logger.info("Real-time monitoring started")
    except Exception as e:
        logger.warning(f"Real-time monitoring initialization failed: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down PhishNet application")
    
    # Stop real-time monitoring
    try:
        from app.services.real_time_monitor import real_time_monitor
        await real_time_monitor.stop_monitoring()
        logger.info("Real-time monitoring stopped")
    except Exception as e:
        logger.warning(f"Error stopping real-time monitoring: {e}")
    
    # Close MongoDB connection
    if MONGODB_AVAILABLE and MongoDBManager.client:
        try:
            await MongoDBManager.close_mongo_connection()
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {e}")
    
    # Close Redis connection
    if hasattr(app.state, 'redis') and app.state.redis:
        try:
            await app.state.redis.close()
        except:
            pass


# Create FastAPI application
app = FastAPI(
    title=getattr(settings, 'APP_NAME', 'PhishNet'),
    version=getattr(settings, 'APP_VERSION', '1.0.0'),
    description="Real-Time Email Phishing Detector with Observability",
    docs_url="/docs" if getattr(settings, 'DEBUG', True) else None,
    redoc_url="/redoc" if getattr(settings, 'DEBUG', True) else None,
    lifespan=lifespan
)

# Add observability middleware first
if OBSERVABILITY_AVAILABLE:
    app.add_middleware(
        ObservabilityMiddleware,
        slow_request_threshold=getattr(settings, 'SLOW_REQUEST_THRESHOLD_MS', 1000.0)
    )
    app.add_middleware(HealthCheckMiddleware)

# Add privacy compliance middleware
if PRIVACY_AVAILABLE:
    app.add_middleware(
        PrivacyComplianceMiddleware,
        enable_pii_redaction=getattr(settings, 'GDPR_COMPLIANCE_ENABLED', True),
        enable_audit_logging=True
    )
    app.add_middleware(
        ConsentEnforcementMiddleware,
        consent_required_paths=['/api/v1/gmail', '/api/v1/analyze', '/api/v1/scan']
    )
    app.add_middleware(DataMinimizationMiddleware)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=getattr(settings, 'CORS_ORIGINS', [
        "http://localhost:3000",
        "http://localhost:5173", 
        "https://localhost:3000",
        "https://localhost:5173",
        "https://phishnet-1ed1.onrender.com",
        "https://phishnet-frontend.vercel.app"
    ]),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Include essential API routers
router_errors = []

# Load essential routers manually (avoiding SQLAlchemy conflicts)
try:
    app.include_router(health_router, tags=["Health"])
    logger.info("Health router loaded successfully")
except Exception as e:
    logger.error(f"Health router failed to load: {e}")
    router_errors.append(f"Health: {e}")

try:
    app.include_router(oauth_router, tags=["OAuth"])
    logger.info("OAuth router loaded successfully")  
except Exception as e:
    logger.error(f"OAuth router failed to load: {e}")
    router_errors.append(f"OAuth: {e}")

# Add routers directly with robust error handling (excluding manually loaded ones)
routers_to_add = [
    # ("app.api.health", "Health"),  # Loaded manually above
    # ("app.api.test_oauth", "Test OAuth"),  # Loaded manually above
    ("app.api.analytics", "Analytics Dashboard"),
    # ("app.api.websocket", "Real-time Monitoring"),  # Temporarily disabled - SQLAlchemy conflict
    # ("app.api.gmail_api", "Gmail Analysis"),  # Temporarily disabled - SQLAlchemy conflict
    # ("app.api.gmail_simple", "Gmail Simple"),  # Temporarily disabled - SQLAlchemy conflict
    ("app.api.auth_simple", "Authentication"),
    ("app.api.simple_oauth", "Simple OAuth"),
    # ("app.api.gmail_oauth", "Gmail OAuth"),  # Temporarily disabled - SQLAlchemy conflict
    ("app.api.simple_analysis", "Email Analysis"),
    # ("app.api.async_analysis", "Async Email Analysis"),  # Temporarily disabled - enum conflict
    ("app.api.websockets", "WebSocket Updates"),
    # ("app.api.link_analysis", "Link Redirect Analysis"),  # Causes SQLAlchemy conflicts
    # ("app.api.threat_intelligence", "Threat Intelligence"),  # Temporarily disabled - missing aiohttp
    # ("app.api.workers", "Worker Management"),  # Temporarily disabled - Redis mock issue
    ("app.observability.routes", "Observability"),
    ("app.privacy.routes", "Privacy & Compliance")
]

for module_path, tag in routers_to_add:
    try:
        module = __import__(module_path, fromlist=['router'])
        app.include_router(module.router, tags=[tag])
        logger.info(f"{tag} router loaded successfully")
    except Exception as e:
        logger.error(f"{tag} router failed to load: {e}")
        router_errors.append(f"{tag}: {e}")

# Try to load main_router as fallback
try:
    from .routers import main_router
    logger.info("Main router also loaded as fallback")
except Exception as e:
    logger.warning(f"Main router could not be loaded: {e}")

# Load v1 compatibility router for OAuth
try:
    from app.api.test_oauth import v1_router
    app.include_router(v1_router, tags=["OAuth v1 Compatibility"])
    logger.info("OAuth v1 compatibility router loaded successfully")
except Exception as e:
    logger.warning(f"OAuth v1 compatibility router failed to load: {e}")

# Load REST compatibility router for OAuth
try:
    from app.api.test_oauth import rest_router
    app.include_router(rest_router, tags=["OAuth REST Compatibility"])
    logger.info("OAuth REST compatibility router loaded successfully")
except Exception as e:
    logger.warning(f"OAuth REST compatibility router failed to load: {e}")

# Debug router for OAuth configuration checking
try:
    from app.api.debug_oauth import router as debug_router
    app.include_router(debug_router, tags=["Debug"])
    logger.info("OAuth debug router loaded successfully")
except Exception as e:
    logger.warning(f"OAuth debug router failed to load: {e}")

# Simple OAuth router without MongoDB complexity
try:
    from app.api.test_oauth import simple_router
    app.include_router(simple_router, tags=["Simple OAuth"])
    logger.info("Simple OAuth router loaded successfully")
except Exception as e:
    logger.warning(f"Simple OAuth router failed to load: {e}")

if router_errors:
    logger.error(f"Router loading errors: {router_errors}")

# Prometheus metrics endpoint (if available) - Legacy support
if METRICS_AVAILABLE and getattr(settings, 'ENABLE_METRICS', False):
    try:
        metrics_app = make_asgi_app()
        app.mount("/legacy-metrics", metrics_app)  # Rename to avoid conflict
    except Exception as e:
        logger.warning(f"Legacy metrics endpoint not available: {e}")


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


@app.get("/test-oauth")
async def test_oauth_direct():
    """Direct test OAuth endpoint in main.py."""
    try:
        import os
        client_id = os.getenv("GMAIL_CLIENT_ID")
        redirect_uri = os.getenv("GMAIL_REDIRECT_URI")
        
        return {
            "success": True,
            "message": "Direct OAuth test endpoint working",
            "has_client_id": bool(client_id),
            "has_redirect_uri": bool(redirect_uri),
            "client_id_start": client_id[:10] + "..." if client_id else None
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/privacy")
async def privacy_policy():
    """Privacy policy page for OAuth consent screen."""
    try:
        from fastapi.responses import FileResponse
        import os
        privacy_path = os.path.join(os.path.dirname(__file__), "templates", "privacy.html")
        return FileResponse(privacy_path, media_type="text/html")
    except Exception as e:
        logger.error(f"Error serving privacy policy: {e}")
        return {"message": "Privacy policy available at our website"}


@app.get("/terms")
async def terms_of_service():
    """Terms of service page for OAuth consent screen."""
    try:
        from fastapi.responses import FileResponse
        import os
        terms_path = os.path.join(os.path.dirname(__file__), "templates", "terms.html")
        return FileResponse(terms_path, media_type="text/html")
    except Exception as e:
        logger.error(f"Error serving terms of service: {e}")
        return {"message": "Terms of service available at our website"}


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
    # Runner moved to single canonical entrypoint `backend/main.py`
    pass

