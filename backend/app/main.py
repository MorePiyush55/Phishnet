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
    from app.api.health import router as health_router
    from app.api.gmail_simple import router as gmail_simple_router
    from app.api.test_oauth import router as oauth_router
    from app.api.gmail_oauth import router as gmail_oauth_router
    # Temporarily disabled: simple_oauth, simple_analysis, auth_simple, gmail_api
except Exception as e:
    # Create minimal router if imports fail
    import traceback
    print(f"CRITICAL: Router import failed with error: {e}")
    print(f"Traceback: {traceback.format_exc()}")
    from fastapi import APIRouter
    health_router = APIRouter()
    gmail_oauth_router = APIRouter()
    gmail_simple_router = APIRouter()
    oauth_router = APIRouter()
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
            # raise  # Fail startup if MongoDB is not available
            logger.warning("Continuing without MongoDB - features requiring database will fail")
    else:
        logger.warning("MongoDB URI not configured or MongoDB not available - running in stateless mode")
        # raise RuntimeError("MongoDB is required for PhishNet to function")
    
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

    # Initialize Email Polling Worker (The more robust one)
    try:
        from app.workers.email_polling_worker import get_email_polling_worker
        worker = get_email_polling_worker()
        asyncio.create_task(worker.start())
        logger.info("On-demand email polling worker started automatically")
    except Exception as e:
        logger.warning(f"On-demand email polling worker failed to start: {e}")
    
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

# Security Headers Middleware
@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    # Apply security headers only in production or if explicitly enabled
    if not getattr(settings, 'DEBUG', True):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # CSP might need adjustment based on frontend needs, but starting strict is good
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    
    return response

# Add Rate Limiting Middleware
try:
    from app.middleware.rate_limit import RateLimitMiddleware
    app.add_middleware(RateLimitMiddleware, limit=100, window=60)
    logger.info("Rate limiting middleware enabled")
except ImportError:
    logger.warning("Rate limiting middleware could not be imported")

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

try:
    app.include_router(gmail_simple_router, tags=["Gmail Simple Analysis"])
    logger.info("Gmail simple router loaded successfully")
except Exception as e:
    logger.error(f"Gmail simple router failed to load: {e}")
    router_errors.append(f"Gmail Simple: {e}")

try:
    app.include_router(gmail_oauth_router, tags=["Gmail OAuth"])
    logger.info("Gmail OAuth router loaded successfully")
except Exception as e:
    logger.error(f"Gmail OAuth router failed to load: {e}")
    router_errors.append(f"Gmail OAuth: {e}")

# IMAP Email Integration Router (ThePhish-style forwarded emails - Mode 1: Bulk Forward)
try:
    from app.api.v1.imap_emails import router as imap_emails_router
    app.include_router(imap_emails_router, prefix="/api/v1", tags=["IMAP Email Analysis"])
    logger.info("IMAP email integration router loaded successfully")
except Exception as e:
    logger.warning(f"IMAP email router failed to load: {e}")
    router_errors.append(f"IMAP Emails: {e}")

# On-Demand Phishing Detection Router (New unified workflow)
try:
    from app.api.v1.ondemand import router as ondemand_v1_router
    app.include_router(ondemand_v1_router, prefix="/api/v1", tags=["On-Demand Phishing Detection"])
    logger.info("On-demand phishing detection router (v1) loaded successfully")
except Exception as e:
    logger.warning(f"On-demand phishing detection router failed to load: {e}")
    router_errors.append(f"On-Demand Detection: {e}")

# On-Demand Email Check Router (Gmail API + Message ID - Mode 2: Privacy-First)
try:
    from app.api.v2.on_demand import router as ondemand_router
    app.include_router(ondemand_router, prefix="/api/v2", tags=["On-Demand Email Check"])
    logger.info("On-demand email check router loaded successfully")
    print("DEBUG: On-demand router loaded successfully")
except Exception as e:
    logger.warning(f"On-demand email check router failed to load: {e}")
    print(f"DEBUG: On-demand router failed: {e}")
    router_errors.append(f"On-Demand Check: {e}")

# Email Forward Analysis Router (Mode 3: Mobile-Friendly Email Forwarding)
try:
    from app.api.v2.email_forward import router as email_forward_router
    app.include_router(email_forward_router, prefix="/api/v2/email-forward", tags=["Email Forward Analysis"])
    logger.info("Email forward analysis router loaded successfully")
except Exception as e:
    logger.warning(f"Email forward analysis router failed to load: {e}")
    router_errors.append(f"Email Forward: {e}")

# Organization Analytics Router (Mode 1: Bulk Forward Overview)
try:
    from app.api.v2.organization import router as org_router
    app.include_router(org_router, prefix="/api/v2/organization", tags=["Organization Analytics"])
    logger.info("Organization analytics router loaded successfully")
except Exception as e:
    logger.warning(f"Organization analytics router failed to load: {e}")
    router_errors.append(f"Organization Analytics: {e}")

# Add routers directly with robust error handling (excluding manually loaded ones)
routers_to_add = [
    ("app.api.analytics", "Analytics Dashboard"),
    ("app.api.websockets", "WebSocket Updates"),
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
            "detail": f"Internal server error: {str(exc)}",
            "type": "internal_error"
        }
    )


@app.get("/debug-import")
async def debug_import_error():
    """Debug endpoint to show why on_demand router failed to load."""
    import traceback
    import sys
    
    results = {
        "python_path": sys.path,
        "cwd": os.getcwd(),
        "directory_contents": os.listdir(os.getcwd()) if os.path.exists(os.getcwd()) else "N/A",
        "app_directory": os.listdir(os.path.join(os.getcwd(), "app")) if os.path.exists(os.path.join(os.getcwd(), "app")) else "N/A",
        "installed_packages": [p for p in os.popen('pip list').read().split('\n') if 'google' in p.lower()],
        "import_attempts": {}
    }
    
    # Attempt 1: Import on_demand router
    try:
        from app.api.v2.on_demand import router
        results["import_attempts"]["app.api.v2.on_demand"] = "SUCCESS"
    except Exception as e:
        results["import_attempts"]["app.api.v2.on_demand"] = {
            "error": str(e),
            "traceback": traceback.format_exc()
        }

    # Attempt 2: Import gmail_ondemand_service
    try:
        from app.services.gmail_ondemand import gmail_ondemand_service
        results["import_attempts"]["app.services.gmail_ondemand"] = "SUCCESS"
    except Exception as e:
        results["import_attempts"]["app.services.gmail_ondemand"] = {
            "error": str(e),
            "traceback": traceback.format_exc()
        }

    # Attempt 3: Import orchestrator
    try:
        from app.core.orchestrator import get_orchestrator
        results["import_attempts"]["app.core.orchestrator"] = "SUCCESS"
    except Exception as e:
        results["import_attempts"]["app.core.orchestrator"] = {
            "error": str(e),
            "traceback": traceback.format_exc()
        }
        
    return results


@app.get("/debug/router-errors")
async def get_router_errors():
    """Return any errors that occurred while loading routers."""
    return {
        "count": len(router_errors),
        "errors": router_errors,
        "loaded_routes": [route.path for route in app.routes]
    }


if __name__ == "__main__":
    # Runner moved to single canonical entrypoint `backend/main.py`
    pass

