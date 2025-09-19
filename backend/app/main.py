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
    from app.api import health, gmail_oauth, simple_oauth
    from app.api import simple_analysis
    from app.api import auth_simple
    from app.api import test_oauth, gmail_api
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

logger = get_logger(__name__)


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
    
    yield
    
    # Shutdown
    logger.info("Shutting down PhishNet application")
    
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
    description="Real-Time Email Phishing Detector",
    docs_url="/docs" if getattr(settings, 'DEBUG', True) else None,
    redoc_url="/redoc" if getattr(settings, 'DEBUG', True) else None,
    lifespan=lifespan
)

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
try:
    from .routers import main_router
    app.include_router(main_router)
    logger.info("Main router loaded successfully")
except Exception as e:
    logger.warning(f"Main router could not be loaded: {e}")
    # Fallback to individual router includes
    
    # Try to include each router individually
    try:
        from app.api import health
        app.include_router(health.router, tags=["Health"])
        logger.info("Health router loaded")
    except Exception as e:
        logger.error(f"Health router failed: {e}")
        router_errors.append(f"health: {e}")
    
    try:
        from app.api import auth_simple
        app.include_router(auth_simple.router, tags=["Authentication"])
        logger.info("Auth router loaded")
    except Exception as e:
        logger.error(f"Auth router failed: {e}")
        router_errors.append(f"auth: {e}")
    
    try:
        from app.api import simple_oauth
        app.include_router(simple_oauth.router, tags=["Simple OAuth"])
        logger.info("Simple OAuth router loaded")
    except Exception as e:
        logger.error(f"Simple OAuth router failed: {e}")
        router_errors.append(f"simple_oauth: {e}")
    
    try:
        from app.api import gmail_oauth
        app.include_router(gmail_oauth.router, tags=["Gmail OAuth"])
        logger.info("Gmail OAuth router loaded")
    except Exception as e:
        logger.error(f"Gmail OAuth router failed: {e}")
        router_errors.append(f"gmail_oauth: {e}")
    
    try:
        from app.api import simple_analysis
        app.include_router(simple_analysis.router, tags=["Email Analysis"])
        logger.info("Analysis router loaded")
    except Exception as e:
        logger.error(f"Analysis router failed: {e}")
        router_errors.append(f"analysis: {e}")

    # Add test_oauth router
    try:
        from app.api import test_oauth
        app.include_router(test_oauth.router, tags=["Test OAuth"])
        logger.info("Test OAuth router loaded")
    except Exception as e:
        logger.error(f"Test OAuth router failed: {e}")
        router_errors.append(f"test_oauth: {e}")

    # Add gmail_api router
    try:
        from app.api import gmail_api
        app.include_router(gmail_api.router, tags=["Gmail Analysis"])
        logger.info("Gmail API router loaded")
    except Exception as e:
        logger.error(f"Gmail API router failed: {e}")
        router_errors.append(f"gmail_api: {e}")

if router_errors:
    logger.error(f"Router loading errors: {router_errors}")

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

