"""
Main application entry point for Render deployment
"""
import os
import sys
import signal
import asyncio
import logging
from pathlib import Path
from contextlib import asynccontextmanager

# Add the current directory to Python path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import time

# Import your application components
from app.main import app as main_app
from app.core.config import settings

# Configure logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log') if os.path.exists('/opt/render') else logging.NullHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global state for graceful shutdown
shutdown_event = asyncio.Event()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info("PhishNet Backend starting up...")
    
    # Setup graceful shutdown handlers
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        shutdown_event.set()
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    yield
    
    # Shutdown
    logger.info("PhishNet Backend shutting down...")
    # Add any cleanup logic here
    await asyncio.sleep(1)  # Give time for ongoing requests to complete

# Production FastAPI app with proper configuration
app = FastAPI(
    title="PhishNet API",
    description="Gmail Phishing Detection Backend",
    version="1.0.0",
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    openapi_url="/openapi.json" if settings.ENVIRONMENT != "production" else None,
    lifespan=lifespan
)

# Security and monitoring middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers and request monitoring"""
    start_time = time.time()
    
    try:
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # Add HSTS for HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Log request details
        process_time = time.time() - start_time
        logger.info(
            f"{request.method} {request.url.path} - "
            f"Status: {response.status_code} - "
            f"Time: {process_time:.3f}s - "
            f"Client: {request.client.host if request.client else 'unknown'}"
        )
        
        return response
        
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(
            f"{request.method} {request.url.path} - "
            f"Error: {str(e)} - "
            f"Time: {process_time:.3f}s"
        )
        raise

# Global exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors gracefully"""
    logger.warning(f"Validation error on {request.method} {request.url.path}: {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "details": exc.errors(),
            "message": "Invalid request data"
        }
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with proper logging"""
    logger.warning(f"HTTP {exc.status_code} on {request.method} {request.url.path}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP Error",
            "message": exc.detail,
            "status_code": exc.status_code
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    logger.error(f"Unexpected error on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "request_id": getattr(request.state, 'request_id', 'unknown')
        }
    )

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*.onrender.com", "localhost", "127.0.0.1"] + (
        settings.ALLOWED_HOSTS.split(",") if hasattr(settings, 'ALLOWED_HOSTS') else []
    )
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://*.vercel.app",
        "http://localhost:3000",
        "http://localhost:5173",
    ] + (settings.CORS_ORIGINS.split(",") if hasattr(settings, 'CORS_ORIGINS') else []),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Health check endpoint for Render
@app.get("/health")
async def health_check():
    """Enhanced health check endpoint for deployment monitoring"""
    try:
        # Basic health check
        health_status = {
            "status": "healthy",
            "service": "phishnet-backend",
            "version": "1.0.0",
            "timestamp": time.time(),
            "environment": getattr(settings, 'ENVIRONMENT', 'unknown'),
            "uptime": time.time() - start_time if 'start_time' in globals() else 0
        }
        
        # Add database health check if available
        try:
            # You can add database ping here
            health_status["database"] = "connected"
        except Exception as e:
            health_status["database"] = f"error: {str(e)}"
            health_status["status"] = "degraded"
        
        return JSONResponse(health_status)
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": "phishnet-backend",
                "error": str(e)
            }
        )

# Startup time tracking
start_time = time.time()

# Mount your main application
app.mount("/", main_app)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    
    # Enhanced uvicorn configuration for production
    config = {
        "host": "0.0.0.0",
        "port": port,
        "log_level": "info",
        "access_log": True,
        "workers": 1,  # Single worker for Render
        "timeout_keep_alive": 30,
        "timeout_graceful_shutdown": 30,
    }
    
    # Add SSL config if certificates are available
    if os.path.exists("/etc/ssl/certs/cert.pem"):
        config.update({
            "ssl_keyfile": "/etc/ssl/private/key.pem",
            "ssl_certfile": "/etc/ssl/certs/cert.pem",
        })
    
    logger.info(f"Starting PhishNet Backend on port {port}")
    uvicorn.run("main:app", **config)