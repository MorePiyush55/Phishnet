"""Centralized router definitions for PhishNet backend."""

from fastapi import APIRouter

# Import all router modules
try:
    from ..api.health import router as health_router
    from ..api.auth import router as auth_router
    from ..api.gmail_oauth import router as gmail_oauth_router
    from ..api.simple_analysis import router as simple_analysis_router
    from ..api.oauth_routes import router as oauth_router
    from ..api.v1.auth import router as v1_auth_router
except ImportError:
    # Fallback if imports fail
    from fastapi import APIRouter
    health_router = APIRouter()
    auth_router = APIRouter()
    gmail_oauth_router = APIRouter()
    simple_analysis_router = APIRouter()
    oauth_router = APIRouter()
    v1_auth_router = APIRouter()

# Create main router that includes all sub-routers
main_router = APIRouter()

# Include all routers with appropriate prefixes and tags
main_router.include_router(health_router, tags=["Health"])
main_router.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
main_router.include_router(v1_auth_router, prefix="/api/v1/auth", tags=["Auth V1"])
main_router.include_router(oauth_router, tags=["OAuth"])
main_router.include_router(gmail_oauth_router, tags=["Gmail OAuth"])
main_router.include_router(simple_analysis_router, tags=["Email Analysis"])

__all__ = ["main_router", "health_router", "auth_router", "v1_auth_router", "oauth_router", "gmail_oauth_router", "simple_analysis_router"]