"""Centralized router definitions for PhishNet backend."""

from fastapi import APIRouter

# Import all router modules
try:
    from ..api.health import router as health_router
    from ..api.auth_simple import router as auth_router
    from ..api.gmail_oauth import router as gmail_oauth_router
    from ..api.simple_oauth import router as simple_oauth_router
    from ..api.simple_analysis import router as simple_analysis_router
    from ..api.oauth_routes import router as oauth_router
except ImportError as e:
    # Fallback if imports fail
    print(f"Router import failed: {e}")
    from fastapi import APIRouter
    health_router = APIRouter()
    auth_router = APIRouter()
    gmail_oauth_router = APIRouter()
    simple_oauth_router = APIRouter()
    simple_analysis_router = APIRouter()
    oauth_router = APIRouter()

# Create main router that includes all sub-routers
main_router = APIRouter()

# Include all routers with appropriate prefixes and tags
main_router.include_router(health_router, tags=["Health"])
main_router.include_router(auth_router, tags=["Authentication"])
main_router.include_router(oauth_router, tags=["OAuth"])
main_router.include_router(gmail_oauth_router, tags=["Gmail OAuth"])
main_router.include_router(simple_oauth_router, tags=["Simple OAuth"])
main_router.include_router(simple_analysis_router, tags=["Email Analysis"])

__all__ = ["main_router", "health_router", "auth_router", "oauth_router", "gmail_oauth_router", "simple_oauth_router", "simple_analysis_router"]