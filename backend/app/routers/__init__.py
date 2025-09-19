"""Centralized router definitions for PhishNet backend."""

from fastapi import APIRouter

# Import all router modules
try:
    from ..api.health import router as health_router
    from ..api.test_oauth import router as test_oauth_router
    from ..api.gmail_api import router as gmail_router
    print("Successfully imported health, test_oauth, and gmail routers")
except ImportError as e:
    # Fallback if imports fail
    print(f"Router import failed: {e}")
    from fastapi import APIRouter
    health_router = APIRouter()
    test_oauth_router = APIRouter()
    gmail_router = APIRouter()
    print("Using fallback routers")

# Create main router that includes all sub-routers
main_router = APIRouter()

# Include all routers with appropriate prefixes and tags
main_router.include_router(health_router, tags=["Health"])
main_router.include_router(test_oauth_router, tags=["Test OAuth"])
main_router.include_router(gmail_router, tags=["Gmail Analysis"])

__all__ = ["main_router", "health_router", "test_oauth_router", "gmail_router"]