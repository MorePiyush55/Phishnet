"""Centralized router definitions for PhishNet backend."""

from fastapi import APIRouter

# Import all router modules
try:
    from ..api.health import router as health_router
    from ..api.test_oauth import router as test_oauth_router
    print("Successfully imported health and test_oauth routers")
except ImportError as e:
    # Fallback if imports fail
    print(f"Router import failed: {e}")
    from fastapi import APIRouter
    health_router = APIRouter()
    test_oauth_router = APIRouter()
    print("Using fallback routers")

# Create main router that includes all sub-routers
main_router = APIRouter()

# Include all routers with appropriate prefixes and tags
main_router.include_router(health_router, tags=["Health"])
main_router.include_router(test_oauth_router, tags=["Test OAuth"])

__all__ = ["main_router", "health_router", "test_oauth_router"]