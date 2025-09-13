"""
PhishNet API v1 - Standardized API contracts
"""

from fastapi import APIRouter
from .auth import router as auth_router
from .emails import router as emails_router
from .links import router as links_router
from .analysis_endpoints import router as analysis_router
from .audits import router as audits_router
from .system import router as system_router
from .threat_analysis import router as threat_analysis_router

# Create v1 API router
v1_router = APIRouter(prefix="/api/v1", tags=["v1"])

# Include all v1 routers
v1_router.include_router(auth_router, prefix="/auth", tags=["auth"])
v1_router.include_router(emails_router, prefix="/emails", tags=["emails"])
v1_router.include_router(links_router, prefix="/links", tags=["links"])
v1_router.include_router(analysis_router, prefix="/analysis", tags=["analysis"])
v1_router.include_router(threat_analysis_router, tags=["threat-analysis"])
v1_router.include_router(audits_router, prefix="/audits", tags=["audits"])
v1_router.include_router(system_router, prefix="/system", tags=["system"])

# WebSocket is handled separately in main.py
