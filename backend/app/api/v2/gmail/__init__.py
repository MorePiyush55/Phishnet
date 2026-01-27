"""
Mode 2 - Gmail On-Demand API Routes
====================================

Privacy-first endpoints for user-initiated email verification via Gmail API.

Routes:
    /check - On-demand email checking
    /oauth - OAuth flow management
    /status - Analysis status tracking
"""

from fastapi import APIRouter

from .check import router as check_router
from .oauth import router as oauth_router

# Main router for Mode 2
router = APIRouter(prefix="/gmail", tags=["Mode 2 - Gmail On-Demand"])

# Include sub-routers
router.include_router(check_router)
router.include_router(oauth_router)

__all__ = ["router"]
