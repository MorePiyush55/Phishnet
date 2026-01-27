"""
Mode 1 - IMAP Bulk Forward API Routes
=====================================

Enterprise endpoints for IMAP-based email analysis workflow.

Routes:
    /emails - Email listing and fetching
    /analysis - Email analysis operations
    /connection - IMAP connection management
    /polling - Background polling control
"""

from fastapi import APIRouter

from .emails import router as emails_router
from .analysis import router as analysis_router
from .connection import router as connection_router

# Main router for Mode 1
router = APIRouter(prefix="/imap", tags=["Mode 1 - IMAP Bulk Forward"])

# Include sub-routers
router.include_router(emails_router)
router.include_router(analysis_router)
router.include_router(connection_router)

__all__ = ["router"]
