"""
Test OAuth Router - Placeholder for OAuth testing endpoints.

This module provides simple test endpoints for OAuth functionality verification.
"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any

router = APIRouter(prefix="/test-oauth", tags=["Test OAuth"])


@router.get("/status")
async def oauth_status() -> Dict[str, Any]:
    """
    Check OAuth configuration status.
    
    Returns:
        Status of OAuth configuration
    """
    return {
        "status": "ok",
        "oauth_configured": True,
        "message": "OAuth test endpoint is available"
    }


@router.get("/health")
async def oauth_health() -> Dict[str, str]:
    """
    Simple health check for OAuth module.
    
    Returns:
        Health status
    """
    return {
        "status": "healthy",
        "module": "test_oauth"
    }
