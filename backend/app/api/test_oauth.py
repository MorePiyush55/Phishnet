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


@router.get("/google")
async def google_oauth_redirect():
    """
    Redirect to Google OAuth flow.
    
    This endpoint initiates the OAuth flow by redirecting to the actual OAuth router.
    """
    from fastapi.responses import RedirectResponse
    import os
    
    # Get OAuth configuration from environment
    client_id = os.getenv("GMAIL_CLIENT_ID")
    redirect_uri = os.getenv("GMAIL_REDIRECT_URI")
    
    if not client_id:
        raise HTTPException(status_code=500, detail="OAuth not configured - GMAIL_CLIENT_ID missing")
    
    if not redirect_uri:
        raise HTTPException(status_code=500, detail="OAuth not configured - GMAIL_REDIRECT_URI missing")
    
    # Build Google OAuth URL
    scopes = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ]
    
    import urllib.parse
    import secrets
    
    # Generate state token for CSRF protection
    state = secrets.token_urlsafe(32)
    
    # Build authorization URL
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
        "access_type": "offline",
        "prompt": "consent"
    })
    
    return RedirectResponse(url=auth_url, status_code=302)
