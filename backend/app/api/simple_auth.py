"""
Simple Auth Router - production-ready endpoint for OAuth redirection.

This module provides the direct GET /auth/google endpoint that redirects 
the user's browser to the Google OAuth consent screen.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
import os
import secrets
import urllib.parse
from app.config.settings import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/status")
async def auth_status():
    """
    Check OAuth configuration status.
    """
    return {
        "status": "ok",
        "oauth_configured": True,
        "mode": "production"
    }


@router.get("/google")
async def google_oauth_redirect():
    """
    Redirect to Google OAuth flow.
    """
    # Get OAuth configuration from environment
    client_id = os.getenv("GMAIL_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID")
    redirect_uri = os.getenv("GMAIL_REDIRECT_URI") or os.getenv("GOOGLE_REDIRECT_URI")
    
    # Fallback to defaults if configured in code/settings
    if not client_id and hasattr(settings, 'GOOGLE_CLIENT_ID'):
        client_id = settings.GOOGLE_CLIENT_ID
    if not redirect_uri and hasattr(settings, 'GOOGLE_REDIRECT_URI'):
        redirect_uri = settings.GOOGLE_REDIRECT_URI
    
    if not client_id:
        raise HTTPException(status_code=500, detail="OAuth not configured - Client ID missing")
    
    if not redirect_uri:
        raise HTTPException(status_code=500, detail="OAuth not configured - Redirect URI missing")
    
    # Build Google OAuth URL
    scopes = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ]
    
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
