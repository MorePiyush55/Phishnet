"""Production-grade Gmail OAuth API endpoints - Clean Implementation."""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
import httpx
import json
import base64

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

# Import only robust dependencies
from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth/gmail", tags=["Gmail OAuth"])

@router.get("/callback")
async def handle_gmail_oauth_callback(
    request: Request,
    code: str = Query(..., description="Authorization code"),
    state: str = Query(..., description="State parameter"),
    scope: Optional[str] = Query(None, description="Granted scopes"),
    error: Optional[str] = Query(None, description="OAuth error"),
    db: Session = Depends(get_db)
):
    """
    Handle OAuth callback from Google.
    
    This endpoint processes the authorization code and exchanges it for tokens.
    Users are redirected here from Google after granting permissions.
    """
    try:
        if error:
            logger.warning(f"OAuth error received: {error}")
            frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_error={error}"
            return RedirectResponse(url=frontend_url, status_code=302)
        
        # Exchange authorization code for tokens
        token_url = "https://oauth2.googleapis.com/token"
        
        client_id = settings.GMAIL_CLIENT_ID or settings.GOOGLE_CLIENT_ID
        client_secret = settings.GMAIL_CLIENT_SECRET or settings.GOOGLE_CLIENT_SECRET
        redirect_uri = settings.GMAIL_REDIRECT_URI or settings.GOOGLE_REDIRECT_URI
        
        token_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        
        async with httpx.AsyncClient() as client:
            token_response = await client.post(token_url, data=token_data)
            
            if token_response.status_code != 200:
                logger.error(f"Token exchange failed: {token_response.text}")
                frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_error=token_exchange_failed"
                return RedirectResponse(url=frontend_url, status_code=302)
            
            tokens = token_response.json()
            access_token = tokens.get("access_token")
            
            # Fetch user info
            user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
            headers = {"Authorization": f"Bearer {access_token}"}
            user_response = await client.get(user_info_url, headers=headers)
            
            if user_response.status_code == 200:
                user_info = user_response.json()
                gmail_email = user_info.get("email")
                logger.info(f"Successfully authenticated Gmail: {gmail_email}")
                
                # Redirect to frontend with success
                frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_success=true&gmail_email={gmail_email}"
                return RedirectResponse(url=frontend_url, status_code=302)
            else:
                logger.error("Failed to fetch user info from Google")
                frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_error=user_info_failed"
                return RedirectResponse(url=frontend_url, status_code=302)

    except Exception as e:
        logger.error(f"OAuth callback unexpected error: {e}")
        frontend_url = f"{settings.FRONTEND_URL}/dashboard?oauth_error=unexpected_error"
        return RedirectResponse(url=frontend_url, status_code=302)

@router.get("/health")
async def gmail_oauth_health():
    """Health check for Gmail OAuth service."""
    return {"status": "healthy", "mode": "clean_implementation"}
