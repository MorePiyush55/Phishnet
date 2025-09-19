"""Minimal OAuth endpoint for testing."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import os
import secrets

router = APIRouter(prefix="/api/test", tags=["Test OAuth"])

class OAuthTestResponse(BaseModel):
    success: bool
    message: str
    authorization_url: str = None

@router.get("/oauth")
async def test_oauth():
    """Test OAuth endpoint."""
    return {"success": True, "message": "OAuth test endpoint working"}

@router.post("/oauth/start")
async def start_oauth():
    """Start OAuth flow."""
    try:
        # Get OAuth credentials from environment
        client_id = os.getenv("GMAIL_CLIENT_ID")
        
        if not client_id:
            raise HTTPException(status_code=500, detail="OAuth credentials not configured")
        
        # Use the correct redirect URI that matches our callback endpoint
        redirect_uri = "https://phishnet-backend-iuoc.onrender.com/api/test/oauth/callback"
        
        # Generate state token
        state = secrets.token_urlsafe(32)
        
        # Create OAuth URL
        auth_url = (
            f"https://accounts.google.com/o/oauth2/auth?"
            f"client_id={client_id}&"
            f"redirect_uri={redirect_uri}&"
            f"scope=https://www.googleapis.com/auth/gmail.readonly&"
            f"response_type=code&"
            f"state={state}&"
            f"access_type=offline&"
            f"prompt=consent"
        )
        
        return OAuthTestResponse(
            success=True,
            message="OAuth URL generated successfully",
            authorization_url=auth_url
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OAuth error: {str(e)}")

@router.get("/oauth/callback")
async def oauth_callback(code: str = None, state: str = None, error: str = None):
    """OAuth callback endpoint."""
    if error:
        return {"success": False, "error": error, "message": "OAuth authorization failed"}
    
    if not code:
        return {"success": False, "error": "no_code", "message": "No authorization code received"}
    
    return {
        "success": True, 
        "message": "OAuth callback received successfully",
        "code": code[:10] + "..." if code else None,
        "state": state[:10] + "..." if state else None,
        "next_step": "Exchange code for access token"
    }