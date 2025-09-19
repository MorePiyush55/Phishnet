"""Simple OAuth endpoint for testing without complex dependencies."""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from app.config.settings import settings
import secrets
import base64
import json

router = APIRouter(prefix="/api/v1/auth/gmail", tags=["Simple Gmail OAuth"])

class SimpleOAuthResponse(BaseModel):
    success: bool
    message: str
    authorization_url: str = None

@router.post("/start-simple", response_model=SimpleOAuthResponse)
async def start_simple_oauth(request: Request):
    """Simple OAuth start endpoint for testing."""
    try:
        # Check if we have the required OAuth credentials
        if not settings.GMAIL_CLIENT_ID or not settings.GMAIL_CLIENT_SECRET:
            raise HTTPException(status_code=500, detail="OAuth credentials not configured")
        
        # Generate a simple state token
        state = secrets.token_urlsafe(32)
        
        # Create basic OAuth URL
        auth_url = (
            f"https://accounts.google.com/o/oauth2/auth?"
            f"client_id={settings.GMAIL_CLIENT_ID}&"
            f"redirect_uri={settings.GMAIL_REDIRECT_URI}&"
            f"scope=https://www.googleapis.com/auth/gmail.readonly&"
            f"response_type=code&"
            f"state={state}&"
            f"access_type=offline&"
            f"prompt=consent"
        )
        
        return SimpleOAuthResponse(
            success=True,
            message="Simple OAuth URL generated",
            authorization_url=auth_url
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OAuth error: {str(e)}")

@router.get("/test")
async def test_endpoint():
    """Simple test endpoint."""
    return {"message": "OAuth router is working", "status": "ok"}