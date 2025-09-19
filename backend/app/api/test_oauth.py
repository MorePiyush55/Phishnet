"""Minimal OAuth endpoint for testing."""

from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
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
        
        # Create OAuth URL with Gmail access scope
        scopes = [
            "openid",
            "email", 
            "profile",
            "https://www.googleapis.com/auth/gmail.readonly"
        ]
        scope_string = " ".join(scopes)
        
        auth_url = (
            f"https://accounts.google.com/o/oauth2/auth?"
            f"client_id={client_id}&"
            f"redirect_uri={redirect_uri}&"
            f"scope={scope_string}&"
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
    """OAuth callback endpoint - completes the OAuth flow and redirects to frontend."""
    if error:
        # Redirect to frontend with error
        frontend_url = "https://phishnet-tau.vercel.app"
        return RedirectResponse(f"{frontend_url}?oauth_error={error}")
    
    if not code:
        # Redirect to frontend with error
        frontend_url = "https://phishnet-tau.vercel.app"
        return RedirectResponse(f"{frontend_url}?oauth_error=no_code")
    
    try:
        # Exchange authorization code for tokens
        token_url = "https://oauth2.googleapis.com/token"
        
        # Get OAuth credentials from environment (same as start_oauth)
        client_id = os.getenv("GMAIL_CLIENT_ID")
        client_secret = os.getenv("GMAIL_CLIENT_SECRET")
        base_url = os.getenv("BASE_URL", "https://phishnet-backend-iuoc.onrender.com")
        
        if not client_id or not client_secret:
            raise Exception("OAuth credentials not configured")
        
        token_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": f"{base_url}/api/test/oauth/callback"
        }
        
        import httpx
        async with httpx.AsyncClient() as client:
            token_response = await client.post(token_url, data=token_data)
            
        if token_response.status_code != 200:
            raise Exception(f"Token exchange failed: {token_response.text}")
            
        tokens = token_response.json()
        access_token = tokens.get("access_token")
        
        if not access_token:
            raise Exception("No access token received")
            
        # Get user info from Google
        userinfo_url = f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}"
        
        async with httpx.AsyncClient() as client:
            userinfo_response = await client.get(userinfo_url)
            
        if userinfo_response.status_code != 200:
            raise Exception(f"Failed to get user info: {userinfo_response.text}")
            
        user_info = userinfo_response.json()
        user_email = user_info.get('email')
        
        if not user_email:
            raise Exception("No email found in user info")
        
        # Store tokens in MongoDB (create or update user)
        from app.db.mongodb import get_mongodb_db
        from app.models.mongodb_models import User
        import pymongo
        from datetime import datetime, timezone
        
        # Get MongoDB connection
        mongo_db = await get_mongodb_db()
        users_collection = mongo_db.users
        
        # Calculate token expiration (Google access tokens expire in 1 hour)
        expires_in = tokens.get('expires_in', 3600)  # Default 1 hour
        expires_at = datetime.now(timezone.utc).timestamp() + expires_in
        
        # Update or create user with tokens
        update_data = {
            "gmail_access_token": access_token,
            "gmail_refresh_token": tokens.get('refresh_token'),
            "gmail_token_expires_at": datetime.fromtimestamp(expires_at, timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "is_verified": True
        }
        
        # Upsert user (create if doesn't exist, update if exists)
        await users_collection.update_one(
            {"email": user_email},
            {
                "$set": update_data,
                "$setOnInsert": {
                    "username": user_email.split('@')[0],
                    "full_name": user_info.get('name', ''),
                    "hashed_password": "oauth_user",  # OAuth users don't have passwords
                    "is_active": True,
                    "created_at": datetime.now(timezone.utc)
                }
            },
            upsert=True
        )
        
        # Store user authentication (in a real app, you'd save this to database)
        # For now, just redirect to frontend with success
        frontend_url = "https://phishnet-tau.vercel.app"
        return RedirectResponse(f"{frontend_url}?oauth_success=true&email={user_email}")
        
    except Exception as e:
        # Redirect to frontend with error
        frontend_url = "https://phishnet-tau.vercel.app"
        return RedirectResponse(f"{frontend_url}?oauth_error=token_exchange_failed")