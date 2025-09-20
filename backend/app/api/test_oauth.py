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

@router.get("/oauth/start")
async def start_oauth_get():
    """Start OAuth flow with GET (direct redirect)."""
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
        
        # Redirect directly to Google OAuth
        return RedirectResponse(auth_url)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OAuth error: {str(e)}")

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
        
        print(f"DEBUG: client_id exists: {bool(client_id)}")
        print(f"DEBUG: client_secret exists: {bool(client_secret)}")
        
        if not client_id or not client_secret:
            raise Exception(f"OAuth credentials not configured - client_id: {bool(client_id)}, client_secret: {bool(client_secret)}")
        
        token_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": f"{base_url}/api/test/oauth/callback"
        }
        
        print(f"DEBUG: Making token request to {token_url}")
        
        # Use requests instead of httpx for better compatibility
        import requests
        token_response = requests.post(token_url, data=token_data)
        
        print(f"DEBUG: Token response status: {token_response.status_code}")
        print(f"DEBUG: Token response text: {token_response.text[:200]}...")
            
        if token_response.status_code != 200:
            raise Exception(f"Token exchange failed ({token_response.status_code}): {token_response.text}")
            
        tokens = token_response.json()
        access_token = tokens.get("access_token")
        
        print(f"DEBUG: Access token received: {bool(access_token)}")
        
        if not access_token:
            raise Exception(f"No access token received. Response: {tokens}")
            
        # Get user info from Google
        userinfo_url = f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}"
        
        userinfo_response = requests.get(userinfo_url)
        
        print(f"DEBUG: User info response status: {userinfo_response.status_code}")
            
        if userinfo_response.status_code != 200:
            raise Exception(f"Failed to get user info ({userinfo_response.status_code}): {userinfo_response.text}")
            
        user_info = userinfo_response.json()
        user_email = user_info.get('email')
        
        print(f"DEBUG: User email: {user_email}")
        
        if not user_email:
            raise Exception(f"No email found in user info: {user_info}")
        
        # Skip MongoDB storage for now to isolate the issue
        print(f"DEBUG: Skipping MongoDB storage, redirecting with success")
        
        # Store user authentication (in a real app, you'd save this to database)
        # For now, just redirect to frontend with success
        frontend_url = "https://phishnet-tau.vercel.app"
        return RedirectResponse(f"{frontend_url}?oauth_success=true&email={user_email}")
        
    except Exception as e:
        print(f"ERROR: OAuth callback failed: {str(e)}")
        # Redirect to frontend with detailed error
        frontend_url = "https://phishnet-tau.vercel.app"
        error_msg = str(e).replace(' ', '_').replace('&', 'and')[:100]  # URL-safe error
        return RedirectResponse(f"{frontend_url}?oauth_error={error_msg}")