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
    """Start OAuth flow with redirect."""
    try:
        # Get OAuth credentials from environment
        client_id = os.getenv("GMAIL_CLIENT_ID")
        
        if not client_id:
            return {"success": False, "message": "OAuth credentials not configured"}
        
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
        return {"success": False, "message": f"OAuth error: {str(e)}"}

@router.get("/auth/google")
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
    frontend_url = "https://phishnet-tau.vercel.app"
    
    print(f"DEBUG: OAuth callback received - code: {bool(code)}, state: {state}, error: {error}")
    
    if error:
        print(f"DEBUG: OAuth error received: {error}")
        return RedirectResponse(f"{frontend_url}?oauth_error={error}")
    
    if not code:
        print(f"DEBUG: No authorization code received")
        return RedirectResponse(f"{frontend_url}?oauth_error=no_code")
    
    try:
        print(f"DEBUG: Starting token exchange with code: {code[:10]}...")
        
        # Exchange authorization code for tokens
        token_url = "https://oauth2.googleapis.com/token"
        
        # Get OAuth credentials from environment (same as start_oauth)
        client_id = os.getenv("GMAIL_CLIENT_ID")
        client_secret = os.getenv("GMAIL_CLIENT_SECRET")
        base_url = os.getenv("BASE_URL", "https://phishnet-backend-iuoc.onrender.com")
        
        print(f"DEBUG: client_id exists: {bool(client_id)}")
        print(f"DEBUG: client_secret exists: {bool(client_secret)}")
        print(f"DEBUG: base_url: {base_url}")
        
        if not client_id or not client_secret:
            error_msg = f"OAuth credentials not configured - client_id: {bool(client_id)}, client_secret: {bool(client_secret)}"
            print(f"ERROR: {error_msg}")
            return RedirectResponse(f"{frontend_url}?oauth_error=missing_credentials")
        
        redirect_uri = f"{base_url}/api/test/oauth/callback"
        print(f"DEBUG: redirect_uri: {redirect_uri}")
        
        token_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri
        }
        
        print(f"DEBUG: Making token request to {token_url}")
        
        # Use requests instead of httpx for better compatibility
        import requests
        
        try:
            token_response = requests.post(token_url, data=token_data, timeout=30)
            print(f"DEBUG: Token response status: {token_response.status_code}")
            
            if token_response.status_code != 200:
                print(f"ERROR: Token exchange failed ({token_response.status_code}): {token_response.text}")
                return RedirectResponse(f"{frontend_url}?oauth_error=token_exchange_failed")
                
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Token request failed: {str(e)}")
            return RedirectResponse(f"{frontend_url}?oauth_error=token_request_failed")
            
        try:
            tokens = token_response.json()
        except Exception as e:
            print(f"ERROR: Failed to parse token response JSON: {str(e)}")
            print(f"Raw response: {token_response.text}")
            return RedirectResponse(f"{frontend_url}?oauth_error=invalid_token_response")
            
        access_token = tokens.get("access_token")
        
        print(f"DEBUG: Access token received: {bool(access_token)}")
        
        if not access_token:
            print(f"ERROR: No access token received. Response: {tokens}")
            return RedirectResponse(f"{frontend_url}?oauth_error=no_access_token")
            
        # Get user info from Google
        userinfo_url = f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}"
        
        try:
            userinfo_response = requests.get(userinfo_url, timeout=30)
            print(f"DEBUG: User info response status: {userinfo_response.status_code}")
                
            if userinfo_response.status_code != 200:
                print(f"ERROR: Failed to get user info ({userinfo_response.status_code}): {userinfo_response.text}")
                return RedirectResponse(f"{frontend_url}?oauth_error=userinfo_failed")
                
        except requests.exceptions.RequestException as e:
            print(f"ERROR: User info request failed: {str(e)}")
            return RedirectResponse(f"{frontend_url}?oauth_error=userinfo_request_failed")
            
        try:
            user_info = userinfo_response.json()
        except Exception as e:
            print(f"ERROR: Failed to parse user info JSON: {str(e)}")
            return RedirectResponse(f"{frontend_url}?oauth_error=invalid_userinfo_response")
            
        user_email = user_info.get('email')
        
        print(f"DEBUG: User email: {user_email}")
        
        if not user_email:
            print(f"ERROR: No email found in user info: {user_info}")
            return RedirectResponse(f"{frontend_url}?oauth_error=no_email")
        
        # Store Gmail tokens in MongoDB for later use by Gmail service
        print(f"DEBUG: Storing Gmail tokens for {user_email}")
        
        try:
            # Import MongoDB connection
            from app.db.mongodb import get_mongodb_db
            
            mongo_db = await get_mongodb_db()
            users_collection = mongo_db.users
            
            # Calculate token expiration
            expires_in = tokens.get('expires_in', 3600)  # Default 1 hour
            from datetime import datetime, timezone, timedelta
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
            
            # Store or update user with Gmail tokens
            user_data = {
                "email": user_email,
                "gmail_access_token": access_token,
                "gmail_refresh_token": tokens.get("refresh_token"),
                "gmail_token_expires_at": expires_at,
                "gmail_scopes": tokens.get("scope", "").split(" "),
                "oauth_connected_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
            
            # Upsert user document
            await users_collection.update_one(
                {"email": user_email},
                {"$set": user_data},
                upsert=True
            )
            
            print(f"DEBUG: Successfully stored Gmail tokens for {user_email}")
            
        except Exception as db_error:
            print(f"WARNING: Failed to store tokens in database: {str(db_error)}")
            # Continue anyway - OAuth still succeeded
        
        print(f"DEBUG: Successfully processed OAuth for {user_email}, redirecting to frontend")
        
        # Redirect to a success page instead of the main page
        return RedirectResponse(f"{frontend_url}/connected?oauth_success=true&email={user_email}")
        
    except Exception as e:
        print(f"ERROR: OAuth callback failed: {str(e)}")
        print(f"ERROR: Exception type: {type(e).__name__}")
        import traceback
        print(f"ERROR: Traceback: {traceback.format_exc()}")
        
        # Redirect to frontend with detailed error
        error_msg = str(e).replace(' ', '_').replace('&', 'and')[:50]  # URL-safe error
        return RedirectResponse(f"{frontend_url}?oauth_error={error_msg}")