"""
Zero-Dependency Gmail OAuth Router.
Guaranteed to load regardless of other project errors.
"""

import os
import httpx
from fastapi import APIRouter, Request, Query
from fastapi.responses import RedirectResponse
from typing import Optional

# Create router - completely standalone
router = APIRouter(prefix="/api/v1/auth/gmail", tags=["Gmail OAuth"])

@router.get("/callback")
async def handle_gmail_oauth_callback(
    request: Request,
    code: str = Query(..., description="Authorization code"),
    state: str = Query(..., description="State parameter"),
    scope: Optional[str] = Query(None, description="Granted scopes"),
    error: Optional[str] = Query(None, description="OAuth error"),
):
    """
    Handle OAuth callback from Google.
    Zero-dependency version to ensure 404 resolution.
    """
    # Hardcoded or OS-env based config
    # We try to replicate the frontend URL logic
    frontend_url_base = os.getenv("FRONTEND_URL", "https://phishnet-tau.vercel.app")
    
    if error:
        return RedirectResponse(
            url=f"{frontend_url_base}/dashboard?oauth_error={error}", 
            status_code=302
        )
    
    try:
        # Configuration
        client_id = os.getenv("GMAIL_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID")
        client_secret = os.getenv("GMAIL_CLIENT_SECRET") or os.getenv("GOOGLE_CLIENT_SECRET")
        redirect_uri = os.getenv("GMAIL_REDIRECT_URI") or os.getenv("GOOGLE_REDIRECT_URI")
        
        if not (client_id and client_secret and redirect_uri):
             return RedirectResponse(
                url=f"{frontend_url_base}/dashboard?oauth_error=server_misconfiguration_missing_env", 
                status_code=302
            )

        # Exchange code
        token_url = "https://oauth2.googleapis.com/token"
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
                print(f"Token error: {token_response.text}")
                return RedirectResponse(
                    url=f"{frontend_url_base}/dashboard?oauth_error=token_exchange_failed", 
                    status_code=302
                )
            
            tokens = token_response.json()
            access_token = tokens.get("access_token")
            
            # Get user info
            user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
            headers = {"Authorization": f"Bearer {access_token}"}
            user_response = await client.get(user_info_url, headers=headers)
            
            if user_response.status_code == 200:
                user_info = user_response.json()
                email = user_info.get("email")
                
                # SUCCESS: Redirect to dashboard
                target = f"{frontend_url_base}/dashboard?oauth_success=true&gmail_email={email}"
                return RedirectResponse(url=target, status_code=302)
            else:
                return RedirectResponse(
                    url=f"{frontend_url_base}/dashboard?oauth_error=user_info_failed", 
                    status_code=302
                )

    except Exception as e:
        print(f"Callback exception: {e}")
        return RedirectResponse(
            url=f"{frontend_url_base}/dashboard?oauth_error=unexpected_error", 
            status_code=302
        )

@router.get("/health")
async def gmail_oauth_health():
    return {"status": "healthy", "mode": "zero_dependency"}
