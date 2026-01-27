"""
Gmail OAuth Routes
==================

OAuth 2.0 flow endpoints for Gmail API access.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import HTMLResponse
from typing import Optional
from pydantic import BaseModel, Field

from app.modes.gmail.oauth import GmailOAuthHandler
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/oauth", tags=["Gmail OAuth"])

# Singleton OAuth handler
_oauth_handler: Optional[GmailOAuthHandler] = None


def get_oauth_handler() -> GmailOAuthHandler:
    """Get singleton OAuth handler."""
    global _oauth_handler
    if _oauth_handler is None:
        _oauth_handler = GmailOAuthHandler()
    return _oauth_handler


# ============================================================================
# Response Models
# ============================================================================

class AuthUrlResponse(BaseModel):
    """Response containing OAuth authorization URL."""
    url: str
    state: str
    message: str = "Redirect user to this URL for authentication"


class TokenStatusResponse(BaseModel):
    """Response for token status check."""
    has_valid_token: bool
    expires_at: Optional[str] = None
    scopes: list = []


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/url", response_model=AuthUrlResponse)
async def get_auth_url(
    user_id: str,
    oauth: GmailOAuthHandler = Depends(get_oauth_handler)
):
    """
    Get the OAuth authorization URL for Gmail access.
    
    Generates a URL that users should be redirected to for
    granting PhishNet read-only access to their Gmail.
    
    Privacy Notes:
    - Only requests gmail.readonly scope
    - No background scanning
    - User-initiated checks only
    
    Args:
        user_id: User identifier for state tracking
        
    Returns:
        Authorization URL and state token
    """
    try:
        url, state = oauth.build_auth_url(user_id)
        
        return AuthUrlResponse(
            url=url,
            state=state
        )
        
    except Exception as e:
        logger.error(f"Failed to generate auth URL for {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate auth URL: {str(e)}"
        )


@router.get("/callback", response_class=HTMLResponse)
async def oauth_callback(
    code: str,
    state: str,
    oauth: GmailOAuthHandler = Depends(get_oauth_handler)
):
    """
    Handle OAuth callback from Google.
    
    This endpoint receives the authorization code after user approves
    access, exchanges it for tokens, and returns an HTML page that
    browser extensions can scrape to retrieve the token.
    
    Args:
        code: Authorization code from Google
        state: State token for CSRF verification
        
    Returns:
        HTML page with embedded token data
    """
    try:
        # Verify state token (CSRF protection)
        state_data = oauth.verify_state(state)
        if not state_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired state token"
            )
        
        user_id = state_data.get("user_id", "unknown")
        
        # Exchange code for tokens
        tokens = await oauth.exchange_code(code)
        
        if not tokens:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to exchange authorization code"
            )
        
        # Return HTML page with embedded token
        # The browser extension can scrape this to get the token
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhishNet Authentication Success</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    margin: 0;
                }}
                .container {{
                    text-align: center;
                    background: white;
                    padding: 3rem;
                    border-radius: 16px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    max-width: 500px;
                }}
                h1 {{
                    color: #1a73e8;
                    margin-bottom: 1rem;
                }}
                p {{
                    color: #5f6368;
                    margin-bottom: 2rem;
                }}
                .success-icon {{
                    font-size: 4rem;
                    margin-bottom: 1rem;
                }}
                .info {{
                    background: #e8f4e8;
                    padding: 1rem;
                    border-radius: 8px;
                    color: #2e7d32;
                    font-size: 0.9rem;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="success-icon">✓</div>
                <h1>Authentication Successful!</h1>
                <p>PhishNet can now check your emails for phishing threats.</p>
                <div class="info">
                    <strong>Privacy Note:</strong> PhishNet only reads emails you specifically 
                    request to check. No background scanning occurs.
                </div>
                <p style="margin-top: 2rem;">You can now close this tab and return to Gmail.</p>
                
                <!-- Token data for browser extension -->
                <div id="phishnet-token-data" style="display: none;"
                     data-token="{tokens.get('access_token', '')}"
                     data-expires="{tokens.get('expires_in', 3600)}"
                     data-user="{user_id}"
                     data-success="true"></div>
            </div>
            
            <script>
                // Auto-close after 10 seconds
                setTimeout(function() {{
                    window.close();
                }}, 10000);
            </script>
        </body>
        </html>
        """
        
        return HTMLResponse(content=html_content)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth callback failed: {e}")
        
        # Return error page
        error_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhishNet Authentication Failed</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    background: #f5f5f5;
                    margin: 0;
                }}
                .container {{
                    text-align: center;
                    background: white;
                    padding: 3rem;
                    border-radius: 16px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                }}
                h1 {{ color: #d32f2f; }}
                p {{ color: #5f6368; }}
                .error-icon {{ font-size: 4rem; margin-bottom: 1rem; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">✗</div>
                <h1>Authentication Failed</h1>
                <p>There was an error completing authentication.</p>
                <p style="font-size: 0.9rem; color: #999;">Error: {str(e)}</p>
                <div id="phishnet-token-data" style="display: none;" data-success="false"></div>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=error_html, status_code=400)


@router.get("/status", response_model=TokenStatusResponse)
async def get_token_status(
    user_id: str,
    oauth: GmailOAuthHandler = Depends(get_oauth_handler)
):
    """
    Check if user has valid Gmail tokens.
    
    Args:
        user_id: User identifier
        
    Returns:
        Token validity status
    """
    try:
        has_token = await oauth.has_valid_token(user_id)
        
        return TokenStatusResponse(
            has_valid_token=has_token,
            scopes=["gmail.readonly"] if has_token else []
        )
        
    except Exception as e:
        logger.error(f"Failed to check token status for {user_id}: {e}")
        return TokenStatusResponse(has_valid_token=False)


@router.post("/revoke")
async def revoke_access(
    user_id: str,
    oauth: GmailOAuthHandler = Depends(get_oauth_handler)
):
    """
    Revoke Gmail access for a user.
    
    Removes stored tokens and revokes the OAuth grant.
    User will need to re-authorize to use on-demand checking.
    
    Args:
        user_id: User identifier
        
    Returns:
        Revocation confirmation
    """
    try:
        success = await oauth.revoke_token(user_id)
        
        return {
            "success": success,
            "user_id": user_id,
            "message": "Gmail access revoked" if success else "No active access to revoke"
        }
        
    except Exception as e:
        logger.error(f"Failed to revoke access for {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke access: {str(e)}"
        )


@router.post("/refresh")
async def refresh_token(
    user_id: str,
    oauth: GmailOAuthHandler = Depends(get_oauth_handler)
):
    """
    Refresh the access token for a user.
    
    Uses the stored refresh token to get a new access token.
    
    Args:
        user_id: User identifier
        
    Returns:
        New access token
    """
    try:
        tokens = await oauth.refresh_access_token(user_id)
        
        if not tokens:
            return {
                "success": False,
                "need_reauth": True,
                "message": "No refresh token available. User must re-authorize."
            }
        
        return {
            "success": True,
            "access_token": tokens.get("access_token"),
            "expires_in": tokens.get("expires_in", 3600)
        }
        
    except Exception as e:
        logger.error(f"Failed to refresh token for {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token refresh failed: {str(e)}"
        )
