"""
OAuth API Endpoints
Handles OAuth flow, authorization, and token management.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel, validator

from app.core.database import get_db
from app.services.oauth_service import get_oauth_service, OAuthService
from app.services.consent_manager import get_consent_manager
from app.core.auth import get_current_user
from app.core.rate_limiter import rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/oauth", tags=["oauth"])

# Initialize templates for consent page
templates = Jinja2Templates(directory="app/templates")

# Pydantic models

class OAuthInitRequest(BaseModel):
    """Request to initiate OAuth flow"""
    requested_scopes: Optional[List[str]] = None
    custom_params: Optional[Dict[str, str]] = None

class OAuthCallbackRequest(BaseModel):
    """OAuth callback request"""
    authorization_code: str
    state_token: str
    consent_preferences: Dict[str, Any]

class OAuthResponse(BaseModel):
    """OAuth response"""
    success: bool
    message: str
    authorization_url: Optional[str] = None
    state_token: Optional[str] = None
    user_id: Optional[str] = None
    granted_scopes: Optional[List[str]] = None

class TokenTestResponse(BaseModel):
    """Token test response"""
    success: bool
    email: Optional[str] = None
    total_messages: Optional[int] = None
    access_verified: bool = False
    error: Optional[str] = None
    needs_reauth: bool = False

# Endpoints

@router.post("/authorize", response_model=OAuthResponse)
@rate_limit("oauth_init", max_requests=10, window_seconds=300)  # 10 requests per 5 minutes
async def initiate_oauth(
    request: Request,
    oauth_request: OAuthInitRequest,
    current_user = Depends(get_current_user),
    oauth_service: OAuthService = Depends(get_oauth_service)
):
    """
    Initiate OAuth authorization flow.
    """
    try:
        logger.info(f"Initiating OAuth for user {current_user.id}")
        
        # Check if user already has active consent
        consent_manager = get_consent_manager()
        existing_consent = await consent_manager.get_user_consent(current_user.id)
        
        if existing_consent and existing_consent.is_consent_valid:
            logger.info(f"User {current_user.id} already has valid consent")
            return OAuthResponse(
                success=False,
                message="User already has valid OAuth consent",
                user_id=current_user.id
            )
        
        # Generate OAuth URL
        auth_url, state_token = oauth_service.generate_oauth_url(
            user_id=current_user.id,
            requested_scopes=oauth_request.requested_scopes,
            custom_params=oauth_request.custom_params
        )
        
        return OAuthResponse(
            success=True,
            message="OAuth authorization URL generated",
            authorization_url=auth_url,
            state_token=state_token,
            user_id=current_user.id
        )
        
    except Exception as e:
        logger.error(f"Error initiating OAuth for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error initiating OAuth flow"
        )

@router.get("/consent")
async def show_consent_page(
    request: Request,
    state: str = Query(..., description="OAuth state token"),
    oauth_service: OAuthService = Depends(get_oauth_service)
):
    """
    Show custom consent page before redirecting to Google.
    """
    try:
        # Get consent page data
        consent_data = oauth_service.get_consent_page_data(state)
        
        return templates.TemplateResponse(
            "oauth_consent.html",
            {
                "request": request,
                "consent_data": consent_data,
                "app_name": "PhishNet",
                "app_url": request.base_url
            }
        )
        
    except Exception as e:
        logger.error(f"Error showing consent page: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error loading consent page"
        )

@router.post("/callback", response_model=OAuthResponse)
@rate_limit("oauth_callback", max_requests=5, window_seconds=300)  # 5 requests per 5 minutes
async def oauth_callback(
    request: Request,
    callback_request: OAuthCallbackRequest,
    oauth_service: OAuthService = Depends(get_oauth_service)
):
    """
    Handle OAuth callback from Google.
    """
    try:
        logger.info(f"Processing OAuth callback with state: {callback_request.state_token}")
        
        # Handle callback
        result = await oauth_service.handle_oauth_callback(
            authorization_code=callback_request.authorization_code,
            state_token=callback_request.state_token,
            consent_preferences=callback_request.consent_preferences
        )
        
        if result["success"]:
            return OAuthResponse(
                success=True,
                message=result["message"],
                user_id=result["user_id"],
                granted_scopes=result["granted_scopes"]
            )
        else:
            return OAuthResponse(
                success=False,
                message=result["message"]
            )
        
    except Exception as e:
        logger.error(f"Error in OAuth callback: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing OAuth callback"
        )

@router.get("/callback")
async def oauth_callback_redirect(
    request: Request,
    code: str = Query(..., description="Authorization code"),
    state: str = Query(..., description="State token"),
    error: Optional[str] = Query(None, description="OAuth error")
):
    """
    Handle OAuth callback redirect from Google (GET request).
    This endpoint receives the redirect from Google OAuth.
    """
    try:
        if error:
            logger.warning(f"OAuth error in callback: {error}")
            # Redirect to frontend with error
            return RedirectResponse(
                url=f"/oauth/error?error={error}",
                status_code=status.HTTP_302_FOUND
            )
        
        # Redirect to frontend consent completion page
        callback_url = f"/oauth/complete?code={code}&state={state}"
        return RedirectResponse(
            url=callback_url,
            status_code=status.HTTP_302_FOUND
        )
        
    except Exception as e:
        logger.error(f"Error in OAuth callback redirect: {e}")
        return RedirectResponse(
            url="/oauth/error?error=internal_error",
            status_code=status.HTTP_302_FOUND
        )

@router.post("/revoke", response_model=OAuthResponse)
@rate_limit("oauth_revoke", max_requests=3, window_seconds=300)  # 3 requests per 5 minutes
async def revoke_oauth(
    request: Request,
    current_user = Depends(get_current_user),
    oauth_service: OAuthService = Depends(get_oauth_service)
):
    """
    Revoke OAuth tokens and consent.
    """
    try:
        logger.info(f"Revoking OAuth for user {current_user.id}")
        
        # Revoke tokens
        success = await oauth_service.revoke_tokens(current_user.id)
        
        if success:
            return OAuthResponse(
                success=True,
                message="OAuth tokens revoked successfully",
                user_id=current_user.id
            )
        else:
            return OAuthResponse(
                success=False,
                message="Failed to revoke OAuth tokens"
            )
        
    except Exception as e:
        logger.error(f"Error revoking OAuth for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error revoking OAuth tokens"
        )

@router.post("/refresh")
async def refresh_token(
    current_user = Depends(get_current_user),
    oauth_service: OAuthService = Depends(get_oauth_service)
):
    """
    Refresh OAuth access token.
    """
    try:
        logger.info(f"Refreshing token for user {current_user.id}")
        
        # Refresh token
        credentials = await oauth_service.refresh_access_token(current_user.id)
        
        if credentials:
            return {
                "success": True,
                "message": "Token refreshed successfully",
                "expires_at": credentials.expiry.isoformat() if credentials.expiry else None
            }
        else:
            return {
                "success": False,
                "message": "Failed to refresh token",
                "needs_reauth": True
            }
        
    except Exception as e:
        logger.error(f"Error refreshing token for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error refreshing token"
        )

@router.get("/test", response_model=TokenTestResponse)
async def test_oauth_access(
    current_user = Depends(get_current_user),
    oauth_service: OAuthService = Depends(get_oauth_service)
):
    """
    Test OAuth access by making a simple Gmail API call.
    """
    try:
        logger.info(f"Testing OAuth access for user {current_user.id}")
        
        # Test Gmail access
        test_result = await oauth_service.test_gmail_access(current_user.id)
        
        return TokenTestResponse(**test_result)
        
    except Exception as e:
        logger.error(f"Error testing OAuth access for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error testing OAuth access"
        )

@router.get("/status")
async def get_oauth_status(
    current_user = Depends(get_current_user),
    oauth_service: OAuthService = Depends(get_oauth_service)
):
    """
    Get OAuth status for the current user.
    """
    try:
        # Get consent status
        consent_manager = get_consent_manager()
        consent = await consent_manager.get_user_consent(current_user.id)
        
        if not consent:
            return {
                "authenticated": False,
                "consent_granted": False,
                "message": "No OAuth consent found"
            }
        
        return {
            "authenticated": consent.is_active,
            "consent_granted": consent.is_consent_valid,
            "granted_scopes": consent.granted_scopes,
            "token_expires_at": consent.token_expires_at.isoformat() if consent.token_expires_at else None,
            "consent_granted_at": consent.consent_granted_at.isoformat() if consent.consent_granted_at else None,
            "email": consent.email,
            "can_access_gmail": "https://www.googleapis.com/auth/gmail.readonly" in consent.granted_scopes,
            "can_modify_gmail": "https://www.googleapis.com/auth/gmail.modify" in consent.granted_scopes
        }
        
    except Exception as e:
        logger.error(f"Error getting OAuth status for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error getting OAuth status"
        )

@router.get("/scopes")
async def get_available_scopes():
    """
    Get information about available OAuth scopes.
    """
    return {
        "required_scopes": [
            {
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
                "description": "Read-only access to Gmail messages",
                "privacy_impact": "Medium - Can read email metadata and content"
            },
            {
                "scope": "https://www.googleapis.com/auth/userinfo.email", 
                "description": "Access to user's email address",
                "privacy_impact": "Low - Only email address"
            }
        ],
        "optional_scopes": [
            {
                "scope": "https://www.googleapis.com/auth/gmail.modify",
                "description": "Ability to label and organize emails",
                "privacy_impact": "Low - Can only modify labels, not content"
            }
        ],
        "privacy_notes": [
            "We use minimal scopes necessary for phishing detection",
            "No access to sending emails or modifying email content",
            "Optional scopes are only for quarantine/labeling features",
            "All access can be revoked at any time"
        ]
    }
