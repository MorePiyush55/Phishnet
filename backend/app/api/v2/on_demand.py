"""
On-Demand Email Analysis API (v2)
Privacy-first endpoints for checking specific emails without full inbox access.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

from app.services.gmail_ondemand import gmail_ondemand_service
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

class CheckRequest(BaseModel):
    message_id: str = Field(..., description="Gmail Message ID to analyze")
    access_token: Optional[str] = Field(None, description="Gmail Access Token (if available)")
    store_consent: bool = Field(False, description="Whether to store the analysis result")
    user_id: str = Field(..., description="User ID requesting the check")

class CheckResponse(BaseModel):
    success: bool
    message_id: Optional[str] = None
    analysis: Optional[Dict[str, Any]] = None
    need_oauth: bool = False
    oauth_url: Optional[str] = None
    message: Optional[str] = None

@router.post("/request-check", response_model=CheckResponse)
async def request_check(request: CheckRequest):
    """
    Request an on-demand check for a specific email.
    If access token is missing or expired, returns need_oauth=True with auth URL.
    """
    try:
        result = await gmail_ondemand_service.check_email_on_demand(
            user_id=request.user_id,
            message_id=request.message_id,
            access_token=request.access_token,
            store_consent=request.store_consent
        )
        return result
    except Exception as e:
        logger.error(f"On-demand check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/auth/url")
async def get_auth_url(user_id: str):
    """Get the incremental OAuth URL for gmail.readonly scope."""
    try:
        url, state = gmail_ondemand_service.build_incremental_auth_url(user_id)
        return {"url": url, "state": state}
    except Exception as e:
        logger.error(f"Failed to generate auth URL: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/auth/callback")
async def auth_callback(code: str, state: str):
    """Handle OAuth callback and return the access token."""
    try:
        # Verify state
        state_data = gmail_ondemand_service.verify_state_token(state)
        
        # Exchange code
        tokens = await gmail_ondemand_service.exchange_code_for_token(code)
        
        return {
            "success": True,
            "access_token": tokens["access_token"],
            "expires_in": tokens["expires_in"],
            "user_id": state_data["user_id"]
        }
    except Exception as e:
        logger.error(f"Auth callback failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))
