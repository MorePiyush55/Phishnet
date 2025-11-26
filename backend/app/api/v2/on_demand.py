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
    """
    Handle OAuth callback and return the access token via HTML for the extension to scrape.
    """
    try:
        # Verify state
        state_data = gmail_ondemand_service.verify_state_token(state)
        
        # Exchange code
        tokens = await gmail_ondemand_service.exchange_code_for_token(code)
        
        # Return HTML with token embedded
        from fastapi.responses import HTMLResponse
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhishNet Authentication Success</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f0f2f5; margin: 0; }}
                .container {{ text-align: center; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                h1 {{ color: #1a73e8; }}
                p {{ color: #5f6368; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Authentication Successful!</h1>
                <p>You can now close this tab and return to Gmail.</p>
                <div id="phishnet-token-data" style="display: none;" 
                     data-token="{tokens['access_token']}" 
                     data-expires="{tokens['expires_in']}"
                     data-user="{state_data['user_id']}"></div>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)

    except Exception as e:
        logger.error(f"Auth callback failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/history")
async def get_check_history(user_id: str, limit: int = 50):
    """
    Get history of on-demand checks for a user.
    Only returns checks where store_consent was True.
    """
    try:
        from app.models.mongodb_models import OnDemandAnalysis
        
        history = await OnDemandAnalysis.find(
            OnDemandAnalysis.user_id == user_id
        ).sort("-created_at").limit(limit).to_list()
        
        return {
            "success": True,
            "count": len(history),
            "history": history
        }
    except Exception as e:
        logger.error(f"Failed to fetch history: {e}")
        raise HTTPException(status_code=500, detail=str(e))
