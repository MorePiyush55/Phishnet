"""
Gmail On-Demand Check Routes
============================

Endpoints for privacy-first on-demand email checking via Gmail API.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

from app.modes.dependencies import get_gmail_orchestrator_dep
from app.modes.gmail.orchestrator import GmailOrchestrator
from app.modes.base import AnalysisRequest, ModeType, AnalysisStatus
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/check", tags=["Gmail Check"])


# ============================================================================
# Request/Response Models
# ============================================================================

class CheckEmailRequest(BaseModel):
    """Request to check a specific email."""
    message_id: str = Field(..., description="Gmail Message ID to analyze")
    access_token: Optional[str] = Field(None, description="Gmail Access Token (if available)")
    store_consent: bool = Field(False, description="Whether to store the analysis result")
    user_id: str = Field(..., description="User ID requesting the check")


class CheckEmailResponse(BaseModel):
    """Response from email check."""
    success: bool
    message_id: Optional[str] = None
    analysis_id: Optional[str] = None
    need_oauth: bool = False
    oauth_url: Optional[str] = None
    verdict: Optional[str] = None
    confidence: Optional[float] = None
    risk_score: Optional[float] = None
    threat_indicators: list = []
    ai_summary: Optional[str] = None
    message: Optional[str] = None


class QuickCheckRequest(BaseModel):
    """Request for quick check with minimal data."""
    message_id: str = Field(..., description="Gmail Message ID")
    user_id: str = Field(..., description="User ID")


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/request", response_model=CheckEmailResponse)
async def request_check(
    request: CheckEmailRequest,
    orchestrator: GmailOrchestrator = Depends(get_gmail_orchestrator_dep)
):
    """
    Request an on-demand check for a specific email.
    
    This is the primary endpoint for Mode 2 (consumer) email verification.
    If the access token is missing or expired, returns need_oauth=True
    with an authorization URL.
    
    Privacy Features:
    - Only reads the specific email requested (gmail.readonly scope)
    - No background inbox scanning
    - Result stored only if store_consent=True
    - Email content not persisted by default
    
    Args:
        request: Check request with message ID and optional token
        
    Returns:
        Analysis result or OAuth redirect URL
    """
    try:
        # Use convenience method on orchestrator
        result = await orchestrator.check_email_on_demand(
            user_id=request.user_id,
            message_id=request.message_id,
            access_token=request.access_token,
            store_consent=request.store_consent
        )
        
        # Handle need OAuth case
        if result.get("need_oauth"):
            return CheckEmailResponse(
                success=False,
                message_id=request.message_id,
                need_oauth=True,
                oauth_url=result.get("oauth_url"),
                message="Authorization required. Please authenticate with Gmail."
            )
        
        # Return analysis result
        return CheckEmailResponse(
            success=result.get("success", False),
            message_id=request.message_id,
            analysis_id=result.get("analysis_id"),
            verdict=result.get("verdict"),
            confidence=result.get("confidence"),
            risk_score=result.get("risk_score"),
            threat_indicators=result.get("threat_indicators", []),
            ai_summary=result.get("ai_summary"),
            message=result.get("message")
        )
        
    except Exception as e:
        logger.error(f"On-demand check failed for {request.message_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/quick")
async def quick_check(
    request: QuickCheckRequest,
    orchestrator: GmailOrchestrator = Depends(get_gmail_orchestrator_dep)
):
    """
    Quick check using stored tokens.
    
    Attempts to use existing stored tokens for the user.
    Returns OAuth URL if no valid tokens available.
    
    Args:
        request: Message ID and user ID
        
    Returns:
        Analysis result or OAuth redirect
    """
    try:
        result = await orchestrator.check_email_on_demand(
            user_id=request.user_id,
            message_id=request.message_id,
            access_token=None,  # Will try to use stored token
            store_consent=False
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Quick check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/status/{analysis_id}")
async def get_check_status(
    analysis_id: str,
    orchestrator: GmailOrchestrator = Depends(get_gmail_orchestrator_dep)
):
    """
    Get status of an on-demand check.
    
    For async processing scenarios, check if analysis is complete.
    
    Args:
        analysis_id: The analysis ID returned from check request
        
    Returns:
        Current status and result if available
    """
    try:
        status_info = await orchestrator.get_analysis_status(analysis_id)
        
        if not status_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis {analysis_id} not found"
            )
        
        return status_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get status for {analysis_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/history")
async def get_user_history(
    user_id: str,
    limit: int = 20
):
    """
    Get check history for a user.
    
    Returns past on-demand checks where user consented to storage.
    
    Args:
        user_id: The user ID
        limit: Maximum results to return
        
    Returns:
        List of past check results
    """
    try:
        from app.models.mongodb_models import OnDemandAnalysis
        
        results = await OnDemandAnalysis.find(
            OnDemandAnalysis.user_id == user_id
        ).sort(-OnDemandAnalysis.analyzed_at).limit(limit).to_list()
        
        return {
            "success": True,
            "count": len(results),
            "results": [
                {
                    "id": str(r.id),
                    "message_id": r.message_id,
                    "subject": r.subject,
                    "verdict": r.verdict,
                    "risk_score": r.risk_score,
                    "checked_at": r.analyzed_at
                }
                for r in results
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get history for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete("/history/{analysis_id}")
async def delete_check_result(
    analysis_id: str,
    user_id: str
):
    """
    Delete a stored check result.
    
    Users can remove their stored analysis results.
    
    Args:
        analysis_id: The analysis ID to delete
        user_id: The user requesting deletion (must own the result)
        
    Returns:
        Deletion confirmation
    """
    try:
        from app.models.mongodb_models import OnDemandAnalysis
        from bson import ObjectId
        
        result = await OnDemandAnalysis.find_one(
            OnDemandAnalysis.id == ObjectId(analysis_id)
        )
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Analysis not found"
            )
        
        # Verify ownership
        if result.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only delete your own results"
            )
        
        await result.delete()
        
        return {
            "success": True,
            "deleted_id": analysis_id,
            "message": "Check result deleted"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete {analysis_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
