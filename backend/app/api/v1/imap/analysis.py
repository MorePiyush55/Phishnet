"""
IMAP Analysis Routes
====================

Endpoints for analyzing forwarded emails via Mode 1 orchestrator.
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

from app.modes.dependencies import get_imap_orchestrator_dep
from app.modes.imap.orchestrator import IMAPOrchestrator
from app.modes.base import AnalysisRequest, ModeType, AnalysisStatus
from app.api.auth import require_analyst, get_current_active_user
from app.models.user import User
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/analysis", tags=["IMAP Analysis"])


# ============================================================================
# Request/Response Models
# ============================================================================

class AnalyzeEmailRequest(BaseModel):
    """Request to analyze a forwarded email."""
    email_uid: str = Field(..., description="IMAP UID of the email to analyze")
    priority: str = Field("normal", description="Analysis priority: low, normal, high")
    notify_analyst: bool = Field(True, description="Send notification when analysis completes")


class AnalysisResultResponse(BaseModel):
    """Response containing analysis results."""
    success: bool
    analysis_id: str
    email_uid: str
    status: str
    verdict: Optional[str] = None
    confidence: Optional[float] = None
    threat_indicators: List[str] = []
    risk_score: Optional[float] = None
    ai_summary: Optional[str] = None
    completed_at: Optional[datetime] = None
    processing_time_ms: Optional[int] = None


class BulkAnalyzeRequest(BaseModel):
    """Request to analyze multiple emails."""
    email_uids: List[str] = Field(..., description="List of IMAP UIDs to analyze")
    priority: str = Field("normal", description="Analysis priority")


class AnalysisStatusResponse(BaseModel):
    """Response for analysis status check."""
    analysis_id: str
    status: str
    progress: Optional[float] = None
    message: Optional[str] = None


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/analyze", response_model=AnalysisResultResponse)
async def analyze_email(
    request: AnalyzeEmailRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_analyst),
    orchestrator: IMAPOrchestrator = Depends(get_imap_orchestrator_dep)
):
    """
    Analyze a forwarded email for phishing indicators.
    
    This triggers the full Mode 1 analysis pipeline:
    1. Fetch email from IMAP
    2. Extract headers, body, links, and attachments
    3. Run phishing analysis engine
    4. Apply organizational policies
    5. Generate AI summary
    6. Store result and send notifications
    
    Requires: Analyst role
    
    Args:
        request: Analysis request with email UID
        
    Returns:
        Analysis result with verdict and threat indicators
    """
    try:
        # Build analysis request
        analysis_request = AnalysisRequest(
            mode=ModeType.IMAP_BULK,
            email_identifier=request.email_uid,
            user_id=str(current_user.id),
            priority=request.priority,
            options={
                "notify_analyst": request.notify_analyst,
                "analyst_email": current_user.email
            }
        )
        
        # Process email
        result = await orchestrator.process_email(analysis_request)
        
        return AnalysisResultResponse(
            success=result.status == AnalysisStatus.COMPLETED,
            analysis_id=result.analysis_id,
            email_uid=request.email_uid,
            status=result.status.value,
            verdict=result.verdict.value if result.verdict else None,
            confidence=result.confidence,
            threat_indicators=result.threat_indicators or [],
            risk_score=result.risk_score,
            ai_summary=result.ai_summary,
            completed_at=result.completed_at,
            processing_time_ms=result.processing_time_ms
        )
        
    except Exception as e:
        logger.error(f"Analysis failed for email {request.email_uid}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@router.post("/analyze-bulk")
async def analyze_bulk(
    request: BulkAnalyzeRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_analyst),
    orchestrator: IMAPOrchestrator = Depends(get_imap_orchestrator_dep)
):
    """
    Queue multiple emails for analysis.
    
    Starts background analysis for multiple forwarded emails.
    Returns immediately with job IDs for tracking progress.
    
    Requires: Analyst role
    
    Args:
        request: List of email UIDs to analyze
        
    Returns:
        Job tracking information
    """
    try:
        jobs = []
        
        for uid in request.email_uids:
            analysis_request = AnalysisRequest(
                mode=ModeType.IMAP_BULK,
                email_identifier=uid,
                user_id=str(current_user.id),
                priority=request.priority,
                options={"analyst_email": current_user.email}
            )
            
            # Queue for background processing
            job_id = f"bulk_{uid}_{datetime.utcnow().timestamp()}"
            background_tasks.add_task(
                orchestrator.process_email,
                analysis_request
            )
            
            jobs.append({
                "email_uid": uid,
                "job_id": job_id,
                "status": "queued"
            })
        
        return {
            "success": True,
            "queued_count": len(jobs),
            "jobs": jobs,
            "message": f"Queued {len(jobs)} emails for analysis"
        }
        
    except Exception as e:
        logger.error(f"Bulk analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Bulk analysis failed: {str(e)}"
        )


@router.get("/status/{analysis_id}", response_model=AnalysisStatusResponse)
async def get_analysis_status(
    analysis_id: str,
    current_user: User = Depends(require_analyst),
    orchestrator: IMAPOrchestrator = Depends(get_imap_orchestrator_dep)
):
    """
    Check the status of an ongoing analysis.
    
    Requires: Analyst role
    
    Args:
        analysis_id: The analysis ID returned from analyze endpoint
        
    Returns:
        Current status and progress
    """
    try:
        status_info = await orchestrator.get_analysis_status(analysis_id)
        
        if not status_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis {analysis_id} not found"
            )
        
        return AnalysisStatusResponse(**status_info)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get status for {analysis_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get status: {str(e)}"
        )


@router.get("/history")
async def get_analysis_history(
    limit: int = 50,
    offset: int = 0,
    verdict_filter: Optional[str] = None,
    current_user: User = Depends(require_analyst)
):
    """
    Get history of analyzed emails.
    
    Requires: Analyst role
    
    Args:
        limit: Maximum number of results
        offset: Pagination offset
        verdict_filter: Filter by verdict (malicious, suspicious, clean)
        
    Returns:
        List of past analysis results
    """
    try:
        from app.models.mongodb_models import ForwardedEmailAnalysis
        
        query = {}
        if verdict_filter:
            query["verdict"] = verdict_filter
        
        results = await ForwardedEmailAnalysis.find(query).skip(offset).limit(limit).to_list()
        
        return {
            "success": True,
            "count": len(results),
            "offset": offset,
            "results": [
                {
                    "id": str(r.id),
                    "subject": r.subject,
                    "sender": r.sender,
                    "verdict": r.verdict,
                    "risk_score": r.risk_score,
                    "analyzed_at": r.analyzed_at,
                    "analyst": r.analyst_notes
                }
                for r in results
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get analysis history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get history: {str(e)}"
        )


@router.delete("/history/{analysis_id}")
async def delete_analysis(
    analysis_id: str,
    current_user: User = Depends(require_analyst)
):
    """
    Delete an analysis result.
    
    Requires: Analyst role
    
    Args:
        analysis_id: The analysis ID to delete
        
    Returns:
        Deletion confirmation
    """
    try:
        from app.models.mongodb_models import ForwardedEmailAnalysis
        from bson import ObjectId
        
        result = await ForwardedEmailAnalysis.find_one(
            ForwardedEmailAnalysis.id == ObjectId(analysis_id)
        )
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis {analysis_id} not found"
            )
        
        await result.delete()
        
        return {
            "success": True,
            "deleted_id": analysis_id,
            "message": "Analysis deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete analysis {analysis_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete: {str(e)}"
        )
