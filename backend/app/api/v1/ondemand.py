"""
On-Demand Phishing Detection API Endpoints
===========================================
REST API for the on-demand email analysis workflow.

Endpoints:
- POST /analyze/{mail_uid} - Analyze a specific forwarded email
- GET /pending - List pending emails awaiting analysis
- GET /jobs - List analysis jobs
- GET /jobs/{job_id} - Get specific job status
- POST /poll - Trigger manual poll cycle
- GET /worker/status - Get background worker status
- POST /worker/start - Start background polling
- POST /worker/stop - Stop background polling
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel

from app.api.auth import get_current_active_user, require_analyst
from app.models.user import User
from app.services.ondemand_orchestrator import get_ondemand_orchestrator, AnalysisJob, JobStatus
from app.workers.email_polling_worker import get_email_polling_worker, WorkerState
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/ondemand", tags=["On-Demand Analysis"])


# ============================================================================
# Response Models
# ============================================================================

class PendingEmailResponse(BaseModel):
    """Response for pending emails list"""
    success: bool
    count: int
    emails: List[Dict[str, Any]]
    message: str


class AnalysisResponse(BaseModel):
    """Response for email analysis"""
    success: bool
    job_id: str
    status: str
    verdict: Optional[str] = None
    total_score: Optional[int] = None
    confidence: Optional[float] = None
    reasons: Optional[List[str]] = None
    guidance: Optional[List[str]] = None
    email_subject: Optional[str] = None
    forwarded_by: Optional[str] = None
    analyzed_at: Optional[str] = None
    error: Optional[str] = None


class WorkerStatusResponse(BaseModel):
    """Response for worker status"""
    state: str
    poll_interval: int
    current_backoff: int
    metrics: Dict[str, Any]


class JobListResponse(BaseModel):
    """Response for job list"""
    success: bool
    count: int
    jobs: List[Dict[str, Any]]


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/pending", response_model=PendingEmailResponse)
async def list_pending_emails(
    current_user: User = Depends(require_analyst)
):
    """
    List all pending forwarded emails awaiting analysis.
    
    These are emails forwarded by users to the PhishNet inbox
    that have not yet been analyzed.
    """
    try:
        orchestrator = get_ondemand_orchestrator()
        pending_emails = orchestrator.imap_service.get_pending_emails()
        
        return PendingEmailResponse(
            success=True,
            count=len(pending_emails),
            emails=pending_emails,
            message=f"Found {len(pending_emails)} emails awaiting analysis"
        )
        
    except Exception as e:
        logger.error(f"Failed to list pending emails: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve pending emails: {str(e)}"
        )


@router.post("/analyze/{mail_uid}", response_model=AnalysisResponse)
async def analyze_email(
    mail_uid: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_analyst)
):
    """
    Analyze a specific forwarded email.
    
    This triggers the complete on-demand workflow:
    1. Fetch and parse the email
    2. Run detection modules (sender, content, links, auth, attachments)
    3. Get Gemini interpretation (plain-language explanation)
    4. Send response to the user who forwarded it
    
    Args:
        mail_uid: IMAP UID of the email to analyze
        
    Returns:
        Complete analysis results including verdict and recommendations
    """
    try:
        logger.info(f"Analysis requested for email {mail_uid} by {current_user.email}")
        
        orchestrator = get_ondemand_orchestrator()
        job = await orchestrator.process_single_email(mail_uid)
        
        # Build response
        response = AnalysisResponse(
            success=True,
            job_id=job.job_id,
            status=job.status.value,
            email_subject=job.original_subject,
            forwarded_by=job.forwarded_by,
            analyzed_at=job.completed_at.isoformat() if job.completed_at else None
        )
        
        if job.detection_result:
            response.verdict = job.detection_result.final_verdict
            response.total_score = job.detection_result.total_score
            response.confidence = job.detection_result.confidence
        
        if job.interpretation:
            response.reasons = job.interpretation.reasons
            response.guidance = job.interpretation.guidance
        
        if job.error:
            response.error = job.error
        
        return response
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Analysis failed for email {mail_uid}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@router.post("/analyze-all")
async def analyze_all_pending(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_analyst)
):
    """
    Analyze all pending forwarded emails.
    
    Triggers analysis for every unread email in the inbox.
    Results are sent to each respective forwarder.
    """
    try:
        logger.info(f"Bulk analysis requested by {current_user.email}")
        
        orchestrator = get_ondemand_orchestrator()
        completed_jobs = await orchestrator.process_all_pending()
        
        # Summarize results
        summary = {
            "total_processed": len(completed_jobs),
            "verdicts": {
                "phishing": 0,
                "suspicious": 0,
                "safe": 0,
                "failed": 0
            },
            "jobs": []
        }
        
        for job in completed_jobs:
            if job.status == JobStatus.FAILED:
                summary["verdicts"]["failed"] += 1
            elif job.detection_result:
                verdict = job.detection_result.final_verdict.lower()
                if verdict in summary["verdicts"]:
                    summary["verdicts"][verdict] += 1
            
            summary["jobs"].append({
                "job_id": job.job_id,
                "subject": job.original_subject,
                "verdict": job.detection_result.final_verdict if job.detection_result else "FAILED",
                "forwarded_by": job.forwarded_by
            })
        
        return {
            "success": True,
            "message": f"Processed {len(completed_jobs)} emails",
            "summary": summary
        }
        
    except Exception as e:
        logger.error(f"Bulk analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Bulk analysis failed: {str(e)}"
        )


@router.get("/jobs", response_model=JobListResponse)
async def list_jobs(
    limit: int = 50,
    current_user: User = Depends(require_analyst)
):
    """
    List recent analysis jobs.
    
    Returns jobs tracked in memory (for production, use database).
    """
    try:
        orchestrator = get_ondemand_orchestrator()
        jobs = orchestrator.get_active_jobs()
        
        # Sort by creation time (newest first)
        sorted_jobs = sorted(jobs, key=lambda j: j.created_at, reverse=True)[:limit]
        
        return JobListResponse(
            success=True,
            count=len(sorted_jobs),
            jobs=[job.to_dict() for job in sorted_jobs]
        )
        
    except Exception as e:
        logger.error(f"Failed to list jobs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve jobs: {str(e)}"
        )


@router.get("/jobs/{job_id}")
async def get_job_status(
    job_id: str,
    current_user: User = Depends(require_analyst)
):
    """
    Get status of a specific analysis job.
    """
    try:
        orchestrator = get_ondemand_orchestrator()
        job = orchestrator.get_job_status(job_id)
        
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job {job_id} not found"
            )
        
        response = {
            "success": True,
            "job": job.to_dict()
        }
        
        # Add detection results if available
        if job.detection_result:
            response["detection"] = {
                "verdict": job.detection_result.final_verdict,
                "total_score": job.detection_result.total_score,
                "confidence": job.detection_result.confidence,
                "risk_factors": job.detection_result.risk_factors
            }
        
        # Add interpretation if available
        if job.interpretation:
            response["interpretation"] = {
                "reasons": job.interpretation.reasons,
                "guidance": job.interpretation.guidance
            }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get job {job_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve job: {str(e)}"
        )


# ============================================================================
# Worker Control Endpoints
# ============================================================================

@router.get("/worker/status", response_model=WorkerStatusResponse)
async def get_worker_status(
    current_user: User = Depends(require_analyst)
):
    """
    Get status of the background email polling worker.
    """
    worker = get_email_polling_worker()
    status_data = worker.get_status()
    
    return WorkerStatusResponse(**status_data)


@router.post("/worker/start")
async def start_worker(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_analyst)
):
    """
    Start the background email polling worker.
    
    The worker will continuously poll the inbox and process new emails.
    """
    worker = get_email_polling_worker()
    
    if worker.is_running:
        return {
            "success": False,
            "message": "Worker is already running",
            "state": worker.state.value
        }
    
    # Start in background
    background_tasks.add_task(worker.start)
    
    return {
        "success": True,
        "message": "Background polling worker started",
        "poll_interval": worker.poll_interval
    }


@router.post("/worker/stop")
async def stop_worker(
    current_user: User = Depends(require_analyst)
):
    """
    Stop the background email polling worker.
    """
    worker = get_email_polling_worker()
    
    if worker.state == WorkerState.STOPPED:
        return {
            "success": False,
            "message": "Worker is not running",
            "state": worker.state.value
        }
    
    await worker.stop()
    
    return {
        "success": True,
        "message": "Worker stopped",
        "state": worker.state.value
    }


@router.post("/worker/pause")
async def pause_worker(
    current_user: User = Depends(require_analyst)
):
    """
    Pause the background polling worker.
    
    Current operation will complete, but no new polls will start.
    """
    worker = get_email_polling_worker()
    
    if not worker.is_running:
        return {
            "success": False,
            "message": "Worker is not running",
            "state": worker.state.value
        }
    
    worker.pause()
    
    return {
        "success": True,
        "message": "Worker paused",
        "state": worker.state.value
    }


@router.post("/worker/resume")
async def resume_worker(
    current_user: User = Depends(require_analyst)
):
    """
    Resume a paused polling worker.
    """
    worker = get_email_polling_worker()
    
    if worker.state != WorkerState.PAUSED:
        return {
            "success": False,
            "message": "Worker is not paused",
            "state": worker.state.value
        }
    
    worker.resume()
    
    return {
        "success": True,
        "message": "Worker resumed",
        "state": worker.state.value
    }


@router.post("/poll")
async def trigger_manual_poll(
    current_user: User = Depends(require_analyst)
):
    """
    Trigger a single manual poll cycle.
    
    Useful for testing or when immediate processing is needed.
    Does not require the background worker to be running.
    """
    try:
        worker = get_email_polling_worker()
        
        logger.info(f"Manual poll triggered by {current_user.email}")
        completed_jobs = await worker.poll_once()
        
        return {
            "success": True,
            "message": f"Manual poll complete: {len(completed_jobs)} emails processed",
            "emails_processed": len(completed_jobs),
            "jobs": [
                {
                    "job_id": job.job_id,
                    "subject": job.original_subject,
                    "verdict": job.detection_result.final_verdict if job.detection_result else None
                }
                for job in completed_jobs
            ]
        }
        
    except Exception as e:
        logger.error(f"Manual poll failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Manual poll failed: {str(e)}"
        )


# ============================================================================
# Health & Stats
# ============================================================================

@router.get("/stats")
async def get_ondemand_stats(
    current_user: User = Depends(require_analyst)
):
    """
    Get on-demand analysis statistics.
    """
    orchestrator = get_ondemand_orchestrator()
    worker = get_email_polling_worker()
    
    # Get pending count
    try:
        pending_emails = orchestrator.imap_service.get_pending_emails()
        pending_count = len(pending_emails)
    except Exception:
        pending_count = -1  # Error fetching
    
    # Get worker metrics
    worker_status = worker.get_status()
    metrics = worker_status.get("metrics", {})
    
    return {
        "success": True,
        "stats": {
            "pending_emails": pending_count,
            "worker_state": worker_status.get("state"),
            "total_processed": metrics.get("total_emails_processed", 0),
            "verdicts": metrics.get("verdicts", {}),
            "last_poll": metrics.get("last_poll_at"),
            "total_polls": metrics.get("total_polls", 0),
            "errors": metrics.get("total_errors", 0)
        }
    }


@router.get("/health")
async def health_check():
    """
    Health check for on-demand service.
    
    Checks:
    - IMAP connection
    - Gemini availability
    - Worker status
    """
    orchestrator = get_ondemand_orchestrator()
    worker = get_email_polling_worker()
    
    health = {
        "status": "healthy",
        "components": {}
    }
    
    # Check IMAP
    try:
        imap_ok = orchestrator.imap_service.test_connection()
        health["components"]["imap"] = {
            "status": "healthy" if imap_ok else "unhealthy",
            "message": "Connection OK" if imap_ok else "Connection failed"
        }
    except Exception as e:
        health["components"]["imap"] = {
            "status": "unhealthy",
            "message": str(e)
        }
        health["status"] = "degraded"
    
    # Check Gemini
    try:
        gemini_available = orchestrator.gemini_client.is_available
        health["components"]["gemini"] = {
            "status": "healthy" if gemini_available else "unavailable",
            "message": "API configured" if gemini_available else "API key not configured"
        }
    except Exception as e:
        health["components"]["gemini"] = {
            "status": "unhealthy",
            "message": str(e)
        }
    
    # Check Worker
    health["components"]["worker"] = {
        "status": worker.state.value,
        "poll_interval": worker.poll_interval
    }
    
    return health
