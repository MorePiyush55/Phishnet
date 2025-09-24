"""API endpoints for Gmail sync operations and monitoring."""

from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.services.enhanced_gmail_service import enhanced_gmail_service
from app.services.gmail_realtime_monitor import gmail_realtime_monitor
from app.services.gmail_quota_backfill import gmail_backfill_service
from app.config.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/gmail", tags=["Gmail Sync"])


# Request/Response Models
class GmailConnectResponse(BaseModel):
    """Gmail connection response."""
    status: str
    message: str
    auth_url: Optional[str] = None


class InitialSyncRequest(BaseModel):
    """Initial sync request."""
    confirm_large_mailbox: bool = False
    max_messages: Optional[int] = None


class InitialSyncResponse(BaseModel):
    """Initial sync response."""
    status: str
    message: str
    sync_id: Optional[str] = None
    total_messages: Optional[int] = None
    estimated_time_minutes: Optional[int] = None
    estimated_api_calls: Optional[int] = None


class SyncProgressResponse(BaseModel):
    """Sync progress response."""
    status: str
    total_messages: Optional[int] = None
    processed_messages: int = 0
    failed_messages: int = 0
    progress_percentage: float = 0.0
    start_time: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    current_batch: int = 0
    last_error: Optional[str] = None


class BackfillRequest(BaseModel):
    """Backfill scan request."""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    chunk_size: int = Field(default=500, ge=100, le=1000)
    max_messages_per_day: int = Field(default=10000, ge=1000, le=50000)


class BackfillResponse(BaseModel):
    """Backfill scan response."""
    status: str
    message: str
    job_id: Optional[str] = None
    estimated_messages: Optional[int] = None
    estimated_duration_hours: Optional[float] = None


class WebhookPayload(BaseModel):
    """Gmail webhook payload from Pub/Sub."""
    message: Dict[str, Any]
    subscription: str


# Endpoints
@router.post("/connect", response_model=GmailConnectResponse)
async def connect_gmail(
    current_user: User = Depends(get_current_user)
) -> GmailConnectResponse:
    """Initiate Gmail OAuth connection."""
    try:
        auth_url = await enhanced_gmail_service.get_auth_url(current_user.id)
        return GmailConnectResponse(
            status="success",
            message="Gmail authorization URL generated",
            auth_url=auth_url
        )
    except Exception as e:
        logger.error(f"Failed to generate Gmail auth URL for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate authorization URL")


@router.get("/callback")
async def gmail_oauth_callback(
    code: str,
    state: str,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """Handle Gmail OAuth callback."""
    try:
        result = await enhanced_gmail_service.handle_oauth_callback(code, state)
        
        if result["status"] == "success":
            # Set up monitoring in background
            user_id = int(state)
            background_tasks.add_task(
                gmail_realtime_monitor.setup_all_gmail_watches
            )
        
        return result
    except Exception as e:
        logger.error(f"Gmail OAuth callback failed: {e}")
        raise HTTPException(status_code=500, detail="OAuth callback failed")


@router.post("/sync/start", response_model=InitialSyncResponse)
async def start_initial_sync(
    request: InitialSyncRequest,
    current_user: User = Depends(get_current_user)
) -> InitialSyncResponse:
    """Start initial Gmail inbox sync."""
    try:
        result = await enhanced_gmail_service.start_initial_sync(
            current_user.id,
            request.confirm_large_mailbox
        )
        
        return InitialSyncResponse(**result)
    except Exception as e:
        logger.error(f"Failed to start initial sync for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start sync")


@router.get("/sync/progress", response_model=SyncProgressResponse)
async def get_sync_progress(
    current_user: User = Depends(get_current_user)
) -> SyncProgressResponse:
    """Get current sync progress."""
    try:
        progress = enhanced_gmail_service.get_sync_progress(current_user.id)
        
        if progress:
            return SyncProgressResponse(**progress)
        else:
            return SyncProgressResponse(
                status="not_started",
                processed_messages=0,
                progress_percentage=0.0
            )
    except Exception as e:
        logger.error(f"Failed to get sync progress for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get progress")


@router.post("/sync/pause")
async def pause_sync(
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Pause ongoing sync."""
    try:
        result = await enhanced_gmail_service.pause_sync(current_user.id)
        return result
    except Exception as e:
        logger.error(f"Failed to pause sync for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to pause sync")


@router.post("/sync/resume")
async def resume_sync(
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Resume paused sync."""
    try:
        result = await enhanced_gmail_service.resume_sync(current_user.id)
        return result
    except Exception as e:
        logger.error(f"Failed to resume sync for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to resume sync")


@router.post("/backfill/start", response_model=BackfillResponse)
async def start_backfill_scan(
    request: BackfillRequest,
    current_user: User = Depends(get_current_user)
) -> BackfillResponse:
    """Start historical backfill scan."""
    try:
        job_id = await gmail_backfill_service.start_backfill_job(
            user_id=current_user.id,
            start_date=request.start_date,
            end_date=request.end_date,
            chunk_size=request.chunk_size
        )
        
        return BackfillResponse(
            status="success",
            message="Backfill job started",
            job_id=job_id
        )
    except Exception as e:
        logger.error(f"Failed to start backfill for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start backfill")


@router.get("/backfill/status/{job_id}")
async def get_backfill_status(
    job_id: str,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get backfill job status."""
    try:
        status = gmail_backfill_service.get_backfill_status(job_id)
        
        if not status:
            raise HTTPException(status_code=404, detail="Backfill job not found")
        
        # Verify job belongs to current user
        if status["user_id"] != current_user.id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        return status
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get backfill status for job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get status")


@router.post("/backfill/pause/{job_id}")
async def pause_backfill(
    job_id: str,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Pause backfill job."""
    try:
        # Verify job belongs to user
        status = gmail_backfill_service.get_backfill_status(job_id)
        if not status or status["user_id"] != current_user.id:
            raise HTTPException(status_code=404, detail="Job not found")
        
        success = await gmail_backfill_service.pause_backfill_job(job_id)
        
        if success:
            return {"status": "success", "message": "Backfill job paused"}
        else:
            raise HTTPException(status_code=400, detail="Failed to pause job")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to pause backfill job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to pause job")


@router.post("/backfill/resume/{job_id}")
async def resume_backfill(
    job_id: str,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Resume backfill job."""
    try:
        # Verify job belongs to user
        status = gmail_backfill_service.get_backfill_status(job_id)
        if not status or status["user_id"] != current_user.id:
            raise HTTPException(status_code=404, detail="Job not found")
        
        success = await gmail_backfill_service.resume_backfill_job(job_id)
        
        if success:
            return {"status": "success", "message": "Backfill job resumed"}
        else:
            raise HTTPException(status_code=400, detail="Failed to resume job")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resume backfill job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to resume job")


@router.get("/backfill/jobs")
async def list_backfill_jobs(
    current_user: User = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """List all backfill jobs for current user."""
    try:
        jobs = gmail_backfill_service.get_all_backfill_jobs(current_user.id)
        return jobs
    except Exception as e:
        logger.error(f"Failed to list backfill jobs for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to list jobs")


@router.post("/webhook")
async def gmail_webhook(
    payload: WebhookPayload,
    request: Request,
    background_tasks: BackgroundTasks
) -> Dict[str, str]:
    """Handle Gmail push notifications from Pub/Sub."""
    try:
        # Verify webhook authenticity (in production, verify JWT token)
        logger.info(f"Received Gmail webhook: {payload.subscription}")
        
        # Process webhook in background
        background_tasks.add_task(
            gmail_realtime_monitor.process_gmail_webhook,
            payload.message
        )
        
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Failed to process Gmail webhook: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")


@router.get("/status")
async def gmail_integration_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Get Gmail integration status for current user."""
    try:
        user = db.query(User).filter(User.id == current_user.id).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get sync progress
        sync_progress = enhanced_gmail_service.get_sync_progress(current_user.id)
        
        # Get backfill jobs
        backfill_jobs = gmail_backfill_service.get_all_backfill_jobs(current_user.id)
        
        # Count recent scan requests
        from sqlalchemy import func, text
        from app.models.email_scan import EmailScanRequest
        
        recent_scans = db.query(func.count(EmailScanRequest.id)).filter(
            EmailScanRequest.user_id == current_user.id,
            EmailScanRequest.created_at >= text("NOW() - INTERVAL '24 hours'")
        ).scalar()
        
        return {
            "gmail_connected": bool(user.gmail_credentials),
            "monitoring_enabled": user.email_monitoring_enabled,
            "sync_status": user.gmail_sync_status,
            "last_sync": user.gmail_last_sync_complete.isoformat() if user.gmail_last_sync_complete else None,
            "watch_expires": user.gmail_watch_expiration.isoformat() if user.gmail_watch_expiration else None,
            "sync_progress": sync_progress,
            "backfill_jobs": len(backfill_jobs),
            "active_backfill_jobs": len([j for j in backfill_jobs if j["status"] == "running"]),
            "recent_scans_24h": recent_scans
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get Gmail status for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get status")


@router.get("/health")
async def gmail_service_health() -> Dict[str, Any]:
    """Gmail service health check."""
    try:
        health_data = await gmail_realtime_monitor.health_check()
        
        # Add quota information
        quota_info = {
            "active_quotas": len(gmail_backfill_service.quota_manager.quota_trackers),
            "backfill_jobs": len(gmail_backfill_service.quota_manager.backfill_jobs)
        }
        
        health_data.update(quota_info)
        return health_data
    except Exception as e:
        logger.error(f"Gmail health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }