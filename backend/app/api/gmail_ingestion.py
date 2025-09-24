"""API endpoints for enhanced Gmail ingestion and monitoring."""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime

from app.config.logging import get_logger
from app.services.enhanced_gmail_service import enhanced_gmail_service
from app.services.gmail_realtime_monitor import gmail_realtime_monitor
from app.services.gmail_quota_backfill import gmail_quota_manager, gmail_backfill_service
from app.auth.dependencies import get_current_user
from app.models.user import User

logger = get_logger(__name__)

router = APIRouter(prefix="/api/gmail", tags=["Gmail Ingestion"])


class SyncConfirmationRequest(BaseModel):
    """Request model for sync confirmation."""
    confirm_large_mailbox: bool = Field(default=False, description="Confirm processing of large mailbox")


class BackfillRequest(BaseModel):
    """Request model for backfill job."""
    start_date: Optional[datetime] = Field(default=None, description="Start date for backfill (defaults to 2 years ago)")
    end_date: Optional[datetime] = Field(default=None, description="End date for backfill (defaults to now)")
    chunk_size_days: int = Field(default=30, description="Size of date chunks to process")


class WebhookMessage(BaseModel):
    """Pub/Sub webhook message model."""
    data: str = Field(description="Base64 encoded message data")
    messageId: Optional[str] = Field(default=None)
    publishTime: Optional[str] = Field(default=None)


@router.get("/auth-url")
async def get_gmail_auth_url(current_user: User = Depends(get_current_user)):
    """Get Gmail OAuth authorization URL."""
    try:
        auth_url = await enhanced_gmail_service.get_auth_url(current_user.id)
        return {"auth_url": auth_url}
    except Exception as e:
        logger.error(f"Failed to get Gmail auth URL for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate authorization URL")


@router.post("/oauth-callback")
async def handle_gmail_oauth_callback(
    code: str = Query(..., description="OAuth authorization code"),
    state: str = Query(..., description="User ID state parameter")
):
    """Handle Gmail OAuth callback."""
    try:
        result = await enhanced_gmail_service.handle_oauth_callback(code, state)
        return result
    except Exception as e:
        logger.error(f"Gmail OAuth callback failed: {e}")
        raise HTTPException(status_code=500, detail="OAuth callback failed")


@router.post("/start-initial-sync")
async def start_initial_sync(
    request: SyncConfirmationRequest,
    current_user: User = Depends(get_current_user)
):
    """Start initial full inbox sync."""
    try:
        result = await enhanced_gmail_service.start_initial_sync(
            current_user.id,
            confirm_large_mailbox=request.confirm_large_mailbox
        )
        return result
    except Exception as e:
        logger.error(f"Failed to start initial sync for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start initial sync")


@router.get("/sync-progress")
async def get_sync_progress(current_user: User = Depends(get_current_user)):
    """Get current sync progress."""
    try:
        progress = enhanced_gmail_service.get_sync_progress(current_user.id)
        if progress:
            return progress
        else:
            return {"status": "no_sync_active", "message": "No active sync found"}
    except Exception as e:
        logger.error(f"Failed to get sync progress for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get sync progress")


@router.post("/pause-sync")
async def pause_sync(current_user: User = Depends(get_current_user)):
    """Pause ongoing sync."""
    try:
        result = await enhanced_gmail_service.pause_sync(current_user.id)
        return result
    except Exception as e:
        logger.error(f"Failed to pause sync for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to pause sync")


@router.post("/resume-sync")
async def resume_sync(current_user: User = Depends(get_current_user)):
    """Resume paused sync."""
    try:
        result = await enhanced_gmail_service.resume_sync(current_user.id)
        return result
    except Exception as e:
        logger.error(f"Failed to resume sync for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to resume sync")


@router.post("/webhook")
async def gmail_webhook(message: WebhookMessage, background_tasks: BackgroundTasks):
    """Handle Gmail Pub/Sub webhook notifications."""
    try:
        # Process webhook in background to return quickly
        background_tasks.add_task(
            gmail_realtime_monitor.process_gmail_webhook,
            {"data": message.data}
        )
        
        return {"status": "webhook_received"}
    except Exception as e:
        logger.error(f"Failed to process Gmail webhook: {e}")
        raise HTTPException(status_code=500, detail="Failed to process webhook")


@router.post("/backfill/start")
async def start_backfill_job(
    request: BackfillRequest,
    current_user: User = Depends(get_current_user)
):
    """Start a backfill job for historical emails."""
    try:
        job_id = await gmail_backfill_service.start_backfill_job(
            user_id=current_user.id,
            start_date=request.start_date,
            end_date=request.end_date,
            chunk_size_days=request.chunk_size_days
        )
        
        return {
            "status": "success",
            "job_id": job_id,
            "message": "Backfill job started"
        }
    except Exception as e:
        logger.error(f"Failed to start backfill job for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start backfill job")


@router.post("/backfill/{job_id}/pause")
async def pause_backfill_job(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Pause a backfill job."""
    try:
        # Verify job belongs to user
        job_status = gmail_backfill_service.get_backfill_status(job_id)
        if not job_status or job_status["user_id"] != current_user.id:
            raise HTTPException(status_code=404, detail="Backfill job not found")
        
        success = await gmail_backfill_service.pause_backfill_job(job_id)
        if success:
            return {"status": "success", "message": "Backfill job paused"}
        else:
            raise HTTPException(status_code=400, detail="Failed to pause backfill job")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to pause backfill job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to pause backfill job")


@router.post("/backfill/{job_id}/resume")
async def resume_backfill_job(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Resume a paused backfill job."""
    try:
        # Verify job belongs to user
        job_status = gmail_backfill_service.get_backfill_status(job_id)
        if not job_status or job_status["user_id"] != current_user.id:
            raise HTTPException(status_code=404, detail="Backfill job not found")
        
        success = await gmail_backfill_service.resume_backfill_job(job_id)
        if success:
            return {"status": "success", "message": "Backfill job resumed"}
        else:
            raise HTTPException(status_code=400, detail="Failed to resume backfill job")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resume backfill job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to resume backfill job")


@router.post("/backfill/{job_id}/cancel")
async def cancel_backfill_job(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Cancel a backfill job."""
    try:
        # Verify job belongs to user
        job_status = gmail_backfill_service.get_backfill_status(job_id)
        if not job_status or job_status["user_id"] != current_user.id:
            raise HTTPException(status_code=404, detail="Backfill job not found")
        
        success = await gmail_backfill_service.cancel_backfill_job(job_id)
        if success:
            return {"status": "success", "message": "Backfill job cancelled"}
        else:
            raise HTTPException(status_code=400, detail="Failed to cancel backfill job")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel backfill job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to cancel backfill job")


@router.get("/backfill/{job_id}/status")
async def get_backfill_job_status(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get status of a specific backfill job."""
    try:
        job_status = gmail_backfill_service.get_backfill_status(job_id)
        if not job_status:
            raise HTTPException(status_code=404, detail="Backfill job not found")
        
        # Verify job belongs to user
        if job_status["user_id"] != current_user.id:
            raise HTTPException(status_code=404, detail="Backfill job not found")
        
        return job_status
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get backfill job status {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get job status")


@router.get("/backfill/jobs")
async def get_backfill_jobs(current_user: User = Depends(get_current_user)):
    """Get all backfill jobs for the current user."""
    try:
        jobs = gmail_backfill_service.get_all_backfill_jobs(user_id=current_user.id)
        return {"jobs": jobs}
    except Exception as e:
        logger.error(f"Failed to get backfill jobs for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get backfill jobs")


@router.get("/quota-status")
async def get_quota_status(current_user: User = Depends(get_current_user)):
    """Get current Gmail API quota status."""
    try:
        status = gmail_quota_manager.get_quota_status()
        return {"quota_status": status}
    except Exception as e:
        logger.error(f"Failed to get quota status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get quota status")


@router.get("/health")
async def gmail_health_check():
    """Health check for Gmail monitoring services."""
    try:
        health_status = await gmail_realtime_monitor.health_check()
        quota_status = gmail_quota_manager.get_quota_status()
        
        overall_status = "healthy" if health_status["status"] == "healthy" else "unhealthy"
        
        return {
            "status": overall_status,
            "gmail_monitor": health_status,
            "quota_manager": quota_status,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Gmail health check failed: {e}")
        raise HTTPException(status_code=500, detail="Health check failed")


@router.post("/setup-watches")
async def setup_gmail_watches():
    """Set up Gmail watches for all users (admin endpoint)."""
    try:
        # This should be protected by admin authentication in production
        count = await gmail_realtime_monitor.setup_all_gmail_watches()
        return {
            "status": "success",
            "watches_setup": count,
            "message": f"Set up Gmail watches for {count} users"
        }
    except Exception as e:
        logger.error(f"Failed to setup Gmail watches: {e}")
        raise HTTPException(status_code=500, detail="Failed to setup Gmail watches")


@router.get("/statistics")
async def get_gmail_statistics(current_user: User = Depends(get_current_user)):
    """Get Gmail ingestion statistics for the user."""
    try:
        from app.core.database import get_session
        
        async with get_session() as db:
            # Get scan request statistics
            stats_query = f"""
            SELECT 
                COUNT(*) as total_messages,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as processed_messages,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_messages,
                COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_messages,
                MIN(received_at) as oldest_message,
                MAX(received_at) as newest_message
            FROM email_scan_requests 
            WHERE user_id = {current_user.id}
            """
            
            result = await db.execute(stats_query)
            stats = result.first()
            
            # Get recent activity (last 24 hours)
            recent_query = f"""
            SELECT COUNT(*) as recent_messages
            FROM email_scan_requests 
            WHERE user_id = {current_user.id} 
            AND created_at > NOW() - INTERVAL '24 hours'
            """
            
            recent_result = await db.execute(recent_query)
            recent_stats = recent_result.first()
            
            return {
                "total_messages": stats.total_messages or 0,
                "processed_messages": stats.processed_messages or 0,
                "pending_messages": stats.pending_messages or 0,
                "failed_messages": stats.failed_messages or 0,
                "recent_24h_messages": recent_stats.recent_messages or 0,
                "oldest_message": stats.oldest_message.isoformat() if stats.oldest_message else None,
                "newest_message": stats.newest_message.isoformat() if stats.newest_message else None,
                "sync_progress": enhanced_gmail_service.get_sync_progress(current_user.id)
            }
            
    except Exception as e:
        logger.error(f"Failed to get Gmail statistics for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get statistics")