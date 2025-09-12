"""
API Routes for Pipeline Progress Integration
FastAPI endpoints that serve the pipeline progress data to the frontend.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, Optional
import logging

from app.core.pipeline_orchestrator import get_pipeline_orchestrator
from app.core.worker_pools import get_worker_pool_manager
from app.core.queue_manager import get_job_queue_manager
from app.core.rate_limiter import get_rate_limiter
from app.models.jobs import JobPriority

logger = logging.getLogger(__name__)

# Create API router
pipeline_router = APIRouter(prefix="/api/pipeline", tags=["pipeline"])

@pipeline_router.post("/jobs")
async def submit_email_scan(
    email_id: str,
    user_id: str,
    tenant_id: Optional[str] = None,
    priority: str = "normal"
):
    """
    Submit an email for scanning through the pipeline.
    
    Args:
        email_id: Email identifier
        user_id: User submitting the scan
        tenant_id: Optional tenant identifier
        priority: Job priority (low, normal, high, urgent)
        
    Returns:
        Job submission response with job_id
    """
    try:
        orchestrator = get_pipeline_orchestrator()
        
        # Convert priority string to enum
        priority_mapping = {
            "low": JobPriority.LOW,
            "normal": JobPriority.NORMAL, 
            "high": JobPriority.HIGH,
            "urgent": JobPriority.URGENT
        }
        job_priority = priority_mapping.get(priority.lower(), JobPriority.NORMAL)
        
        # Submit job
        job_id = await orchestrator.submit_email_scan(
            email_id=email_id,
            user_id=user_id,
            tenant_id=tenant_id,
            priority=job_priority
        )
        
        return {
            "success": True,
            "job_id": job_id,
            "email_id": email_id,
            "status": "submitted",
            "message": f"Email scan job {job_id} submitted successfully"
        }
        
    except Exception as e:
        logger.error(f"Error submitting email scan: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to submit email scan: {str(e)}"
        )

@pipeline_router.get("/jobs/{job_id}/status")
async def get_job_status(job_id: str):
    """
    Get current status of a pipeline job.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Detailed job status with progress information
    """
    try:
        orchestrator = get_pipeline_orchestrator()
        
        status = await orchestrator.get_job_status(job_id)
        
        if not status:
            raise HTTPException(
                status_code=404,
                detail=f"Job {job_id} not found"
            )
        
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job status: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get job status: {str(e)}"
        )

@pipeline_router.get("/orchestrator/stats")
async def get_orchestrator_stats():
    """
    Get orchestrator statistics and health metrics.
    
    Returns:
        Orchestrator statistics including active jobs, queue stats, worker stats
    """
    try:
        orchestrator = get_pipeline_orchestrator()
        stats = orchestrator.get_orchestrator_stats()
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting orchestrator stats: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get orchestrator stats: {str(e)}"
        )

@pipeline_router.get("/queues/stats")
async def get_queue_stats():
    """
    Get detailed queue statistics.
    
    Returns:
        Queue statistics including lengths, processing rates
    """
    try:
        queue_manager = get_job_queue_manager()
        stats = queue_manager.get_queue_stats()
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting queue stats: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get queue stats: {str(e)}"
        )

@pipeline_router.get("/workers/stats")
async def get_worker_stats():
    """
    Get worker pool statistics.
    
    Returns:
        Worker pool statistics including health, performance metrics
    """
    try:
        worker_manager = get_worker_pool_manager()
        stats = worker_manager.get_all_stats()
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting worker stats: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get worker stats: {str(e)}"
        )

@pipeline_router.get("/rate-limits/stats")
async def get_rate_limit_stats(
    service: Optional[str] = None,
    identifier: str = "default",
    tenant_id: Optional[str] = None
):
    """
    Get rate limiting statistics.
    
    Args:
        service: Optional service name filter
        identifier: Rate limit identifier
        tenant_id: Optional tenant filter
        
    Returns:
        Rate limit statistics and current usage
    """
    try:
        rate_limiter = get_rate_limiter()
        stats = await rate_limiter.get_rate_limit_status(
            service=service,
            identifier=identifier,
            tenant_id=tenant_id
        )
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting rate limit stats: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get rate limit stats: {str(e)}"
        )

@pipeline_router.get("/health")
async def pipeline_health():
    """
    Get overall pipeline health status.
    
    Returns:
        Health status of all pipeline components
    """
    try:
        orchestrator = get_pipeline_orchestrator()
        worker_manager = get_worker_pool_manager()
        queue_manager = get_job_queue_manager()
        
        # Get component health
        orchestrator_stats = orchestrator.get_orchestrator_stats()
        worker_stats = worker_manager.get_all_stats()
        queue_stats = queue_manager.get_queue_stats()
        
        # Determine overall health
        is_healthy = True
        issues = []
        
        # Check if orchestrator is running
        if not orchestrator_stats.get('is_running', False):
            is_healthy = False
            issues.append("Orchestrator is not running")
        
        # Check for high error rates
        failed_jobs = orchestrator_stats.get('stage_distribution', {}).get('failed', 0)
        total_jobs = orchestrator_stats.get('active_jobs', 0) + failed_jobs
        
        if total_jobs > 0 and failed_jobs / total_jobs > 0.1:  # >10% failure rate
            is_healthy = False
            issues.append(f"High job failure rate: {failed_jobs}/{total_jobs}")
        
        # Check queue backlogs
        total_pending = queue_stats.get('total_pending', 0)
        if total_pending > 100:  # Arbitrary threshold
            issues.append(f"High queue backlog: {total_pending} jobs pending")
        
        # Check dead letter queue
        dead_letter_size = queue_stats.get('dead_letter_size', 0)
        if dead_letter_size > 10:
            issues.append(f"Dead letter queue has {dead_letter_size} failed jobs")
        
        health_status = {
            "healthy": is_healthy,
            "status": "healthy" if is_healthy else "degraded",
            "timestamp": orchestrator_stats.get('timestamp'),
            "components": {
                "orchestrator": {
                    "healthy": orchestrator_stats.get('is_running', False),
                    "active_jobs": orchestrator_stats.get('active_jobs', 0)
                },
                "workers": {
                    "healthy": worker_stats.get('is_running', False),
                    "total_workers": worker_stats.get('total_workers', 0)
                },
                "queues": {
                    "healthy": total_pending < 100,
                    "total_pending": total_pending,
                    "dead_letter_size": dead_letter_size
                }
            },
            "issues": issues
        }
        
        return health_status
        
    except Exception as e:
        logger.error(f"Error getting pipeline health: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get pipeline health: {str(e)}"
        )

# WebSocket endpoint for real-time updates
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import json

@pipeline_router.websocket("/ws/job/{job_id}")
async def job_status_websocket(websocket: WebSocket, job_id: str):
    """
    WebSocket endpoint for real-time job status updates.
    
    Args:
        websocket: WebSocket connection
        job_id: Job to monitor
    """
    await websocket.accept()
    
    try:
        orchestrator = get_pipeline_orchestrator()
        
        while True:
            try:
                # Get current job status
                status = await orchestrator.get_job_status(job_id)
                
                if status:
                    await websocket.send_text(json.dumps(status))
                    
                    # Stop monitoring if job is complete
                    if status.get('status') in ['completed', 'failed']:
                        break
                else:
                    await websocket.send_text(json.dumps({
                        "error": f"Job {job_id} not found"
                    }))
                    break
                
                # Wait before next update
                await asyncio.sleep(2)
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error in job status WebSocket: {e}")
                await websocket.send_text(json.dumps({
                    "error": f"Internal error: {str(e)}"
                }))
                break
                
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
    finally:
        try:
            await websocket.close()
        except:
            pass

@pipeline_router.websocket("/ws/stats")
async def stats_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time orchestrator statistics.
    """
    await websocket.accept()
    
    try:
        orchestrator = get_pipeline_orchestrator()
        
        while True:
            try:
                # Get current stats
                stats = orchestrator.get_orchestrator_stats()
                await websocket.send_text(json.dumps(stats))
                
                # Wait before next update
                await asyncio.sleep(5)
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error in stats WebSocket: {e}")
                await websocket.send_text(json.dumps({
                    "error": f"Internal error: {str(e)}"
                }))
                break
                
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
    finally:
        try:
            await websocket.close()
        except:
            pass
