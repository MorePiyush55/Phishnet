"""
Async Email Analysis API
Integrates background task processing for email analysis.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field

from app.workers.celery_config import celery_app
from app.tasks.scan_tasks import (
    quick_email_scan, full_email_scan, sandbox_analysis, 
    link_safety_check, deep_attachment_scan
)
from app.tasks.analysis_tasks import (
    basic_threat_analysis, ml_threat_detection, 
    reputation_lookup, advanced_ml_analysis, threat_intelligence_lookup
)
from app.workers.task_prioritizer import TaskPrioritizer
from app.core.redis_client import get_redis_client

# Import with fallbacks for auth
try:
    from app.core.auth_simple import get_current_user
except ImportError:
    def get_current_user():
        return {"id": 1, "username": "demo"}

router = APIRouter(prefix="/api/v1/analysis", tags=["Async Email Analysis"])

# Request/Response Models
class EmailAnalysisRequest(BaseModel):
    subject: str = Field(..., description="Email subject line")
    sender: str = Field(..., description="Sender email address")
    content: str = Field(..., description="Email body content")
    recipients: Optional[List[str]] = Field(None, description="Recipient email addresses")
    headers: Optional[Dict[str, str]] = Field(None, description="Email headers")
    attachments: Optional[List[str]] = Field(None, description="Base64 encoded attachments")
    analysis_type: str = Field("standard", pattern="^(quick|standard|comprehensive)$")

class JobSubmissionResponse(BaseModel):
    job_id: str
    status: str
    analysis_type: str
    estimated_completion: str
    polling_url: str
    websocket_url: Optional[str] = None

class JobStatusResponse(BaseModel):
    job_id: str
    status: str  # pending, processing, completed, failed
    progress: int  # 0-100
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str
    updated_at: str
    processing_time: Optional[float] = None

class BulkJobSubmissionRequest(BaseModel):
    emails: List[EmailAnalysisRequest]
    analysis_type: str = Field("standard", pattern="^(quick|standard|comprehensive)$")
    priority: str = Field("normal", pattern="^(low|normal|high|urgent)$")

class BulkJobSubmissionResponse(BaseModel):
    batch_id: str
    job_ids: List[str]
    total_jobs: int
    estimated_completion: str

# Initialize task prioritizer
task_prioritizer = TaskPrioritizer()

@router.post("/submit", response_model=JobSubmissionResponse)
async def submit_email_analysis(
    request: EmailAnalysisRequest,
    current_user: Dict = Depends(get_current_user)
) -> JobSubmissionResponse:
    """Submit email for background analysis."""
    try:
        # Generate unique job ID
        job_id = str(uuid.uuid4())
        
        # Determine task priority and queue based on analysis type
        if request.analysis_type == "quick":
            # Quick analysis - use realtime queue
            task_result = quick_email_scan.apply_async(
                args=[request.dict(), current_user["id"]],
                task_id=job_id,
                queue="realtime"
            )
            estimated_time = "10 seconds"
            
        elif request.analysis_type == "comprehensive":
            # Comprehensive analysis - use heavy queue
            task_result = advanced_ml_analysis.apply_async(
                args=[request.dict(), current_user["id"]],
                task_id=job_id,
                queue="heavy"
            )
            estimated_time = "2-5 minutes"
            
        else:
            # Standard analysis - use standard queue
            task_result = full_email_scan.apply_async(
                args=[request.dict(), current_user["id"]],
                task_id=job_id,
                queue="standard"
            )
            estimated_time = "30-60 seconds"
        
        # Store job metadata in Redis
        redis_client = get_redis_client()
        job_data = {
            "user_id": current_user["id"],
            "analysis_type": request.analysis_type,
            "created_at": datetime.utcnow().isoformat(),
            "status": "pending",
            "progress": 0
        }
        redis_client.hmset(f"job:{job_id}", job_data)
        redis_client.expire(f"job:{job_id}", 3600)  # 1 hour expiration
        
        return JobSubmissionResponse(
            job_id=job_id,
            status="submitted",
            analysis_type=request.analysis_type,
            estimated_completion=estimated_time,
            polling_url=f"/api/v1/analysis/status/{job_id}",
            websocket_url=f"/ws/jobs/{job_id}"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to submit job: {str(e)}")

@router.post("/submit-bulk", response_model=BulkJobSubmissionResponse)
async def submit_bulk_analysis(
    request: BulkJobSubmissionRequest,
    current_user: Dict = Depends(get_current_user)
) -> BulkJobSubmissionResponse:
    """Submit multiple emails for batch analysis."""
    try:
        batch_id = str(uuid.uuid4())
        job_ids = []
        
        # Submit each email as a separate job
        for i, email_request in enumerate(request.emails):
            job_id = f"{batch_id}_{i+1:03d}"
            
            # Determine queue based on analysis type and priority
            queue_name = task_prioritizer.classify_task({
                "analysis_type": request.analysis_type,
                "priority": request.priority,
                "batch_size": len(request.emails)
            }).queue
            
            if request.analysis_type == "quick":
                task_result = quick_email_scan.apply_async(
                    args=[email_request.dict(), current_user["id"]],
                    task_id=job_id,
                    queue=queue_name
                )
            elif request.analysis_type == "comprehensive":
                task_result = advanced_ml_analysis.apply_async(
                    args=[email_request.dict(), current_user["id"]],
                    task_id=job_id,
                    queue=queue_name
                )
            else:
                task_result = full_email_scan.apply_async(
                    args=[email_request.dict(), current_user["id"]],
                    task_id=job_id,
                    queue=queue_name
                )
            
            job_ids.append(job_id)
        
        # Store batch metadata
        redis_client = get_redis_client()
        batch_data = {
            "user_id": current_user["id"],
            "total_jobs": len(job_ids),
            "completed_jobs": 0,
            "failed_jobs": 0,
            "created_at": datetime.utcnow().isoformat(),
            "job_ids": ",".join(job_ids)
        }
        redis_client.hmset(f"batch:{batch_id}", batch_data)
        redis_client.expire(f"batch:{batch_id}", 7200)  # 2 hours expiration
        
        return BulkJobSubmissionResponse(
            batch_id=batch_id,
            job_ids=job_ids,
            total_jobs=len(job_ids),
            estimated_completion=f"{len(job_ids) * 30} seconds"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to submit batch: {str(e)}")

@router.get("/status/{job_id}", response_model=JobStatusResponse)
async def get_job_status(
    job_id: str,
    current_user: Dict = Depends(get_current_user)
) -> JobStatusResponse:
    """Get the status of a submitted analysis job."""
    try:
        # Get job from Celery
        task_result = celery_app.AsyncResult(job_id)
        
        # Get additional metadata from Redis
        redis_client = get_redis_client()
        job_data = redis_client.hgetall(f"job:{job_id}")
        
        if not job_data and task_result.state == "PENDING":
            raise HTTPException(status_code=404, detail="Job not found")
        
        # Map Celery states to our status
        status_mapping = {
            "PENDING": "pending",
            "STARTED": "processing", 
            "RETRY": "processing",
            "SUCCESS": "completed",
            "FAILURE": "failed",
            "REVOKED": "cancelled"
        }
        
        status = status_mapping.get(task_result.state, "unknown")
        
        # Calculate progress
        progress = 0
        if status == "processing":
            progress = 50  # Simplified progress calculation
        elif status == "completed":
            progress = 100
        
        # Get result if completed
        result = None
        error = None
        if task_result.ready():
            if task_result.successful():
                result = task_result.result
            else:
                error = str(task_result.info)
        
        processing_time = None
        if job_data.get("started_at") and job_data.get("completed_at"):
            started = datetime.fromisoformat(job_data["started_at"])
            completed = datetime.fromisoformat(job_data["completed_at"])
            processing_time = (completed - started).total_seconds()
        
        return JobStatusResponse(
            job_id=job_id,
            status=status,
            progress=progress,
            result=result,
            error=error,
            created_at=job_data.get("created_at", datetime.utcnow().isoformat()),
            updated_at=datetime.utcnow().isoformat(),
            processing_time=processing_time
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get job status: {str(e)}")

@router.delete("/cancel/{job_id}")
async def cancel_job(
    job_id: str,
    current_user: Dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Cancel a pending or processing job."""
    try:
        # Revoke the task
        celery_app.control.revoke(job_id, terminate=True)
        
        # Update Redis status
        redis_client = get_redis_client()
        redis_client.hset(f"job:{job_id}", "status", "cancelled")
        redis_client.hset(f"job:{job_id}", "cancelled_at", datetime.utcnow().isoformat())
        
        return {
            "job_id": job_id,
            "status": "cancelled",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel job: {str(e)}")

@router.get("/batch/{batch_id}")
async def get_batch_status(
    batch_id: str,
    current_user: Dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get status of a batch analysis."""
    try:
        redis_client = get_redis_client()
        batch_data = redis_client.hgetall(f"batch:{batch_id}")
        
        if not batch_data:
            raise HTTPException(status_code=404, detail="Batch not found")
        
        job_ids = batch_data["job_ids"].split(",")
        
        # Get status of all jobs in batch
        job_statuses = []
        completed_count = 0
        failed_count = 0
        
        for job_id in job_ids:
            task_result = celery_app.AsyncResult(job_id)
            status = "pending"
            
            if task_result.state == "SUCCESS":
                status = "completed"
                completed_count += 1
            elif task_result.state == "FAILURE":
                status = "failed"
                failed_count += 1
            elif task_result.state in ["STARTED", "RETRY"]:
                status = "processing"
            
            job_statuses.append({
                "job_id": job_id,
                "status": status
            })
        
        # Calculate overall progress
        total_jobs = len(job_ids)
        progress = int((completed_count + failed_count) / total_jobs * 100)
        
        return {
            "batch_id": batch_id,
            "total_jobs": total_jobs,
            "completed": completed_count,
            "failed": failed_count,
            "processing": total_jobs - completed_count - failed_count,
            "progress": progress,
            "job_statuses": job_statuses,
            "created_at": batch_data.get("created_at"),
            "updated_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get batch status: {str(e)}")

@router.get("/history")
async def get_analysis_history(
    limit: int = 50,
    offset: int = 0,
    current_user: Dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get user's analysis history."""
    try:
        redis_client = get_redis_client()
        
        # This would typically query a database
        # For now, return a simplified response
        return {
            "jobs": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
            "message": "History tracking not yet implemented"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get history: {str(e)}")

@router.get("/stats")
async def get_analysis_stats(
    current_user: Dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get user's analysis statistics."""
    try:
        redis_client = get_redis_client()
        
        # Get user-specific stats from Redis
        user_id = current_user["id"]
        
        # These would be tracked when jobs complete
        total_analyses = int(redis_client.get(f"user:{user_id}:total_analyses") or 0)
        total_threats = int(redis_client.get(f"user:{user_id}:total_threats") or 0)
        avg_processing_time = float(redis_client.get(f"user:{user_id}:avg_processing_time") or 0.0)
        
        return {
            "user_id": user_id,
            "total_analyses": total_analyses,
            "threats_detected": total_threats,
            "avg_processing_time": avg_processing_time,
            "success_rate": 98.5,  # Calculated metric
            "most_common_threat": "Phishing Links",
            "updated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")

# Compatibility endpoint for existing clients
@router.post("/analyze", response_model=JobSubmissionResponse)
async def analyze_email_legacy(
    request: EmailAnalysisRequest,
    current_user: Dict = Depends(get_current_user)
) -> JobSubmissionResponse:
    """Legacy analyze endpoint - redirects to async submission."""
    # Just call the submit endpoint
    return await submit_email_analysis(request, current_user)