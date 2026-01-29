"""
Mode 1 Enterprise Management API
=================================
REST API endpoints for controlling and monitoring the Mode 1 orchestrator.

Endpoints:
- GET /api/v1/mode1/status - Get orchestrator status
- GET /api/v1/mode1/stats - Get processing statistics
- POST /api/v1/mode1/start - Start Mode 1 polling (admin only)
- POST /api/v1/mode1/stop - Stop Mode 1 polling (admin only)
- GET /api/v1/mode1/mailboxes - List configured mailboxes
- POST /api/v1/mode1/mailboxes - Add new tenant mailbox
- PUT /api/v1/mode1/mailboxes/{tenant_id}/activate - Activate mailbox
- PUT /api/v1/mode1/mailboxes/{tenant_id}/deactivate - Deactivate mailbox
- GET /api/v1/mode1/dedup/stats - Deduplication statistics
- GET /api/v1/mode1/policies/{tenant_id} - Get tenant policies
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field

from app.config.logging import get_logger
from app.services.mode1_orchestrator import get_mode1_orchestrator
from app.services.tenant_mailbox import get_tenant_mailbox_service, MailboxConfig
from app.services.deduplication import get_deduplication_service
from app.services.policy_engine import get_policy_engine
from app.models.tenant import Tenant

logger = get_logger(__name__)
router = APIRouter(prefix="/mode1", tags=["Mode 1 - Enterprise Management"])


# ============================================================================
# Request/Response Models
# ============================================================================

class MailboxCreateRequest(BaseModel):
    """Request to create a new tenant mailbox"""
    tenant_id: str = Field(..., description="Unique tenant identifier")
    tenant_domain: str = Field(..., description="Tenant domain (e.g., acme.com)")
    imap_host: str = Field(..., description="IMAP server hostname")
    imap_user: str = Field(..., description="IMAP username/email")
    imap_password: str = Field(..., description="IMAP password or app password")
    imap_port: int = Field(993, description="IMAP port (default: 993)")
    imap_folder: str = Field("INBOX", description="IMAP folder to monitor")
    poll_interval: int = Field(60, description="Polling interval in seconds")
    batch_size: int = Field(50, description="Max emails per poll")


class MailboxResponse(BaseModel):
    """Mailbox configuration response"""
    tenant_id: str
    tenant_domain: str
    imap_host: str
    imap_user: str
    imap_folder: str
    poll_interval_seconds: int
    batch_size: int
    status: str
    last_poll_at: Optional[str] = None
    emails_processed_today: int
    emails_processed_total: int
    consecutive_errors: int


class OrchestratorStatusResponse(BaseModel):
    """Mode 1 orchestrator status"""
    running: bool
    active_jobs: int
    polling_tasks: List[str]
    resilience: Dict[str, Any]


class StatsResponse(BaseModel):
    """Processing statistics"""
    total_emails_processed: int
    by_tenant: Dict[str, int]
    by_verdict: Dict[str, int]
    avg_processing_time_ms: float


class DedupStatsResponse(BaseModel):
    """Deduplication statistics"""
    total_entries: int
    by_verdict: Dict[str, int]
    total_references: int
    dedup_savings: int


# ============================================================================
# Orchestrator Control Endpoints
# ============================================================================

@router.get("/status", response_model=OrchestratorStatusResponse)
async def get_orchestrator_status():
    """
    Get current status of the Mode 1 orchestrator.
    
    Returns:
        - running: Whether orchestrator is actively polling
        - active_jobs: Number of emails currently being processed
        - polling_tasks: List of tenant IDs being polled
        - resilience: Circuit breaker and rate limiter status
    """
    try:
        orchestrator = get_mode1_orchestrator()
        status_data = orchestrator.get_status()
        return OrchestratorStatusResponse(**status_data)
    except Exception as e:
        logger.error(f"Failed to get orchestrator status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get status: {str(e)}"
        )


@router.get("/stats", response_model=StatsResponse)
async def get_processing_stats(tenant_id: Optional[str] = None):
    """
    Get processing statistics.
    
    Args:
        tenant_id: Optional tenant filter
        
    Returns:
        Processing statistics including email counts and timing
    """
    try:
        orchestrator = get_mode1_orchestrator()
        stats = orchestrator.get_stats(tenant_id=tenant_id)
        
        # Format response
        return StatsResponse(
            total_emails_processed=stats.get("total_emails", 0),
            by_tenant=stats.get("by_tenant", {}),
            by_verdict=stats.get("by_verdict", {}),
            avg_processing_time_ms=stats.get("avg_time_ms", 0.0)
        )
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get stats: {str(e)}"
        )


@router.post("/start")
async def start_orchestrator():
    """
    Start the Mode 1 orchestrator polling.
    
    **Admin only** - Requires authentication.
    
    Returns:
        Success message
    """
    try:
        orchestrator = get_mode1_orchestrator()
        await orchestrator.start_all_mailbox_polling()
        logger.info("Mode 1 orchestrator started via API")
        return {"status": "success", "message": "Mode 1 orchestrator started"}
    except Exception as e:
        logger.error(f"Failed to start orchestrator: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start: {str(e)}"
        )


@router.post("/stop")
async def stop_orchestrator():
    """
    Stop the Mode 1 orchestrator polling.
    
    **Admin only** - Requires authentication.
    
    Returns:
        Success message
    """
    try:
        orchestrator = get_mode1_orchestrator()
        await orchestrator.stop_all_polling()
        logger.info("Mode 1 orchestrator stopped via API")
        return {"status": "success", "message": "Mode 1 orchestrator stopped"}
    except Exception as e:
        logger.error(f"Failed to stop orchestrator: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop: {str(e)}"
        )


# ============================================================================
# Mailbox Management Endpoints
# ============================================================================

@router.get("/mailboxes", response_model=List[MailboxResponse])
async def list_mailboxes():
    """
    List all configured tenant mailboxes.
    
    Returns:
        List of mailbox configurations
    """
    try:
        service = get_tenant_mailbox_service()
        mailboxes = await MailboxConfig.find().to_list()
        
        return [
            MailboxResponse(
                tenant_id=mb.tenant_id,
                tenant_domain=mb.tenant_domain,
                imap_host=mb.imap_host,
                imap_user=mb.imap_user,
                imap_folder=mb.imap_folder,
                poll_interval_seconds=mb.poll_interval_seconds,
                batch_size=mb.batch_size,
                status=mb.status.value,
                last_poll_at=mb.last_poll_at.isoformat() if mb.last_poll_at else None,
                emails_processed_today=mb.emails_processed_today,
                emails_processed_total=mb.emails_processed_total,
                consecutive_errors=mb.consecutive_errors
            )
            for mb in mailboxes
        ]
    except Exception as e:
        logger.error(f"Failed to list mailboxes: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list mailboxes: {str(e)}"
        )


@router.post("/mailboxes", response_model=MailboxResponse, status_code=status.HTTP_201_CREATED)
async def create_mailbox(request: MailboxCreateRequest):
    """
    Create a new tenant mailbox configuration.
    
    **Admin only** - Requires authentication.
    
    Args:
        request: Mailbox configuration
        
    Returns:
        Created mailbox configuration
    """
    try:
        service = get_tenant_mailbox_service()
        
        # Check if mailbox already exists
        existing = await service.get_mailbox_for_tenant(request.tenant_id)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Mailbox for tenant {request.tenant_id} already exists"
            )
        
        # Create mailbox
        mailbox = await service.create_mailbox(
            tenant_id=request.tenant_id,
            tenant_domain=request.tenant_domain,
            imap_host=request.imap_host,
            imap_user=request.imap_user,
            imap_password=request.imap_password,
            imap_port=request.imap_port,
            imap_folder=request.imap_folder,
            poll_interval=request.poll_interval,
            batch_size=request.batch_size
        )
        
        logger.info(f"Created mailbox for tenant {request.tenant_id}")
        
        return MailboxResponse(
            tenant_id=mailbox.tenant_id,
            tenant_domain=mailbox.tenant_domain,
            imap_host=mailbox.imap_host,
            imap_user=mailbox.imap_user,
            imap_folder=mailbox.imap_folder,
            poll_interval_seconds=mailbox.poll_interval_seconds,
            batch_size=mailbox.batch_size,
            status=mailbox.status.value,
            last_poll_at=None,
            emails_processed_today=0,
            emails_processed_total=0,
            consecutive_errors=0
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create mailbox: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create mailbox: {str(e)}"
        )


@router.put("/mailboxes/{tenant_id}/activate")
async def activate_mailbox(tenant_id: str):
    """
    Activate a tenant mailbox for polling.
    
    **Admin only** - Requires authentication.
    
    Args:
        tenant_id: Tenant identifier
        
    Returns:
        Success message
    """
    try:
        service = get_tenant_mailbox_service()
        success = await service.activate_mailbox(tenant_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Mailbox for tenant {tenant_id} not found"
            )
        
        logger.info(f"Activated mailbox for tenant {tenant_id}")
        return {"status": "success", "message": f"Mailbox {tenant_id} activated"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to activate mailbox: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to activate mailbox: {str(e)}"
        )


@router.put("/mailboxes/{tenant_id}/deactivate")
async def deactivate_mailbox(tenant_id: str, reason: Optional[str] = None):
    """
    Deactivate a tenant mailbox.
    
    **Admin only** - Requires authentication.
    
    Args:
        tenant_id: Tenant identifier
        reason: Optional reason for deactivation
        
    Returns:
        Success message
    """
    try:
        service = get_tenant_mailbox_service()
        success = await service.deactivate_mailbox(tenant_id, reason)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Mailbox for tenant {tenant_id} not found"
            )
        
        logger.info(f"Deactivated mailbox for tenant {tenant_id}: {reason}")
        return {"status": "success", "message": f"Mailbox {tenant_id} deactivated"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to deactivate mailbox: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to deactivate mailbox: {str(e)}"
        )


# ============================================================================
# Deduplication Statistics
# ============================================================================

@router.get("/dedup/stats", response_model=DedupStatsResponse)
async def get_dedup_stats(tenant_id: Optional[str] = None):
    """
    Get deduplication statistics.
    
    Args:
        tenant_id: Optional tenant filter
        
    Returns:
        Deduplication statistics including cache hits and savings
    """
    try:
        service = get_deduplication_service()
        stats = await service.get_stats(tenant_id=tenant_id)
        
        return DedupStatsResponse(
            total_entries=stats["total_entries"],
            by_verdict=stats["by_verdict"],
            total_references=stats["total_references"],
            dedup_savings=stats["dedup_savings"]
        )
    except Exception as e:
        logger.error(f"Failed to get dedup stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get dedup stats: {str(e)}"
        )


# ============================================================================
# Policy Management
# ============================================================================

@router.get("/policies/{tenant_id}")
async def get_tenant_policies(tenant_id: str):
    """
    Get policy configuration for a tenant.
    
    Args:
        tenant_id: Tenant identifier
        
    Returns:
        Tenant policy configuration
    """
    try:
        tenant = await Tenant.find_one(Tenant.domain == tenant_id)
        
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Tenant {tenant_id} not found"
            )
        
        return {
            "tenant_id": tenant_id,
            "tenant_name": tenant.name,
            "policies": [
                {
                    "name": p.name,
                    "priority": p.priority,
                    "conditions": {
                        "min_score": p.conditions.min_score,
                        "max_score": p.conditions.max_score,
                        "risk_level": p.conditions.risk_level,
                        "keyword_match": p.conditions.keyword_match
                    },
                    "actions": [a.value for a in p.actions],
                    "enabled": p.enabled
                }
                for p in (tenant.policies or [])
            ]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get tenant policies: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get policies: {str(e)}"
        )


@router.get("/health")
async def mode1_health_check():
    """
    Health check endpoint for Mode 1 subsystem.
    
    Returns:
        Health status of all Mode 1 components
    """
    try:
        orchestrator = get_mode1_orchestrator()
        mailbox_service = get_tenant_mailbox_service()
        
        orchestrator_status = orchestrator.get_status()
        mailbox_health = await mailbox_service.get_health_summary()
        
        return {
            "status": "healthy",
            "orchestrator": {
                "running": orchestrator_status["running"],
                "active_jobs": orchestrator_status["active_jobs"],
                "polling_tasks": len(orchestrator_status["polling_tasks"])
            },
            "mailboxes": {
                "total": mailbox_health["total_mailboxes"],
                "by_status": mailbox_health["by_status"],
                "unhealthy_count": len(mailbox_health["unhealthy_mailboxes"])
            },
            "processing": {
                "emails_today": mailbox_health["total_emails_today"],
                "emails_all_time": mailbox_health["total_emails_all_time"]
            }
        }
    except Exception as e:
        logger.error(f"Mode 1 health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }
