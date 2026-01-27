"""
Mode 1 Enterprise API Endpoints
===============================
REST API for the automatic email processing pipeline.

Endpoints:
- Status and health
- Manual trigger
- Statistics and metrics
- Tenant management
- Audit log queries
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field

from app.api.auth import get_current_active_user, require_analyst, require_admin
from app.models.user import User
from app.config.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/mode1", tags=["Mode 1 - Automatic Email Processing"])


# ═══════════════════════════════════════════════════════════════════════════
# REQUEST/RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════

class Mode1StatusResponse(BaseModel):
    """Mode 1 orchestrator status"""
    running: bool
    active_jobs: int
    polling_tasks: List[str]
    resilience: Dict[str, Any]


class Mode1StatsResponse(BaseModel):
    """Mode 1 statistics"""
    deduplication: Dict[str, Any]
    policy: Dict[str, Any]
    resilience: Dict[str, Any]


class TenantMailboxCreate(BaseModel):
    """Request to create a tenant mailbox"""
    tenant_id: str = Field(..., description="Unique tenant identifier")
    tenant_domain: str = Field(..., description="Tenant's email domain")
    imap_host: str = Field(..., description="IMAP server hostname")
    imap_user: str = Field(..., description="IMAP username/email")
    imap_password: str = Field(..., description="IMAP password or app password")
    imap_port: int = Field(993, description="IMAP port (993 for SSL)")
    imap_folder: str = Field("INBOX", description="Folder to monitor")
    poll_interval: int = Field(60, description="Poll interval in seconds")
    batch_size: int = Field(50, description="Max emails per poll")


class TenantMailboxResponse(BaseModel):
    """Tenant mailbox configuration response"""
    tenant_id: str
    tenant_domain: str
    imap_host: str
    imap_user: str
    status: str
    last_poll_at: Optional[datetime]
    emails_processed_today: int
    emails_processed_total: int


class ManualProcessRequest(BaseModel):
    """Request to manually process an email"""
    mail_uid: str = Field(..., description="IMAP UID of email to process")
    tenant_id: Optional[str] = Field("default", description="Tenant ID")


class AuditLogQuery(BaseModel):
    """Query parameters for audit log"""
    job_id: Optional[str] = None
    tenant_id: Optional[str] = None
    event_types: Optional[List[str]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(100, le=1000)


class AuditLogEntry(BaseModel):
    """Audit log entry response"""
    sequence_id: int
    job_id: str
    event_type: str
    severity: str
    message: str
    timestamp: datetime
    verdict: Optional[str] = None
    score: Optional[float] = None


# ═══════════════════════════════════════════════════════════════════════════
# STATUS & HEALTH
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/status", response_model=Mode1StatusResponse)
async def get_mode1_status(
    current_user: User = Depends(require_analyst)
):
    """
    Get Mode 1 orchestrator status.
    
    Returns current running state, active jobs, and resilience health.
    """
    from app.services.mode1_orchestrator import get_mode1_orchestrator
    
    orchestrator = get_mode1_orchestrator()
    return orchestrator.get_status()


@router.get("/stats", response_model=Mode1StatsResponse)
async def get_mode1_stats(
    tenant_id: Optional[str] = Query(None, description="Filter by tenant"),
    current_user: User = Depends(require_analyst)
):
    """
    Get Mode 1 processing statistics.
    
    Includes deduplication savings, policy evaluations, and resilience metrics.
    """
    from app.services.mode1_orchestrator import get_mode1_orchestrator
    
    orchestrator = get_mode1_orchestrator()
    return await orchestrator.get_stats(tenant_id)


@router.get("/health")
async def get_mode1_health():
    """
    Get Mode 1 health check (public endpoint for monitoring).
    """
    from app.services.mode1_orchestrator import get_mode1_orchestrator
    from app.services.worker_resilience import get_resilience_manager
    
    try:
        orchestrator = get_mode1_orchestrator()
        resilience = get_resilience_manager()
        
        health = resilience.get_health_status()
        
        # Check circuit breakers
        open_circuits = [
            name for name, cb in health["circuit_breakers"].items()
            if cb["state"] == "open"
        ]
        
        # Check backpressure
        bp = health["backpressure"]
        under_pressure = bp["in_backpressure"]
        
        status = "healthy"
        if open_circuits:
            status = "degraded"
        if under_pressure:
            status = "overloaded"
        
        return {
            "status": status,
            "running": orchestrator._is_running,
            "open_circuits": open_circuits,
            "backpressure_active": under_pressure,
            "queue_utilization": bp["utilization"]
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }


# ═══════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR CONTROL
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/start")
async def start_mode1_polling(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin)
):
    """
    Start Mode 1 automatic email polling.
    
    Requires admin privileges.
    """
    from app.services.mode1_orchestrator import get_mode1_orchestrator
    
    orchestrator = get_mode1_orchestrator()
    
    if orchestrator._is_running:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Mode 1 orchestrator already running"
        )
    
    # Start in background
    background_tasks.add_task(orchestrator.start_all_mailbox_polling)
    
    return {"message": "Mode 1 orchestrator starting", "status": "starting"}


@router.post("/stop")
async def stop_mode1_polling(
    current_user: User = Depends(require_admin)
):
    """
    Stop Mode 1 automatic email polling.
    
    Requires admin privileges.
    """
    from app.services.mode1_orchestrator import get_mode1_orchestrator
    
    orchestrator = get_mode1_orchestrator()
    
    if not orchestrator._is_running:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Mode 1 orchestrator not running"
        )
    
    await orchestrator.stop_all_polling()
    
    return {"message": "Mode 1 orchestrator stopped", "status": "stopped"}


@router.post("/process")
async def manual_process_email(
    request: ManualProcessRequest,
    current_user: User = Depends(require_analyst)
):
    """
    Manually trigger processing of a specific email.
    
    Useful for testing or re-processing.
    """
    from app.services.mode1_orchestrator import get_mode1_orchestrator
    from app.services.quick_imap import QuickIMAPService
    
    orchestrator = get_mode1_orchestrator()
    
    try:
        # Use default IMAP service for manual processing
        imap_service = QuickIMAPService()
        
        job = await orchestrator.process_email(
            tenant_id=request.tenant_id or "default",
            mail_uid=request.mail_uid,
            message_id=None,
            imap_service=imap_service
        )
        
        return {
            "job_id": job.job_id,
            "status": job.status.value,
            "verdict": job.analysis_result.final_verdict if job.analysis_result else None,
            "score": job.analysis_result.total_score if job.analysis_result else None,
            "duration_ms": job.total_duration_ms,
            "actions": job.policy_actions
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# ═══════════════════════════════════════════════════════════════════════════
# TENANT MAILBOX MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/mailboxes", response_model=List[TenantMailboxResponse])
async def list_tenant_mailboxes(
    current_user: User = Depends(require_admin)
):
    """
    List all configured tenant mailboxes.
    
    Requires admin privileges.
    """
    from app.services.tenant_mailbox import get_tenant_mailbox_service
    
    service = get_tenant_mailbox_service()
    mailboxes = await service.get_all_active_mailboxes()
    
    return [
        TenantMailboxResponse(
            tenant_id=mb.tenant_id,
            tenant_domain=mb.tenant_domain,
            imap_host=mb.imap_host,
            imap_user=mb.imap_user,
            status=mb.status.value,
            last_poll_at=mb.last_poll_at,
            emails_processed_today=mb.emails_processed_today,
            emails_processed_total=mb.emails_processed_total
        )
        for mb in mailboxes
    ]


@router.post("/mailboxes", response_model=TenantMailboxResponse)
async def create_tenant_mailbox(
    request: TenantMailboxCreate,
    current_user: User = Depends(require_admin)
):
    """
    Create a new tenant mailbox configuration.
    
    Requires admin privileges.
    """
    from app.services.tenant_mailbox import get_tenant_mailbox_service
    
    service = get_tenant_mailbox_service()
    
    # Check if already exists
    existing = await service.get_mailbox_for_tenant(request.tenant_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Mailbox for tenant {request.tenant_id} already exists"
        )
    
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
    
    return TenantMailboxResponse(
        tenant_id=mailbox.tenant_id,
        tenant_domain=mailbox.tenant_domain,
        imap_host=mailbox.imap_host,
        imap_user=mailbox.imap_user,
        status=mailbox.status.value,
        last_poll_at=mailbox.last_poll_at,
        emails_processed_today=mailbox.emails_processed_today,
        emails_processed_total=mailbox.emails_processed_total
    )


@router.post("/mailboxes/{tenant_id}/activate")
async def activate_tenant_mailbox(
    tenant_id: str,
    current_user: User = Depends(require_admin)
):
    """
    Activate a tenant mailbox for polling.
    """
    from app.services.tenant_mailbox import get_tenant_mailbox_service
    
    service = get_tenant_mailbox_service()
    success = await service.activate_mailbox(tenant_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mailbox for tenant {tenant_id} not found"
        )
    
    return {"message": f"Mailbox {tenant_id} activated"}


@router.post("/mailboxes/{tenant_id}/deactivate")
async def deactivate_tenant_mailbox(
    tenant_id: str,
    reason: Optional[str] = Query(None),
    current_user: User = Depends(require_admin)
):
    """
    Deactivate a tenant mailbox.
    """
    from app.services.tenant_mailbox import get_tenant_mailbox_service
    
    service = get_tenant_mailbox_service()
    success = await service.deactivate_mailbox(tenant_id, reason)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mailbox for tenant {tenant_id} not found"
        )
    
    return {"message": f"Mailbox {tenant_id} deactivated"}


@router.get("/mailboxes/health")
async def get_mailbox_health(
    current_user: User = Depends(require_analyst)
):
    """
    Get health summary of all tenant mailboxes.
    """
    from app.services.tenant_mailbox import get_tenant_mailbox_service
    
    service = get_tenant_mailbox_service()
    return await service.get_health_summary()


# ═══════════════════════════════════════════════════════════════════════════
# DEDUPLICATION
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/dedup/stats")
async def get_dedup_stats(
    tenant_id: Optional[str] = Query(None),
    current_user: User = Depends(require_analyst)
):
    """
    Get deduplication statistics.
    
    Shows cache entries, hit rate, and savings.
    """
    from app.services.deduplication import get_deduplication_service
    
    service = get_deduplication_service()
    return await service.get_stats(tenant_id)


# ═══════════════════════════════════════════════════════════════════════════
# AUDIT LOGS
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/audit/job/{job_id}", response_model=List[AuditLogEntry])
async def get_job_audit_trail(
    job_id: str,
    current_user: User = Depends(require_analyst)
):
    """
    Get complete audit trail for a specific job.
    
    Returns all audit events in chronological order.
    """
    from app.services.mode1_audit import get_mode1_audit_logger
    
    audit = get_mode1_audit_logger()
    entries = await audit.get_job_audit_trail(job_id)
    
    return [
        AuditLogEntry(
            sequence_id=e.sequence_id,
            job_id=e.job_id,
            event_type=e.event_type,
            severity=e.severity,
            message=e.message,
            timestamp=e.timestamp,
            verdict=e.verdict,
            score=e.score
        )
        for e in entries
    ]


@router.post("/audit/query", response_model=List[AuditLogEntry])
async def query_audit_logs(
    query: AuditLogQuery,
    current_user: User = Depends(require_analyst)
):
    """
    Query audit logs with filters.
    """
    from app.services.mode1_audit import get_mode1_audit_logger, AuditEventType
    
    audit = get_mode1_audit_logger()
    
    # Convert event type strings to enums
    event_types = None
    if query.event_types:
        event_types = [AuditEventType(e) for e in query.event_types]
    
    entries = await audit.get_tenant_audit_trail(
        tenant_id=query.tenant_id or "default",
        start_time=query.start_time,
        end_time=query.end_time,
        event_types=event_types,
        limit=query.limit
    )
    
    return [
        AuditLogEntry(
            sequence_id=e.sequence_id,
            job_id=e.job_id,
            event_type=e.event_type,
            severity=e.severity,
            message=e.message,
            timestamp=e.timestamp,
            verdict=e.verdict,
            score=e.score
        )
        for e in entries
    ]


@router.get("/audit/verify-integrity")
async def verify_audit_integrity(
    limit: int = Query(1000, le=10000),
    current_user: User = Depends(require_admin)
):
    """
    Verify audit log chain integrity.
    
    Checks hash chain for tampering. Requires admin privileges.
    """
    from app.services.mode1_audit import get_mode1_audit_logger
    
    audit = get_mode1_audit_logger()
    result = await audit.verify_chain_integrity(limit)
    
    return result


# ═══════════════════════════════════════════════════════════════════════════
# RESILIENCE
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/resilience/circuits")
async def get_circuit_breakers(
    current_user: User = Depends(require_analyst)
):
    """
    Get status of all circuit breakers.
    """
    from app.services.worker_resilience import get_resilience_manager
    
    manager = get_resilience_manager()
    return {
        name: cb.get_status()
        for name, cb in manager.circuit_breakers.items()
    }


@router.post("/resilience/circuits/{name}/reset")
async def reset_circuit_breaker(
    name: str,
    current_user: User = Depends(require_admin)
):
    """
    Manually reset a circuit breaker to closed state.
    
    Requires admin privileges.
    """
    from app.services.worker_resilience import get_resilience_manager, CircuitState
    
    manager = get_resilience_manager()
    
    if name not in manager.circuit_breakers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Circuit breaker {name} not found"
        )
    
    cb = manager.circuit_breakers[name]
    cb._state.state = CircuitState.CLOSED
    cb._state.failure_count = 0
    cb._state.success_count = 0
    
    return {"message": f"Circuit breaker {name} reset to CLOSED"}


@router.get("/resilience/rate-limiters")
async def get_rate_limiters(
    current_user: User = Depends(require_analyst)
):
    """
    Get status of all rate limiters.
    """
    from app.services.worker_resilience import get_resilience_manager
    
    manager = get_resilience_manager()
    return {
        name: rl.get_stats()
        for name, rl in manager.rate_limiters.items()
    }


@router.get("/resilience/backpressure")
async def get_backpressure_status(
    current_user: User = Depends(require_analyst)
):
    """
    Get backpressure controller status.
    """
    from app.services.worker_resilience import get_resilience_manager
    
    manager = get_resilience_manager()
    return manager.backpressure.get_stats()


@router.get("/resilience/bulkheads")
async def get_bulkhead_status(
    current_user: User = Depends(require_analyst)
):
    """
    Get tenant bulkhead status.
    """
    from app.services.worker_resilience import get_resilience_manager
    
    manager = get_resilience_manager()
    return manager.bulkhead.get_all_stats()
