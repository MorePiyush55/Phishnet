"""
IMAP Connection Routes
======================

Endpoints for managing IMAP connection and configuration.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional
from pydantic import BaseModel, Field

from app.modes.dependencies import get_imap_service_dep, get_imap_orchestrator_dep
from app.modes.imap.service import IMAPEmailService
from app.modes.imap.orchestrator import IMAPOrchestrator
from app.api.auth import require_analyst, require_admin
from app.models.user import User
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/connection", tags=["IMAP Connection"])


# ============================================================================
# Response Models
# ============================================================================

class ConnectionStatusResponse(BaseModel):
    """Response for connection status check."""
    success: bool
    status: str
    message: str
    server: Optional[str] = None
    folder: Optional[str] = None
    email_count: Optional[int] = None


class PollingStatusResponse(BaseModel):
    """Response for polling status."""
    is_running: bool
    interval_seconds: int
    last_poll: Optional[str] = None
    next_poll: Optional[str] = None
    emails_processed_today: int = 0


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/test", response_model=ConnectionStatusResponse)
async def test_connection(
    current_user: User = Depends(require_analyst),
    imap_service: IMAPEmailService = Depends(get_imap_service_dep)
):
    """
    Test IMAP connection to the forwarding inbox.
    
    Verifies that PhishNet can connect to the email account
    where users forward suspicious emails.
    
    Requires: Analyst role
    
    Returns:
        Connection status and server info
    """
    try:
        success = await imap_service.test_connection()
        
        if success:
            return ConnectionStatusResponse(
                success=True,
                status="connected",
                message="IMAP connection successful",
                server=imap_service._imap_host or "configured",
                folder="INBOX"
            )
        else:
            return ConnectionStatusResponse(
                success=False,
                status="error",
                message="IMAP connection failed - check credentials"
            )
            
    except Exception as e:
        logger.error(f"IMAP connection test error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Connection test failed: {str(e)}"
        )


@router.get("/status", response_model=ConnectionStatusResponse)
async def get_connection_status(
    current_user: User = Depends(require_analyst),
    imap_service: IMAPEmailService = Depends(get_imap_service_dep)
):
    """
    Get current IMAP connection status.
    
    Returns details about the current connection state
    and email inbox statistics.
    
    Requires: Analyst role
    """
    try:
        # Test connection and get stats
        is_connected = await imap_service.test_connection()
        
        if is_connected:
            emails = await imap_service.list_pending(limit=1000)
            
            return ConnectionStatusResponse(
                success=True,
                status="connected",
                message="IMAP service is running",
                server=imap_service._imap_host or "configured",
                folder="INBOX",
                email_count=len(emails)
            )
        else:
            return ConnectionStatusResponse(
                success=False,
                status="disconnected",
                message="IMAP service is not connected"
            )
            
    except Exception as e:
        logger.error(f"Failed to get connection status: {e}")
        return ConnectionStatusResponse(
            success=False,
            status="error",
            message=f"Error checking status: {str(e)}"
        )


@router.get("/polling", response_model=PollingStatusResponse)
async def get_polling_status(
    current_user: User = Depends(require_analyst),
    orchestrator: IMAPOrchestrator = Depends(get_imap_orchestrator_dep)
):
    """
    Get background polling status.
    
    Returns information about the automatic inbox polling
    that checks for new forwarded emails.
    
    Requires: Analyst role
    """
    try:
        return PollingStatusResponse(
            is_running=orchestrator._polling_active,
            interval_seconds=orchestrator._poll_interval,
            last_poll=orchestrator._last_poll_time.isoformat() if orchestrator._last_poll_time else None,
            emails_processed_today=orchestrator._metrics.get("emails_processed_today", 0)
        )
    except Exception as e:
        logger.error(f"Failed to get polling status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get polling status: {str(e)}"
        )


@router.post("/polling/start")
async def start_polling(
    interval_seconds: int = 60,
    current_user: User = Depends(require_admin),
    orchestrator: IMAPOrchestrator = Depends(get_imap_orchestrator_dep)
):
    """
    Start background polling for new emails.
    
    Begins automatic polling of the IMAP inbox at the specified interval.
    New forwarded emails will be automatically analyzed.
    
    Requires: Admin role
    
    Args:
        interval_seconds: Polling interval (default: 60 seconds)
    """
    try:
        await orchestrator.start_background_polling(interval_seconds)
        
        return {
            "success": True,
            "message": f"Polling started with {interval_seconds}s interval",
            "interval_seconds": interval_seconds
        }
    except Exception as e:
        logger.error(f"Failed to start polling: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start polling: {str(e)}"
        )


@router.post("/polling/stop")
async def stop_polling(
    current_user: User = Depends(require_admin),
    orchestrator: IMAPOrchestrator = Depends(get_imap_orchestrator_dep)
):
    """
    Stop background polling.
    
    Halts automatic polling of the IMAP inbox.
    Manual analysis requests will still work.
    
    Requires: Admin role
    """
    try:
        await orchestrator.stop_background_polling()
        
        return {
            "success": True,
            "message": "Polling stopped"
        }
    except Exception as e:
        logger.error(f"Failed to stop polling: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop polling: {str(e)}"
        )


@router.post("/polling/trigger")
async def trigger_poll(
    current_user: User = Depends(require_analyst),
    orchestrator: IMAPOrchestrator = Depends(get_imap_orchestrator_dep)
):
    """
    Trigger an immediate poll of the inbox.
    
    Manually triggers a check for new emails without waiting
    for the next scheduled poll.
    
    Requires: Analyst role
    """
    try:
        result = await orchestrator.poll_inbox()
        
        return {
            "success": True,
            "emails_found": result.get("emails_found", 0),
            "emails_processed": result.get("emails_processed", 0),
            "message": "Poll completed"
        }
    except Exception as e:
        logger.error(f"Manual poll failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Poll failed: {str(e)}"
        )


@router.post("/verify-smtp")
async def verify_smtp_config(
    target_email: str,
    current_user: User = Depends(require_analyst)
):
    """
    Send a test email to verify SMTP settings.
    
    Useful for verifying that notification emails can be sent.
    
    Requires: Analyst role
    
    Args:
        target_email: Email address to send test to
    """
    try:
        from app.services.email_sender import send_email
        
        success = await send_email(
            to_email=target_email,
            subject="PhishNet SMTP Verification",
            body="If you see this, the backend can successfully send emails!",
            html=False
        )
        
        return {
            "success": success,
            "recipient": target_email,
            "message": "Test email sent" if success else "Failed to send test email"
        }
    except Exception as e:
        logger.error(f"SMTP verification failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }
