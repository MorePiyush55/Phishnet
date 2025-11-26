"""
Privacy compliance API endpoints.
Provides REST API for consent management, data subject rights, and privacy controls.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import io
import json

from app.privacy import (
    PrivacyComplianceManager,
    ConsentType,
    PrivacyRightType,
    redact_sensitive_data
)
from app.core.config import get_settings
from app.observability import get_logger, trace_function

router = APIRouter(prefix="/privacy", tags=["Privacy & Compliance"])
logger = get_logger(__name__)
settings = get_settings()

# Pydantic models for API
class ConsentRequest(BaseModel):
    """Request model for recording consent."""
    consent_type: ConsentType
    granted: bool
    privacy_policy_version: str = "1.0"

class ConsentResponse(BaseModel):
    """Response model for consent operations."""
    success: bool
    message: str
    consent_id: Optional[str] = None

class DataSubjectRequest(BaseModel):
    """Request model for data subject rights."""
    request_type: PrivacyRightType
    description: str = ""
    requested_data_types: List[str] = Field(default_factory=list)

class DataSubjectResponse(BaseModel):
    """Response model for data subject rights requests."""
    success: bool
    request_id: str
    message: str
    estimated_completion: str

class PrivacyDashboard(BaseModel):
    """User privacy dashboard data."""
    user_id: str
    consents: Dict[str, bool]
    active_requests: List[Dict[str, Any]]
    data_retention_info: Dict[str, str]
    last_activity: Optional[str]

# Dependency to get privacy manager
async def get_privacy_manager() -> PrivacyComplianceManager:
    """Dependency to get privacy compliance manager."""
    # In production, this would be injected properly
    from app.db.mongodb import MongoDBManager
    encryption_key = getattr(settings, 'PRIVACY_ENCRYPTION_KEY', 'default-key-change-in-production')
    return PrivacyComplianceManager(MongoDBManager, encryption_key)

# Consent Management Endpoints
@router.post("/consent", response_model=ConsentResponse)
@trace_function("privacy.api.record_consent")
async def record_consent(
    consent_request: ConsentRequest,
    request: Request,
    privacy_manager: PrivacyComplianceManager = Depends(get_privacy_manager)
):
    """Record user consent for data processing."""
    try:
        # Extract request info
        user_id = getattr(request.state, 'user_id', 'anonymous')  # Get from auth middleware
        ip_address = request.client.host
        user_agent = request.headers.get('user-agent', 'unknown')
        
        # Record consent
        consent_record = await privacy_manager.consent_manager.record_consent(
            user_id=user_id,
            consent_type=consent_request.consent_type,
            granted=consent_request.granted,
            ip_address=ip_address,
            user_agent=user_agent,
            privacy_policy_version=consent_request.privacy_policy_version
        )
        
        # Log audit trail
        await privacy_manager.audit_manager.log_consent_change(
            user_id=user_id,
            consent_type=consent_request.consent_type,
            old_value=False,  # Simplified - would get actual previous value
            new_value=consent_request.granted,
            ip_address=ip_address
        )
        
        logger.info(
            "Consent recorded via API",
            user_id=user_id,
            consent_type=consent_request.consent_type.value,
            granted=consent_request.granted
        )
        
        return ConsentResponse(
            success=True,
            message=f"Consent {'granted' if consent_request.granted else 'withdrawn'} successfully",
            consent_id=str(consent_record.timestamp.timestamp())
        )
        
    except Exception as e:
        logger.error("Failed to record consent", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to record consent")

@router.get("/consent")
@trace_function("privacy.api.get_consents")
async def get_user_consents(
    request: Request,
    privacy_manager: PrivacyComplianceManager = Depends(get_privacy_manager)
):
    """Get all consent records for the authenticated user."""
    try:
        user_id = getattr(request.state, 'user_id', 'anonymous')
        
        consent_records = await privacy_manager.consent_manager.get_user_consents(user_id)
        
        # Convert to API response format
        consents = {}
        for record in consent_records:
            consents[record.consent_type.value] = {
                "granted": record.granted,
                "timestamp": record.timestamp.isoformat(),
                "version": record.version
            }
        
        return {
            "success": True,
            "consents": consents
        }
        
    except Exception as e:
        logger.error("Failed to get consents", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve consents")

@router.post("/consent/withdraw/{consent_type}")
@trace_function("privacy.api.withdraw_consent")
async def withdraw_consent(
    consent_type: ConsentType,
    request: Request,
    privacy_manager: PrivacyComplianceManager = Depends(get_privacy_manager)
):
    """Withdraw specific consent."""
    try:
        user_id = getattr(request.state, 'user_id', 'anonymous')
        ip_address = request.client.host
        user_agent = request.headers.get('user-agent', 'unknown')
        
        await privacy_manager.consent_manager.withdraw_consent(
            user_id=user_id,
            consent_type=consent_type,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return ConsentResponse(
            success=True,
            message=f"Consent for {consent_type.value} withdrawn successfully"
        )
        
    except Exception as e:
        logger.error("Failed to withdraw consent", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to withdraw consent")

# Data Subject Rights Endpoints
@router.post("/rights/request", response_model=DataSubjectResponse)
@trace_function("privacy.api.submit_rights_request")
async def submit_data_subject_request(
    rights_request: DataSubjectRequest,
    request: Request,
    privacy_manager: PrivacyComplianceManager = Depends(get_privacy_manager)
):
    """Submit a data subject rights request (GDPR Article 12-22)."""
    try:
        user_id = getattr(request.state, 'user_id', 'anonymous')
        
        # Submit the request
        data_request = await privacy_manager.rights_manager.submit_request(
            user_id=user_id,
            request_type=rights_request.request_type,
            description=rights_request.description,
            requested_data_types=rights_request.requested_data_types
        )
        
        # Log audit trail
        await privacy_manager.audit_manager.log_data_access(
            user_id=user_id,
            accessed_by=user_id,
            data_type="privacy_rights_request",
            action=f"submitted_{rights_request.request_type.value}_request",
            ip_address=request.client.host,
            legal_basis="data_subject_rights"
        )
        
        estimated_completion = (datetime.utcnow() + timedelta(days=30)).isoformat()
        
        return DataSubjectResponse(
            success=True,
            request_id=data_request.request_id,
            message=f"{rights_request.request_type.value.title()} request submitted successfully",
            estimated_completion=estimated_completion
        )
        
    except Exception as e:
        logger.error("Failed to submit rights request", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to submit request")

@router.get("/rights/requests")
@trace_function("privacy.api.get_rights_requests")
async def get_data_subject_requests(
    request: Request,
    privacy_manager: PrivacyComplianceManager = Depends(get_privacy_manager)
):
    """Get all data subject rights requests for the authenticated user."""
    try:
        user_id = getattr(request.state, 'user_id', 'anonymous')
        
        # This would query the database for user's requests
        # Simplified for demo
        requests = []  # await privacy_manager.db.get_user_rights_requests(user_id)
        
        return {
            "success": True,
            "requests": requests
        }
        
    except Exception as e:
        logger.error("Failed to get rights requests", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve requests")

@router.get("/data/export")
@trace_function("privacy.api.export_data")
async def export_user_data(
    request: Request,
    privacy_manager: PrivacyComplianceManager = Depends(get_privacy_manager)
):
    """Export all user data (right to portability)."""
    try:
        user_id = getattr(request.state, 'user_id', 'anonymous')
        
        # Create a portability request
        data_request = await privacy_manager.rights_manager.submit_request(
            user_id=user_id,
            request_type=PrivacyRightType.PORTABILITY,
            description="Data export via API"
        )
        
        # Process the request immediately for API calls
        export_data = await privacy_manager.rights_manager.process_portability_request(data_request)
        
        # Create streaming response
        def generate():
            yield export_data
        
        return StreamingResponse(
            generate(),
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=user_data_{user_id}_{datetime.utcnow().strftime('%Y%m%d')}.json"
            }
        )
        
    except Exception as e:
        logger.error("Failed to export user data", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to export data")

@router.delete("/data/delete")
@trace_function("privacy.api.delete_data")
async def delete_user_data(
    request: Request,
    privacy_manager: PrivacyComplianceManager = Depends(get_privacy_manager)
):
    """Request deletion of all user data (right to be forgotten)."""
    try:
        user_id = getattr(request.state, 'user_id', 'anonymous')
        
        # Submit erasure request
        data_request = await privacy_manager.rights_manager.submit_request(
            user_id=user_id,
            request_type=PrivacyRightType.ERASURE,
            description="Data deletion via API"
        )
        
        logger.warning(
            "Data deletion requested",
            user_id=user_id,
            request_id=data_request.request_id
        )
        
        return {
            "success": True,
            "message": "Data deletion request submitted. This will be processed within 30 days.",
            "request_id": data_request.request_id,
            "warning": "This action cannot be undone. Your account will be permanently deleted."
        }
        
    except Exception as e:
        logger.error("Failed to request data deletion", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to request data deletion")

# Privacy Dashboard
@router.get("/dashboard", response_model=PrivacyDashboard)
@trace_function("privacy.api.get_dashboard")
async def get_privacy_dashboard(
    request: Request,
    privacy_manager: PrivacyComplianceManager = Depends(get_privacy_manager)
):
    """Get user's privacy dashboard with all privacy-related information."""
    try:
        user_id = getattr(request.state, 'user_id', 'anonymous')
        
        # Get user's consents
        consent_records = await privacy_manager.consent_manager.get_user_consents(user_id)
        consents = {}
        for record in consent_records:
            consents[record.consent_type.value] = record.granted
        
        # Get active rights requests
        active_requests = []  # Would query database
        
        # Data retention info
        retention_info = {
            "email_scans": "90 days",
            "oauth_tokens": "90 days", 
            "consent_records": "7 years (legal requirement)",
            "audit_logs": "7 years (legal requirement)"
        }
        
        return PrivacyDashboard(
            user_id=user_id,
            consents=consents,
            active_requests=active_requests,
            data_retention_info=retention_info,
            last_activity=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error("Failed to get privacy dashboard", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to load privacy dashboard")

# Privacy Policy and Legal Pages
@router.get("/policy")
@trace_function("privacy.api.get_policy")
async def get_privacy_policy():
    """Get current privacy policy."""
    return {
        "version": "1.0",
        "last_updated": "2024-01-01",
        "policy": {
            "data_collection": "We collect minimal data necessary for email security analysis",
            "data_usage": "Data is used solely for phishing detection and user security",
            "data_sharing": "We do not share personal data with third parties",
            "data_retention": "Email scan data is retained for 90 days, consent records for 7 years",
            "user_rights": "Users have rights to access, rectify, erase, and port their data",
            "contact": "privacy@phishnet.com"
        }
    }

@router.get("/terms")
@trace_function("privacy.api.get_terms")
async def get_terms_of_service():
    """Get current terms of service."""
    return {
        "version": "1.0",
        "last_updated": "2024-01-01",
        "terms": {
            "service_description": "PhishNet provides email security analysis and phishing detection",
            "user_responsibilities": "Users must not abuse the service or attempt to bypass security",
            "service_availability": "We provide best-effort availability with no guarantees",
            "limitation_of_liability": "Liability is limited to the extent permitted by law",
            "termination": "Either party may terminate the agreement at any time",
            "governing_law": "Governed by laws of the jurisdiction where service is provided"
        }
    }

# Health Check
@router.get("/health")
@trace_function("privacy.api.health_check")
async def privacy_health_check(
    privacy_manager: PrivacyComplianceManager = Depends(get_privacy_manager)
):
    """Health check for privacy compliance system."""
    try:
        health_status = await privacy_manager.health_check()
        return health_status
    except Exception as e:
        logger.error("Privacy health check failed", error=str(e))
        return {
            "status": "unhealthy",
            "error": str(e)
        }