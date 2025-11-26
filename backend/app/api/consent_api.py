"""
Consent Management API Endpoints
Provides comprehensive consent management with GDPR compliance and legal controls.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Query, Body
from fastapi.security import HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.auth import get_current_user
from app.schemas.auth import TokenPayload
from app.services.consent_oauth_service import get_consent_oauth_service
from app.services.consent_tracking_service import get_consent_tracking_service
from app.models.consent import ConsentScope, DataProcessingType, RetentionPolicy

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/consent", tags=["consent-management"])
security = HTTPBearer()

# Pydantic models for API

class ConsentInitRequest(BaseModel):
    """Request model for initializing consent flow."""
    requested_scopes: Optional[List[str]] = Field(
        default=None, 
        description="OAuth scopes being requested"
    )
    consent_preferences: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Initial consent preferences"
    )
    redirect_after_consent: Optional[str] = Field(
        default=None,
        description="URL to redirect to after consent"
    )

class ConsentPreferencesUpdate(BaseModel):
    """Request model for updating consent preferences."""
    allow_subject_analysis: Optional[bool] = Field(default=None)
    allow_body_analysis: Optional[bool] = Field(default=None)
    allow_attachment_scanning: Optional[bool] = Field(default=None)
    allow_llm_processing: Optional[bool] = Field(default=None)
    allow_threat_intel_lookup: Optional[bool] = Field(default=None)
    opt_out_ai_analysis: Optional[bool] = Field(default=None)
    opt_out_persistent_storage: Optional[bool] = Field(default=None)
    allow_analytics: Optional[bool] = Field(default=None)
    allow_performance_monitoring: Optional[bool] = Field(default=None)
    share_threat_intelligence: Optional[bool] = Field(default=None)
    retention_policy: Optional[str] = Field(default=None)
    custom_retention_days: Optional[int] = Field(default=None)
    data_processing_region: Optional[str] = Field(default=None)
    gdpr_consent: Optional[bool] = Field(default=None)
    ccpa_opt_out: Optional[bool] = Field(default=None)
    update_reason: Optional[str] = Field(default="User preference update")

class ConsentCallbackRequest(BaseModel):
    """Request model for OAuth consent callback."""
    authorization_code: str = Field(..., description="Authorization code from OAuth provider")
    state_token: str = Field(..., description="State token for CSRF protection")
    user_consent_data: Dict[str, Any] = Field(..., description="User's explicit consent choices")

class DataArtifactRequest(BaseModel):
    """Request model for tracking data artifacts."""
    artifact_type: str = Field(..., description="Type of data artifact")
    artifact_id: str = Field(..., description="Unique identifier for artifact")
    storage_location: Optional[str] = Field(default=None)
    size_bytes: Optional[int] = Field(default=0)
    content_hash: Optional[str] = Field(default=None)
    tags: Optional[List[str]] = Field(default=None)

class ConsentRevocationRequest(BaseModel):
    """Request model for revoking consent."""
    revocation_reason: str = Field(..., description="Reason for consent revocation")
    cleanup_data: bool = Field(default=True, description="Whether to delete user data")
    immediate_revocation: bool = Field(default=True, description="Immediate or scheduled revocation")

class ProcessingPermissionQuery(BaseModel):
    """Query model for checking processing permissions."""
    processing_type: str = Field(..., description="Type of data processing")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Processing context")

# API Endpoints

@router.post("/initialize")
async def initialize_consent_flow(
    request: Request,
    consent_request: ConsentInitRequest,
    current_user: TokenPayload = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Initialize OAuth consent flow with comprehensive consent tracking.
    
    This endpoint starts the consent process, generating authorization URLs
    and setting up consent context for legal compliance.
    """
    try:
        # Get request metadata
        request_context = {
            "ip_address": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "source": "api"
        }
        
        # Initialize consent flow
        oauth_service = get_consent_oauth_service()
        result = await oauth_service.initialize_consent_flow(
            user_id=current_user.sub,
            requested_scopes=consent_request.requested_scopes,
            consent_preferences=consent_request.consent_preferences
        )
        
        if not result["success"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": result["error"],
                    "error_code": result.get("error_code", "CONSENT_INIT_FAILED")
                }
            )
        
        logger.info(f"Consent flow initialized for user {current_user.sub}")
        
        return {
            "success": True,
            "data": {
                "authorization_url": result["authorization_url"],
                "state_token": result["state_token"],
                "requested_scopes": result["requested_scopes"],
                "consent_requirements": result["consent_requirements"],
                "expires_at": result["expires_at"],
                "redirect_after_consent": consent_request.redirect_after_consent
            },
            "message": "Consent flow initialized successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to initialize consent flow: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error during consent initialization",
                "error_code": "CONSENT_INIT_ERROR"
            }
        )

@router.post("/callback")
async def handle_consent_callback(
    request: Request,
    callback_data: ConsentCallbackRequest,
    current_user: TokenPayload = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Handle OAuth consent callback with comprehensive consent recording.
    
    This endpoint processes the OAuth callback, exchanges tokens, and
    creates detailed consent records for legal compliance.
    """
    try:
        # Get request metadata
        request_context = {
            "ip_address": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "source": "oauth_callback"
        }
        
        # Handle consent callback
        oauth_service = get_consent_oauth_service()
        result = await oauth_service.handle_consent_callback(
            authorization_code=callback_data.authorization_code,
            state_token=callback_data.state_token,
            user_consent_data=callback_data.user_consent_data,
            request_context=request_context
        )
        
        if not result["success"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": result["error"],
                    "error_code": result.get("error_code", "CONSENT_CALLBACK_FAILED")
                }
            )
        
        logger.info(f"Consent callback processed for user {current_user.sub}")
        
        return {
            "success": True,
            "data": {
                "consent_id": result["consent_id"],
                "user_email": result["user_email"],
                "granted_scopes": result["granted_scopes"],
                "consent_status": result["consent_status"],
                "next_actions": result["next_actions"]
            },
            "message": "Consent granted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to handle consent callback: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error during consent callback",
                "error_code": "CONSENT_CALLBACK_ERROR"
            }
        )

@router.get("/status")
async def get_consent_status(
    current_user: TokenPayload = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get comprehensive consent status for the current user.
    
    Returns detailed information about consent status, permissions,
    data artifacts, and legal compliance details.
    """
    try:
        # Get consent summary
        tracking_service = get_consent_tracking_service()
        oauth_service = get_consent_oauth_service()
        
        consent_summary = await tracking_service.get_consent_summary(current_user.sub)
        oauth_status = await oauth_service.get_consent_status(current_user.sub)
        
        # Combine information
        combined_status = {
            **consent_summary,
            "oauth_status": oauth_status,
            "legal_rights": {
                "data_portability": True,
                "right_to_rectification": True,
                "right_to_erasure": True,
                "right_to_restrict_processing": True,
                "right_to_object": True,
                "data_export_available": True,
                "consent_withdrawal_available": consent_summary.get("status") == "active"
            },
            "contact_information": {
                "data_protection_officer": "dpo@phishnet.security",
                "privacy_policy": "/privacy",
                "terms_of_service": "/terms",
                "support_contact": "support@phishnet.security"
            }
        }
        
        return {
            "success": True,
            "data": combined_status,
            "message": "Consent status retrieved successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to get consent status: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error retrieving consent status",
                "error_code": "CONSENT_STATUS_ERROR"
            }
        )

@router.patch("/preferences")
async def update_consent_preferences(
    request: Request,
    preferences: ConsentPreferencesUpdate,
    current_user: TokenPayload = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Update user consent preferences with full audit trail.
    
    Allows users to modify their consent preferences while maintaining
    comprehensive audit logs for legal compliance.
    """
    try:
        # Get request metadata
        request_context = {
            "ip_address": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "source": "preferences_update"
        }
        
        # Update preferences
        tracking_service = get_consent_tracking_service()
        result = await tracking_service.update_consent_preferences(
            user_id=current_user.sub,
            consent_updates=preferences.dict(exclude_none=True),
            request_context=request_context
        )
        
        if not result["success"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": result["error"],
                    "error_code": result.get("error_code", "PREFERENCES_UPDATE_FAILED")
                }
            )
        
        logger.info(f"Consent preferences updated for user {current_user.sub}")
        
        return {
            "success": True,
            "data": {
                "updated_fields": result["updated_fields"],
                "updated_at": result["updated_at"],
                "preferences": result["preferences"],
                "retention_updated": result.get("retention_updated", False)
            },
            "message": "Consent preferences updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update consent preferences: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error updating preferences",
                "error_code": "PREFERENCES_UPDATE_ERROR"
            }
        )

@router.post("/revoke")
async def revoke_consent(
    request: Request,
    revocation: ConsentRevocationRequest,
    current_user: TokenPayload = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Revoke user consent and cleanup data (GDPR Right to be Forgotten).
    
    This endpoint handles consent revocation, token cleanup, and optional
    data deletion in compliance with GDPR requirements.
    """
    try:
        # Get request metadata
        request_context = {
            "ip_address": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "source": "consent_revocation"
        }
        
        # Revoke consent
        oauth_service = get_consent_oauth_service()
        result = await oauth_service.revoke_consent(
            user_id=current_user.sub,
            revocation_reason=revocation.revocation_reason,
            request_context=request_context,
            cleanup_data=revocation.cleanup_data
        )
        
        if not result["success"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": result["error"],
                    "error_code": result.get("error_code", "CONSENT_REVOCATION_FAILED")
                }
            )
        
        logger.info(f"Consent revoked for user {current_user.sub}: {revocation.revocation_reason}")
        
        return {
            "success": True,
            "data": {
                "consent_revoked": result["consent_revoked"],
                "tokens_revoked": result["tokens_revoked"],
                "data_cleanup": result["data_cleanup"],
                "revocation_timestamp": result["revocation_timestamp"],
                "legal_notice": "Your consent has been revoked and tokens invalidated. Data cleanup has been initiated as requested."
            },
            "message": "Consent revoked successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke consent: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error during consent revocation",
                "error_code": "CONSENT_REVOCATION_ERROR"
            }
        )

@router.get("/export")
async def export_user_data(
    request: Request,
    current_user: TokenPayload = Depends(get_current_user),
    format: str = Query(default="json", description="Export format (json, csv)")
) -> Dict[str, Any]:
    """
    Export all user data for GDPR compliance (Right to Data Portability).
    
    Provides comprehensive data export including consent records,
    data artifacts, and audit trails in machine-readable format.
    """
    try:
        # Get request metadata
        request_context = {
            "ip_address": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "source": "data_export",
            "export_format": format
        }
        
        # Export user data
        oauth_service = get_consent_oauth_service()
        result = await oauth_service.export_user_data(
            user_id=current_user.sub,
            request_context=request_context
        )
        
        if not result["success"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": result["error"],
                    "error_code": result.get("error_code", "DATA_EXPORT_FAILED")
                }
            )
        
        logger.info(f"Data export generated for user {current_user.sub}")
        
        return {
            "success": True,
            "data": {
                "export_data": result["export_data"],
                "export_summary": result["export_summary"],
                "legal_information": {
                    "export_purpose": "GDPR Article 20 - Right to data portability",
                    "data_controller": "PhishNet Email Security",
                    "retention_notice": "This export contains all personal data processed by our service",
                    "format": format.upper(),
                    "completeness": "Complete export of all personal data"
                }
            },
            "message": "Data export completed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export user data: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error during data export",
                "error_code": "DATA_EXPORT_ERROR"
            }
        )

@router.post("/track-artifact")
async def track_data_artifact(
    artifact: DataArtifactRequest,
    current_user: TokenPayload = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Track a data artifact for retention and cleanup management.
    
    This endpoint is used internally to track data artifacts created
    during email processing for GDPR compliance and data retention.
    """
    try:
        # Track artifact
        tracking_service = get_consent_tracking_service()
        result = await tracking_service.track_data_artifact(
            user_id=current_user.sub,
            artifact_type=artifact.artifact_type,
            artifact_id=artifact.artifact_id,
            metadata={
                "storage_location": artifact.storage_location,
                "size_bytes": artifact.size_bytes,
                "content_hash": artifact.content_hash
            },
            tags=artifact.tags
        )
        
        if not result["success"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": result["error"],
                    "error_code": result.get("error_code", "ARTIFACT_TRACKING_FAILED")
                }
            )
        
        return {
            "success": True,
            "data": {
                "artifact_id": result["artifact_id"],
                "expires_at": result["expires_at"],
                "retention_days": result["retention_days"],
                "storage_permitted": result["storage_permitted"]
            },
            "message": "Data artifact tracked successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to track data artifact: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error tracking artifact",
                "error_code": "ARTIFACT_TRACKING_ERROR"
            }
        )

@router.post("/check-permission")
async def check_processing_permission(
    permission_query: ProcessingPermissionQuery,
    current_user: TokenPayload = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Check if user has granted permission for specific data processing.
    
    This endpoint verifies processing permissions before performing
    any data processing activities to ensure consent compliance.
    """
    try:
        # Validate processing type
        try:
            processing_type = DataProcessingType(permission_query.processing_type)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": f"Invalid processing type: {permission_query.processing_type}",
                    "error_code": "INVALID_PROCESSING_TYPE",
                    "valid_types": [pt.value for pt in DataProcessingType]
                }
            )
        
        # Check permission
        tracking_service = get_consent_tracking_service()
        result = await tracking_service.check_processing_permission(
            user_id=current_user.sub,
            processing_type=processing_type
        )
        
        return {
            "success": True,
            "data": {
                "permission_granted": result["permission_granted"],
                "processing_type": result["processing_type"],
                "reason": result["reason"],
                "alternatives": result.get("alternatives", []),
                "user_id": current_user.sub,
                "consent_id": result.get("consent_id")
            },
            "message": "Permission check completed"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to check processing permission: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error checking permission",
                "error_code": "PERMISSION_CHECK_ERROR"
            }
        )

# Admin endpoints for compliance management

@router.get("/admin/cleanup-expired")
async def cleanup_expired_artifacts(
    current_user: TokenPayload = Depends(get_current_user),
    # admin_required: bool = Depends(require_admin_role)  # Implement admin check
) -> Dict[str, Any]:
    """
    Admin endpoint to cleanup expired data artifacts.
    
    This endpoint runs maintenance tasks to cleanup expired data
    artifacts in compliance with retention policies.
    """
    try:
        # Run cleanup
        tracking_service = get_consent_tracking_service()
        result = await tracking_service.cleanup_expired_artifacts()
        
        logger.info(f"Artifact cleanup completed: {result.get('cleanup_stats', {})}")
        
        return {
            "success": True,
            "data": result,
            "message": "Expired artifacts cleanup completed"
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup expired artifacts: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error during cleanup",
                "error_code": "CLEANUP_ERROR"
            }
        )

@router.get("/legal/retention-policies")
async def get_retention_policies() -> Dict[str, Any]:
    """
    Get available data retention policies and legal information.
    
    Provides information about available retention policies,
    legal basis, and compliance frameworks.
    """
    try:
        policies = []
        for policy in RetentionPolicy:
            if policy == RetentionPolicy.NO_STORAGE:
                days = 0
                description = "No data storage - process and discard immediately"
            elif policy == RetentionPolicy.MINIMAL_7_DAYS:
                days = 7
                description = "Minimal metadata storage for 7 days"
            elif policy == RetentionPolicy.STANDARD_30_DAYS:
                days = 30
                description = "Standard retention for security analysis and pattern recognition"
            elif policy == RetentionPolicy.EXTENDED_90_DAYS:
                days = 90
                description = "Extended retention for threat research and investigation"
            elif policy == RetentionPolicy.CUSTOM:
                days = None
                description = "User-defined retention period"
            
            policies.append({
                "policy": policy.value,
                "retention_days": days,
                "description": description,
                "legal_basis": "Legitimate interest in cybersecurity protection",
                "data_minimization": policy in [RetentionPolicy.NO_STORAGE, RetentionPolicy.MINIMAL_7_DAYS]
            })
        
        return {
            "success": True,
            "data": {
                "retention_policies": policies,
                "legal_framework": {
                    "gdpr_compliance": True,
                    "ccpa_compliance": True,
                    "data_minimization_principle": "We collect and retain only necessary data",
                    "purpose_limitation": "Data used only for phishing detection and security",
                    "storage_limitation": "Automatic deletion based on retention policy"
                },
                "user_rights": {
                    "right_to_access": "View all your data and processing activities",
                    "right_to_rectification": "Correct inaccurate personal data",
                    "right_to_erasure": "Delete your data (right to be forgotten)",
                    "right_to_restrict": "Limit processing of your data",
                    "right_to_portability": "Export your data in machine-readable format",
                    "right_to_object": "Object to processing based on legitimate interest",
                    "withdrawal_of_consent": "Withdraw consent at any time"
                }
            },
            "message": "Retention policies and legal information retrieved"
        }
        
    except Exception as e:
        logger.error(f"Failed to get retention policies: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error retrieving policies",
                "error_code": "POLICIES_RETRIEVAL_ERROR"
            }
        )