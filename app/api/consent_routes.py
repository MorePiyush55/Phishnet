"""
OAuth Consent API Endpoints
Handles consent granting, updating, revocation, and data management.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel, validator

from app.core.database import get_db
from app.services.consent_manager import get_consent_manager, ConsentManager
from app.models.consent import ConsentScope, DataProcessingType, RetentionPolicy
from app.core.auth import get_current_user
from app.core.rate_limiter import rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/consent", tags=["consent"])

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models for request/response

class ConsentPreferences(BaseModel):
    """User consent preferences"""
    allow_subject_analysis: bool = True
    allow_body_analysis: bool = True
    allow_attachment_scanning: bool = False
    allow_llm_processing: bool = True
    allow_threat_intel_lookup: bool = True
    opt_out_ai_analysis: bool = False
    opt_out_persistent_storage: bool = False
    retention_policy: str = RetentionPolicy.STANDARD_30_DAYS.value
    custom_retention_days: Optional[int] = None
    data_processing_region: str = "US"
    allow_analytics: bool = False
    allow_performance_monitoring: bool = True
    share_threat_intelligence: bool = True
    gdpr_consent: bool = False
    ccpa_opt_out: bool = False

    @validator('retention_policy')
    def validate_retention_policy(cls, v):
        valid_policies = [policy.value for policy in RetentionPolicy]
        if v not in valid_policies:
            raise ValueError(f"Invalid retention policy. Must be one of: {valid_policies}")
        return v

    @validator('custom_retention_days')
    def validate_custom_retention(cls, v, values):
        if values.get('retention_policy') == RetentionPolicy.CUSTOM.value:
            if not v or v < 1 or v > 365:
                raise ValueError("Custom retention days must be between 1 and 365")
        return v

class GrantConsentRequest(BaseModel):
    """Request to grant consent"""
    google_user_id: str
    access_token: str
    refresh_token: str
    token_expires_at: datetime
    granted_scopes: List[str]
    consent_preferences: ConsentPreferences

class UpdateConsentRequest(BaseModel):
    """Request to update consent preferences"""
    consent_preferences: ConsentPreferences

class ConsentResponse(BaseModel):
    """Consent response"""
    user_id: str
    email: str
    is_active: bool
    consent_granted_at: Optional[datetime]
    consent_updated_at: Optional[datetime]
    consent_revoked_at: Optional[datetime]
    granted_scopes: List[str]
    consent_preferences: Dict[str, Any]
    is_consent_valid: bool
    effective_retention_days: int

class DataSummaryResponse(BaseModel):
    """User data summary response"""
    user_id: str
    consent_status: str
    retention_policy: str
    retention_days: int
    total_artifacts: int
    total_size_bytes: int
    artifact_types: Dict[str, Any]
    consent_granted: Optional[str]
    last_updated: Optional[str]

class RevocationResponse(BaseModel):
    """Consent revocation response"""
    success: bool
    message: str
    cleanup_scheduled: bool

# Helper functions

def get_request_context(request: Request) -> Dict[str, Any]:
    """Extract request context for audit logging"""
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "request_id": request.headers.get("x-request-id"),
        "source": "api"
    }

def get_consent_manager_dependency() -> ConsentManager:
    """Dependency injection for consent manager"""
    return get_consent_manager()

# API Endpoints

@router.post("/grant", response_model=ConsentResponse)
@rate_limit("consent_grant", max_requests=5, window_seconds=300)  # 5 requests per 5 minutes
async def grant_consent(
    request: Request,
    consent_request: GrantConsentRequest,
    current_user = Depends(get_current_user),
    consent_manager: ConsentManager = Depends(get_consent_manager_dependency),
    db: Session = Depends(get_db)
):
    """
    Grant initial consent for OAuth access.
    """
    try:
        logger.info(f"Granting consent for user {current_user.id}")
        
        # Extract request context
        request_context = get_request_context(request)
        
        # Grant consent
        consent = await consent_manager.grant_consent(
            user_id=current_user.id,
            email=current_user.email,
            google_user_id=consent_request.google_user_id,
            access_token=consent_request.access_token,
            refresh_token=consent_request.refresh_token,
            token_expires_at=consent_request.token_expires_at,
            granted_scopes=consent_request.granted_scopes,
            consent_preferences=consent_request.consent_preferences.dict(),
            request_context=request_context
        )
        
        return ConsentResponse(
            user_id=consent.user_id,
            email=consent.email,
            is_active=consent.is_active,
            consent_granted_at=consent.consent_granted_at,
            consent_updated_at=consent.consent_updated_at,
            consent_revoked_at=consent.consent_revoked_at,
            granted_scopes=consent.granted_scopes,
            consent_preferences=consent.to_preferences_dict(),
            is_consent_valid=consent.is_consent_valid,
            effective_retention_days=consent.effective_retention_days
        )
        
    except ValueError as e:
        logger.warning(f"Invalid consent request for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error granting consent for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/status", response_model=ConsentResponse)
async def get_consent_status(
    current_user = Depends(get_current_user),
    consent_manager: ConsentManager = Depends(get_consent_manager_dependency)
):
    """
    Get current consent status for the user.
    """
    try:
        consent = await consent_manager.get_user_consent(current_user.id)
        
        if not consent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No consent found for user"
            )
        
        return ConsentResponse(
            user_id=consent.user_id,
            email=consent.email,
            is_active=consent.is_active,
            consent_granted_at=consent.consent_granted_at,
            consent_updated_at=consent.consent_updated_at,
            consent_revoked_at=consent.consent_revoked_at,
            granted_scopes=consent.granted_scopes,
            consent_preferences=consent.to_preferences_dict(),
            is_consent_valid=consent.is_consent_valid,
            effective_retention_days=consent.effective_retention_days
        )
        
    except Exception as e:
        logger.error(f"Error getting consent status for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.put("/update", response_model=ConsentResponse)
@rate_limit("consent_update", max_requests=10, window_seconds=300)  # 10 requests per 5 minutes
async def update_consent(
    request: Request,
    update_request: UpdateConsentRequest,
    current_user = Depends(get_current_user),
    consent_manager: ConsentManager = Depends(get_consent_manager_dependency)
):
    """
    Update consent preferences for the user.
    """
    try:
        logger.info(f"Updating consent for user {current_user.id}")
        
        request_context = get_request_context(request)
        
        # Update consent
        consent = await consent_manager.update_consent(
            user_id=current_user.id,
            consent_preferences=update_request.consent_preferences.dict(),
            request_context=request_context
        )
        
        return ConsentResponse(
            user_id=consent.user_id,
            email=consent.email,
            is_active=consent.is_active,
            consent_granted_at=consent.consent_granted_at,
            consent_updated_at=consent.consent_updated_at,
            consent_revoked_at=consent.consent_revoked_at,
            granted_scopes=consent.granted_scopes,
            consent_preferences=consent.to_preferences_dict(),
            is_consent_valid=consent.is_consent_valid,
            effective_retention_days=consent.effective_retention_days
        )
        
    except ValueError as e:
        logger.warning(f"Invalid consent update for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error updating consent for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/revoke", response_model=RevocationResponse)
@rate_limit("consent_revoke", max_requests=3, window_seconds=300)  # 3 requests per 5 minutes
async def revoke_consent(
    request: Request,
    cleanup_data: bool = True,
    current_user = Depends(get_current_user),
    consent_manager: ConsentManager = Depends(get_consent_manager_dependency)
):
    """
    Revoke consent and optionally cleanup user data.
    
    Args:
        cleanup_data: Whether to schedule cleanup of user data (default: True)
    """
    try:
        logger.info(f"Revoking consent for user {current_user.id}, cleanup: {cleanup_data}")
        
        request_context = get_request_context(request)
        
        # Revoke consent
        success = await consent_manager.revoke_consent(
            user_id=current_user.id,
            request_context=request_context,
            cleanup_data=cleanup_data
        )
        
        if not success:
            return RevocationResponse(
                success=False,
                message="No active consent found to revoke",
                cleanup_scheduled=False
            )
        
        return RevocationResponse(
            success=True,
            message="Consent revoked successfully",
            cleanup_scheduled=cleanup_data
        )
        
    except Exception as e:
        logger.error(f"Error revoking consent for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/data-summary", response_model=DataSummaryResponse)
async def get_data_summary(
    current_user = Depends(get_current_user),
    consent_manager: ConsentManager = Depends(get_consent_manager_dependency)
):
    """
    Get summary of user's data and retention status.
    """
    try:
        summary = await consent_manager.get_user_data_summary(current_user.id)
        
        if "error" in summary:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=summary["error"]
            )
        
        return DataSummaryResponse(**summary)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting data summary for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/verify-processing/{processing_type}")
async def verify_processing_permission(
    processing_type: str,
    current_user = Depends(get_current_user),
    consent_manager: ConsentManager = Depends(get_consent_manager_dependency)
):
    """
    Verify if user has granted permission for specific data processing.
    
    Args:
        processing_type: Type of processing (subject_analysis, body_analysis, etc.)
    """
    try:
        # Convert string to enum
        try:
            processing_enum = DataProcessingType(processing_type)
        except ValueError:
            valid_types = [pt.value for pt in DataProcessingType]
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid processing type. Must be one of: {valid_types}"
            )
        
        allowed, reason = await consent_manager.verify_processing_permission(
            current_user.id,
            processing_enum
        )
        
        return {
            "allowed": allowed,
            "processing_type": processing_type,
            "reason": reason
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying processing permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/scopes")
async def get_available_scopes():
    """
    Get available OAuth scopes and their descriptions.
    """
    scopes = {
        ConsentScope.GMAIL_READONLY.value: {
            "description": "Read-only access to Gmail messages",
            "required": True,
            "privacy_impact": "low"
        },
        ConsentScope.GMAIL_MODIFY.value: {
            "description": "Ability to modify Gmail messages (labeling, quarantine)",
            "required": False,
            "privacy_impact": "medium"
        },
        ConsentScope.AI_ANALYSIS.value: {
            "description": "Allow AI analysis of email content",
            "required": False,
            "privacy_impact": "high"
        },
        ConsentScope.PERSISTENT_STORAGE.value: {
            "description": "Store email data for threat intelligence",
            "required": False,
            "privacy_impact": "high"
        }
    }
    
    return {
        "scopes": scopes,
        "minimal_required": ["gmail.readonly"],
        "recommended": ["gmail.readonly", "gmail.modify"]
    }

@router.get("/retention-policies")
async def get_retention_policies():
    """
    Get available data retention policies.
    """
    policies = {}
    for policy in RetentionPolicy:
        if policy == RetentionPolicy.CUSTOM:
            policies[policy.value] = {
                "description": "Custom retention period (1-365 days)",
                "default_days": None,
                "configurable": True
            }
        else:
            # Extract days from policy name (e.g., "STANDARD_30_DAYS" -> 30)
            days = int(policy.value.split('_')[1]) if '_' in policy.value else 30
            policies[policy.value] = {
                "description": f"Standard retention for {days} days",
                "default_days": days,
                "configurable": False
            }
    
    return {
        "policies": policies,
        "default": RetentionPolicy.STANDARD_30_DAYS.value
    }

# Admin endpoints (require admin privileges)

@router.post("/admin/cleanup-expired")
async def cleanup_expired_data(
    batch_size: int = 100,
    current_user = Depends(get_current_user),
    consent_manager: ConsentManager = Depends(get_consent_manager_dependency)
):
    """
    Admin endpoint to cleanup expired data artifacts.
    """
    # Check if user has admin privileges
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    try:
        cleanup_count = await consent_manager.cleanup_expired_artifacts(batch_size)
        
        return {
            "cleaned_up": cleanup_count,
            "batch_size": batch_size,
            "status": "completed"
        }
        
    except Exception as e:
        logger.error(f"Error in admin cleanup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
