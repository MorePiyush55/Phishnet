"""
Consent Tracking and Management Service
Provides comprehensive consent lifecycle management with GDPR compliance.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import json
import secrets
from enum import Enum

from backend.app.models.consent import (
    UserConsent, ConsentAuditLog, UserDataArtifact, ConsentTemplate,
    ConsentScope, DataProcessingType, RetentionPolicy,
    create_default_consent_template, calculate_artifact_expiry
)
from backend.app.core.database import get_db
from backend.app.core.config import get_settings
from backend.app.core.redis_client import get_redis_client

logger = logging.getLogger(__name__)

class ConsentStatus(Enum):
    """Consent status values."""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"

class ConsentTrackingService:
    """
    Service for tracking user consent, permissions, and data lifecycle.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.redis_client = get_redis_client()

    async def create_consent_record(self,
                                  user_id: str,
                                  consent_data: Dict[str, Any],
                                  request_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new consent record with comprehensive tracking.
        
        Args:
            user_id: Unique user identifier
            consent_data: Consent preferences and data
            request_context: Request metadata for audit trail
            
        Returns:
            Dict containing consent record details and status
        """
        try:
            with get_db() as db:
                # Check for existing active consent
                existing_consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id,
                    UserConsent.is_active == True
                ).first()
                
                if existing_consent:
                    # Update existing consent instead of creating new one
                    return await self.update_consent_preferences(
                        user_id=user_id,
                        consent_updates=consent_data,
                        request_context=request_context
                    )
                
                # Create new consent record
                consent = UserConsent(
                    user_id=user_id,
                    email=consent_data.get("email"),
                    google_user_id=consent_data.get("google_user_id"),
                    
                    # OAuth token hashes (will be set by OAuth service)
                    access_token_hash=consent_data.get("access_token_hash"),
                    refresh_token_hash=consent_data.get("refresh_token_hash"),
                    token_expires_at=consent_data.get("token_expires_at"),
                    
                    # Granted scopes
                    granted_scopes=consent_data.get("granted_scopes", []),
                    
                    # Data processing preferences
                    allow_subject_analysis=consent_data.get("allow_subject_analysis", True),
                    allow_body_analysis=consent_data.get("allow_body_analysis", True),
                    allow_attachment_scanning=consent_data.get("allow_attachment_scanning", False),
                    allow_llm_processing=consent_data.get("allow_llm_processing", True),
                    allow_threat_intel_lookup=consent_data.get("allow_threat_intel_lookup", True),
                    opt_out_ai_analysis=consent_data.get("opt_out_ai_analysis", False),
                    opt_out_persistent_storage=consent_data.get("opt_out_persistent_storage", False),
                    
                    # Privacy preferences
                    allow_analytics=consent_data.get("allow_analytics", False),
                    allow_performance_monitoring=consent_data.get("allow_performance_monitoring", True),
                    share_threat_intelligence=consent_data.get("share_threat_intelligence", True),
                    
                    # Retention settings
                    retention_policy=consent_data.get("retention_policy", RetentionPolicy.STANDARD_30_DAYS.value),
                    custom_retention_days=consent_data.get("custom_retention_days"),
                    data_processing_region=consent_data.get("data_processing_region", "US"),
                    
                    # Legal compliance
                    privacy_policy_version=consent_data.get("privacy_policy_version", "1.0"),
                    terms_of_service_version=consent_data.get("terms_of_service_version", "1.0"),
                    gdpr_consent=consent_data.get("gdpr_consent", False),
                    ccpa_opt_out=consent_data.get("ccpa_opt_out", False),
                    
                    # Request metadata
                    ip_address=request_context.get("ip_address"),
                    user_agent=request_context.get("user_agent"),
                    consent_source=request_context.get("source", "web_ui")
                )
                
                db.add(consent)
                db.flush()  # Get the ID
                
                # Log consent creation
                await self._log_consent_event(
                    db=db,
                    consent_id=consent.id,
                    event_type="consent_created",
                    event_details={
                        "initial_preferences": consent_data,
                        "granted_scopes": consent.granted_scopes,
                        "retention_policy": consent.retention_policy
                    },
                    request_context=request_context
                )
                
                db.commit()
                
                logger.info(f"Consent record created for user {user_id}")
                
                return {
                    "success": True,
                    "consent_id": consent.id,
                    "consent_status": ConsentStatus.ACTIVE.value,
                    "created_at": consent.consent_granted_at.isoformat(),
                    "preferences": consent.to_dict(),
                    "next_actions": self._get_recommended_actions(consent)
                }
                
        except Exception as e:
            logger.error(f"Failed to create consent record for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "CONSENT_CREATION_FAILED"
            }

    async def update_consent_preferences(self,
                                       user_id: str,
                                       consent_updates: Dict[str, Any],
                                       request_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update user consent preferences with full audit trail.
        
        Args:
            user_id: User identifier
            consent_updates: Updated consent preferences
            request_context: Request metadata
            
        Returns:
            Dict containing update status and new preferences
        """
        try:
            with get_db() as db:
                consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id,
                    UserConsent.is_active == True
                ).first()
                
                if not consent:
                    return {
                        "success": False,
                        "error": "No active consent record found",
                        "error_code": "NO_ACTIVE_CONSENT"
                    }
                
                # Store previous values for audit
                previous_values = consent.to_dict()
                
                # Update preferences
                updatable_fields = [
                    "allow_subject_analysis", "allow_body_analysis", "allow_attachment_scanning",
                    "allow_llm_processing", "allow_threat_intel_lookup", "opt_out_ai_analysis",
                    "opt_out_persistent_storage", "allow_analytics", "allow_performance_monitoring",
                    "share_threat_intelligence", "retention_policy", "custom_retention_days",
                    "data_processing_region", "gdpr_consent", "ccpa_opt_out"
                ]
                
                updated_fields = {}
                for field in updatable_fields:
                    if field in consent_updates:
                        old_value = getattr(consent, field)
                        new_value = consent_updates[field]
                        if old_value != new_value:
                            setattr(consent, field, new_value)
                            updated_fields[field] = {"old": old_value, "new": new_value}
                
                # Update timestamp
                consent.consent_updated_at = datetime.utcnow()
                
                # Log the update
                await self._log_consent_event(
                    db=db,
                    consent_id=consent.id,
                    event_type="consent_updated",
                    event_details={
                        "updated_fields": updated_fields,
                        "update_reason": consent_updates.get("update_reason", "User preference change")
                    },
                    request_context=request_context,
                    previous_values=previous_values,
                    new_values=consent.to_dict()
                )
                
                # Update data artifact retention if policy changed
                if "retention_policy" in updated_fields or "custom_retention_days" in updated_fields:
                    await self._update_artifact_retention(db, consent.id, consent)
                
                db.commit()
                
                logger.info(f"Consent preferences updated for user {user_id}: {list(updated_fields.keys())}")
                
                return {
                    "success": True,
                    "updated_fields": list(updated_fields.keys()),
                    "updated_at": consent.consent_updated_at.isoformat(),
                    "preferences": consent.to_dict(),
                    "retention_updated": "retention_policy" in updated_fields
                }
                
        except Exception as e:
            logger.error(f"Failed to update consent for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "CONSENT_UPDATE_FAILED"
            }

    async def track_data_artifact(self,
                                user_id: str,
                                artifact_type: str,
                                artifact_id: str,
                                metadata: Dict[str, Any],
                                tags: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Track a data artifact for retention and cleanup management.
        
        Args:
            user_id: User identifier
            artifact_type: Type of data artifact (email_metadata, analysis_result, etc.)
            artifact_id: Unique identifier for the artifact
            metadata: Artifact metadata (size, location, etc.)
            tags: Optional tags for categorization
            
        Returns:
            Dict containing artifact tracking status
        """
        try:
            with get_db() as db:
                consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id,
                    UserConsent.is_active == True
                ).first()
                
                if not consent:
                    return {
                        "success": False,
                        "error": "No active consent record found",
                        "error_code": "NO_ACTIVE_CONSENT"
                    }
                
                # Check if user allows persistent storage
                if consent.opt_out_persistent_storage:
                    return {
                        "success": False,
                        "error": "User has opted out of persistent storage",
                        "error_code": "STORAGE_NOT_PERMITTED"
                    }
                
                # Calculate expiry based on retention policy
                retention_policy = RetentionPolicy(consent.retention_policy)
                expires_at = calculate_artifact_expiry(retention_policy, consent.custom_retention_days)
                
                # Create artifact record
                artifact = UserDataArtifact(
                    user_consent_id=consent.id,
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                    storage_location=metadata.get("storage_location"),
                    expires_at=expires_at,
                    size_bytes=metadata.get("size_bytes", 0),
                    content_hash=metadata.get("content_hash"),
                    tags=tags or []
                )
                
                db.add(artifact)
                
                # Log artifact tracking
                await self._log_consent_event(
                    db=db,
                    consent_id=consent.id,
                    event_type="data_artifact_tracked",
                    event_details={
                        "artifact_type": artifact_type,
                        "artifact_id": artifact_id,
                        "expires_at": expires_at.isoformat(),
                        "size_bytes": artifact.size_bytes,
                        "tags": tags
                    },
                    request_context=metadata.get("request_context", {})
                )
                
                db.commit()
                
                return {
                    "success": True,
                    "artifact_id": artifact.id,
                    "expires_at": expires_at.isoformat(),
                    "retention_days": consent.effective_retention_days,
                    "storage_permitted": True
                }
                
        except Exception as e:
            logger.error(f"Failed to track data artifact for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "ARTIFACT_TRACKING_FAILED"
            }

    async def check_processing_permission(self,
                                        user_id: str,
                                        processing_type: DataProcessingType) -> Dict[str, Any]:
        """
        Check if user has given permission for specific data processing.
        
        Args:
            user_id: User identifier
            processing_type: Type of data processing requested
            
        Returns:
            Dict containing permission status and details
        """
        try:
            with get_db() as db:
                consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id,
                    UserConsent.is_active == True
                ).first()
                
                if not consent:
                    return {
                        "permission_granted": False,
                        "reason": "No active consent record",
                        "error_code": "NO_ACTIVE_CONSENT"
                    }
                
                if not consent.is_consent_valid:
                    return {
                        "permission_granted": False,
                        "reason": "Consent is expired or invalid",
                        "error_code": "CONSENT_INVALID"
                    }
                
                # Check specific processing permission
                permission_granted = consent.can_process_data(processing_type)
                
                return {
                    "permission_granted": permission_granted,
                    "processing_type": processing_type.value,
                    "user_id": user_id,
                    "consent_id": consent.id,
                    "reason": self._get_permission_reason(consent, processing_type, permission_granted),
                    "alternatives": self._get_processing_alternatives(processing_type, permission_granted)
                }
                
        except Exception as e:
            logger.error(f"Failed to check processing permission for user {user_id}: {str(e)}")
            return {
                "permission_granted": False,
                "error": str(e),
                "error_code": "PERMISSION_CHECK_FAILED"
            }

    async def get_consent_summary(self, user_id: str) -> Dict[str, Any]:
        """
        Get comprehensive consent summary for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dict containing complete consent information
        """
        try:
            with get_db() as db:
                consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id
                ).order_by(UserConsent.consent_granted_at.desc()).first()
                
                if not consent:
                    return {
                        "consent_exists": False,
                        "status": ConsentStatus.PENDING.value,
                        "requires_consent": True
                    }
                
                # Get artifact statistics
                total_artifacts = db.query(UserDataArtifact).filter(
                    UserDataArtifact.user_consent_id == consent.id
                ).count()
                
                active_artifacts = db.query(UserDataArtifact).filter(
                    UserDataArtifact.user_consent_id == consent.id,
                    UserDataArtifact.deleted_at.is_(None),
                    UserDataArtifact.expires_at > datetime.utcnow()
                ).count()
                
                expired_artifacts = db.query(UserDataArtifact).filter(
                    UserDataArtifact.user_consent_id == consent.id,
                    UserDataArtifact.deleted_at.is_(None),
                    UserDataArtifact.expires_at <= datetime.utcnow()
                ).count()
                
                # Get recent audit events
                recent_events = db.query(ConsentAuditLog).filter(
                    ConsentAuditLog.user_consent_id == consent.id
                ).order_by(ConsentAuditLog.event_timestamp.desc()).limit(10).all()
                
                # Determine current status
                if not consent.is_active:
                    status = ConsentStatus.REVOKED.value
                elif not consent.is_consent_valid:
                    status = ConsentStatus.EXPIRED.value
                else:
                    status = ConsentStatus.ACTIVE.value
                
                return {
                    "consent_exists": True,
                    "status": status,
                    "consent_id": consent.id,
                    "user_id": user_id,
                    "email": consent.email,
                    "granted_at": consent.consent_granted_at.isoformat(),
                    "updated_at": consent.consent_updated_at.isoformat(),
                    "revoked_at": consent.consent_revoked_at.isoformat() if consent.consent_revoked_at else None,
                    "consent_version": consent.consent_version,
                    "scopes": {
                        "granted": consent.granted_scopes,
                        "required": [ConsentScope.GMAIL_READONLY.value],
                        "optional": [ConsentScope.GMAIL_MODIFY.value]
                    },
                    "data_processing": {
                        "subject_analysis": consent.allow_subject_analysis,
                        "body_analysis": consent.allow_body_analysis,
                        "attachment_scanning": consent.allow_attachment_scanning,
                        "llm_processing": consent.allow_llm_processing,
                        "threat_intel_lookup": consent.allow_threat_intel_lookup,
                        "ai_analysis_opt_out": consent.opt_out_ai_analysis,
                        "persistent_storage_opt_out": consent.opt_out_persistent_storage
                    },
                    "privacy_settings": {
                        "allow_analytics": consent.allow_analytics,
                        "allow_performance_monitoring": consent.allow_performance_monitoring,
                        "share_threat_intelligence": consent.share_threat_intelligence
                    },
                    "retention": {
                        "policy": consent.retention_policy,
                        "effective_days": consent.effective_retention_days,
                        "data_region": consent.data_processing_region
                    },
                    "data_artifacts": {
                        "total": total_artifacts,
                        "active": active_artifacts,
                        "expired": expired_artifacts
                    },
                    "legal_compliance": {
                        "gdpr_consent": consent.gdpr_consent,
                        "ccpa_opt_out": consent.ccpa_opt_out,
                        "privacy_policy_version": consent.privacy_policy_version,
                        "terms_version": consent.terms_of_service_version
                    },
                    "recent_activity": [
                        {
                            "event": event.event_type,
                            "timestamp": event.event_timestamp.isoformat(),
                            "details": event.event_details
                        }
                        for event in recent_events
                    ],
                    "requires_consent": status != ConsentStatus.ACTIVE.value
                }
                
        except Exception as e:
            logger.error(f"Failed to get consent summary for user {user_id}: {str(e)}")
            return {
                "consent_exists": False,
                "status": "error",
                "error": str(e)
            }

    async def cleanup_expired_artifacts(self) -> Dict[str, Any]:
        """
        Background task to cleanup expired data artifacts.
        
        Returns:
            Dict containing cleanup statistics
        """
        try:
            with get_db() as db:
                # Find expired artifacts
                expired_artifacts = db.query(UserDataArtifact).filter(
                    UserDataArtifact.expires_at <= datetime.utcnow(),
                    UserDataArtifact.deleted_at.is_(None)
                ).all()
                
                cleanup_stats = {
                    "total_expired": len(expired_artifacts),
                    "cleanup_successful": 0,
                    "cleanup_failed": 0,
                    "size_freed": 0,
                    "artifact_types": {}
                }
                
                for artifact in expired_artifacts:
                    try:
                        # Mark as deleted
                        artifact.deleted_at = datetime.utcnow()
                        
                        # Update statistics
                        cleanup_stats["cleanup_successful"] += 1
                        cleanup_stats["size_freed"] += artifact.size_bytes or 0
                        
                        if artifact.artifact_type not in cleanup_stats["artifact_types"]:
                            cleanup_stats["artifact_types"][artifact.artifact_type] = 0
                        cleanup_stats["artifact_types"][artifact.artifact_type] += 1
                        
                        # Log cleanup
                        await self._log_consent_event(
                            db=db,
                            consent_id=artifact.user_consent_id,
                            event_type="artifact_expired_cleanup",
                            event_details={
                                "artifact_id": artifact.artifact_id,
                                "artifact_type": artifact.artifact_type,
                                "size_bytes": artifact.size_bytes,
                                "expired_at": artifact.expires_at.isoformat()
                            },
                            request_context={"source": "automated_cleanup"}
                        )
                        
                    except Exception as e:
                        cleanup_stats["cleanup_failed"] += 1
                        logger.error(f"Failed to cleanup artifact {artifact.id}: {str(e)}")
                
                db.commit()
                
                logger.info(f"Cleaned up {cleanup_stats['cleanup_successful']} expired artifacts")
                
                return {
                    "success": True,
                    "cleanup_stats": cleanup_stats,
                    "cleanup_timestamp": datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Failed to cleanup expired artifacts: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "CLEANUP_FAILED"
            }

    # Private helper methods

    async def _log_consent_event(self,
                               db,
                               consent_id: int,
                               event_type: str,
                               event_details: Dict[str, Any],
                               request_context: Dict[str, Any],
                               previous_values: Optional[Dict[str, Any]] = None,
                               new_values: Optional[Dict[str, Any]] = None) -> None:
        """Log consent event to audit trail."""
        
        try:
            audit_log = ConsentAuditLog(
                user_consent_id=consent_id,
                event_type=event_type,
                event_details=event_details,
                ip_address=request_context.get("ip_address"),
                user_agent=request_context.get("user_agent"),
                request_id=request_context.get("request_id"),
                previous_values=previous_values,
                new_values=new_values
            )
            
            db.add(audit_log)
            
        except Exception as e:
            logger.error(f"Failed to log consent event: {str(e)}")

    async def _update_artifact_retention(self,
                                       db,
                                       consent_id: int,
                                       consent: UserConsent) -> None:
        """Update retention for existing artifacts when policy changes."""
        
        try:
            active_artifacts = db.query(UserDataArtifact).filter(
                UserDataArtifact.user_consent_id == consent_id,
                UserDataArtifact.deleted_at.is_(None)
            ).all()
            
            retention_policy = RetentionPolicy(consent.retention_policy)
            
            for artifact in active_artifacts:
                new_expiry = calculate_artifact_expiry(retention_policy, consent.custom_retention_days)
                artifact.expires_at = new_expiry
                
            logger.info(f"Updated retention for {len(active_artifacts)} artifacts")
            
        except Exception as e:
            logger.error(f"Failed to update artifact retention: {str(e)}")

    def _get_recommended_actions(self, consent: UserConsent) -> List[Dict[str, Any]]:
        """Get recommended actions for user based on consent preferences."""
        
        actions = []
        
        # Recommend enabling additional protections
        if not consent.allow_attachment_scanning:
            actions.append({
                "type": "enable_feature",
                "feature": "attachment_scanning",
                "title": "Enable Attachment Scanning",
                "description": "Scan email attachments for malware and threats",
                "impact": "Enhanced security protection"
            })
        
        if consent.opt_out_ai_analysis:
            actions.append({
                "type": "review_setting",
                "setting": "ai_analysis",
                "title": "Review AI Analysis Setting",
                "description": "Consider enabling AI analysis for better threat detection",
                "impact": "Improved phishing detection accuracy"
            })
        
        # Data retention recommendations
        if consent.retention_policy == RetentionPolicy.NO_STORAGE.value:
            actions.append({
                "type": "review_retention",
                "setting": "data_retention",
                "title": "Consider Data Retention",
                "description": "Minimal data storage can improve threat detection",
                "impact": "Better pattern recognition and protection"
            })
        
        return actions

    def _get_permission_reason(self,
                             consent: UserConsent,
                             processing_type: DataProcessingType,
                             permission_granted: bool) -> str:
        """Get human-readable reason for permission status."""
        
        if permission_granted:
            return f"User has consented to {processing_type.value}"
        
        # Check specific opt-outs
        if consent.opt_out_ai_analysis and processing_type == DataProcessingType.LLM_PROCESSING:
            return "User has opted out of AI analysis"
        
        if consent.opt_out_persistent_storage and processing_type in [
            DataProcessingType.METADATA_STORAGE, 
            DataProcessingType.ARTIFACT_STORAGE
        ]:
            return "User has opted out of persistent storage"
        
        # Check specific permissions
        if processing_type == DataProcessingType.ATTACHMENT_SCAN and not consent.allow_attachment_scanning:
            return "User has not consented to attachment scanning"
        
        return f"User has not granted permission for {processing_type.value}"

    def _get_processing_alternatives(self,
                                   processing_type: DataProcessingType,
                                   permission_granted: bool) -> List[str]:
        """Get alternative processing options if permission denied."""
        
        if permission_granted:
            return []
        
        alternatives = []
        
        if processing_type == DataProcessingType.LLM_PROCESSING:
            alternatives.extend([
                "Use rule-based analysis only",
                "Process without AI/ML components",
                "Generate basic threat scores"
            ])
        
        if processing_type == DataProcessingType.ATTACHMENT_SCAN:
            alternatives.extend([
                "Skip attachment analysis",
                "Flag attachments for manual review",
                "Provide attachment safety warnings"
            ])
        
        if processing_type in [DataProcessingType.METADATA_STORAGE, DataProcessingType.ARTIFACT_STORAGE]:
            alternatives.extend([
                "Process data without storage",
                "Provide real-time analysis only",
                "Use temporary processing only"
            ])
        
        return alternatives


# Global service instance
_consent_tracking_service = None

def get_consent_tracking_service() -> ConsentTrackingService:
    """Get global consent tracking service instance."""
    global _consent_tracking_service
    if _consent_tracking_service is None:
        _consent_tracking_service = ConsentTrackingService()
    return _consent_tracking_service