"""
OAuth Consent and Permission Management Service
Handles consent granting, updating, revocation, and data cleanup.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
import hashlib
import secrets
import asyncio

from app.models.consent import (
    UserConsent, ConsentAuditLog, UserDataArtifact, ConsentTemplate,
    ConsentScope, DataProcessingType, RetentionPolicy,
    calculate_artifact_expiry, get_minimal_required_scopes
)
from app.core.redis_client import get_redis_client
from app.core.database import get_db

logger = logging.getLogger(__name__)

class ConsentManager:
    """
    Manages user consent, permissions, and data retention.
    """
    
    def __init__(self, db_session: Session = None):
        self.db = db_session or next(get_db())
        self.redis_client = get_redis_client()
        
    def hash_token(self, token: str) -> str:
        """Securely hash OAuth tokens"""
        salt = "phishnet_oauth_salt_2024"  # Use environment variable in production
        return hashlib.sha256((token + salt).encode()).hexdigest()
    
    async def grant_consent(self, 
                          user_id: str,
                          email: str,
                          google_user_id: str,
                          access_token: str,
                          refresh_token: str,
                          token_expires_at: datetime,
                          granted_scopes: List[str],
                          consent_preferences: Dict[str, Any],
                          request_context: Dict[str, Any]) -> UserConsent:
        """
        Grant initial consent for a user.
        
        Args:
            user_id: Internal user identifier
            email: User's email address
            google_user_id: Google user ID
            access_token: OAuth access token
            refresh_token: OAuth refresh token
            token_expires_at: Token expiration time
            granted_scopes: List of granted OAuth scopes
            consent_preferences: User's consent preferences
            request_context: Request context (IP, user agent, etc.)
            
        Returns:
            UserConsent: Created consent record
        """
        try:
            # Check if consent already exists
            existing_consent = self.db.query(UserConsent).filter_by(user_id=user_id).first()
            if existing_consent:
                raise ValueError(f"Consent already exists for user {user_id}")
            
            # Validate scopes
            required_scopes = get_minimal_required_scopes()
            if not all(scope in granted_scopes for scope in required_scopes):
                missing = set(required_scopes) - set(granted_scopes)
                raise ValueError(f"Missing required scopes: {missing}")
            
            # Create consent record
            consent = UserConsent(
                user_id=user_id,
                email=email,
                google_user_id=google_user_id,
                access_token_hash=self.hash_token(access_token),
                refresh_token_hash=self.hash_token(refresh_token),
                token_expires_at=token_expires_at,
                granted_scopes=granted_scopes,
                
                # Apply consent preferences
                allow_subject_analysis=consent_preferences.get('allow_subject_analysis', True),
                allow_body_analysis=consent_preferences.get('allow_body_analysis', True),
                allow_attachment_scanning=consent_preferences.get('allow_attachment_scanning', False),
                allow_llm_processing=consent_preferences.get('allow_llm_processing', True),
                allow_threat_intel_lookup=consent_preferences.get('allow_threat_intel_lookup', True),
                opt_out_ai_analysis=consent_preferences.get('opt_out_ai_analysis', False),
                opt_out_persistent_storage=consent_preferences.get('opt_out_persistent_storage', False),
                
                # Retention settings
                retention_policy=consent_preferences.get('retention_policy', RetentionPolicy.STANDARD_30_DAYS.value),
                custom_retention_days=consent_preferences.get('custom_retention_days'),
                data_processing_region=consent_preferences.get('data_region', 'US'),
                
                # Privacy preferences
                allow_analytics=consent_preferences.get('allow_analytics', False),
                allow_performance_monitoring=consent_preferences.get('allow_performance_monitoring', True),
                share_threat_intelligence=consent_preferences.get('share_threat_intelligence', True),
                
                # Compliance
                gdpr_consent=consent_preferences.get('gdpr_consent', False),
                ccpa_opt_out=consent_preferences.get('ccpa_opt_out', False),
                
                # Context
                user_agent=request_context.get('user_agent'),
                ip_address=request_context.get('ip_address'),
                consent_source=request_context.get('source', 'web_ui')
            )
            
            self.db.add(consent)
            self.db.commit()
            self.db.refresh(consent)
            
            # Create audit log
            await self._create_audit_log(
                consent.id,
                "granted",
                {"scopes": granted_scopes, "preferences": consent_preferences},
                request_context
            )
            
            # Cache consent for quick access
            await self._cache_consent(consent)
            
            logger.info(f"Consent granted for user {user_id} with scopes: {granted_scopes}")
            return consent
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error granting consent for user {user_id}: {e}")
            raise
    
    async def update_consent(self,
                           user_id: str,
                           consent_preferences: Dict[str, Any],
                           request_context: Dict[str, Any]) -> UserConsent:
        """
        Update user consent preferences.
        
        Args:
            user_id: User identifier
            consent_preferences: Updated preferences
            request_context: Request context
            
        Returns:
            UserConsent: Updated consent record
        """
        try:
            consent = self.db.query(UserConsent).filter_by(
                user_id=user_id, is_active=True
            ).first()
            
            if not consent:
                raise ValueError(f"No active consent found for user {user_id}")
            
            # Store previous values for audit
            previous_values = consent.to_dict()
            
            # Update preferences
            for key, value in consent_preferences.items():
                if hasattr(consent, key):
                    setattr(consent, key, value)
            
            consent.consent_updated_at = datetime.utcnow()
            
            self.db.commit()
            self.db.refresh(consent)
            
            # Create audit log
            await self._create_audit_log(
                consent.id,
                "updated",
                {
                    "previous": previous_values,
                    "new": consent_preferences
                },
                request_context
            )
            
            # Update cached consent
            await self._cache_consent(consent)
            
            logger.info(f"Consent updated for user {user_id}")
            return consent
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error updating consent for user {user_id}: {e}")
            raise
    
    async def revoke_consent(self,
                           user_id: str,
                           request_context: Dict[str, Any],
                           cleanup_data: bool = True) -> bool:
        """
        Revoke user consent and optionally cleanup data.
        
        Args:
            user_id: User identifier
            request_context: Request context
            cleanup_data: Whether to cleanup user data
            
        Returns:
            bool: Success status
        """
        try:
            consent = self.db.query(UserConsent).filter_by(
                user_id=user_id, is_active=True
            ).first()
            
            if not consent:
                logger.warning(f"No active consent found for user {user_id}")
                return False
            
            # Revoke consent
            consent.is_active = False
            consent.consent_revoked_at = datetime.utcnow()
            
            self.db.commit()
            
            # Create audit log
            await self._create_audit_log(
                consent.id,
                "revoked",
                {"cleanup_requested": cleanup_data},
                request_context
            )
            
            # Remove from cache
            await self._remove_consent_cache(user_id)
            
            # Schedule data cleanup if requested
            if cleanup_data:
                await self._schedule_data_cleanup(user_id)
            
            logger.info(f"Consent revoked for user {user_id}, cleanup: {cleanup_data}")
            return True
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error revoking consent for user {user_id}: {e}")
            raise
    
    async def get_user_consent(self, user_id: str) -> Optional[UserConsent]:
        """Get user consent from cache or database"""
        try:
            # Try cache first
            cached_consent = await self._get_cached_consent(user_id)
            if cached_consent:
                return cached_consent
            
            # Fall back to database
            consent = self.db.query(UserConsent).filter_by(
                user_id=user_id, is_active=True
            ).first()
            
            if consent:
                await self._cache_consent(consent)
            
            return consent
            
        except Exception as e:
            logger.error(f"Error getting consent for user {user_id}: {e}")
            return None
    
    async def verify_processing_permission(self,
                                         user_id: str,
                                         processing_type: DataProcessingType) -> Tuple[bool, Optional[str]]:
        """
        Verify if user has granted permission for specific data processing.
        
        Args:
            user_id: User identifier
            processing_type: Type of processing to verify
            
        Returns:
            Tuple[bool, Optional[str]]: (allowed, reason if not allowed)
        """
        try:
            consent = await self.get_user_consent(user_id)
            
            if not consent:
                return False, "No active consent found"
            
            if not consent.is_consent_valid:
                return False, "Consent is no longer valid"
            
            if not consent.can_process_data(processing_type):
                return False, f"User has not granted permission for {processing_type.value}"
            
            return True, None
            
        except Exception as e:
            logger.error(f"Error verifying processing permission: {e}")
            return False, "Internal error verifying permissions"
    
    async def track_data_artifact(self,
                                user_id: str,
                                artifact_type: str,
                                artifact_id: str,
                                storage_location: str,
                                size_bytes: int = 0,
                                tags: List[str] = None) -> UserDataArtifact:
        """
        Track a data artifact for retention management.
        
        Args:
            user_id: User identifier
            artifact_type: Type of artifact (email_metadata, analysis_result, etc.)
            artifact_id: Unique identifier for the artifact
            storage_location: Where the artifact is stored
            size_bytes: Size of the artifact
            tags: Optional tags for categorization
            
        Returns:
            UserDataArtifact: Created artifact record
        """
        try:
            consent = await self.get_user_consent(user_id)
            if not consent:
                raise ValueError(f"No active consent for user {user_id}")
            
            # Calculate expiry based on retention policy
            retention_policy = RetentionPolicy(consent.retention_policy)
            expires_at = calculate_artifact_expiry(
                retention_policy, 
                consent.custom_retention_days
            )
            
            artifact = UserDataArtifact(
                user_consent_id=consent.id,
                artifact_type=artifact_type,
                artifact_id=artifact_id,
                storage_location=storage_location,
                expires_at=expires_at,
                size_bytes=size_bytes,
                tags=tags or []
            )
            
            self.db.add(artifact)
            self.db.commit()
            self.db.refresh(artifact)
            
            logger.debug(f"Tracked artifact {artifact_id} for user {user_id}, expires: {expires_at}")
            return artifact
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error tracking artifact: {e}")
            raise
    
    async def cleanup_expired_artifacts(self, batch_size: int = 100) -> int:
        """
        Cleanup expired data artifacts.
        
        Args:
            batch_size: Number of artifacts to process at once
            
        Returns:
            int: Number of artifacts cleaned up
        """
        try:
            # Find expired artifacts
            expired_artifacts = self.db.query(UserDataArtifact).filter(
                and_(
                    UserDataArtifact.expires_at <= datetime.utcnow(),
                    UserDataArtifact.deleted_at.is_(None)
                )
            ).limit(batch_size).all()
            
            cleanup_count = 0
            
            for artifact in expired_artifacts:
                try:
                    # Delete from storage
                    await self._delete_artifact_data(artifact)
                    
                    # Mark as deleted
                    artifact.deleted_at = datetime.utcnow()
                    cleanup_count += 1
                    
                except Exception as e:
                    logger.error(f"Error deleting artifact {artifact.id}: {e}")
            
            self.db.commit()
            
            if cleanup_count > 0:
                logger.info(f"Cleaned up {cleanup_count} expired artifacts")
            
            return cleanup_count
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error cleaning up expired artifacts: {e}")
            return 0
    
    async def get_user_data_summary(self, user_id: str) -> Dict[str, Any]:
        """
        Get summary of user's data and retention status.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dict: Data summary including artifacts and retention info
        """
        try:
            consent = await self.get_user_consent(user_id)
            if not consent:
                return {"error": "No consent found"}
            
            # Get artifact summary
            artifacts = self.db.query(UserDataArtifact).filter_by(
                user_consent_id=consent.id
            ).all()
            
            artifact_summary = {}
            total_size = 0
            
            for artifact in artifacts:
                if artifact.deleted_at:
                    continue
                    
                artifact_type = artifact.artifact_type
                if artifact_type not in artifact_summary:
                    artifact_summary[artifact_type] = {
                        "count": 0,
                        "total_size": 0,
                        "oldest": None,
                        "newest": None
                    }
                
                artifact_summary[artifact_type]["count"] += 1
                artifact_summary[artifact_type]["total_size"] += artifact.size_bytes
                total_size += artifact.size_bytes
                
                if not artifact_summary[artifact_type]["oldest"] or artifact.created_at < artifact_summary[artifact_type]["oldest"]:
                    artifact_summary[artifact_type]["oldest"] = artifact.created_at
                
                if not artifact_summary[artifact_type]["newest"] or artifact.created_at > artifact_summary[artifact_type]["newest"]:
                    artifact_summary[artifact_type]["newest"] = artifact.created_at
            
            return {
                "user_id": user_id,
                "consent_status": "active" if consent.is_consent_valid else "inactive",
                "retention_policy": consent.retention_policy,
                "retention_days": consent.effective_retention_days,
                "total_artifacts": len([a for a in artifacts if not a.deleted_at]),
                "total_size_bytes": total_size,
                "artifact_types": artifact_summary,
                "consent_granted": consent.consent_granted_at.isoformat() if consent.consent_granted_at else None,
                "last_updated": consent.consent_updated_at.isoformat() if consent.consent_updated_at else None
            }
            
        except Exception as e:
            logger.error(f"Error getting user data summary: {e}")
            return {"error": str(e)}
    
    # Private helper methods
    
    async def _create_audit_log(self,
                              consent_id: int,
                              event_type: str,
                              event_details: Dict[str, Any],
                              request_context: Dict[str, Any]) -> None:
        """Create audit log entry"""
        try:
            audit_log = ConsentAuditLog(
                user_consent_id=consent_id,
                event_type=event_type,
                event_details=event_details,
                ip_address=request_context.get('ip_address'),
                user_agent=request_context.get('user_agent'),
                request_id=request_context.get('request_id')
            )
            
            self.db.add(audit_log)
            self.db.commit()
            
        except Exception as e:
            logger.error(f"Error creating audit log: {e}")
    
    async def _cache_consent(self, consent: UserConsent) -> None:
        """Cache consent for quick access"""
        try:
            cache_key = f"user_consent:{consent.user_id}"
            cache_data = consent.to_dict()
            
            # Cache for 1 hour
            await self.redis_client.setex(
                cache_key, 
                3600, 
                str(cache_data)
            )
            
        except Exception as e:
            logger.error(f"Error caching consent: {e}")
    
    async def _get_cached_consent(self, user_id: str) -> Optional[UserConsent]:
        """Get consent from cache"""
        try:
            cache_key = f"user_consent:{user_id}"
            cached_data = await self.redis_client.get(cache_key)
            
            if cached_data:
                # Note: In production, implement proper deserialization
                return None  # Simplified for this example
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached consent: {e}")
            return None
    
    async def _remove_consent_cache(self, user_id: str) -> None:
        """Remove consent from cache"""
        try:
            cache_key = f"user_consent:{user_id}"
            await self.redis_client.delete(cache_key)
            
        except Exception as e:
            logger.error(f"Error removing consent cache: {e}")
    
    async def _schedule_data_cleanup(self, user_id: str) -> None:
        """Schedule data cleanup for revoked user"""
        try:
            # Add to cleanup queue
            cleanup_job = {
                "user_id": user_id,
                "scheduled_at": datetime.utcnow().isoformat(),
                "type": "consent_revocation_cleanup"
            }
            
            await self.redis_client.lpush(
                "data_cleanup_queue",
                str(cleanup_job)
            )
            
            logger.info(f"Scheduled data cleanup for user {user_id}")
            
        except Exception as e:
            logger.error(f"Error scheduling data cleanup: {e}")
    
    async def _delete_artifact_data(self, artifact: UserDataArtifact) -> None:
        """Delete actual artifact data from storage"""
        try:
            # Delete from Redis if it's a Redis key
            if artifact.storage_location.startswith("redis:"):
                redis_key = artifact.storage_location.replace("redis:", "")
                await self.redis_client.delete(redis_key)
            
            # Add other storage backends as needed (S3, filesystem, etc.)
            
        except Exception as e:
            logger.error(f"Error deleting artifact data: {e}")

# Global consent manager instance
_consent_manager = None

def get_consent_manager() -> ConsentManager:
    """Get global consent manager instance"""
    global _consent_manager
    if not _consent_manager:
        _consent_manager = ConsentManager()
    return _consent_manager
