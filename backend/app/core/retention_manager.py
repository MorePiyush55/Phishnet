"""
Data Retention and Cleanup Policies
Configurable retention periods with automatic cleanup.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, text

from app.core.database import get_db
from app.core.redis_client import get_redis_client
from app.core.config import get_settings
from app.models.consent import UserDataArtifact, UserConsent
from app.core.audit_logger import get_audit_logger, AuditEventType

logger = logging.getLogger(__name__)

class RetentionCategory(Enum):
    """Data retention categories with different policies"""
    SCREENSHOTS = "screenshots"  # 7 days
    EMAIL_METADATA = "email_metadata"  # 90 days
    SCAN_RESULTS = "scan_results"  # 30 days
    THREAT_INTELLIGENCE = "threat_intelligence"  # 6 months
    USER_SESSIONS = "user_sessions"  # 24 hours
    AUDIT_LOGS = "audit_logs"  # 7 years
    COMPLIANCE_DATA = "compliance_data"  # 7 years
    PERFORMANCE_METRICS = "performance_metrics"  # 30 days
    ERROR_LOGS = "error_logs"  # 90 days

@dataclass
class RetentionPolicy:
    """Retention policy configuration"""
    category: RetentionCategory
    default_days: int
    min_days: int
    max_days: int
    user_configurable: bool
    auto_cleanup: bool
    compliance_required: bool
    description: str

class DataRetentionManager:
    """
    Manages data retention policies and automatic cleanup.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.redis_client = get_redis_client()
        self.audit_logger = get_audit_logger()
        
        # Define retention policies
        self.policies = {
            RetentionCategory.SCREENSHOTS: RetentionPolicy(
                category=RetentionCategory.SCREENSHOTS,
                default_days=7,
                min_days=1,
                max_days=30,
                user_configurable=True,
                auto_cleanup=True,
                compliance_required=False,
                description="Browser screenshots from phishing analysis"
            ),
            RetentionCategory.EMAIL_METADATA: RetentionPolicy(
                category=RetentionCategory.EMAIL_METADATA,
                default_days=90,
                min_days=30,
                max_days=365,
                user_configurable=True,
                auto_cleanup=True,
                compliance_required=False,
                description="Email headers, subjects, sender info (sanitized)"
            ),
            RetentionCategory.SCAN_RESULTS: RetentionPolicy(
                category=RetentionCategory.SCAN_RESULTS,
                default_days=30,
                min_days=7,
                max_days=180,
                user_configurable=True,
                auto_cleanup=True,
                compliance_required=False,
                description="Phishing scan results and threat scores"
            ),
            RetentionCategory.THREAT_INTELLIGENCE: RetentionPolicy(
                category=RetentionCategory.THREAT_INTELLIGENCE,
                default_days=180,
                min_days=90,
                max_days=365,
                user_configurable=False,  # Managed by security team
                auto_cleanup=True,
                compliance_required=False,
                description="Threat intelligence data and IOCs"
            ),
            RetentionCategory.USER_SESSIONS: RetentionPolicy(
                category=RetentionCategory.USER_SESSIONS,
                default_days=1,
                min_days=1,
                max_days=7,
                user_configurable=False,
                auto_cleanup=True,
                compliance_required=False,
                description="User session data and tokens"
            ),
            RetentionCategory.AUDIT_LOGS: RetentionPolicy(
                category=RetentionCategory.AUDIT_LOGS,
                default_days=2555,  # 7 years
                min_days=2555,
                max_days=2555,
                user_configurable=False,
                auto_cleanup=False,  # Manual compliance review required
                compliance_required=True,
                description="Security and compliance audit logs"
            ),
            RetentionCategory.COMPLIANCE_DATA: RetentionPolicy(
                category=RetentionCategory.COMPLIANCE_DATA,
                default_days=2555,  # 7 years
                min_days=2555,
                max_days=2555,
                user_configurable=False,
                auto_cleanup=False,
                compliance_required=True,
                description="Consent records and privacy compliance data"
            ),
            RetentionCategory.PERFORMANCE_METRICS: RetentionPolicy(
                category=RetentionCategory.PERFORMANCE_METRICS,
                default_days=30,
                min_days=7,
                max_days=90,
                user_configurable=False,
                auto_cleanup=True,
                compliance_required=False,
                description="System performance and monitoring metrics"
            ),
            RetentionCategory.ERROR_LOGS: RetentionPolicy(
                category=RetentionCategory.ERROR_LOGS,
                default_days=90,
                min_days=30,
                max_days=180,
                user_configurable=False,
                auto_cleanup=True,
                compliance_required=False,
                description="Application error logs and stack traces"
            )
        }
    
    def get_retention_policy(self, category: RetentionCategory) -> RetentionPolicy:
        """Get retention policy for a category"""
        return self.policies[category]
    
    def calculate_expiry_date(self, 
                            category: RetentionCategory,
                            user_preference_days: Optional[int] = None,
                            created_at: datetime = None) -> datetime:
        """
        Calculate expiry date for data based on retention policy.
        
        Args:
            category: Data category
            user_preference_days: User's custom retention preference
            created_at: When data was created (defaults to now)
            
        Returns:
            Expiry datetime
        """
        policy = self.policies[category]
        created_at = created_at or datetime.utcnow()
        
        # Use user preference if allowed and within limits
        if policy.user_configurable and user_preference_days:
            retention_days = max(
                policy.min_days,
                min(user_preference_days, policy.max_days)
            )
        else:
            retention_days = policy.default_days
        
        return created_at + timedelta(days=retention_days)
    
    def mark_for_retention(self,
                          data_id: str,
                          category: RetentionCategory,
                          storage_location: str,
                          size_bytes: int = 0,
                          user_id: str = None,
                          user_preference_days: Optional[int] = None,
                          metadata: Dict[str, Any] = None) -> UserDataArtifact:
        """
        Mark data for retention tracking.
        
        Args:
            data_id: Unique identifier for the data
            category: Retention category
            storage_location: Where data is stored
            size_bytes: Size of data in bytes
            user_id: Associated user ID
            user_preference_days: User's retention preference
            metadata: Additional metadata
            
        Returns:
            UserDataArtifact record
        """
        try:
            db = next(get_db())
            
            # Calculate expiry
            expires_at = self.calculate_expiry_date(
                category, 
                user_preference_days
            )
            
            # Get or create user consent record
            user_consent = None
            if user_id:
                user_consent = db.query(UserConsent).filter_by(
                    user_id=user_id, is_active=True
                ).first()
            
            # Create artifact record
            artifact = UserDataArtifact(
                user_consent_id=user_consent.id if user_consent else None,
                artifact_type=category.value,
                artifact_id=data_id,
                storage_location=storage_location,
                expires_at=expires_at,
                size_bytes=size_bytes,
                tags=metadata.get('tags', []) if metadata else [],
                metadata=metadata or {}
            )
            
            db.add(artifact)
            db.commit()
            db.refresh(artifact)
            
            # Cache for quick lookup
            self._cache_artifact_expiry(data_id, expires_at)
            
            # Audit the retention marking
            self.audit_logger.log_event(
                AuditEventType.DATA_RETENTION_MARKED,
                f"Data marked for retention: {category.value}",
                details={
                    'data_id': data_id,
                    'category': category.value,
                    'expires_at': expires_at.isoformat(),
                    'size_bytes': size_bytes,
                    'user_configurable': self.policies[category].user_configurable
                }
            )
            
            return artifact
            
        except Exception as e:
            logger.error(f"Error marking data for retention: {e}")
            db.rollback()
            raise
    
    def _cache_artifact_expiry(self, data_id: str, expires_at: datetime):
        """Cache artifact expiry for quick checks"""
        try:
            cache_key = f"retention:expiry:{data_id}"
            expires_timestamp = int(expires_at.timestamp())
            
            # Store with TTL slightly longer than expiry
            ttl = int((expires_at - datetime.utcnow()).total_seconds()) + 3600
            self.redis_client.setex(cache_key, ttl, expires_timestamp)
            
        except Exception as e:
            logger.error(f"Error caching artifact expiry: {e}")
    
    def is_data_expired(self, data_id: str) -> bool:
        """Check if data has expired"""
        try:
            # Check cache first
            cache_key = f"retention:expiry:{data_id}"
            cached_expiry = self.redis_client.get(cache_key)
            
            if cached_expiry:
                expires_at = datetime.fromtimestamp(int(cached_expiry))
                return datetime.utcnow() > expires_at
            
            # Fall back to database
            db = next(get_db())
            artifact = db.query(UserDataArtifact).filter_by(
                artifact_id=data_id
            ).first()
            
            if artifact:
                return datetime.utcnow() > artifact.expires_at
            
            return False  # No retention record found
            
        except Exception as e:
            logger.error(f"Error checking data expiry: {e}")
            return False
    
    async def cleanup_expired_data(self, 
                                 categories: List[RetentionCategory] = None,
                                 batch_size: int = 100,
                                 dry_run: bool = False) -> Dict[str, Any]:
        """
        Clean up expired data across categories.
        
        Args:
            categories: Categories to clean (all if None)
            batch_size: Items to process per batch
            dry_run: Only identify, don't delete
            
        Returns:
            Cleanup results
        """
        try:
            db = next(get_db())
            
            cleanup_results = {
                'total_processed': 0,
                'total_deleted': 0,
                'total_size_freed': 0,
                'categories': {},
                'errors': []
            }
            
            # Get categories to process
            target_categories = categories or list(self.policies.keys())
            
            for category in target_categories:
                policy = self.policies[category]
                
                # Skip if auto cleanup disabled
                if not policy.auto_cleanup:
                    logger.info(f"Skipping {category.value} - auto cleanup disabled")
                    continue
                
                category_results = await self._cleanup_category_data(
                    category, batch_size, dry_run, db
                )
                
                cleanup_results['categories'][category.value] = category_results
                cleanup_results['total_processed'] += category_results['processed']
                cleanup_results['total_deleted'] += category_results['deleted']
                cleanup_results['total_size_freed'] += category_results['size_freed']
            
            # Audit cleanup operation
            self.audit_logger.log_event(
                AuditEventType.DATA_CLEANUP,
                f"Data cleanup completed: {cleanup_results['total_deleted']} items",
                details={
                    'dry_run': dry_run,
                    'categories_processed': [c.value for c in target_categories],
                    'total_processed': cleanup_results['total_processed'],
                    'total_deleted': cleanup_results['total_deleted'],
                    'size_freed_bytes': cleanup_results['total_size_freed']
                }
            )
            
            return cleanup_results
            
        except Exception as e:
            logger.error(f"Error during data cleanup: {e}")
            cleanup_results['errors'].append(str(e))
            return cleanup_results
    
    async def _cleanup_category_data(self,
                                   category: RetentionCategory,
                                   batch_size: int,
                                   dry_run: bool,
                                   db: Session) -> Dict[str, Any]:
        """Clean up expired data for a specific category"""
        try:
            results = {
                'processed': 0,
                'deleted': 0,
                'size_freed': 0,
                'errors': []
            }
            
            # Find expired artifacts
            expired_artifacts = db.query(UserDataArtifact).filter(
                and_(
                    UserDataArtifact.artifact_type == category.value,
                    UserDataArtifact.expires_at <= datetime.utcnow(),
                    UserDataArtifact.deleted_at.is_(None)
                )
            ).limit(batch_size).all()
            
            results['processed'] = len(expired_artifacts)
            
            for artifact in expired_artifacts:
                try:
                    if not dry_run:
                        # Delete actual data
                        await self._delete_artifact_data(artifact)
                        
                        # Mark as deleted
                        artifact.deleted_at = datetime.utcnow()
                        artifact.deletion_method = 'auto_cleanup'
                        
                        results['deleted'] += 1
                        results['size_freed'] += artifact.size_bytes
                    else:
                        # Dry run - just count
                        results['deleted'] += 1
                        results['size_freed'] += artifact.size_bytes
                        
                except Exception as e:
                    error_msg = f"Error deleting artifact {artifact.id}: {e}"
                    logger.error(error_msg)
                    results['errors'].append(error_msg)
            
            if not dry_run:
                db.commit()
            
            logger.info(
                f"Category {category.value}: processed {results['processed']}, "
                f"deleted {results['deleted']}, freed {results['size_freed']} bytes"
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Error cleaning up category {category.value}: {e}")
            db.rollback()
            return {
                'processed': 0,
                'deleted': 0,
                'size_freed': 0,
                'errors': [str(e)]
            }
    
    async def _delete_artifact_data(self, artifact: UserDataArtifact):
        """Delete actual artifact data from storage"""
        try:
            storage_location = artifact.storage_location
            
            if storage_location.startswith('redis:'):
                # Delete from Redis
                redis_key = storage_location.replace('redis:', '')
                await self.redis_client.delete(redis_key)
                
            elif storage_location.startswith('file:'):
                # Delete file
                import os
                file_path = storage_location.replace('file:', '')
                if os.path.exists(file_path):
                    os.remove(file_path)
                    
            elif storage_location.startswith('s3:'):
                # Delete from S3 (implement as needed)
                logger.warning(f"S3 deletion not implemented: {storage_location}")
                
            elif storage_location.startswith('db:'):
                # Delete from database table
                table_info = storage_location.replace('db:', '')
                # Implement database deletion based on table_info
                logger.warning(f"DB deletion not implemented: {storage_location}")
                
            else:
                logger.warning(f"Unknown storage location type: {storage_location}")
                
        except Exception as e:
            logger.error(f"Error deleting artifact data: {e}")
            raise
    
    def update_user_retention_preferences(self,
                                        user_id: str,
                                        preferences: Dict[str, int]) -> Dict[str, Any]:
        """
        Update user's retention preferences.
        
        Args:
            user_id: User identifier
            preferences: Category -> days mapping
            
        Returns:
            Updated preferences with validation results
        """
        try:
            db = next(get_db())
            
            # Get user consent record
            consent = db.query(UserConsent).filter_by(
                user_id=user_id, is_active=True
            ).first()
            
            if not consent:
                raise ValueError(f"No active consent found for user {user_id}")
            
            validated_preferences = {}
            validation_errors = []
            
            # Validate each preference
            for category_name, days in preferences.items():
                try:
                    category = RetentionCategory(category_name)
                    policy = self.policies[category]
                    
                    if not policy.user_configurable:
                        validation_errors.append(
                            f"{category_name} retention is not user-configurable"
                        )
                        continue
                    
                    # Validate days within limits
                    if days < policy.min_days or days > policy.max_days:
                        validation_errors.append(
                            f"{category_name} must be between {policy.min_days} and {policy.max_days} days"
                        )
                        continue
                    
                    validated_preferences[category_name] = days
                    
                except ValueError:
                    validation_errors.append(f"Unknown retention category: {category_name}")
            
            # Update consent record with validated preferences
            if validated_preferences:
                # Store in consent metadata
                if not consent.metadata:
                    consent.metadata = {}
                
                consent.metadata['retention_preferences'] = validated_preferences
                consent.consent_updated_at = datetime.utcnow()
                
                db.commit()
                
                # Audit the change
                self.audit_logger.log_event(
                    AuditEventType.CONSENT_UPDATED,
                    "User updated retention preferences",
                    details={
                        'user_id': user_id,
                        'updated_preferences': validated_preferences,
                        'validation_errors': validation_errors
                    }
                )
            
            return {
                'success': len(validation_errors) == 0,
                'validated_preferences': validated_preferences,
                'validation_errors': validation_errors
            }
            
        except Exception as e:
            logger.error(f"Error updating retention preferences: {e}")
            db.rollback()
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_user_data_summary(self, user_id: str) -> Dict[str, Any]:
        """
        Get summary of user's data and retention status.
        
        Args:
            user_id: User identifier
            
        Returns:
            Data summary with retention information
        """
        try:
            db = next(get_db())
            
            # Get user's artifacts
            artifacts = db.query(UserDataArtifact).join(UserConsent).filter(
                and_(
                    UserConsent.user_id == user_id,
                    UserDataArtifact.deleted_at.is_(None)
                )
            ).all()
            
            # Group by category
            summary = {
                'user_id': user_id,
                'total_artifacts': len(artifacts),
                'total_size_bytes': sum(a.size_bytes for a in artifacts),
                'categories': {},
                'retention_preferences': {},
                'upcoming_expirations': []
            }
            
            # Get user's retention preferences
            consent = db.query(UserConsent).filter_by(
                user_id=user_id, is_active=True
            ).first()
            
            if consent and consent.metadata and 'retention_preferences' in consent.metadata:
                summary['retention_preferences'] = consent.metadata['retention_preferences']
            
            # Group artifacts by category
            for artifact in artifacts:
                category = artifact.artifact_type
                
                if category not in summary['categories']:
                    summary['categories'][category] = {
                        'count': 0,
                        'total_size': 0,
                        'oldest_expires': None,
                        'newest_expires': None
                    }
                
                cat_summary = summary['categories'][category]
                cat_summary['count'] += 1
                cat_summary['total_size'] += artifact.size_bytes
                
                # Track expiration dates
                if not cat_summary['oldest_expires'] or artifact.expires_at < cat_summary['oldest_expires']:
                    cat_summary['oldest_expires'] = artifact.expires_at
                
                if not cat_summary['newest_expires'] or artifact.expires_at > cat_summary['newest_expires']:
                    cat_summary['newest_expires'] = artifact.expires_at
                
                # Track upcoming expirations (next 30 days)
                days_until_expiry = (artifact.expires_at - datetime.utcnow()).days
                if 0 <= days_until_expiry <= 30:
                    summary['upcoming_expirations'].append({
                        'artifact_id': artifact.artifact_id,
                        'category': category,
                        'expires_at': artifact.expires_at.isoformat(),
                        'days_remaining': days_until_expiry,
                        'size_bytes': artifact.size_bytes
                    })
            
            # Convert datetime objects to ISO strings
            for category in summary['categories'].values():
                if category['oldest_expires']:
                    category['oldest_expires'] = category['oldest_expires'].isoformat()
                if category['newest_expires']:
                    category['newest_expires'] = category['newest_expires'].isoformat()
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting user data summary: {e}")
            return {'error': str(e)}
    
    def get_retention_policies_info(self) -> Dict[str, Any]:
        """Get information about all retention policies"""
        return {
            'policies': {
                category.value: {
                    'default_days': policy.default_days,
                    'min_days': policy.min_days,
                    'max_days': policy.max_days,
                    'user_configurable': policy.user_configurable,
                    'auto_cleanup': policy.auto_cleanup,
                    'compliance_required': policy.compliance_required,
                    'description': policy.description
                }
                for category, policy in self.policies.items()
            }
        }

# Global retention manager instance
_retention_manager = None

def get_retention_manager() -> DataRetentionManager:
    """Get global retention manager instance"""
    global _retention_manager
    if _retention_manager is None:
        _retention_manager = DataRetentionManager()
    return _retention_manager

# Convenience functions

def mark_data_for_retention(data_id: str,
                          category: RetentionCategory,
                          storage_location: str,
                          **kwargs) -> UserDataArtifact:
    """Mark data for retention tracking"""
    manager = get_retention_manager()
    return manager.mark_for_retention(
        data_id, category, storage_location, **kwargs
    )

async def cleanup_expired_data(categories: List[RetentionCategory] = None) -> Dict[str, Any]:
    """Run data cleanup for expired items"""
    manager = get_retention_manager()
    return await manager.cleanup_expired_data(categories)
