"""
Scan Permission System
Provides granular control over email scanning permissions with user consent tracking.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from enum import Enum
import json

from backend.app.models.consent import (
    UserConsent, ConsentAuditLog, DataProcessingType
)
from backend.app.core.database import get_db
from backend.app.core.config import get_settings
from backend.app.core.redis_client import get_redis_client

logger = logging.getLogger(__name__)

class ScanPermissionType(Enum):
    """Types of scan permissions."""
    AUTOMATIC_SCAN = "automatic_scan"
    MANUAL_SCAN = "manual_scan"  
    REAL_TIME_MONITORING = "real_time_monitoring"
    BATCH_ANALYSIS = "batch_analysis"
    HISTORICAL_SCAN = "historical_scan"

class ScanScope(Enum):
    """Scope of email scanning."""
    INBOX_ONLY = "inbox_only"
    ALL_FOLDERS = "all_folders"
    SENT_ITEMS = "sent_items"
    SPECIFIC_LABELS = "specific_labels"

class ScanTrigger(Enum):
    """What triggers a scan."""
    USER_INITIATED = "user_initiated"
    SCHEDULED = "scheduled"
    NEW_EMAIL_RECEIVED = "new_email_received"
    THREAT_INTELLIGENCE_UPDATE = "threat_intelligence_update"
    ADMIN_REQUESTED = "admin_requested"

class ScanPermissionService:
    """
    Service for managing granular email scanning permissions with user consent.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.redis_client = get_redis_client()
        
        # Cache scan permissions in Redis for fast lookup
        self.permission_cache_ttl = 300  # 5 minutes

    async def configure_scan_permissions(self,
                                       user_id: str,
                                       permission_config: Dict[str, Any],
                                       request_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Configure detailed scan permissions for a user.
        
        Args:
            user_id: User identifier
            permission_config: Scan permission configuration
            request_context: Request metadata for audit
            
        Returns:
            Dict containing configuration results
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
                
                # Store scan permissions in Redis with structured format
                scan_permissions = {
                    "user_id": user_id,
                    "consent_id": consent.id,
                    "configured_at": datetime.utcnow().isoformat(),
                    "permissions": {
                        # Automatic scanning settings
                        "automatic_scan_enabled": permission_config.get("automatic_scan_enabled", False),
                        "automatic_scan_schedule": permission_config.get("automatic_scan_schedule", "daily"),
                        "automatic_scan_time": permission_config.get("automatic_scan_time", "02:00"),
                        
                        # Real-time monitoring
                        "real_time_monitoring": permission_config.get("real_time_monitoring", False),
                        "monitoring_sensitivity": permission_config.get("monitoring_sensitivity", "medium"),
                        
                        # Scan scope settings
                        "scan_scope": permission_config.get("scan_scope", ScanScope.INBOX_ONLY.value),
                        "included_folders": permission_config.get("included_folders", ["INBOX"]),
                        "excluded_folders": permission_config.get("excluded_folders", []),
                        "specific_labels": permission_config.get("specific_labels", []),
                        
                        # Historical scanning
                        "allow_historical_scan": permission_config.get("allow_historical_scan", False),
                        "historical_scan_limit_days": permission_config.get("historical_scan_limit_days", 30),
                        
                        # Batch processing
                        "allow_batch_analysis": permission_config.get("allow_batch_analysis", True),
                        "batch_size_limit": permission_config.get("batch_size_limit", 100),
                        
                        # Trigger settings
                        "allowed_triggers": permission_config.get("allowed_triggers", [
                            ScanTrigger.USER_INITIATED.value,
                            ScanTrigger.NEW_EMAIL_RECEIVED.value
                        ]),
                        
                        # Privacy controls
                        "anonymize_scan_results": permission_config.get("anonymize_scan_results", False),
                        "limit_result_retention": permission_config.get("limit_result_retention", True),
                        "opt_out_threat_sharing": permission_config.get("opt_out_threat_sharing", False),
                        
                        # Notification preferences
                        "notify_on_threats": permission_config.get("notify_on_threats", True),
                        "threat_notification_threshold": permission_config.get("threat_notification_threshold", "medium"),
                        "scan_completion_notifications": permission_config.get("scan_completion_notifications", False),
                        
                        # Rate limiting
                        "max_scans_per_hour": permission_config.get("max_scans_per_hour", 10),
                        "max_scans_per_day": permission_config.get("max_scans_per_day", 50),
                        
                        # Advanced features
                        "enable_attachment_deep_scan": permission_config.get("enable_attachment_deep_scan", False),
                        "enable_url_reputation_check": permission_config.get("enable_url_reputation_check", True),
                        "enable_sender_reputation_analysis": permission_config.get("enable_sender_reputation_analysis", True)
                    },
                    "data_processing_consent": {
                        "allow_content_analysis": consent.allow_body_analysis,
                        "allow_attachment_scan": consent.allow_attachment_scanning,
                        "allow_llm_processing": consent.allow_llm_processing,
                        "allow_threat_intel_lookup": consent.allow_threat_intel_lookup,
                        "storage_permitted": not consent.opt_out_persistent_storage
                    },
                    "legal_basis": {
                        "consent_granted": True,
                        "consent_timestamp": consent.consent_granted_at.isoformat(),
                        "privacy_policy_version": consent.privacy_policy_version,
                        "retention_policy": consent.retention_policy
                    }
                }
                
                # Cache permissions in Redis
                cache_key = f"scan_permissions:{user_id}"
                await self.redis_client.setex(
                    cache_key,
                    self.permission_cache_ttl,
                    json.dumps(scan_permissions)
                )
                
                # Log configuration
                await self._log_permission_event(
                    db=db,
                    consent_id=consent.id,
                    event_type="scan_permissions_configured",
                    event_details={
                        "permission_config": permission_config,
                        "configured_permissions": scan_permissions["permissions"],
                        "configuration_source": request_context.get("source", "user_interface")
                    },
                    request_context=request_context
                )
                
                db.commit()
                
                logger.info(f"Scan permissions configured for user {user_id}")
                
                return {
                    "success": True,
                    "permissions_configured": True,
                    "configuration_timestamp": scan_permissions["configured_at"],
                    "permissions": scan_permissions["permissions"],
                    "cache_duration_seconds": self.permission_cache_ttl,
                    "next_actions": self._get_permission_recommendations(scan_permissions)
                }
                
        except Exception as e:
            logger.error(f"Failed to configure scan permissions for {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "SCAN_PERMISSION_CONFIG_FAILED"
            }

    async def check_scan_permission(self,
                                  user_id: str,
                                  scan_type: ScanPermissionType,
                                  scan_trigger: ScanTrigger,
                                  scan_scope: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Check if user has granted permission for specific scan operation.
        
        Args:
            user_id: User identifier
            scan_type: Type of scan requested
            scan_trigger: What triggered the scan
            scan_scope: Optional scope details (folders, labels, etc.)
            
        Returns:
            Dict containing permission status and details
        """
        try:
            # Try to get cached permissions first
            cached_permissions = await self._get_cached_permissions(user_id)
            
            if not cached_permissions:
                # Fallback to database
                permissions = await self._load_permissions_from_db(user_id)
                if not permissions:
                    return {
                        "permission_granted": False,
                        "reason": "No scan permissions configured",
                        "error_code": "NO_SCAN_PERMISSIONS"
                    }
            else:
                permissions = cached_permissions
            
            # Check specific permission
            permission_result = self._evaluate_scan_permission(
                permissions=permissions,
                scan_type=scan_type,
                scan_trigger=scan_trigger,
                scan_scope=scan_scope
            )
            
            # Log permission check
            await self._log_permission_check(
                user_id=user_id,
                scan_type=scan_type,
                scan_trigger=scan_trigger,
                permission_result=permission_result
            )
            
            return permission_result
            
        except Exception as e:
            logger.error(f"Failed to check scan permission for {user_id}: {str(e)}")
            return {
                "permission_granted": False,
                "error": str(e),
                "error_code": "PERMISSION_CHECK_FAILED"
            }

    async def request_scan_permission(self,
                                    user_id: str,
                                    scan_request: Dict[str, Any],
                                    request_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Request permission for a specific scan operation.
        
        Args:
            user_id: User identifier
            scan_request: Details of the scan being requested
            request_context: Request metadata
            
        Returns:
            Dict containing permission request result
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
                
                scan_type = ScanPermissionType(scan_request.get("scan_type"))
                scan_trigger = ScanTrigger(scan_request.get("scan_trigger"))
                
                # Check if permission is needed
                permission_check = await self.check_scan_permission(
                    user_id=user_id,
                    scan_type=scan_type,
                    scan_trigger=scan_trigger,
                    scan_scope=scan_request.get("scan_scope")
                )
                
                if permission_check["permission_granted"]:
                    return {
                        "success": True,
                        "permission_granted": True,
                        "can_proceed": True,
                        "permission_details": permission_check,
                        "scan_limitations": self._get_scan_limitations(user_id, scan_request)
                    }
                
                # Permission not granted - provide options
                return {
                    "success": True,
                    "permission_granted": False,
                    "can_proceed": False,
                    "permission_required": True,
                    "required_permissions": self._get_required_permissions(scan_type, scan_trigger),
                    "consent_update_needed": True,
                    "alternative_actions": self._get_alternative_actions(scan_type, permission_check)
                }
                
        except Exception as e:
            logger.error(f"Failed to request scan permission for {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "SCAN_PERMISSION_REQUEST_FAILED"
            }

    async def track_scan_execution(self,
                                 user_id: str,
                                 scan_details: Dict[str, Any],
                                 scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Track executed scan for audit and rate limiting.
        
        Args:
            user_id: User identifier
            scan_details: Details of the executed scan
            scan_results: Results of the scan
            
        Returns:
            Dict containing tracking confirmation
        """
        try:
            scan_execution = {
                "user_id": user_id,
                "scan_id": scan_details.get("scan_id"),
                "scan_type": scan_details.get("scan_type"),
                "scan_trigger": scan_details.get("scan_trigger"),
                "executed_at": datetime.utcnow().isoformat(),
                "scope": scan_details.get("scope", {}),
                "results_summary": {
                    "emails_scanned": scan_results.get("emails_scanned", 0),
                    "threats_detected": scan_results.get("threats_detected", 0),
                    "processing_time_ms": scan_results.get("processing_time_ms", 0),
                    "scan_status": scan_results.get("scan_status", "completed")
                },
                "permissions_used": scan_details.get("permissions_used", []),
                "data_processing_activities": scan_details.get("data_processing_activities", [])
            }
            
            # Store in Redis for rate limiting and recent activity tracking
            execution_key = f"scan_execution:{user_id}:{scan_details.get('scan_id')}"
            await self.redis_client.setex(
                execution_key,
                86400,  # 24 hours
                json.dumps(scan_execution)
            )
            
            # Update rate limiting counters
            await self._update_rate_limiting_counters(user_id, scan_execution)
            
            # Log execution in database
            with get_db() as db:
                consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id,
                    UserConsent.is_active == True
                ).first()
                
                if consent:
                    await self._log_permission_event(
                        db=db,
                        consent_id=consent.id,
                        event_type="scan_executed",
                        event_details=scan_execution,
                        request_context={"source": "scan_execution_tracker"}
                    )
                    db.commit()
            
            return {
                "success": True,
                "scan_tracked": True,
                "tracking_id": execution_key,
                "rate_limit_status": await self._get_rate_limit_status(user_id)
            }
            
        except Exception as e:
            logger.error(f"Failed to track scan execution for {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "SCAN_TRACKING_FAILED"
            }

    async def get_scan_permission_summary(self, user_id: str) -> Dict[str, Any]:
        """
        Get comprehensive scan permission summary for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dict containing complete permission summary
        """
        try:
            permissions = await self._get_cached_permissions(user_id)
            if not permissions:
                permissions = await self._load_permissions_from_db(user_id)
            
            if not permissions:
                return {
                    "success": False,
                    "error": "No scan permissions configured",
                    "error_code": "NO_PERMISSIONS_CONFIGURED"
                }
            
            # Get rate limiting status
            rate_limit_status = await self._get_rate_limit_status(user_id)
            
            # Get recent scan activity
            recent_scans = await self._get_recent_scan_activity(user_id)
            
            return {
                "success": True,
                "permissions": permissions["permissions"],
                "data_processing_consent": permissions["data_processing_consent"],
                "legal_basis": permissions["legal_basis"],
                "rate_limiting": rate_limit_status,
                "recent_activity": recent_scans,
                "permission_status": {
                    "automatic_scan": permissions["permissions"].get("automatic_scan_enabled", False),
                    "real_time_monitoring": permissions["permissions"].get("real_time_monitoring", False),
                    "historical_scan": permissions["permissions"].get("allow_historical_scan", False),
                    "batch_analysis": permissions["permissions"].get("allow_batch_analysis", True)
                },
                "recommendations": self._get_permission_recommendations(permissions)
            }
            
        except Exception as e:
            logger.error(f"Failed to get scan permission summary for {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "PERMISSION_SUMMARY_FAILED"
            }

    # Private helper methods

    async def _get_cached_permissions(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get scan permissions from Redis cache."""
        
        try:
            cache_key = f"scan_permissions:{user_id}"
            cached_data = await self.redis_client.get(cache_key)
            
            if cached_data:
                return json.loads(cached_data)
            return None
            
        except Exception as e:
            logger.error(f"Failed to get cached permissions: {str(e)}")
            return None

    async def _load_permissions_from_db(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Load scan permissions from database."""
        
        try:
            with get_db() as db:
                consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id,
                    UserConsent.is_active == True
                ).first()
                
                if not consent:
                    return None
                
                # Create default permissions based on consent
                permissions = {
                    "user_id": user_id,
                    "consent_id": consent.id,
                    "configured_at": consent.consent_updated_at.isoformat(),
                    "permissions": {
                        "automatic_scan_enabled": False,
                        "real_time_monitoring": False,
                        "scan_scope": ScanScope.INBOX_ONLY.value,
                        "allow_historical_scan": False,
                        "allow_batch_analysis": True,
                        "allowed_triggers": [ScanTrigger.USER_INITIATED.value],
                        "max_scans_per_hour": 10,
                        "max_scans_per_day": 50
                    },
                    "data_processing_consent": {
                        "allow_content_analysis": consent.allow_body_analysis,
                        "allow_attachment_scan": consent.allow_attachment_scanning,
                        "allow_llm_processing": consent.allow_llm_processing,
                        "allow_threat_intel_lookup": consent.allow_threat_intel_lookup,
                        "storage_permitted": not consent.opt_out_persistent_storage
                    },
                    "legal_basis": {
                        "consent_granted": True,
                        "consent_timestamp": consent.consent_granted_at.isoformat(),
                        "privacy_policy_version": consent.privacy_policy_version,
                        "retention_policy": consent.retention_policy
                    }
                }
                
                return permissions
                
        except Exception as e:
            logger.error(f"Failed to load permissions from DB: {str(e)}")
            return None

    def _evaluate_scan_permission(self,
                                permissions: Dict[str, Any],
                                scan_type: ScanPermissionType,
                                scan_trigger: ScanTrigger,
                                scan_scope: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate if specific scan is permitted."""
        
        perms = permissions["permissions"]
        consent = permissions["data_processing_consent"]
        
        # Check basic consent requirements
        if not consent["allow_content_analysis"] and scan_type in [
            ScanPermissionType.AUTOMATIC_SCAN,
            ScanPermissionType.BATCH_ANALYSIS
        ]:
            return {
                "permission_granted": False,
                "reason": "Content analysis not permitted",
                "required_consent": "allow_body_analysis"
            }
        
        # Check scan type permissions
        if scan_type == ScanPermissionType.AUTOMATIC_SCAN:
            if not perms.get("automatic_scan_enabled", False):
                return {
                    "permission_granted": False,
                    "reason": "Automatic scanning not enabled",
                    "required_permission": "automatic_scan_enabled"
                }
        
        elif scan_type == ScanPermissionType.REAL_TIME_MONITORING:
            if not perms.get("real_time_monitoring", False):
                return {
                    "permission_granted": False,
                    "reason": "Real-time monitoring not enabled",
                    "required_permission": "real_time_monitoring"
                }
        
        elif scan_type == ScanPermissionType.HISTORICAL_SCAN:
            if not perms.get("allow_historical_scan", False):
                return {
                    "permission_granted": False,
                    "reason": "Historical scanning not permitted",
                    "required_permission": "allow_historical_scan"
                }
        
        # Check trigger permissions
        allowed_triggers = perms.get("allowed_triggers", [])
        if scan_trigger.value not in allowed_triggers:
            return {
                "permission_granted": False,
                "reason": f"Scan trigger '{scan_trigger.value}' not permitted",
                "allowed_triggers": allowed_triggers
            }
        
        # Check scope permissions
        if scan_scope:
            scope_check = self._check_scope_permission(perms, scan_scope)
            if not scope_check["permitted"]:
                return {
                    "permission_granted": False,
                    "reason": scope_check["reason"],
                    "scope_limitations": scope_check.get("limitations")
                }
        
        return {
            "permission_granted": True,
            "scan_type": scan_type.value,
            "scan_trigger": scan_trigger.value,
            "consent_basis": "User consent granted",
            "limitations": self._get_scan_limitations_from_permissions(perms)
        }

    def _check_scope_permission(self, permissions: Dict[str, Any], scan_scope: Dict[str, Any]) -> Dict[str, Any]:
        """Check if scan scope is permitted."""
        
        configured_scope = permissions.get("scan_scope", ScanScope.INBOX_ONLY.value)
        requested_folders = scan_scope.get("folders", ["INBOX"])
        
        # Check scope restrictions
        if configured_scope == ScanScope.INBOX_ONLY.value:
            if any(folder.upper() != "INBOX" for folder in requested_folders):
                return {
                    "permitted": False,
                    "reason": "Only inbox scanning is permitted",
                    "limitations": {"allowed_folders": ["INBOX"]}
                }
        
        # Check excluded folders
        excluded_folders = permissions.get("excluded_folders", [])
        if any(folder in excluded_folders for folder in requested_folders):
            return {
                "permitted": False,
                "reason": "Requested folder is excluded from scanning",
                "limitations": {"excluded_folders": excluded_folders}
            }
        
        return {"permitted": True}

    def _get_scan_limitations_from_permissions(self, permissions: Dict[str, Any]) -> Dict[str, Any]:
        """Get scan limitations based on permissions."""
        
        return {
            "max_scans_per_hour": permissions.get("max_scans_per_hour", 10),
            "max_scans_per_day": permissions.get("max_scans_per_day", 50),
            "allowed_folders": permissions.get("included_folders", ["INBOX"]),
            "excluded_folders": permissions.get("excluded_folders", []),
            "batch_size_limit": permissions.get("batch_size_limit", 100),
            "historical_limit_days": permissions.get("historical_scan_limit_days", 30)
        }

    async def _update_rate_limiting_counters(self, user_id: str, scan_execution: Dict[str, Any]) -> None:
        """Update rate limiting counters."""
        
        try:
            now = datetime.utcnow()
            hour_key = f"scan_rate_hour:{user_id}:{now.strftime('%Y%m%d%H')}"
            day_key = f"scan_rate_day:{user_id}:{now.strftime('%Y%m%d')}"
            
            # Increment hourly counter
            await self.redis_client.incr(hour_key)
            await self.redis_client.expire(hour_key, 3600)  # 1 hour
            
            # Increment daily counter
            await self.redis_client.incr(day_key)
            await self.redis_client.expire(day_key, 86400)  # 24 hours
            
        except Exception as e:
            logger.error(f"Failed to update rate limiting counters: {str(e)}")

    async def _get_rate_limit_status(self, user_id: str) -> Dict[str, Any]:
        """Get current rate limiting status."""
        
        try:
            now = datetime.utcnow()
            hour_key = f"scan_rate_hour:{user_id}:{now.strftime('%Y%m%d%H')}"
            day_key = f"scan_rate_day:{user_id}:{now.strftime('%Y%m%d')}"
            
            hour_count = await self.redis_client.get(hour_key) or 0
            day_count = await self.redis_client.get(day_key) or 0
            
            return {
                "scans_this_hour": int(hour_count),
                "scans_today": int(day_count),
                "hour_limit": 10,  # Default, should come from permissions
                "day_limit": 50,   # Default, should come from permissions
                "hour_remaining": max(0, 10 - int(hour_count)),
                "day_remaining": max(0, 50 - int(day_count)),
                "rate_limited": int(hour_count) >= 10 or int(day_count) >= 50
            }
            
        except Exception as e:
            logger.error(f"Failed to get rate limit status: {str(e)}")
            return {"error": str(e)}

    async def _get_recent_scan_activity(self, user_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scan activity for user."""
        
        try:
            # Get recent scan execution keys
            pattern = f"scan_execution:{user_id}:*"
            keys = await self.redis_client.keys(pattern)
            
            recent_scans = []
            for key in keys[:limit]:
                scan_data = await self.redis_client.get(key)
                if scan_data:
                    recent_scans.append(json.loads(scan_data))
            
            # Sort by execution time
            recent_scans.sort(key=lambda x: x.get("executed_at", ""), reverse=True)
            
            return recent_scans[:limit]
            
        except Exception as e:
            logger.error(f"Failed to get recent scan activity: {str(e)}")
            return []

    def _get_permission_recommendations(self, permissions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get recommendations for improving scan permissions."""
        
        recommendations = []
        perms = permissions["permissions"]
        
        if not perms.get("automatic_scan_enabled", False):
            recommendations.append({
                "type": "enable_feature",
                "feature": "automatic_scan",
                "title": "Enable Automatic Scanning",
                "description": "Set up regular automatic scans for continuous protection",
                "impact": "Improved threat detection without manual intervention"
            })
        
        if not perms.get("real_time_monitoring", False):
            recommendations.append({
                "type": "enable_feature",
                "feature": "real_time_monitoring",
                "title": "Enable Real-Time Monitoring",
                "description": "Monitor new emails as they arrive for immediate threat detection",
                "impact": "Fastest possible threat detection and response"
            })
        
        if perms.get("scan_scope") == ScanScope.INBOX_ONLY.value:
            recommendations.append({
                "type": "expand_scope",
                "feature": "scan_scope",
                "title": "Expand Scan Scope",
                "description": "Include additional folders like Sent Items for comprehensive protection",
                "impact": "More complete email security coverage"
            })
        
        return recommendations

    async def _log_permission_event(self,
                                  db,
                                  consent_id: int,
                                  event_type: str,
                                  event_details: Dict[str, Any],
                                  request_context: Dict[str, Any]) -> None:
        """Log permission-related events."""
        
        try:
            audit_log = ConsentAuditLog(
                user_consent_id=consent_id,
                event_type=event_type,
                event_details=event_details,
                ip_address=request_context.get("ip_address"),
                user_agent=request_context.get("user_agent"),
                request_id=request_context.get("request_id")
            )
            db.add(audit_log)
            
        except Exception as e:
            logger.error(f"Failed to log permission event: {str(e)}")

    async def _log_permission_check(self,
                                  user_id: str,
                                  scan_type: ScanPermissionType,
                                  scan_trigger: ScanTrigger,
                                  permission_result: Dict[str, Any]) -> None:
        """Log permission checks for audit."""
        
        try:
            log_entry = {
                "user_id": user_id,
                "scan_type": scan_type.value,
                "scan_trigger": scan_trigger.value,
                "permission_granted": permission_result["permission_granted"],
                "check_timestamp": datetime.utcnow().isoformat(),
                "result": permission_result
            }
            
            log_key = f"permission_check_log:{user_id}:{int(datetime.utcnow().timestamp())}"
            await self.redis_client.setex(log_key, 86400, json.dumps(log_entry))  # 24 hours
            
        except Exception as e:
            logger.error(f"Failed to log permission check: {str(e)}")

    def _get_required_permissions(self, scan_type: ScanPermissionType, scan_trigger: ScanTrigger) -> List[str]:
        """Get list of required permissions for scan type/trigger."""
        
        required = []
        
        if scan_type == ScanPermissionType.AUTOMATIC_SCAN:
            required.append("automatic_scan_enabled")
        elif scan_type == ScanPermissionType.REAL_TIME_MONITORING:
            required.append("real_time_monitoring")
        elif scan_type == ScanPermissionType.HISTORICAL_SCAN:
            required.append("allow_historical_scan")
        
        required.append(f"allow_trigger_{scan_trigger.value}")
        
        return required

    def _get_alternative_actions(self, scan_type: ScanPermissionType, permission_check: Dict[str, Any]) -> List[str]:
        """Get alternative actions when permission is denied."""
        
        alternatives = []
        
        if scan_type == ScanPermissionType.AUTOMATIC_SCAN:
            alternatives.extend([
                "Use manual scan instead",
                "Configure scan permissions in settings",
                "Enable automatic scanning with consent"
            ])
        elif scan_type == ScanPermissionType.HISTORICAL_SCAN:
            alternatives.extend([
                "Scan recent emails only",
                "Enable historical scanning in preferences",
                "Use batch analysis for specific folders"
            ])
        
        alternatives.append("Review and update consent preferences")
        
        return alternatives

    def _get_scan_limitations(self, user_id: str, scan_request: Dict[str, Any]) -> Dict[str, Any]:
        """Get scan limitations for specific request."""
        
        return {
            "rate_limiting": "Subject to hourly and daily scan limits",
            "scope_restrictions": "May be limited to specific folders or labels",
            "data_processing": "Subject to data processing consent settings",
            "retention": "Results retained according to retention policy",
            "privacy": "Processing respects opt-out preferences"
        }


# Global service instance
_scan_permission_service = None

def get_scan_permission_service() -> ScanPermissionService:
    """Get global scan permission service instance."""
    global _scan_permission_service
    if _scan_permission_service is None:
        _scan_permission_service = ScanPermissionService()
    return _scan_permission_service