"""GDPR compliance and privacy management system."""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import traceback

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db
from app.core.redis_client import redis_client
from app.models.email_scan import (
    EmailScanRequest, ThreatResult, AuditLog, UserConsent, DataRetention
)
from app.models.user import User, OAuthToken
from app.services.gmail_secure import gmail_service
from app.services.websocket_manager import websocket_manager

logger = get_logger(__name__)


class GDPRComplianceManager:
    """Manages GDPR compliance and data privacy."""
    
    def __init__(self):
        """Initialize GDPR compliance manager."""
        self.default_retention_periods = {
            "email_metadata": 365,  # 1 year
            "scan_results": 365,    # 1 year
            "oauth_tokens": 90,     # 3 months
            "audit_logs": 2555,     # 7 years (legal requirement)
            "threat_results": 365   # 1 year
        }
    
    async def handle_consent_granted(
        self,
        user_id: int,
        consent_type: str,
        scopes: List[str],
        purposes: List[str],
        ip_address: str = None,
        user_agent: str = None
    ) -> bool:
        """Handle user consent being granted."""
        try:
            async with get_db() as db:
                # Create or update consent record
                existing_consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id,
                    UserConsent.consent_type == consent_type
                ).first()
                
                if existing_consent:
                    # Update existing consent
                    existing_consent.granted = True
                    existing_consent.scopes = scopes
                    existing_consent.purposes = purposes
                    existing_consent.granted_at = datetime.utcnow()
                    existing_consent.revoked_at = None
                    existing_consent.ip_address = ip_address
                    existing_consent.user_agent = user_agent
                    consent = existing_consent
                else:
                    # Create new consent record
                    consent = UserConsent(
                        user_id=user_id,
                        consent_type=consent_type,
                        granted=True,
                        scopes=scopes,
                        purposes=purposes,
                        consent_version="1.0",
                        ip_address=ip_address,
                        user_agent=user_agent,
                        retention_period_days=self.default_retention_periods.get("email_metadata", 365)
                    )
                    db.add(consent)
                
                # Create audit log
                audit = AuditLog(
                    user_id=user_id,
                    action="consent_granted",
                    resource_type="user_consent",
                    resource_id=consent_type,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={
                        "consent_type": consent_type,
                        "scopes": scopes,
                        "purposes": purposes,
                        "consent_version": "1.0"
                    },
                    legal_basis="consent",
                    data_processed=["consent_data", "oauth_tokens"]
                )
                db.add(audit)
                
                # Schedule data retention
                await self._schedule_data_retention(user_id, consent.retention_period_days)
                
                db.commit()
                
                logger.info(f"Consent granted for user {user_id}: {consent_type}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to handle consent granted for user {user_id}: {e}")
            return False
    
    async def handle_consent_revoked(
        self,
        user_id: int,
        consent_type: str,
        ip_address: str = None,
        user_agent: str = None
    ) -> bool:
        """Handle user consent being revoked."""
        try:
            async with get_db() as db:
                # Update consent record
                consent = db.query(UserConsent).filter(
                    UserConsent.user_id == user_id,
                    UserConsent.consent_type == consent_type
                ).first()
                
                if consent:
                    consent.granted = False
                    consent.revoked_at = datetime.utcnow()
                
                # Create audit log
                audit = AuditLog(
                    user_id=user_id,
                    action="consent_revoked",
                    resource_type="user_consent",
                    resource_id=consent_type,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={
                        "consent_type": consent_type,
                        "revoked_reason": "user_request"
                    },
                    legal_basis="consent_withdrawal"
                )
                db.add(audit)
                
                db.commit()
                
                # Trigger immediate data cleanup if required
                if consent_type == "gmail_scanning":
                    await self._cleanup_user_data(user_id, "consent_revoked")
                
                logger.info(f"Consent revoked for user {user_id}: {consent_type}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to handle consent revoked for user {user_id}: {e}")
            return False
    
    async def handle_data_deletion_request(
        self,
        user_id: int,
        deletion_type: str = "complete",  # "complete", "partial", "specific"
        specific_data_types: List[str] = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> Dict[str, Any]:
        """Handle user data deletion request (Right to Erasure)."""
        try:
            logger.info(f"Processing data deletion request for user {user_id}: {deletion_type}")
            
            deletion_summary = {
                "user_id": user_id,
                "deletion_type": deletion_type,
                "requested_at": datetime.utcnow().isoformat(),
                "data_types_deleted": [],
                "records_deleted": {},
                "success": False
            }
            
            async with get_db() as db:
                # Create audit log for deletion request
                audit = AuditLog(
                    user_id=user_id,
                    action="data_deletion_requested",
                    resource_type="user_data",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={
                        "deletion_type": deletion_type,
                        "specific_data_types": specific_data_types
                    },
                    legal_basis="right_to_erasure"
                )
                db.add(audit)
                db.commit()
            
            # Determine what data to delete
            if deletion_type == "complete":
                data_types_to_delete = [
                    "email_scan_requests", "threat_results", "oauth_tokens", 
                    "user_consents", "analysis_component_results"
                ]
            elif deletion_type == "partial":
                data_types_to_delete = specific_data_types or []
            else:
                data_types_to_delete = specific_data_types or []
            
            # Execute deletions
            for data_type in data_types_to_delete:
                try:
                    deleted_count = await self._delete_user_data_type(user_id, data_type)
                    deletion_summary["records_deleted"][data_type] = deleted_count
                    deletion_summary["data_types_deleted"].append(data_type)
                    logger.info(f"Deleted {deleted_count} records of type {data_type} for user {user_id}")
                except Exception as e:
                    logger.error(f"Failed to delete {data_type} for user {user_id}: {e}")
                    deletion_summary["records_deleted"][data_type] = f"Error: {str(e)}"
            
            # Revoke OAuth tokens
            if "oauth_tokens" in data_types_to_delete:
                await gmail_service.revoke_access(user_id, ip_address)
            
            # Create completion audit log
            async with get_db() as db:
                completion_audit = AuditLog(
                    user_id=user_id,
                    action="data_deletion_completed",
                    resource_type="user_data",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details=deletion_summary,
                    legal_basis="right_to_erasure"
                )
                db.add(completion_audit)
                db.commit()
            
            deletion_summary["success"] = True
            deletion_summary["completed_at"] = datetime.utcnow().isoformat()
            
            # Send notification
            await websocket_manager.send_system_notification(
                user_id,
                "data_deletion",
                "Data Deletion Completed",
                f"Your data deletion request has been processed. {len(deletion_summary['data_types_deleted'])} data types were removed.",
                "info"
            )
            
            logger.info(f"Data deletion completed for user {user_id}")
            return deletion_summary
            
        except Exception as e:
            logger.error(f"Data deletion failed for user {user_id}: {e}")
            logger.error(traceback.format_exc())
            
            return {
                "user_id": user_id,
                "success": False,
                "error": str(e),
                "requested_at": datetime.utcnow().isoformat()
            }
    
    async def _delete_user_data_type(self, user_id: int, data_type: str) -> int:
        """Delete specific data type for user."""
        deleted_count = 0
        
        try:
            async with get_db() as db:
                if data_type == "email_scan_requests":
                    records = db.query(EmailScanRequest).filter(EmailScanRequest.user_id == user_id).all()
                    for record in records:
                        db.delete(record)
                    deleted_count = len(records)
                
                elif data_type == "threat_results":
                    # Get threat results through scan requests
                    scan_requests = db.query(EmailScanRequest).filter(EmailScanRequest.user_id == user_id).all()
                    for scan_request in scan_requests:
                        if scan_request.threat_result:
                            db.delete(scan_request.threat_result)
                            deleted_count += 1
                
                elif data_type == "oauth_tokens":
                    records = db.query(OAuthToken).filter(OAuthToken.user_id == user_id).all()
                    for record in records:
                        db.delete(record)
                    deleted_count = len(records)
                
                elif data_type == "user_consents":
                    records = db.query(UserConsent).filter(UserConsent.user_id == user_id).all()
                    for record in records:
                        db.delete(record)
                    deleted_count = len(records)
                
                # Don't delete audit logs - legal requirement to keep them
                
                db.commit()
                
        except Exception as e:
            logger.error(f"Failed to delete {data_type} for user {user_id}: {e}")
            raise
        
        return deleted_count
    
    async def _cleanup_user_data(self, user_id: int, reason: str):
        """Cleanup user data when consent is revoked."""
        try:
            logger.info(f"Cleaning up data for user {user_id}, reason: {reason}")
            
            # Clear OAuth credentials
            await gmail_service.revoke_access(user_id)
            
            # Clear Redis data
            await redis_client.delete(f"gmail_watch:{user_id}")
            await redis_client.delete(f"oauth_csrf:{user_id}")
            
            # Mark future data for deletion
            await self._schedule_immediate_deletion(user_id, reason)
            
            logger.info(f"Data cleanup completed for user {user_id}")
            
        except Exception as e:
            logger.error(f"Data cleanup failed for user {user_id}: {e}")
    
    async def _schedule_data_retention(self, user_id: int, retention_period_days: int):
        """Schedule data for deletion based on retention policy."""
        try:
            deletion_date = datetime.utcnow() + timedelta(days=retention_period_days)
            
            async with get_db() as db:
                for data_type, default_retention in self.default_retention_periods.items():
                    # Skip audit logs - they have longer retention
                    if data_type == "audit_logs":
                        continue
                    
                    retention_record = DataRetention(
                        user_id=user_id,
                        data_type=data_type,
                        retention_period_days=retention_period_days,
                        scheduled_deletion_date=deletion_date,
                        records_scheduled=0  # Will be calculated later
                    )
                    
                    db.add(retention_record)
                
                db.commit()
            
            logger.info(f"Scheduled data retention for user {user_id}, deletion date: {deletion_date}")
            
        except Exception as e:
            logger.error(f"Failed to schedule data retention for user {user_id}: {e}")
    
    async def _schedule_immediate_deletion(self, user_id: int, reason: str):
        """Schedule immediate data deletion."""
        try:
            deletion_date = datetime.utcnow() + timedelta(hours=1)  # 1 hour grace period
            
            async with get_db() as db:
                retention_record = DataRetention(
                    user_id=user_id,
                    data_type="all_user_data",
                    retention_period_days=0,
                    scheduled_deletion_date=deletion_date,
                    notes=f"Immediate deletion due to: {reason}"
                )
                
                db.add(retention_record)
                db.commit()
            
            logger.info(f"Scheduled immediate deletion for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to schedule immediate deletion for user {user_id}: {e}")
    
    async def export_user_data(
        self,
        user_id: int,
        ip_address: str = None
    ) -> Dict[str, Any]:
        """Export user data (Right to Data Portability)."""
        try:
            logger.info(f"Exporting data for user {user_id}")
            
            export_data = {
                "user_id": user_id,
                "export_requested_at": datetime.utcnow().isoformat(),
                "data": {}
            }
            
            async with get_db() as db:
                # User information
                user = db.query(User).filter(User.id == user_id).first()
                if user:
                    export_data["data"]["user_profile"] = {
                        "email": user.email,
                        "username": user.username,
                        "full_name": user.full_name,
                        "created_at": user.created_at.isoformat() if user.created_at else None,
                        "email_monitoring_enabled": user.email_monitoring_enabled
                    }
                
                # Consent records
                consents = db.query(UserConsent).filter(UserConsent.user_id == user_id).all()
                export_data["data"]["consents"] = [
                    {
                        "consent_type": consent.consent_type,
                        "granted": consent.granted,
                        "granted_at": consent.granted_at.isoformat() if consent.granted_at else None,
                        "scopes": consent.scopes,
                        "purposes": consent.purposes
                    }
                    for consent in consents
                ]
                
                # Email scan history (metadata only)
                scan_requests = db.query(EmailScanRequest).filter(
                    EmailScanRequest.user_id == user_id
                ).order_by(EmailScanRequest.created_at.desc()).limit(100).all()
                
                export_data["data"]["email_scans"] = [
                    {
                        "scan_id": str(scan.id),
                        "status": scan.status,
                        "created_at": scan.created_at.isoformat() if scan.created_at else None,
                        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                        "sender_domain": scan.sender_domain,
                        "threat_level": scan.threat_result.threat_level if scan.threat_result else None,
                        "threat_score": scan.threat_result.threat_score if scan.threat_result else None
                    }
                    for scan in scan_requests
                ]
                
                # Audit logs (limited)
                audit_logs = db.query(AuditLog).filter(
                    AuditLog.user_id == user_id
                ).order_by(AuditLog.timestamp.desc()).limit(50).all()
                
                export_data["data"]["activity_log"] = [
                    {
                        "action": log.action,
                        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                        "success": log.success,
                        "resource_type": log.resource_type
                    }
                    for log in audit_logs
                ]
                
                # Create audit log for export
                export_audit = AuditLog(
                    user_id=user_id,
                    action="data_export_requested",
                    resource_type="user_data",
                    ip_address=ip_address,
                    details={
                        "export_size": len(str(export_data)),
                        "data_types_exported": list(export_data["data"].keys())
                    },
                    legal_basis="data_portability"
                )
                db.add(export_audit)
                db.commit()
            
            export_data["export_completed_at"] = datetime.utcnow().isoformat()
            
            logger.info(f"Data export completed for user {user_id}")
            return export_data
            
        except Exception as e:
            logger.error(f"Data export failed for user {user_id}: {e}")
            return {
                "user_id": user_id,
                "error": str(e),
                "export_requested_at": datetime.utcnow().isoformat()
            }
    
    async def run_retention_cleanup(self):
        """Run scheduled data retention cleanup."""
        try:
            logger.info("Running scheduled data retention cleanup")
            
            async with get_db() as db:
                # Get retention records ready for deletion
                overdue_retentions = db.query(DataRetention).filter(
                    DataRetention.scheduled_deletion_date <= datetime.utcnow(),
                    DataRetention.deleted_at.is_(None)
                ).all()
                
                for retention in overdue_retentions:
                    try:
                        # Execute deletion
                        if retention.data_type == "all_user_data":
                            # Complete user data deletion
                            result = await self.handle_data_deletion_request(
                                retention.user_id, 
                                "complete"
                            )
                            deleted_count = sum(
                                v for v in result.get("records_deleted", {}).values()
                                if isinstance(v, int)
                            )
                        else:
                            # Specific data type deletion
                            deleted_count = await self._delete_user_data_type(
                                retention.user_id, 
                                retention.data_type
                            )
                        
                        # Update retention record
                        retention.deleted_at = datetime.utcnow()
                        retention.records_deleted = deleted_count
                        retention.deletion_method = "automated"
                        
                        logger.info(f"Retention cleanup: deleted {deleted_count} records of type {retention.data_type} for user {retention.user_id}")
                        
                    except Exception as e:
                        logger.error(f"Retention cleanup failed for {retention.id}: {e}")
                
                db.commit()
                
                logger.info(f"Retention cleanup completed, processed {len(overdue_retentions)} retention records")
                
        except Exception as e:
            logger.error(f"Retention cleanup failed: {e}")


# Global GDPR compliance manager
gdpr_manager = GDPRComplianceManager()


async def start_retention_scheduler():
    """Start the data retention scheduler."""
    logger.info("Starting data retention scheduler")
    
    while True:
        try:
            await gdpr_manager.run_retention_cleanup()
            await asyncio.sleep(86400)  # Run daily
        except Exception as e:
            logger.error(f"Retention scheduler error: {e}")
            await asyncio.sleep(3600)  # Wait 1 hour on error


if __name__ == "__main__":
    asyncio.run(start_retention_scheduler())
