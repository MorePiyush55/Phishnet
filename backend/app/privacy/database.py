"""
Database operations for privacy compliance.
Handles CRUD operations for consent, audit logs, and data subject requests.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from backend.app.privacy.models import (
    ConsentRecord,
    DataSubjectRequest,
    AuditLog,
    EncryptedToken,
    PrivacySettings,
    DataProcessingLog,
    ComplianceReport
)
from backend.app.privacy import ConsentType, PrivacyRightType, DataRetentionPeriod
from backend.app.observability import get_logger, trace_function

logger = get_logger(__name__)

class PrivacyDatabaseManager:
    """Database manager for privacy compliance operations."""
    
    @trace_function("privacy.db.store_consent")
    async def store_consent_record(self, consent_record) -> ConsentRecord:
        """Store a consent record in the database."""
        db_record = ConsentRecord(
            user_id=consent_record.user_id,
            consent_type=consent_record.consent_type,
            granted=consent_record.granted,
            timestamp=consent_record.timestamp,
            ip_address=consent_record.ip_address,
            user_agent=consent_record.user_agent,
            privacy_policy_version=consent_record.version
        )
        
        await db_record.create()
        
        logger.info(
            "Consent record stored",
            user_id=consent_record.user_id,
            consent_type=consent_record.consent_type.value,
            granted=consent_record.granted
        )
        
        return db_record
    
    @trace_function("privacy.db.get_consents")
    async def get_consent_records(self, user_id: str) -> List[ConsentRecord]:
        """Get all consent records for a user."""
        records = await ConsentRecord.find(
            ConsentRecord.user_id == user_id
        ).sort(-ConsentRecord.timestamp).to_list()
        
        return records
    
    @trace_function("privacy.db.store_rights_request")
    async def store_data_subject_request(self, request) -> DataSubjectRequest:
        """Store a data subject rights request."""
        db_request = DataSubjectRequest(
            request_id=request.request_id,
            user_id=request.user_id,
            request_type=request.request_type,
            timestamp=request.timestamp,
            status=request.status,
            description=request.description,
            requested_data_types=request.requested_data_types,
            completion_deadline=request.completion_deadline
        )
        
        await db_request.create()
        
        logger.info(
            "Data subject request stored",
            request_id=request.request_id,
            user_id=request.user_id,
            request_type=request.request_type.value
        )
        
        return db_request
    
    @trace_function("privacy.db.update_request_status")
    async def update_request_status(
        self,
        request_id: str,
        status: str,
        rejection_reason: Optional[str] = None
    ):
        """Update the status of a data subject request."""
        request = await DataSubjectRequest.find_one(
            DataSubjectRequest.request_id == request_id
        )
        
        if not request:
            raise ValueError(f"Request {request_id} not found")
        
        request.status = status
        if status == "completed":
            request.completed_at = datetime.utcnow()
        elif status == "rejected" and rejection_reason:
            request.rejection_reason = rejection_reason
        
        await request.save()
        
        logger.info(
            "Request status updated",
            request_id=request_id,
            new_status=status,
            rejection_reason=rejection_reason
        )
    
    @trace_function("privacy.db.store_audit_log")
    async def store_audit_log(self, audit_entry: Dict[str, Any]) -> AuditLog:
        """Store an audit log entry."""
        log_entry = AuditLog(**audit_entry)
        await log_entry.create()
        
        logger.debug(
            "Audit log stored",
            event_id=audit_entry["event_id"],
            event_type=audit_entry.get("event_type", "general")
        )
        
        return log_entry
    
    @trace_function("privacy.db.get_audit_logs")
    async def get_audit_logs(
        self,
        start_date: datetime,
        end_date: datetime,
        user_id: Optional[str] = None
    ) -> List[AuditLog]:
        """Get audit logs for a date range and optionally a specific user."""
        query = AuditLog.timestamp >= start_date, AuditLog.timestamp <= end_date
        
        if user_id:
            query = (*query, AuditLog.user_id == user_id)
        
        logs = await AuditLog.find(*query).sort(-AuditLog.timestamp).to_list()
        return logs
    
    @trace_function("privacy.db.get_user_audit_logs")
    async def get_user_audit_logs(self, user_id: str, limit: int = 100) -> List[AuditLog]:
        """Get audit logs for a specific user."""
        logs = await AuditLog.find(
            AuditLog.user_id == user_id
        ).sort(-AuditLog.timestamp).limit(limit).to_list()
        
        return logs
    
    @trace_function("privacy.db.store_encrypted_token")
    async def store_encrypted_token(
        self,
        user_id: str,
        token_type: str,
        encrypted_token: str,
        provider: str,
        expires_at: Optional[datetime] = None,
        scope: Optional[str] = None
    ) -> EncryptedToken:
        """Store an encrypted OAuth token."""
        # Remove existing token of same type for user/provider
        await EncryptedToken.find(
            EncryptedToken.user_id == user_id,
            EncryptedToken.provider == provider,
            EncryptedToken.token_type == token_type
        ).delete()
        
        token = EncryptedToken(
            user_id=user_id,
            token_type=token_type,
            encrypted_token=encrypted_token,
            provider=provider,
            expires_at=expires_at,
            scope=scope
        )
        
        await token.create()
        
        logger.info(
            "Encrypted token stored",
            user_id=user_id,
            provider=provider,
            token_type=token_type
        )
        
        return token
    
    @trace_function("privacy.db.get_encrypted_token")
    async def get_encrypted_token(
        self,
        user_id: str,
        provider: str,
        token_type: str
    ) -> Optional[EncryptedToken]:
        """Get an encrypted token for a user."""
        token = await EncryptedToken.find_one(
            EncryptedToken.user_id == user_id,
            EncryptedToken.provider == provider,
            EncryptedToken.token_type == token_type
        )
        
        # Update last used timestamp
        if token:
            token.last_used = datetime.utcnow()
            await token.save()
        
        return token
    
    @trace_function("privacy.db.delete_user_tokens")
    async def delete_user_oauth_tokens(self, user_id: str):
        """Delete all OAuth tokens for a user (for data erasure)."""
        result = await EncryptedToken.find(
            EncryptedToken.user_id == user_id
        ).delete()
        
        logger.info(
            "User OAuth tokens deleted",
            user_id=user_id,
            deleted_count=result.deleted_count if result else 0
        )
    
    @trace_function("privacy.db.get_privacy_settings")
    async def get_privacy_settings(self, user_id: str) -> Optional[PrivacySettings]:
        """Get privacy settings for a user."""
        return await PrivacySettings.find_one(PrivacySettings.user_id == user_id)
    
    @trace_function("privacy.db.update_privacy_settings")
    async def update_privacy_settings(self, user_id: str, settings: Dict[str, Any]) -> PrivacySettings:
        """Update privacy settings for a user."""
        privacy_settings = await self.get_privacy_settings(user_id)
        
        if not privacy_settings:
            privacy_settings = PrivacySettings(user_id=user_id)
        
        # Update settings
        for key, value in settings.items():
            if hasattr(privacy_settings, key):
                setattr(privacy_settings, key, value)
        
        privacy_settings.last_updated = datetime.utcnow()
        await privacy_settings.save()
        
        logger.info(
            "Privacy settings updated",
            user_id=user_id,
            updated_fields=list(settings.keys())
        )
        
        return privacy_settings
    
    @trace_function("privacy.db.log_data_processing")
    async def log_data_processing(
        self,
        user_id: str,
        activity: str,
        purpose: str,
        legal_basis: str,
        data_categories: List[str],
        retention_period: DataRetentionPeriod,
        automated: bool = True
    ) -> DataProcessingLog:
        """Log data processing activity."""
        log_entry = DataProcessingLog(
            user_id=user_id,
            processing_activity=activity,
            purpose=purpose,
            legal_basis=legal_basis,
            data_categories=data_categories,
            retention_period=retention_period,
            automated_processing=automated
        )
        
        await log_entry.create()
        
        logger.info(
            "Data processing logged",
            user_id=user_id,
            activity=activity,
            legal_basis=legal_basis
        )
        
        return log_entry
    
    @trace_function("privacy.db.delete_expired_data")
    async def delete_expired_data(self, data_type: str, cutoff_date: datetime) -> int:
        """Delete expired data based on retention policies."""
        deleted_count = 0
        
        if data_type == "consent_records":
            # Don't delete consent records - they have legal retention requirements
            pass
        elif data_type == "audit_logs":
            # Don't delete audit logs - they have legal retention requirements  
            pass
        elif data_type == "encrypted_tokens":
            result = await EncryptedToken.find(
                EncryptedToken.created_at < cutoff_date
            ).delete()
            deleted_count = result.deleted_count if result else 0
        elif data_type == "data_processing_logs":
            result = await DataProcessingLog.find(
                DataProcessingLog.timestamp < cutoff_date
            ).delete()
            deleted_count = result.deleted_count if result else 0
        
        if deleted_count > 0:
            logger.info(
                "Expired data deleted",
                data_type=data_type,
                cutoff_date=cutoff_date.isoformat(),
                deleted_count=deleted_count
            )
        
        return deleted_count
    
    @trace_function("privacy.db.get_user_data_summary")
    async def get_user_data_summary(self, user_id: str) -> Dict[str, Any]:
        """Get summary of all user data for export/analysis."""
        summary = {
            "user_id": user_id,
            "data_summary": {
                "consent_records": await ConsentRecord.find(
                    ConsentRecord.user_id == user_id
                ).count(),
                "data_subject_requests": await DataSubjectRequest.find(
                    DataSubjectRequest.user_id == user_id
                ).count(),
                "audit_logs": await AuditLog.find(
                    AuditLog.user_id == user_id
                ).count(),
                "oauth_tokens": await EncryptedToken.find(
                    EncryptedToken.user_id == user_id
                ).count(),
                "processing_logs": await DataProcessingLog.find(
                    DataProcessingLog.user_id == user_id
                ).count()
            },
            "privacy_settings": await self.get_privacy_settings(user_id)
        }
        
        return summary
    
    @trace_function("privacy.db.delete_all_user_data")
    async def delete_all_user_data(self, user_id: str) -> Dict[str, int]:
        """Delete all user data (for right to erasure)."""
        deletion_summary = {}
        
        # Delete user data (keep consent withdrawal records and audit logs for legal compliance)
        
        # Delete OAuth tokens
        token_result = await EncryptedToken.find(
            EncryptedToken.user_id == user_id
        ).delete()
        deletion_summary["oauth_tokens"] = token_result.deleted_count if token_result else 0
        
        # Delete privacy settings
        settings_result = await PrivacySettings.find(
            PrivacySettings.user_id == user_id
        ).delete()
        deletion_summary["privacy_settings"] = settings_result.deleted_count if settings_result else 0
        
        # Delete processing logs older than legal requirement
        processing_cutoff = datetime.utcnow() - timedelta(days=365)  # Keep 1 year for legal
        processing_result = await DataProcessingLog.find(
            DataProcessingLog.user_id == user_id,
            DataProcessingLog.timestamp < processing_cutoff
        ).delete()
        deletion_summary["processing_logs"] = processing_result.deleted_count if processing_result else 0
        
        logger.warning(
            "User data deleted",
            user_id=user_id,
            deletion_summary=deletion_summary
        )
        
        return deletion_summary
    
    @trace_function("privacy.db.generate_compliance_report")
    async def generate_compliance_report(
        self,
        report_type: str,
        period_start: datetime,
        period_end: datetime,
        generated_by: str
    ) -> ComplianceReport:
        """Generate a compliance report."""
        # Collect data for report
        consent_count = await ConsentRecord.find(
            ConsentRecord.timestamp >= period_start,
            ConsentRecord.timestamp <= period_end
        ).count()
        
        rights_requests_count = await DataSubjectRequest.find(
            DataSubjectRequest.timestamp >= period_start,
            DataSubjectRequest.timestamp <= period_end
        ).count()
        
        audit_events_count = await AuditLog.find(
            AuditLog.timestamp >= period_start,
            AuditLog.timestamp <= period_end
        ).count()
        
        report_data = {
            "consent_records": consent_count,
            "rights_requests": rights_requests_count,
            "audit_events": audit_events_count,
            "period_days": (period_end - period_start).days
        }
        
        # Create report
        report = ComplianceReport(
            report_id=f"{report_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            report_type=report_type,
            period_start=period_start,
            period_end=period_end,
            generated_by=generated_by,
            report_data=report_data,
            compliance_status="compliant"  # Would have actual compliance analysis
        )
        
        await report.create()
        
        logger.info(
            "Compliance report generated",
            report_id=report.report_id,
            report_type=report_type
        )
        
        return report

# Global instance
privacy_db = PrivacyDatabaseManager()