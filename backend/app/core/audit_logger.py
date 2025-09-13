"""
Comprehensive Audit Trail System
Logs every action with request IDs and proper retention for compliance.
"""

import logging
import json
import uuid
import asyncio
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from contextlib import contextmanager
from sqlalchemy import Column, String, DateTime, Text, Integer, Boolean, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.encryption import EncryptedAudit, get_encryption_manager
from app.core.redis_client import get_redis_client
from app.core.config import get_settings

logger = logging.getLogger(__name__)

class AuditEventType(Enum):
    """Types of audit events"""
    # Scan events
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"
    
    # Analysis events
    URL_ANALYZED = "url_analyzed"
    EMAIL_ANALYZED = "email_analyzed"
    REDIRECT_TRACED = "redirect_traced"
    THREAT_DETECTED = "threat_detected"
    
    # User actions
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_VIEW_RESULTS = "user_view_results"
    USER_EXPORT_DATA = "user_export_data"
    USER_DELETE_DATA = "user_delete_data"
    
    # Consent events
    CONSENT_GRANTED = "consent_granted"
    CONSENT_UPDATED = "consent_updated"
    CONSENT_REVOKED = "consent_revoked"
    
    # Email actions
    EMAIL_QUARANTINED = "email_quarantined"
    EMAIL_RESTORED = "email_restored"
    EMAIL_LABELED = "email_labeled"
    
    # API events
    API_CALL_MADE = "api_call_made"
    API_QUOTA_EXCEEDED = "api_quota_exceeded"
    API_ERROR = "api_error"
    
    # Security events
    IP_BLOCKED = "ip_blocked"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    
    # Data events
    DATA_ENCRYPTED = "data_encrypted"
    DATA_DECRYPTED = "data_decrypted"
    DATA_SANITIZED = "data_sanitized"
    DATA_EXPIRED = "data_expired"
    DATA_CLEANUP = "data_cleanup"

class AuditSeverity(Enum):
    """Audit event severity levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class AuditContext:
    """Context for audit events"""
    request_id: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    source: Optional[str] = None  # web, api, background_task, etc.
    correlation_id: Optional[str] = None

@dataclass
class AuditEvent:
    """Audit event data structure"""
    event_type: AuditEventType
    severity: AuditSeverity
    message: str
    context: AuditContext
    details: Dict[str, Any]
    timestamp: datetime
    event_id: str
    duration_ms: Optional[int] = None
    result: Optional[str] = None  # success, failure, partial
    affected_resources: Optional[List[str]] = None

# Database model for audit logs
Base = declarative_base()

class AuditLog(Base):
    """Database model for audit logs"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(36), unique=True, index=True)
    event_type = Column(String(50), index=True)
    severity = Column(String(20), index=True)
    message = Column(Text)
    
    # Context fields (some encrypted)
    request_id = Column(String(36), index=True)
    user_id = Column(String(255), index=True)
    session_id = Column(EncryptedAudit)
    ip_address = Column(EncryptedAudit)
    user_agent = Column(EncryptedAudit)
    source = Column(String(50))
    correlation_id = Column(String(36), index=True)
    
    # Event details (encrypted)
    details = Column(EncryptedAudit)
    
    # Metadata
    timestamp = Column(DateTime, index=True)
    duration_ms = Column(Integer)
    result = Column(String(20))
    affected_resources = Column(Text)  # JSON array
    
    # Retention
    retention_category = Column(String(50), index=True)
    expires_at = Column(DateTime, index=True)
    
    # Indexes for efficient querying
    __table_args__ = (
        Index('idx_audit_user_time', 'user_id', 'timestamp'),
        Index('idx_audit_request_id', 'request_id'),
        Index('idx_audit_type_severity', 'event_type', 'severity'),
        Index('idx_audit_expires', 'expires_at'),
    )

class AuditLogger:
    """
    Comprehensive audit logging system with encryption and retention.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.redis_client = get_redis_client()
        self.encryption_manager = get_encryption_manager()
        
        # Retention policies by category
        self.retention_policies = {
            'security': timedelta(days=2555),  # 7 years for security events
            'compliance': timedelta(days=2555),  # 7 years for compliance
            'consent': timedelta(days=2555),  # 7 years for consent events
            'operational': timedelta(days=90),  # 90 days for operational events
            'debug': timedelta(days=7),  # 7 days for debug events
            'user_action': timedelta(days=365),  # 1 year for user actions
            'api_call': timedelta(days=30),  # 30 days for API calls
        }
        
        # Initialize current context
        self._context_stack = []
    
    def log_event(self, 
                 event_type: AuditEventType,
                 message: str,
                 severity: AuditSeverity = AuditSeverity.INFO,
                 details: Dict[str, Any] = None,
                 context: AuditContext = None,
                 duration_ms: Optional[int] = None,
                 result: Optional[str] = None,
                 affected_resources: Optional[List[str]] = None):
        """
        Log an audit event.
        
        Args:
            event_type: Type of event
            message: Human-readable message
            severity: Event severity
            details: Additional event details
            context: Audit context (uses current if not provided)
            duration_ms: Duration in milliseconds
            result: Event result (success, failure, partial)
            affected_resources: List of affected resource IDs
        """
        try:
            # Use provided context or current context
            if context is None:
                context = self.get_current_context()
            
            # Create audit event
            event = AuditEvent(
                event_type=event_type,
                severity=severity,
                message=message,
                context=context,
                details=details or {},
                timestamp=datetime.utcnow(),
                event_id=str(uuid.uuid4()),
                duration_ms=duration_ms,
                result=result,
                affected_resources=affected_resources
            )
            
            # Store in database
            self._store_audit_event(event)
            
            # Cache recent events in Redis for quick access
            self._cache_recent_event(event)
            
            # Log to standard logger for immediate visibility
            log_level = getattr(logging, severity.value.upper())
            logger.log(
                log_level,
                f"AUDIT: {event_type.value} - {message}",
                extra={
                    'event_id': event.event_id,
                    'request_id': context.request_id,
                    'user_id': context.user_id
                }
            )
            
        except Exception as e:
            # Never let audit logging break the main flow
            logger.error(f"Failed to log audit event: {e}")
    
    def _store_audit_event(self, event: AuditEvent):
        """Store audit event in database"""
        try:
            db = next(get_db())
            
            # Determine retention category
            retention_category = self._get_retention_category(event.event_type)
            expires_at = datetime.utcnow() + self.retention_policies[retention_category]
            
            # Create database record
            audit_record = AuditLog(
                event_id=event.event_id,
                event_type=event.event_type.value,
                severity=event.severity.value,
                message=event.message,
                request_id=event.context.request_id,
                user_id=event.context.user_id,
                session_id=event.context.session_id,
                ip_address=event.context.ip_address,
                user_agent=event.context.user_agent,
                source=event.context.source,
                correlation_id=event.context.correlation_id,
                details=json.dumps(event.details),
                timestamp=event.timestamp,
                duration_ms=event.duration_ms,
                result=event.result,
                affected_resources=json.dumps(event.affected_resources) if event.affected_resources else None,
                retention_category=retention_category,
                expires_at=expires_at
            )
            
            db.add(audit_record)
            db.commit()
            
        except Exception as e:
            logger.error(f"Failed to store audit event in database: {e}")
            # Try to rollback
            try:
                db.rollback()
            except:
                pass
    
    def _cache_recent_event(self, event: AuditEvent):
        """Cache recent event in Redis for quick access"""
        try:
            # Cache user's recent events
            if event.context.user_id:
                cache_key = f"audit:recent:{event.context.user_id}"
                event_data = {
                    'event_id': event.event_id,
                    'event_type': event.event_type.value,
                    'message': event.message,
                    'timestamp': event.timestamp.isoformat(),
                    'severity': event.severity.value
                }
                
                # Add to list (keep last 100 events)
                self.redis_client.lpush(cache_key, json.dumps(event_data))
                self.redis_client.ltrim(cache_key, 0, 99)
                self.redis_client.expire(cache_key, 3600)  # 1 hour TTL
            
            # Cache by request ID
            if event.context.request_id:
                request_cache_key = f"audit:request:{event.context.request_id}"
                self.redis_client.lpush(request_cache_key, event.event_id)
                self.redis_client.expire(request_cache_key, 3600)
            
        except Exception as e:
            logger.error(f"Failed to cache audit event: {e}")
    
    def _get_retention_category(self, event_type: AuditEventType) -> str:
        """Determine retention category for event type"""
        security_events = {
            AuditEventType.IP_BLOCKED,
            AuditEventType.RATE_LIMIT_EXCEEDED,
            AuditEventType.UNAUTHORIZED_ACCESS
        }
        
        compliance_events = {
            AuditEventType.CONSENT_GRANTED,
            AuditEventType.CONSENT_UPDATED,
            AuditEventType.CONSENT_REVOKED,
            AuditEventType.USER_EXPORT_DATA,
            AuditEventType.USER_DELETE_DATA
        }
        
        user_action_events = {
            AuditEventType.USER_LOGIN,
            AuditEventType.USER_LOGOUT,
            AuditEventType.USER_VIEW_RESULTS,
            AuditEventType.EMAIL_QUARANTINED,
            AuditEventType.EMAIL_RESTORED
        }
        
        api_events = {
            AuditEventType.API_CALL_MADE,
            AuditEventType.API_QUOTA_EXCEEDED,
            AuditEventType.API_ERROR
        }
        
        if event_type in security_events:
            return 'security'
        elif event_type in compliance_events:
            return 'compliance'
        elif event_type in user_action_events:
            return 'user_action'
        elif event_type in api_events:
            return 'api_call'
        else:
            return 'operational'
    
    @contextmanager
    def audit_context(self, 
                     request_id: str = None,
                     user_id: str = None,
                     session_id: str = None,
                     ip_address: str = None,
                     user_agent: str = None,
                     source: str = None,
                     correlation_id: str = None):
        """
        Context manager for audit logging context.
        
        Usage:
            with audit_logger.audit_context(request_id="123", user_id="user456"):
                audit_logger.log_event(AuditEventType.SCAN_STARTED, "Scan initiated")
        """
        context = AuditContext(
            request_id=request_id or str(uuid.uuid4()),
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            source=source,
            correlation_id=correlation_id
        )
        
        self._context_stack.append(context)
        try:
            yield context
        finally:
            self._context_stack.pop()
    
    def get_current_context(self) -> AuditContext:
        """Get current audit context"""
        if self._context_stack:
            return self._context_stack[-1]
        else:
            # Return minimal context
            return AuditContext(request_id=str(uuid.uuid4()))
    
    def get_user_audit_trail(self, 
                           user_id: str,
                           start_date: datetime = None,
                           end_date: datetime = None,
                           event_types: List[AuditEventType] = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit trail for a specific user.
        
        Args:
            user_id: User identifier
            start_date: Start date filter
            end_date: End date filter
            event_types: Event types to filter
            limit: Maximum number of events
            
        Returns:
            List of audit events
        """
        try:
            db = next(get_db())
            
            query = db.query(AuditLog).filter(AuditLog.user_id == user_id)
            
            if start_date:
                query = query.filter(AuditLog.timestamp >= start_date)
            
            if end_date:
                query = query.filter(AuditLog.timestamp <= end_date)
            
            if event_types:
                event_type_values = [et.value for et in event_types]
                query = query.filter(AuditLog.event_type.in_(event_type_values))
            
            audit_logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
            
            # Convert to dict format
            events = []
            for log in audit_logs:
                event_dict = {
                    'event_id': log.event_id,
                    'event_type': log.event_type,
                    'severity': log.severity,
                    'message': log.message,
                    'timestamp': log.timestamp.isoformat(),
                    'request_id': log.request_id,
                    'result': log.result,
                    'duration_ms': log.duration_ms
                }
                
                # Decrypt and add details if user has access
                try:
                    if log.details:
                        event_dict['details'] = json.loads(
                            self.encryption_manager.decrypt_audit_data(log.details)
                        )
                except Exception as e:
                    logger.warning(f"Could not decrypt audit details: {e}")
                    event_dict['details'] = {}
                
                events.append(event_dict)
            
            return events
            
        except Exception as e:
            logger.error(f"Error getting user audit trail: {e}")
            return []
    
    def cleanup_expired_audit_logs(self, batch_size: int = 1000) -> int:
        """
        Clean up expired audit logs.
        
        Args:
            batch_size: Number of logs to process at once
            
        Returns:
            Number of logs cleaned up
        """
        try:
            db = next(get_db())
            
            # Find expired logs
            expired_logs = db.query(AuditLog).filter(
                AuditLog.expires_at <= datetime.utcnow()
            ).limit(batch_size).all()
            
            cleanup_count = 0
            for log in expired_logs:
                try:
                    # Remove from database
                    db.delete(log)
                    cleanup_count += 1
                except Exception as e:
                    logger.error(f"Error deleting audit log {log.id}: {e}")
            
            db.commit()
            
            if cleanup_count > 0:
                logger.info(f"Cleaned up {cleanup_count} expired audit logs")
            
            return cleanup_count
            
        except Exception as e:
            logger.error(f"Error cleaning up audit logs: {e}")
            db.rollback()
            return 0
    
    def export_user_audit_data(self, user_id: str) -> Dict[str, Any]:
        """
        Export all audit data for a user (GDPR Article 15).
        
        Args:
            user_id: User identifier
            
        Returns:
            Complete audit data export
        """
        try:
            # Get all audit events for user
            events = self.get_user_audit_trail(
                user_id=user_id,
                limit=10000  # Large limit for complete export
            )
            
            # Organize by category
            export_data = {
                'user_id': user_id,
                'export_timestamp': datetime.utcnow().isoformat(),
                'total_events': len(events),
                'events_by_type': {},
                'events': events
            }
            
            # Group by event type
            for event in events:
                event_type = event['event_type']
                if event_type not in export_data['events_by_type']:
                    export_data['events_by_type'][event_type] = []
                export_data['events_by_type'][event_type].append(event)
            
            return export_data
            
        except Exception as e:
            logger.error(f"Error exporting user audit data: {e}")
            return {'error': str(e)}

# Global audit logger instance
_audit_logger = None

def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger

# Convenience functions for common audit events

def audit_scan_started(request_id: str, user_id: str, scan_details: Dict[str, Any]):
    """Audit scan started event"""
    audit_logger = get_audit_logger()
    with audit_logger.audit_context(request_id=request_id, user_id=user_id):
        audit_logger.log_event(
            AuditEventType.SCAN_STARTED,
            "Email scan initiated",
            details=scan_details
        )

def audit_scan_completed(request_id: str, user_id: str, results: Dict[str, Any], duration_ms: int):
    """Audit scan completed event"""
    audit_logger = get_audit_logger()
    with audit_logger.audit_context(request_id=request_id, user_id=user_id):
        audit_logger.log_event(
            AuditEventType.SCAN_COMPLETED,
            "Email scan completed successfully",
            details=results,
            duration_ms=duration_ms,
            result="success"
        )

def audit_consent_action(user_id: str, action: str, details: Dict[str, Any]):
    """Audit consent-related actions"""
    audit_logger = get_audit_logger()
    
    event_type_map = {
        'granted': AuditEventType.CONSENT_GRANTED,
        'updated': AuditEventType.CONSENT_UPDATED,
        'revoked': AuditEventType.CONSENT_REVOKED
    }
    
    event_type = event_type_map.get(action, AuditEventType.CONSENT_UPDATED)
    
    with audit_logger.audit_context(user_id=user_id):
        audit_logger.log_event(
            event_type,
            f"User consent {action}",
            severity=AuditSeverity.INFO,
            details=details
        )

def audit_api_call(service: str, endpoint: str, response_code: int, duration_ms: int, request_id: str = None):
    """Audit API calls to third-party services"""
    audit_logger = get_audit_logger()
    
    severity = AuditSeverity.INFO
    result = "success"
    
    if response_code >= 400:
        severity = AuditSeverity.WARNING if response_code < 500 else AuditSeverity.ERROR
        result = "failure"
    
    with audit_logger.audit_context(request_id=request_id):
        audit_logger.log_event(
            AuditEventType.API_CALL_MADE,
            f"API call to {service} {endpoint}",
            severity=severity,
            details={
                'service': service,
                'endpoint': endpoint,
                'response_code': response_code
            },
            duration_ms=duration_ms,
            result=result
        )
