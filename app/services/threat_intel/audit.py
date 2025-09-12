"""Audit service for comprehensive logging and compliance."""

import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import and_, desc

from app.config.logging import get_logger
from app.models.analysis.scoring import AuditLog, AuditEventType
from app.core.database import SessionLocal

logger = get_logger(__name__)


class AuditService:
    """Service for comprehensive audit logging."""
    
    def __init__(self):
        self.sensitive_fields = {
            'password', 'token', 'secret', 'key', 'credential'
        }
    
    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from audit data."""
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            if any(sensitive in key_lower for sensitive in self.sensitive_fields):
                sanitized[key] = "*****"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_data(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_data(item) if isinstance(item, dict) else item 
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    async def log_event(self, event_type: AuditEventType, entity_type: str, 
                       entity_id: str, user_id: int, details: Dict[str, Any] = None,
                       db: Session = None) -> AuditLog:
        """Log an audit event."""
        should_close_db = False
        if db is None:
            db = SessionLocal()
            should_close_db = True
        
        try:
            # Sanitize sensitive data
            sanitized_details = self._sanitize_data(details or {})
            
            audit_log = AuditLog(
                event_type=event_type,
                entity_type=entity_type,
                entity_id=entity_id,
                user_id=user_id,
                details=sanitized_details,
                ip_address=sanitized_details.get('ip_address'),
                user_agent=sanitized_details.get('user_agent')
            )
            
            db.add(audit_log)
            db.commit()
            db.refresh(audit_log)
            
            # Also log to application logger for immediate visibility
            logger.info(
                f"AUDIT: {event_type.value} - {entity_type}:{entity_id} by user:{user_id}",
                extra={
                    'audit_id': audit_log.id,
                    'event_type': event_type.value,
                    'entity_type': entity_type,
                    'entity_id': entity_id,
                    'user_id': user_id,
                    'details': sanitized_details
                }
            )
            
            return audit_log
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}")
            raise
        finally:
            if should_close_db:
                db.close()
    
    # Email Analysis Events
    async def log_email_received(self, email_id: int, sender: str, subject: str, 
                                user_id: int, db: Session = None) -> AuditLog:
        """Log email received for analysis."""
        return await self.log_event(
            AuditEventType.EMAIL_RECEIVED,
            "email",
            str(email_id),
            user_id,
            {
                'sender': sender,
                'subject': subject[:100],  # Truncate long subjects
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            db
        )
    
    async def log_email_analyzed(self, email_id: int, analysis_type: str, 
                                result: Dict[str, Any], user_id: int, db: Session = None) -> AuditLog:
        """Log email analysis completion."""
        return await self.log_event(
            AuditEventType.EMAIL_ANALYZED,
            "email",
            str(email_id),
            user_id,
            {
                'analysis_type': analysis_type,
                'result_summary': {
                    'risk_score': result.get('risk_score'),
                    'threats_found': result.get('threats_found', 0),
                    'components_analyzed': result.get('components_analyzed', [])
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            db
        )
    
    async def log_email_scored(self, email_id: int, final_score: float, 
                              risk_level: str, user_id: int, db: Session = None) -> AuditLog:
        """Log email scoring completion."""
        return await self.log_event(
            AuditEventType.EMAIL_SCORED,
            "email",
            str(email_id),
            user_id,
            {
                'final_score': final_score,
                'risk_level': risk_level,
                'threshold_triggered': final_score >= 0.7,
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            db
        )
    
    # Action Events
    async def log_action_taken(self, action_id: int, action_type: str, 
                              target_email_id: int, user_id: int, 
                              automatic: bool = True, db: Session = None) -> AuditLog:
        """Log when an action is taken on an email."""
        return await self.log_event(
            AuditEventType.ACTION_TAKEN,
            "email_action",
            str(action_id),
            user_id,
            {
                'action_type': action_type,
                'target_email_id': target_email_id,
                'automatic': automatic,
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            db
        )
    
    async def log_action_completed(self, action_id: int, success: bool, 
                                  result: Dict[str, Any], user_id: int, db: Session = None) -> AuditLog:
        """Log action completion."""
        event_type = AuditEventType.ACTION_COMPLETED if success else AuditEventType.ACTION_FAILED
        
        return await self.log_event(
            event_type,
            "email_action",
            str(action_id),
            user_id,
            {
                'success': success,
                'result': result,
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            db
        )
    
    async def log_action_failed(self, action_id: str, error: str, 
                               user_id: int, db: Session = None) -> AuditLog:
        """Log action failure."""
        return await self.log_event(
            AuditEventType.ACTION_FAILED,
            "system_action",
            action_id,
            user_id,
            {
                'error': error,
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            db
        )
    
    # Configuration Events
    async def log_config_changed(self, config_type: str, config_id: str, 
                                changes: Dict[str, Any], user_id: int, db: Session = None) -> AuditLog:
        """Log configuration changes."""
        return await self.log_event(
            AuditEventType.CONFIG_CHANGED,
            config_type,
            config_id,
            user_id,
            {
                'changes': changes,
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            db
        )
    
    # User Events
    async def log_user_login(self, user_id: int, ip_address: str = None, 
                            user_agent: str = None, db: Session = None) -> AuditLog:
        """Log user login."""
        return await self.log_event(
            AuditEventType.USER_LOGIN,
            "user",
            str(user_id),
            user_id,
            {
                'ip_address': ip_address,
                'user_agent': user_agent,
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            db
        )
    
    async def log_user_logout(self, user_id: int, db: Session = None) -> AuditLog:
        """Log user logout."""
        return await self.log_event(
            AuditEventType.USER_LOGOUT,
            "user",
            str(user_id),
            user_id,
            {
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            db
        )
    
    async def log_permission_denied(self, user_id: int, attempted_action: str, 
                                   resource: str, db: Session = None) -> AuditLog:
        """Log permission denied events."""
        return await self.log_event(
            AuditEventType.PERMISSION_DENIED,
            "security",
            f"permission_denied_{user_id}_{datetime.now().timestamp()}",
            user_id,
            {
                'attempted_action': attempted_action,
                'resource': resource,
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            db
        )
    
    # System Events
    async def log_system_error(self, error_type: str, error_message: str, 
                              user_id: int = None, context: Dict[str, Any] = None, 
                              db: Session = None) -> AuditLog:
        """Log system errors."""
        return await self.log_event(
            AuditEventType.SYSTEM_ERROR,
            "system",
            f"error_{datetime.now().timestamp()}",
            user_id or 0,  # System user
            {
                'error_type': error_type,
                'error_message': error_message,
                'context': context or {},
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            db
        )
    
    # Query Methods
    async def get_audit_logs(self, entity_type: str = None, entity_id: str = None,
                            user_id: int = None, event_type: AuditEventType = None,
                            start_date: datetime = None, end_date: datetime = None,
                            limit: int = 100, db: Session = None) -> List[AuditLog]:
        """Get audit logs with filtering."""
        should_close_db = False
        if db is None:
            db = SessionLocal()
            should_close_db = True
        
        try:
            query = db.query(AuditLog)
            
            if entity_type:
                query = query.filter(AuditLog.entity_type == entity_type)
            
            if entity_id:
                query = query.filter(AuditLog.entity_id == entity_id)
            
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            
            if event_type:
                query = query.filter(AuditLog.event_type == event_type)
            
            if start_date:
                query = query.filter(AuditLog.timestamp >= start_date)
            
            if end_date:
                query = query.filter(AuditLog.timestamp <= end_date)
            
            return query.order_by(desc(AuditLog.timestamp)).limit(limit).all()
            
        finally:
            if should_close_db:
                db.close()
    
    async def get_user_activity(self, user_id: int, days: int = 30, 
                               db: Session = None) -> Dict[str, Any]:
        """Get user activity summary."""
        should_close_db = False
        if db is None:
            db = SessionLocal()
            should_close_db = True
        
        try:
            from datetime import timedelta
            
            start_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            logs = await self.get_audit_logs(
                user_id=user_id,
                start_date=start_date,
                limit=1000,
                db=db
            )
            
            # Aggregate activity
            activity = {
                'total_events': len(logs),
                'emails_analyzed': 0,
                'actions_taken': 0,
                'logins': 0,
                'config_changes': 0,
                'events_by_type': {},
                'events_by_day': {},
                'recent_events': []
            }
            
            for log in logs:
                event_type = log.event_type.value
                event_date = log.timestamp.date().isoformat()
                
                # Count by type
                activity['events_by_type'][event_type] = activity['events_by_type'].get(event_type, 0) + 1
                
                # Count by day
                activity['events_by_day'][event_date] = activity['events_by_day'].get(event_date, 0) + 1
                
                # Specific counters
                if log.event_type == AuditEventType.EMAIL_ANALYZED:
                    activity['emails_analyzed'] += 1
                elif log.event_type == AuditEventType.ACTION_TAKEN:
                    activity['actions_taken'] += 1
                elif log.event_type == AuditEventType.USER_LOGIN:
                    activity['logins'] += 1
                elif log.event_type == AuditEventType.CONFIG_CHANGED:
                    activity['config_changes'] += 1
                
                # Recent events (latest 10)
                if len(activity['recent_events']) < 10:
                    activity['recent_events'].append({
                        'timestamp': log.timestamp.isoformat(),
                        'event_type': event_type,
                        'entity_type': log.entity_type,
                        'entity_id': log.entity_id,
                        'details': log.details
                    })
            
            return activity
            
        finally:
            if should_close_db:
                db.close()
    
    async def get_email_audit_trail(self, email_id: int, db: Session = None) -> List[AuditLog]:
        """Get complete audit trail for an email."""
        return await self.get_audit_logs(
            entity_type="email",
            entity_id=str(email_id),
            limit=1000,
            db=db
        )
    
    async def export_audit_logs(self, filters: Dict[str, Any] = None, 
                               format: str = "json", db: Session = None) -> str:
        """Export audit logs for compliance reporting."""
        logs = await self.get_audit_logs(
            entity_type=filters.get('entity_type') if filters else None,
            user_id=filters.get('user_id') if filters else None,
            event_type=filters.get('event_type') if filters else None,
            start_date=filters.get('start_date') if filters else None,
            end_date=filters.get('end_date') if filters else None,
            limit=filters.get('limit', 10000) if filters else 10000,
            db=db
        )
        
        if format == "json":
            return json.dumps([
                {
                    'id': log.id,
                    'timestamp': log.timestamp.isoformat(),
                    'event_type': log.event_type.value,
                    'entity_type': log.entity_type,
                    'entity_id': log.entity_id,
                    'user_id': log.user_id,
                    'details': log.details,
                    'ip_address': log.ip_address,
                    'user_agent': log.user_agent
                }
                for log in logs
            ], indent=2)
        
        # Could add CSV, XML, etc. formats here
        return ""


# Create the singleton instance
audit_service = AuditService()
