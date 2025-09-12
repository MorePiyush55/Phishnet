"""
AuditLog service for comprehensive audit trail management with correlation tracking.

This service provides methods for logging user actions, system events,
and security incidents with proper categorization, correlation IDs, and querying capabilities.
"""

import uuid
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Union
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func
import asyncio
import json

from app.models.audit_log import AuditLog
from app.db.session import get_db
from app.config.logging import get_logger
from app.core.redis_client import get_redis_connection
from app.observability.correlation import add_correlation_to_audit, get_correlation_context, get_structured_logger

logger = get_structured_logger(__name__)


class AuditLogService:
    """
    Service for managing audit logs with high-performance logging and querying.
    
    Features:
    - Asynchronous logging with batching
    - Query filtering and pagination  
    - Security event detection
    - Compliance reporting
    - Performance metrics
    """
    
    def __init__(self):
        """Initialize audit log service."""
        self.pending_logs: List[AuditLog] = []
        self.batch_size = 50
        self.flush_interval = 10  # seconds
        self.last_flush = time.time()
        
        # Start background task for flushing logs
        asyncio.create_task(self._periodic_flush())
        
        logger.info("AuditLogService initialized")
    
    async def log_user_action(
        self,
        action: str,
        user_id: int,
        description: str,
        details: Optional[Dict[str, Any]] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        user_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_path: Optional[str] = None,
        request_method: Optional[str] = None,
        response_status: Optional[int] = None,
        duration_ms: Optional[int] = None,
        severity: str = 'info'
    ) -> AuditLog:
        """
        Log a user action with automatic correlation context.
        
        Args:
            action: Action type (login, logout, view_email, quarantine, etc.)
            user_id: ID of user performing action
            description: Human-readable description
            details: Additional structured data
            resource_type: Type of resource affected (email, user, etc.)
            resource_id: ID of resource affected
            request_id: Request correlation ID (auto-populated from context)
            session_id: User session ID
            user_ip: User's IP address
            user_agent: User's browser/client info
            request_path: API endpoint or page path
            request_method: HTTP method
            response_status: HTTP response status
            duration_ms: Action duration in milliseconds
            severity: Log severity level
            
        Returns:
            Created AuditLog entry
        """
        # Get correlation context automatically
        correlation_context = get_correlation_context()
        
        # Prepare audit data with correlation context
        audit_data = {
            "action": action,
            "user_id": user_id,
            "description": description,
            "details": details or {},
            "resource_type": resource_type,
            "resource_id": str(resource_id) if resource_id else None,
            "request_id": request_id or correlation_context.get("request_id") or self._generate_request_id(),
            "session_id": session_id,
            "user_ip": user_ip,
            "user_agent": user_agent,
            "request_path": request_path,
            "request_method": request_method,
            "response_status": response_status,
            "duration_ms": duration_ms,
            "severity": severity
        }
        
        # Add correlation context to audit data
        audit_data_with_correlation = add_correlation_to_audit(audit_data)
        
        audit_log = AuditLog(
            request_id=audit_data_with_correlation["request_id"],
            correlation_id=audit_data_with_correlation.get("correlation_id"),
            span_id=audit_data_with_correlation.get("span_id"),
            trace_id=audit_data_with_correlation.get("trace_id"),
            user_id=user_id,
            session_id=session_id,
            user_ip=user_ip,
            user_agent=user_agent,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            severity=severity,
            category='user',
            description=description,
            details=audit_data_with_correlation["details"],
            request_path=request_path,
            request_method=request_method,
            response_status=response_status,
            duration_ms=duration_ms,
            created_at=datetime.utcnow()
        )
        
        # Log structured event
        logger.info("User action logged", extra={
            "action": action,
            "user_id": user_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "severity": severity,
            "correlation_id": audit_data_with_correlation.get("correlation_id"),
            "trace_id": audit_data_with_correlation.get("trace_id")
        })
        
        await self._queue_log(audit_log)
        return audit_log
    
    async def log_system_event(
        self,
        action: str,
        description: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = 'info',
        category: str = 'system',
        request_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        duration_ms: Optional[int] = None
    ) -> AuditLog:
        """
        Log a system event.
        
        Args:
            action: System action type (scan_started, scan_finished, api_call, etc.)
            description: Event description
            details: Additional event data
            severity: Event severity
            category: Event category (system, scan, api, etc.)
            request_id: Request correlation ID
            resource_type: Resource type if applicable
            resource_id: Resource ID if applicable
            duration_ms: Event duration
            
        Returns:
            Created AuditLog entry
        """
        audit_log = AuditLog(
            request_id=request_id or self._generate_request_id(),
            action=action,
            severity=severity,
            category=category,
            description=description,
            details=details or {},
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            duration_ms=duration_ms,
            created_at=datetime.utcnow()
        )
        
        await self._queue_log(audit_log)
        return audit_log
    
    async def log_security_event(
        self,
        action: str,
        description: str,
        user_id: Optional[int] = None,
        user_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        is_suspicious: bool = True,
        security_violation: bool = False,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_path: Optional[str] = None
    ) -> AuditLog:
        """
        Log a security event.
        
        Args:
            action: Security action type (failed_login, xss_attempt, etc.)
            description: Security event description
            user_id: User ID if known
            user_ip: IP address of actor
            user_agent: User agent string
            details: Additional security details
            is_suspicious: Whether event is suspicious
            security_violation: Whether event violates security policy
            request_id: Request correlation ID
            session_id: Session ID if available
            request_path: Path where event occurred
            
        Returns:
            Created AuditLog entry
        """
        severity = 'critical' if security_violation else ('warning' if is_suspicious else 'error')
        
        audit_log = AuditLog(
            request_id=request_id or self._generate_request_id(),
            user_id=user_id,
            session_id=session_id,
            user_ip=user_ip,
            user_agent=user_agent,
            action=action,
            severity=severity,
            category='security',
            description=description,
            details=details or {},
            request_path=request_path,
            is_suspicious=is_suspicious,
            security_violation=security_violation,
            created_at=datetime.utcnow()
        )
        
        await self._queue_log(audit_log)
        
        # Immediate alert for critical security events
        if security_violation:
            await self._alert_security_violation(audit_log)
        
        return audit_log
    
    async def log_orchestrator_event(
        self,
        action: str,
        request_id: str,
        user_id: Optional[int],
        email_id: Optional[str],
        description: str,
        details: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        severity: str = 'info'
    ) -> AuditLog:
        """
        Log orchestrator events (scan operations).
        
        Args:
            action: Orchestrator action (scan_started, scan_finished, etc.)
            request_id: Request correlation ID
            user_id: User who initiated scan
            email_id: Email being scanned
            description: Event description
            details: Scan details (threat score, services used, etc.)
            duration_ms: Scan duration
            severity: Event severity
            
        Returns:
            Created AuditLog entry
        """
        return await self.log_system_event(
            action=action,
            description=description,
            details={
                'user_id': user_id,
                'email_id': email_id,
                **(details or {})
            },
            severity=severity,
            category='orchestrator',
            request_id=request_id,
            resource_type='email',
            resource_id=email_id,
            duration_ms=duration_ms
        )
    
    async def log_api_failure(
        self,
        service: str,
        action: str,
        error: str,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        """
        Log external API failures.
        
        Args:
            service: External service name (virustotal, abuseipdb, etc.)
            action: API action that failed
            error: Error description
            request_id: Request correlation ID
            details: Additional error details
            
        Returns:
            Created AuditLog entry
        """
        return await self.log_system_event(
            action=f"api_failure_{service}",
            description=f"{service} API failure: {error}",
            details={
                'service': service,
                'api_action': action,
                'error': error,
                **(details or {})
            },
            severity='error',
            category='api',
            request_id=request_id
        )
    
    async def query_logs(
        self,
        user_id: Optional[int] = None,
        action: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        is_suspicious: Optional[bool] = None,
        security_violation: Optional[bool] = None,
        request_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = 'created_at',
        order_desc: bool = True
    ) -> Dict[str, Any]:
        """
        Query audit logs with filtering and pagination.
        
        Returns:
            Dictionary with logs, total count, and pagination info
        """
        await self._flush_pending_logs()  # Ensure recent logs are included
        
        db = next(get_db())
        try:
            query = db.query(AuditLog)
            
            # Apply filters
            if user_id is not None:
                query = query.filter(AuditLog.user_id == user_id)
            if action:
                query = query.filter(AuditLog.action == action)
            if category:
                query = query.filter(AuditLog.category == category)
            if severity:
                query = query.filter(AuditLog.severity == severity)
            if start_date:
                query = query.filter(AuditLog.created_at >= start_date)
            if end_date:
                query = query.filter(AuditLog.created_at <= end_date)
            if resource_type:
                query = query.filter(AuditLog.resource_type == resource_type)
            if resource_id:
                query = query.filter(AuditLog.resource_id == resource_id)
            if is_suspicious is not None:
                query = query.filter(AuditLog.is_suspicious == is_suspicious)
            if security_violation is not None:
                query = query.filter(AuditLog.security_violation == security_violation)
            if request_id:
                query = query.filter(AuditLog.request_id == request_id)
            
            # Get total count
            total_count = query.count()
            
            # Apply ordering
            order_column = getattr(AuditLog, order_by, AuditLog.created_at)
            if order_desc:
                query = query.order_by(desc(order_column))
            else:
                query = query.order_by(order_column)
            
            # Apply pagination
            logs = query.offset(offset).limit(limit).all()
            
            return {
                'logs': [log.to_dict() for log in logs],
                'total_count': total_count,
                'limit': limit,
                'offset': offset,
                'has_more': (offset + limit) < total_count
            }
            
        finally:
            db.close()
    
    async def get_security_summary(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get security event summary for dashboard.
        
        Returns:
            Security metrics and recent events
        """
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=7)
        if not end_date:
            end_date = datetime.utcnow()
        
        db = next(get_db())
        try:
            # Security event counts
            security_query = db.query(AuditLog).filter(
                and_(
                    AuditLog.category == 'security',
                    AuditLog.created_at >= start_date,
                    AuditLog.created_at <= end_date
                )
            )
            
            total_security_events = security_query.count()
            suspicious_events = security_query.filter(AuditLog.is_suspicious == True).count()
            violations = security_query.filter(AuditLog.security_violation == True).count()
            
            # Recent critical events
            critical_events = security_query.filter(
                AuditLog.severity == 'critical'
            ).order_by(desc(AuditLog.created_at)).limit(10).all()
            
            # Activity by category
            category_stats = db.query(
                AuditLog.category,
                func.count(AuditLog.id).label('count')
            ).filter(
                and_(
                    AuditLog.created_at >= start_date,
                    AuditLog.created_at <= end_date
                )
            ).group_by(AuditLog.category).all()
            
            return {
                'period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'security_metrics': {
                    'total_security_events': total_security_events,
                    'suspicious_events': suspicious_events,
                    'security_violations': violations,
                    'risk_score': min(100, (violations * 10) + (suspicious_events * 2))
                },
                'category_breakdown': {
                    category: count for category, count in category_stats
                },
                'recent_critical_events': [
                    event.to_dict() for event in critical_events
                ]
            }
            
        finally:
            db.close()
    
    async def get_user_activity(
        self,
        user_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 50
    ) -> Dict[str, Any]:
        """
        Get user activity summary.
        
        Returns:
            User's recent actions and statistics
        """
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()
        
        db = next(get_db())
        try:
            # Recent user actions
            recent_actions = db.query(AuditLog).filter(
                and_(
                    AuditLog.user_id == user_id,
                    AuditLog.created_at >= start_date,
                    AuditLog.created_at <= end_date
                )
            ).order_by(desc(AuditLog.created_at)).limit(limit).all()
            
            # Action counts
            action_stats = db.query(
                AuditLog.action,
                func.count(AuditLog.id).label('count')
            ).filter(
                and_(
                    AuditLog.user_id == user_id,
                    AuditLog.created_at >= start_date,
                    AuditLog.created_at <= end_date
                )
            ).group_by(AuditLog.action).all()
            
            return {
                'user_id': user_id,
                'period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'activity_summary': {
                    'total_actions': len(recent_actions),
                    'action_breakdown': {
                        action: count for action, count in action_stats
                    }
                },
                'recent_actions': [
                    action.to_dict() for action in recent_actions
                ]
            }
            
        finally:
            db.close()
    
    async def _queue_log(self, audit_log: AuditLog):
        """Add log to pending queue for batch processing."""
        self.pending_logs.append(audit_log)
        
        # Flush if batch is full or if it's a critical event
        if (len(self.pending_logs) >= self.batch_size or 
            audit_log.severity == 'critical' or
            audit_log.security_violation):
            await self._flush_pending_logs()
    
    async def _flush_pending_logs(self):
        """Flush pending logs to database."""
        if not self.pending_logs:
            return
        
        db = next(get_db())
        try:
            db.add_all(self.pending_logs)
            db.commit()
            
            logger.info(f"Flushed {len(self.pending_logs)} audit logs to database")
            self.pending_logs.clear()
            self.last_flush = time.time()
            
        except Exception as e:
            logger.error(f"Failed to flush audit logs: {e}")
            db.rollback()
        finally:
            db.close()
    
    async def _periodic_flush(self):
        """Periodically flush pending logs."""
        while True:
            try:
                await asyncio.sleep(self.flush_interval)
                
                if time.time() - self.last_flush >= self.flush_interval:
                    await self._flush_pending_logs()
                    
            except Exception as e:
                logger.error(f"Periodic flush error: {e}")
    
    async def _alert_security_violation(self, audit_log: AuditLog):
        """Send immediate alert for security violations."""
        try:
            # Cache alert to prevent spam
            redis = get_redis_connection()
            alert_key = f"security_alert:{audit_log.user_ip}:{audit_log.action}"
            
            if not await redis.get(alert_key):
                # Set alert cooldown
                await redis.setex(alert_key, 300, "1")  # 5 minute cooldown
                
                # Log critical alert
                logger.critical(
                    f"SECURITY VIOLATION: {audit_log.action} from {audit_log.user_ip} "
                    f"(User: {audit_log.user_id}, Request: {audit_log.request_id})"
                )
                
                # Here you could add integration with alerting systems
                # (email, Slack, PagerDuty, etc.)
                
        except Exception as e:
            logger.error(f"Failed to send security alert: {e}")
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        return f"req_{uuid.uuid4().hex[:16]}"


# Singleton instance for global use
_audit_service_instance: Optional[AuditLogService] = None


def get_audit_service() -> AuditLogService:
    """Get the global AuditLogService instance."""
    global _audit_service_instance
    
    if _audit_service_instance is None:
        _audit_service_instance = AuditLogService()
    
    return _audit_service_instance


# Convenience functions for common logging operations
async def log_user_login(user_id: int, session_id: str, user_ip: str, user_agent: str, success: bool = True):
    """Log user login attempt."""
    service = get_audit_service()
    
    if success:
        await service.log_user_action(
            action="login_success",
            user_id=user_id,
            description=f"User {user_id} logged in successfully",
            session_id=session_id,
            user_ip=user_ip,
            user_agent=user_agent,
            details={'login_method': 'password'}
        )
    else:
        await service.log_security_event(
            action="login_failed",
            description=f"Failed login attempt for user {user_id}",
            user_id=user_id,
            user_ip=user_ip,
            user_agent=user_agent,
            is_suspicious=True
        )


async def log_email_view(user_id: int, email_id: str, request_id: str):
    """Log email viewing action."""
    service = get_audit_service()
    await service.log_user_action(
        action="view_email",
        user_id=user_id,
        description=f"User viewed email {email_id}",
        resource_type="email",
        resource_id=email_id,
        request_id=request_id
    )


async def log_email_quarantine(user_id: int, email_id: str, reason: str, request_id: str):
    """Log email quarantine action."""
    service = get_audit_service()
    await service.log_user_action(
        action="quarantine_email",
        user_id=user_id,
        description=f"User quarantined email {email_id}: {reason}",
        resource_type="email",
        resource_id=email_id,
        request_id=request_id,
        details={'quarantine_reason': reason},
        severity='warning'
    )


async def log_scan_started(request_id: str, user_id: Optional[int], email_id: str, scan_type: str):
    """Log scan operation start."""
    service = get_audit_service()
    await service.log_orchestrator_event(
        action="scan_started",
        request_id=request_id,
        user_id=user_id,
        email_id=email_id,
        description=f"Started {scan_type} scan for email {email_id}",
        details={'scan_type': scan_type}
    )


async def log_scan_completed(
    request_id: str,
    user_id: Optional[int],
    email_id: str,
    threat_score: float,
    verdict: str,
    duration_ms: int,
    services_used: List[str]
):
    """Log scan operation completion."""
    service = get_audit_service()
    await service.log_orchestrator_event(
        action="scan_completed",
        request_id=request_id,
        user_id=user_id,
        email_id=email_id,
        description=f"Completed scan for email {email_id}: {verdict} (score: {threat_score:.2f})",
        details={
            'threat_score': threat_score,
            'verdict': verdict,
            'services_used': services_used
        },
        duration_ms=duration_ms,
        severity='warning' if threat_score > 0.7 else 'info'
    )
