"""
Audit Logging System for PhishNet Sandbox

Comprehensive logging for sandbox operations with compliance, security,
and operational audit trails. Designed for enterprise security requirements.
"""

import json
import time
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
import structlog
from cryptography.fernet import Fernet
import asyncio
import aiofiles
import os

from app.config.settings import settings

logger = structlog.get_logger(__name__)


class AuditEventType(Enum):
    """Types of audit events."""
    # Job Lifecycle
    JOB_SUBMITTED = "job_submitted"
    JOB_STARTED = "job_started"
    JOB_COMPLETED = "job_completed"
    JOB_FAILED = "job_failed"
    JOB_CANCELLED = "job_cancelled"
    JOB_TIMEOUT = "job_timeout"
    
    # Container Events
    CONTAINER_CREATED = "container_created"
    CONTAINER_STARTED = "container_started"
    CONTAINER_STOPPED = "container_stopped"
    CONTAINER_REMOVED = "container_removed"
    CONTAINER_ERROR = "container_error"
    
    # Security Events
    SECURITY_VIOLATION = "security_violation"
    NETWORK_BLOCKED = "network_blocked"
    RESOURCE_LIMIT_HIT = "resource_limit_hit"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    ACCESS_DENIED = "access_denied"
    
    # System Events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIGURATION_CHANGE = "configuration_change"
    MAINTENANCE_START = "maintenance_start"
    MAINTENANCE_END = "maintenance_end"
    
    # Evidence Events
    EVIDENCE_COLLECTED = "evidence_collected"
    EVIDENCE_ACCESSED = "evidence_accessed"
    EVIDENCE_DELETED = "evidence_deleted"
    EVIDENCE_EXPORTED = "evidence_exported"
    
    # Compliance Events
    DATA_RETENTION_APPLIED = "data_retention_applied"
    GDPR_REQUEST = "gdpr_request"
    COMPLIANCE_SCAN = "compliance_scan"
    AUDIT_EXPORT = "audit_export"


class AuditSeverity(Enum):
    """Audit event severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Audit event structure."""
    event_id: str
    event_type: AuditEventType
    severity: AuditSeverity
    timestamp: datetime
    session_id: Optional[str] = None
    job_id: Optional[str] = None
    user_id: Optional[str] = None
    container_id: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    target_url_hash: Optional[str] = None  # Never store actual URLs
    message: str = ""
    details: Dict[str, Any] = None
    metadata: Dict[str, Any] = None
    compliance_tags: List[str] = None
    retention_policy: str = "standard"


@dataclass
class SecurityMetrics:
    """Security metrics for monitoring."""
    blocked_requests: int = 0
    security_violations: int = 0
    suspicious_activities: int = 0
    failed_authentications: int = 0
    resource_limit_hits: int = 0
    container_escapes: int = 0
    network_anomalies: int = 0


@dataclass
class ComplianceRecord:
    """Compliance audit record."""
    record_id: str
    event_id: str
    compliance_framework: str  # "SOC2", "GDPR", "HIPAA", etc.
    control_objective: str
    evidence_collected: bool
    data_classification: str
    retention_days: int
    anonymization_applied: bool
    created_at: datetime


class AuditLogger:
    """Core audit logging functionality."""
    
    def __init__(self):
        self.audit_dir = Path(settings.AUDIT_LOG_DIR)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize encryption for sensitive data
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Log rotation settings
        self.max_log_size = getattr(settings, 'AUDIT_MAX_LOG_SIZE', 100 * 1024 * 1024)  # 100MB
        self.max_log_files = getattr(settings, 'AUDIT_MAX_LOG_FILES', 30)
        
        # Current log file
        self.current_log_file = self._get_current_log_file()
        
        # Security metrics
        self.security_metrics = SecurityMetrics()
        
        # Compliance settings
        self.compliance_enabled = getattr(settings, 'COMPLIANCE_ENABLED', True)
        self.data_retention_days = getattr(settings, 'AUDIT_RETENTION_DAYS', 2555)  # 7 years
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for sensitive data."""
        key_file = self.audit_dir / ".audit_key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Restrict access
            return key
    
    def _get_current_log_file(self) -> Path:
        """Get current log file path."""
        date_str = datetime.now().strftime("%Y-%m-%d")
        return self.audit_dir / f"audit_{date_str}.jsonl"
    
    def _hash_sensitive_data(self, data: str) -> str:
        """Hash sensitive data for audit trails."""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _encrypt_sensitive_field(self, data: str) -> str:
        """Encrypt sensitive field data."""
        return self.cipher.encrypt(data.encode()).decode()
    
    async def log_event(self, event: AuditEvent):
        """Log an audit event."""
        try:
            # Ensure event has required fields
            if not event.event_id:
                event.event_id = str(uuid.uuid4())
            
            if not event.timestamp:
                event.timestamp = datetime.now(timezone.utc)
            
            # Hash any URLs for privacy
            if hasattr(event, 'target_url') and event.target_url:
                event.target_url_hash = self._hash_sensitive_data(event.target_url)
                delattr(event, 'target_url')  # Remove actual URL
            
            # Prepare log entry
            log_entry = {
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "severity": event.severity.value,
                "timestamp": event.timestamp.isoformat(),
                "session_id": event.session_id,
                "job_id": event.job_id,
                "user_id": event.user_id,
                "container_id": event.container_id,
                "source_ip": event.source_ip,
                "user_agent": event.user_agent,
                "target_url_hash": event.target_url_hash,
                "message": event.message,
                "details": event.details or {},
                "metadata": event.metadata or {},
                "compliance_tags": event.compliance_tags or [],
                "retention_policy": event.retention_policy
            }
            
            # Remove None values
            log_entry = {k: v for k, v in log_entry.items() if v is not None}
            
            # Write to log file
            await self._write_log_entry(log_entry)
            
            # Update security metrics
            await self._update_security_metrics(event)
            
            # Handle compliance recording
            if self.compliance_enabled:
                await self._create_compliance_record(event)
            
            # Structured logging
            logger.info("Audit event logged", 
                       event_id=event.event_id,
                       event_type=event.event_type.value,
                       severity=event.severity.value)
            
        except Exception as e:
            logger.error("Failed to log audit event", 
                        event_type=event.event_type.value,
                        error=str(e))
    
    async def _write_log_entry(self, log_entry: Dict[str, Any]):
        """Write log entry to file."""
        try:
            # Check if log rotation is needed
            await self._check_log_rotation()
            
            # Write entry
            async with aiofiles.open(self.current_log_file, 'a') as f:
                await f.write(json.dumps(log_entry) + '\n')
            
        except Exception as e:
            logger.error("Failed to write log entry", error=str(e))
            raise
    
    async def _check_log_rotation(self):
        """Check if log rotation is needed."""
        try:
            if self.current_log_file.exists():
                file_size = self.current_log_file.stat().st_size
                
                if file_size >= self.max_log_size:
                    await self._rotate_logs()
            
        except Exception as e:
            logger.error("Error checking log rotation", error=str(e))
    
    async def _rotate_logs(self):
        """Rotate audit logs."""
        try:
            # Get new log file for today
            new_log_file = self._get_current_log_file()
            
            # If it's the same file, add timestamp
            if new_log_file == self.current_log_file:
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                new_log_file = self.audit_dir / f"audit_{timestamp}.jsonl"
            
            self.current_log_file = new_log_file
            
            # Clean old log files
            await self._clean_old_logs()
            
            logger.info("Audit logs rotated", new_file=str(new_log_file))
            
        except Exception as e:
            logger.error("Failed to rotate logs", error=str(e))
    
    async def _clean_old_logs(self):
        """Clean old audit log files."""
        try:
            log_files = list(self.audit_dir.glob("audit_*.jsonl"))
            log_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Keep only the newest files
            for old_file in log_files[self.max_log_files:]:
                old_file.unlink()
                logger.info("Deleted old audit log", file=str(old_file))
            
        except Exception as e:
            logger.error("Failed to clean old logs", error=str(e))
    
    async def _update_security_metrics(self, event: AuditEvent):
        """Update security metrics based on event."""
        try:
            if event.event_type == AuditEventType.SECURITY_VIOLATION:
                self.security_metrics.security_violations += 1
            elif event.event_type == AuditEventType.NETWORK_BLOCKED:
                self.security_metrics.blocked_requests += 1
            elif event.event_type == AuditEventType.SUSPICIOUS_ACTIVITY:
                self.security_metrics.suspicious_activities += 1
            elif event.event_type == AuditEventType.RESOURCE_LIMIT_HIT:
                self.security_metrics.resource_limit_hits += 1
            elif event.event_type == AuditEventType.ACCESS_DENIED:
                self.security_metrics.failed_authentications += 1
            
        except Exception as e:
            logger.error("Failed to update security metrics", error=str(e))
    
    async def _create_compliance_record(self, event: AuditEvent):
        """Create compliance record for audit event."""
        try:
            if not event.compliance_tags:
                return
            
            record = ComplianceRecord(
                record_id=str(uuid.uuid4()),
                event_id=event.event_id,
                compliance_framework="SOC2",  # Default framework
                control_objective="AC-3",  # Access Control
                evidence_collected=True,
                data_classification="internal",
                retention_days=self.data_retention_days,
                anonymization_applied=bool(event.target_url_hash),
                created_at=datetime.now(timezone.utc)
            )
            
            # Write compliance record
            compliance_file = self.audit_dir / "compliance_records.jsonl"
            async with aiofiles.open(compliance_file, 'a') as f:
                await f.write(json.dumps(asdict(record), default=str) + '\n')
            
        except Exception as e:
            logger.error("Failed to create compliance record", error=str(e))
    
    async def query_events(self, 
                          start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None,
                          event_types: Optional[List[AuditEventType]] = None,
                          session_id: Optional[str] = None,
                          job_id: Optional[str] = None,
                          severity: Optional[AuditSeverity] = None,
                          limit: int = 1000) -> List[Dict[str, Any]]:
        """Query audit events with filters."""
        try:
            events = []
            
            # Get relevant log files
            log_files = self._get_log_files_for_timerange(start_time, end_time)
            
            for log_file in log_files:
                if not log_file.exists():
                    continue
                
                async with aiofiles.open(log_file, 'r') as f:
                    async for line in f:
                        try:
                            event = json.loads(line.strip())
                            
                            # Apply filters
                            if not self._event_matches_filters(event, start_time, end_time, 
                                                             event_types, session_id, 
                                                             job_id, severity):
                                continue
                            
                            events.append(event)
                            
                            if len(events) >= limit:
                                break
                                
                        except json.JSONDecodeError:
                            continue
                
                if len(events) >= limit:
                    break
            
            # Sort by timestamp (newest first)
            events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            return events[:limit]
            
        except Exception as e:
            logger.error("Failed to query events", error=str(e))
            return []
    
    def _get_log_files_for_timerange(self, 
                                    start_time: Optional[datetime], 
                                    end_time: Optional[datetime]) -> List[Path]:
        """Get log files that might contain events in the time range."""
        log_files = list(self.audit_dir.glob("audit_*.jsonl"))
        
        if not start_time and not end_time:
            return sorted(log_files, key=lambda x: x.stat().st_mtime, reverse=True)
        
        # Filter files by modification time (rough approximation)
        relevant_files = []
        for log_file in log_files:
            mtime = datetime.fromtimestamp(log_file.stat().st_mtime, tz=timezone.utc)
            
            if start_time and mtime < start_time - timedelta(days=1):
                continue
            if end_time and mtime > end_time + timedelta(days=1):
                continue
            
            relevant_files.append(log_file)
        
        return sorted(relevant_files, key=lambda x: x.stat().st_mtime, reverse=True)
    
    def _event_matches_filters(self, event: Dict[str, Any], 
                              start_time: Optional[datetime],
                              end_time: Optional[datetime],
                              event_types: Optional[List[AuditEventType]],
                              session_id: Optional[str],
                              job_id: Optional[str],
                              severity: Optional[AuditSeverity]) -> bool:
        """Check if event matches query filters."""
        try:
            # Time range filter
            if start_time or end_time:
                event_time = datetime.fromisoformat(event['timestamp'])
                if start_time and event_time < start_time:
                    return False
                if end_time and event_time > end_time:
                    return False
            
            # Event type filter
            if event_types:
                event_type_values = [et.value for et in event_types]
                if event.get('event_type') not in event_type_values:
                    return False
            
            # Session ID filter
            if session_id and event.get('session_id') != session_id:
                return False
            
            # Job ID filter
            if job_id and event.get('job_id') != job_id:
                return False
            
            # Severity filter
            if severity and event.get('severity') != severity.value:
                return False
            
            return True
            
        except Exception:
            return False
    
    async def get_security_metrics(self) -> SecurityMetrics:
        """Get current security metrics."""
        return self.security_metrics
    
    async def export_audit_trail(self, 
                                start_time: datetime,
                                end_time: datetime,
                                format: str = "json") -> Path:
        """Export audit trail for compliance."""
        try:
            export_id = str(uuid.uuid4())
            export_file = self.audit_dir / f"audit_export_{export_id}.{format}"
            
            # Log export event
            await self.log_event(AuditEvent(
                event_id=str(uuid.uuid4()),
                event_type=AuditEventType.AUDIT_EXPORT,
                severity=AuditSeverity.INFO,
                timestamp=datetime.now(timezone.utc),
                message=f"Audit trail exported: {start_time} to {end_time}",
                details={"export_id": export_id, "format": format},
                compliance_tags=["audit_export", "compliance"]
            ))
            
            # Query events
            events = await self.query_events(
                start_time=start_time,
                end_time=end_time,
                limit=100000  # Large limit for export
            )
            
            # Write export file
            if format == "json":
                async with aiofiles.open(export_file, 'w') as f:
                    await f.write(json.dumps({
                        "export_metadata": {
                            "export_id": export_id,
                            "start_time": start_time.isoformat(),
                            "end_time": end_time.isoformat(),
                            "event_count": len(events),
                            "generated_at": datetime.now(timezone.utc).isoformat()
                        },
                        "events": events
                    }, indent=2))
            
            logger.info("Audit trail exported", 
                       export_id=export_id,
                       event_count=len(events),
                       file=str(export_file))
            
            return export_file
            
        except Exception as e:
            logger.error("Failed to export audit trail", error=str(e))
            raise


class SandboxAuditLogger:
    """Specialized audit logger for sandbox operations."""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
    
    async def log_job_submitted(self, job_id: str, session_id: str, 
                               target_url: str, user_id: Optional[str] = None,
                               source_ip: Optional[str] = None):
        """Log job submission."""
        await self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.JOB_SUBMITTED,
            severity=AuditSeverity.INFO,
            job_id=job_id,
            session_id=session_id,
            user_id=user_id,
            source_ip=source_ip,
            target_url_hash=self.audit_logger._hash_sensitive_data(target_url),
            message=f"Sandbox job submitted: {job_id}",
            details={"action": "submit_job"},
            compliance_tags=["job_lifecycle", "user_action"],
            timestamp=datetime.now(timezone.utc)
        ))
    
    async def log_container_created(self, job_id: str, session_id: str, 
                                   container_id: str):
        """Log container creation."""
        await self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.CONTAINER_CREATED,
            severity=AuditSeverity.INFO,
            job_id=job_id,
            session_id=session_id,
            container_id=container_id,
            message=f"Container created for job {job_id}",
            details={"action": "create_container"},
            compliance_tags=["container_lifecycle"],
            timestamp=datetime.now(timezone.utc)
        ))
    
    async def log_security_violation(self, job_id: str, session_id: str,
                                    violation_type: str, details: Dict[str, Any]):
        """Log security violation."""
        await self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.SECURITY_VIOLATION,
            severity=AuditSeverity.ERROR,
            job_id=job_id,
            session_id=session_id,
            message=f"Security violation detected: {violation_type}",
            details=details,
            compliance_tags=["security", "violation"],
            timestamp=datetime.now(timezone.utc)
        ))
    
    async def log_evidence_collected(self, job_id: str, session_id: str,
                                    evidence_type: str, evidence_hash: str):
        """Log evidence collection."""
        await self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.EVIDENCE_COLLECTED,
            severity=AuditSeverity.INFO,
            job_id=job_id,
            session_id=session_id,
            message=f"Evidence collected: {evidence_type}",
            details={
                "evidence_type": evidence_type,
                "evidence_hash": evidence_hash
            },
            compliance_tags=["evidence", "collection"],
            timestamp=datetime.now(timezone.utc)
        ))
    
    async def log_job_completed(self, job_id: str, session_id: str,
                               status: str, execution_time: float):
        """Log job completion."""
        severity = AuditSeverity.INFO if status == "completed" else AuditSeverity.ERROR
        
        await self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.JOB_COMPLETED,
            severity=severity,
            job_id=job_id,
            session_id=session_id,
            message=f"Sandbox job {status}: {job_id}",
            details={
                "status": status,
                "execution_time": execution_time
            },
            compliance_tags=["job_lifecycle"],
            timestamp=datetime.now(timezone.utc)
        ))


# Global audit logger instance
sandbox_audit_logger = SandboxAuditLogger()