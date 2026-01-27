"""
Enterprise Audit Logging for Mode 1 Pipeline
=============================================
Immutable audit trail for all email processing actions.

Requirements:
1. Append-only (no updates/deletes)
2. Tamper-evident (hash chain)
3. Full traceability (who, what, when, why)
4. Compliance-ready (GDPR, SOC2)

Records:
- Email ingestion events
- Analysis decisions
- Policy actions taken
- User/analyst interventions
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum
from dataclasses import dataclass

from beanie import Document, Indexed
from pydantic import Field
from pymongo import IndexModel, ASCENDING, DESCENDING

from app.config.logging import get_logger

logger = get_logger(__name__)


class AuditEventType(str, Enum):
    """Categories of audit events"""
    # Ingestion
    EMAIL_RECEIVED = "email_received"
    EMAIL_PARSED = "email_parsed"
    EMAIL_DEDUPLICATED = "email_deduplicated"
    
    # Analysis
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYSIS_FAILED = "analysis_failed"
    
    # Verdict
    VERDICT_ASSIGNED = "verdict_assigned"
    VERDICT_OVERRIDDEN = "verdict_overridden"
    
    # Policy
    POLICY_EVALUATED = "policy_evaluated"
    POLICY_EXECUTED = "policy_executed"
    
    # Actions
    ACTION_REPLY_SENT = "action_reply_sent"
    ACTION_QUARANTINE = "action_quarantine"
    ACTION_SOC_NOTIFIED = "action_soc_notified"
    ACTION_DELETED = "action_deleted"
    
    # User/Analyst
    ANALYST_REVIEW = "analyst_review"
    ANALYST_OVERRIDE = "analyst_override"
    FALSE_POSITIVE_REPORTED = "false_positive_reported"
    FALSE_NEGATIVE_REPORTED = "false_negative_reported"
    
    # System
    SYSTEM_ERROR = "system_error"
    RATE_LIMIT_HIT = "rate_limit_hit"
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"


class AuditSeverity(str, Enum):
    """Severity levels for audit events"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Mode1AuditLog(Document):
    """
    Immutable audit log entry for Mode 1 pipeline.
    
    Design:
    - Append-only: No update/delete methods exposed
    - Hash chain: Each entry includes hash of previous entry
    - Structured: All fields typed for querying
    """
    # Identity
    sequence_id: Indexed(int)  # Monotonically increasing
    previous_hash: str  # Hash of previous entry (chain integrity)
    entry_hash: str  # Hash of this entry (tamper detection)
    
    # Context
    job_id: Indexed(str)  # Analysis job identifier
    tenant_id: Optional[Indexed(str)] = None
    tenant_domain: Optional[str] = None
    
    # Event
    event_type: Indexed(str)
    severity: str = AuditSeverity.INFO.value
    
    # Actor
    actor_type: str = "system"  # system, user, analyst, policy
    actor_id: Optional[str] = None
    actor_email: Optional[str] = None
    
    # Target
    target_type: Optional[str] = None  # email, analysis, policy
    target_id: Optional[str] = None
    
    # Details
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    
    # Email context (for email events)
    email_message_id: Optional[str] = None
    email_subject: Optional[str] = None
    email_sender: Optional[str] = None
    email_recipient: Optional[str] = None
    
    # Verdict context (for analysis events)
    verdict: Optional[str] = None
    score: Optional[float] = None
    confidence: Optional[float] = None
    
    # Policy context
    policy_name: Optional[str] = None
    actions_taken: List[str] = Field(default_factory=list)
    
    # Timestamps
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Immutability marker
    is_immutable: bool = True
    
    class Settings:
        name = "mode1_audit_logs"
        indexes = [
            IndexModel([("sequence_id", DESCENDING)], unique=True),
            IndexModel([("job_id", ASCENDING)]),
            IndexModel([("tenant_id", ASCENDING), ("timestamp", DESCENDING)]),
            IndexModel([("event_type", ASCENDING), ("timestamp", DESCENDING)]),
            IndexModel([("email_message_id", ASCENDING)]),
            IndexModel([("actor_id", ASCENDING), ("timestamp", DESCENDING)]),
            IndexModel([("severity", ASCENDING), ("timestamp", DESCENDING)]),
            # TTL: Keep audit logs for 2 years
            IndexModel([("timestamp", ASCENDING)], expireAfterSeconds=2*365*24*60*60),
        ]


class Mode1AuditLogger:
    """
    Enterprise audit logger with hash chain integrity.
    
    Usage:
        audit = Mode1AuditLogger()
        await audit.log_email_received(job_id, tenant_id, email_data)
        await audit.log_analysis_complete(job_id, verdict, score)
    """
    
    def __init__(self):
        self._sequence_counter: Optional[int] = None
        self._last_hash: Optional[str] = None
    
    async def _get_next_sequence(self) -> tuple[int, str]:
        """Get next sequence ID and previous hash atomically"""
        # Find the last entry
        last_entry = await Mode1AuditLog.find_one(
            sort=[("sequence_id", -1)]
        )
        
        if last_entry:
            next_seq = last_entry.sequence_id + 1
            prev_hash = last_entry.entry_hash
        else:
            next_seq = 1
            prev_hash = "GENESIS"
        
        return next_seq, prev_hash
    
    def _compute_entry_hash(self, entry: Mode1AuditLog) -> str:
        """Compute tamper-evident hash of entry"""
        # Include all critical fields in hash
        data = {
            "sequence_id": entry.sequence_id,
            "previous_hash": entry.previous_hash,
            "job_id": entry.job_id,
            "event_type": entry.event_type,
            "message": entry.message,
            "timestamp": entry.timestamp.isoformat(),
            "details": entry.details
        }
        payload = json.dumps(data, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()
    
    async def _log(
        self,
        event_type: AuditEventType,
        job_id: str,
        message: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        tenant_id: Optional[str] = None,
        tenant_domain: Optional[str] = None,
        actor_type: str = "system",
        actor_id: Optional[str] = None,
        actor_email: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        email_message_id: Optional[str] = None,
        email_subject: Optional[str] = None,
        email_sender: Optional[str] = None,
        email_recipient: Optional[str] = None,
        verdict: Optional[str] = None,
        score: Optional[float] = None,
        confidence: Optional[float] = None,
        policy_name: Optional[str] = None,
        actions_taken: Optional[List[str]] = None
    ) -> Mode1AuditLog:
        """Core logging method - creates immutable audit entry"""
        
        # Get sequence and chain hash
        sequence_id, previous_hash = await self._get_next_sequence()
        
        # Create entry
        entry = Mode1AuditLog(
            sequence_id=sequence_id,
            previous_hash=previous_hash,
            entry_hash="",  # Computed below
            job_id=job_id,
            tenant_id=tenant_id,
            tenant_domain=tenant_domain,
            event_type=event_type.value,
            severity=severity.value,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_email=actor_email,
            target_type=target_type,
            target_id=target_id,
            message=message,
            details=details or {},
            email_message_id=email_message_id,
            email_subject=email_subject,
            email_sender=email_sender,
            email_recipient=email_recipient,
            verdict=verdict,
            score=score,
            confidence=confidence,
            policy_name=policy_name,
            actions_taken=actions_taken or []
        )
        
        # Compute and set entry hash
        entry.entry_hash = self._compute_entry_hash(entry)
        
        # Save (append-only)
        await entry.save()
        
        logger.debug(f"Audit[{sequence_id}]: {event_type.value} - {message}")
        
        return entry
    
    # ═══════════════════════════════════════════════════════════════════════
    # INGESTION EVENTS
    # ═══════════════════════════════════════════════════════════════════════
    
    async def log_email_received(
        self,
        job_id: str,
        tenant_id: Optional[str],
        tenant_domain: Optional[str],
        message_id: str,
        subject: str,
        sender: str,
        recipient: str,
        mail_uid: str
    ) -> Mode1AuditLog:
        """Log email received for analysis"""
        return await self._log(
            event_type=AuditEventType.EMAIL_RECEIVED,
            job_id=job_id,
            message=f"Email received for analysis: {subject[:50]}",
            tenant_id=tenant_id,
            tenant_domain=tenant_domain,
            target_type="email",
            target_id=mail_uid,
            email_message_id=message_id,
            email_subject=subject,
            email_sender=sender,
            email_recipient=recipient,
            details={"mail_uid": mail_uid}
        )
    
    async def log_email_deduplicated(
        self,
        job_id: str,
        message_id: str,
        original_analysis_id: str,
        match_type: str,
        cached_verdict: str,
        cached_score: float
    ) -> Mode1AuditLog:
        """Log that email was deduplicated (skipped)"""
        return await self._log(
            event_type=AuditEventType.EMAIL_DEDUPLICATED,
            job_id=job_id,
            message=f"Email deduplicated via {match_type} match",
            target_type="email",
            email_message_id=message_id,
            verdict=cached_verdict,
            score=cached_score,
            details={
                "original_analysis_id": original_analysis_id,
                "match_type": match_type,
                "action": "skipped_reused_result"
            }
        )
    
    # ═══════════════════════════════════════════════════════════════════════
    # ANALYSIS EVENTS
    # ═══════════════════════════════════════════════════════════════════════
    
    async def log_analysis_started(
        self,
        job_id: str,
        tenant_id: Optional[str],
        message_id: str
    ) -> Mode1AuditLog:
        """Log analysis started"""
        return await self._log(
            event_type=AuditEventType.ANALYSIS_STARTED,
            job_id=job_id,
            message="Phishing analysis started",
            tenant_id=tenant_id,
            target_type="analysis",
            target_id=job_id,
            email_message_id=message_id
        )
    
    async def log_analysis_completed(
        self,
        job_id: str,
        tenant_id: Optional[str],
        message_id: str,
        verdict: str,
        score: float,
        confidence: float,
        risk_factors: List[str],
        module_scores: Dict[str, float]
    ) -> Mode1AuditLog:
        """Log analysis completed with results"""
        return await self._log(
            event_type=AuditEventType.ANALYSIS_COMPLETED,
            job_id=job_id,
            message=f"Analysis completed: {verdict} (score: {score:.0f})",
            tenant_id=tenant_id,
            target_type="analysis",
            target_id=job_id,
            email_message_id=message_id,
            verdict=verdict,
            score=score,
            confidence=confidence,
            details={
                "risk_factors": risk_factors,
                "module_scores": module_scores
            }
        )
    
    async def log_analysis_failed(
        self,
        job_id: str,
        tenant_id: Optional[str],
        message_id: str,
        error: str,
        error_type: str
    ) -> Mode1AuditLog:
        """Log analysis failure"""
        return await self._log(
            event_type=AuditEventType.ANALYSIS_FAILED,
            job_id=job_id,
            message=f"Analysis failed: {error_type}",
            severity=AuditSeverity.ERROR,
            tenant_id=tenant_id,
            target_type="analysis",
            target_id=job_id,
            email_message_id=message_id,
            details={"error": error, "error_type": error_type}
        )
    
    # ═══════════════════════════════════════════════════════════════════════
    # POLICY EVENTS
    # ═══════════════════════════════════════════════════════════════════════
    
    async def log_policy_evaluated(
        self,
        job_id: str,
        tenant_id: Optional[str],
        policy_name: str,
        matched: bool,
        conditions: Dict[str, Any]
    ) -> Mode1AuditLog:
        """Log policy evaluation"""
        return await self._log(
            event_type=AuditEventType.POLICY_EVALUATED,
            job_id=job_id,
            message=f"Policy '{policy_name}' {'matched' if matched else 'did not match'}",
            tenant_id=tenant_id,
            target_type="policy",
            target_id=policy_name,
            policy_name=policy_name,
            details={"matched": matched, "conditions": conditions}
        )
    
    async def log_policy_executed(
        self,
        job_id: str,
        tenant_id: Optional[str],
        policy_name: str,
        actions: List[str],
        action_results: Dict[str, bool]
    ) -> Mode1AuditLog:
        """Log policy actions executed"""
        return await self._log(
            event_type=AuditEventType.POLICY_EXECUTED,
            job_id=job_id,
            message=f"Policy '{policy_name}' executed: {', '.join(actions)}",
            tenant_id=tenant_id,
            target_type="policy",
            target_id=policy_name,
            policy_name=policy_name,
            actions_taken=actions,
            details={"action_results": action_results}
        )
    
    # ═══════════════════════════════════════════════════════════════════════
    # ACTION EVENTS
    # ═══════════════════════════════════════════════════════════════════════
    
    async def log_reply_sent(
        self,
        job_id: str,
        tenant_id: Optional[str],
        recipient: str,
        verdict: str,
        success: bool
    ) -> Mode1AuditLog:
        """Log email reply sent to user"""
        return await self._log(
            event_type=AuditEventType.ACTION_REPLY_SENT,
            job_id=job_id,
            message=f"Analysis reply {'sent' if success else 'failed'} to {recipient}",
            severity=AuditSeverity.INFO if success else AuditSeverity.WARNING,
            tenant_id=tenant_id,
            target_type="email",
            email_recipient=recipient,
            verdict=verdict,
            actions_taken=["reply_user"],
            details={"success": success}
        )
    
    async def log_quarantine(
        self,
        job_id: str,
        tenant_id: Optional[str],
        message_id: str,
        success: bool,
        quarantine_location: Optional[str] = None
    ) -> Mode1AuditLog:
        """Log email quarantined"""
        return await self._log(
            event_type=AuditEventType.ACTION_QUARANTINE,
            job_id=job_id,
            message=f"Email {'quarantined' if success else 'quarantine failed'}",
            severity=AuditSeverity.INFO if success else AuditSeverity.WARNING,
            tenant_id=tenant_id,
            target_type="email",
            email_message_id=message_id,
            actions_taken=["quarantine"],
            details={"success": success, "location": quarantine_location}
        )
    
    async def log_soc_notified(
        self,
        job_id: str,
        tenant_id: Optional[str],
        notification_channel: str,
        recipient: str,
        success: bool
    ) -> Mode1AuditLog:
        """Log SOC notification"""
        return await self._log(
            event_type=AuditEventType.ACTION_SOC_NOTIFIED,
            job_id=job_id,
            message=f"SOC notified via {notification_channel}",
            tenant_id=tenant_id,
            target_type="soc",
            actions_taken=["notify_soc"],
            details={
                "channel": notification_channel,
                "recipient": recipient,
                "success": success
            }
        )
    
    # ═══════════════════════════════════════════════════════════════════════
    # ANALYST EVENTS
    # ═══════════════════════════════════════════════════════════════════════
    
    async def log_analyst_override(
        self,
        job_id: str,
        analyst_id: str,
        analyst_email: str,
        original_verdict: str,
        new_verdict: str,
        reason: str
    ) -> Mode1AuditLog:
        """Log analyst verdict override"""
        return await self._log(
            event_type=AuditEventType.ANALYST_OVERRIDE,
            job_id=job_id,
            message=f"Analyst overrode verdict: {original_verdict} → {new_verdict}",
            severity=AuditSeverity.WARNING,
            actor_type="analyst",
            actor_id=analyst_id,
            actor_email=analyst_email,
            target_type="analysis",
            target_id=job_id,
            verdict=new_verdict,
            details={
                "original_verdict": original_verdict,
                "override_reason": reason
            }
        )
    
    async def log_false_positive(
        self,
        job_id: str,
        reporter_id: str,
        reporter_email: str,
        original_verdict: str,
        feedback: str
    ) -> Mode1AuditLog:
        """Log false positive report"""
        return await self._log(
            event_type=AuditEventType.FALSE_POSITIVE_REPORTED,
            job_id=job_id,
            message=f"False positive reported for {original_verdict} verdict",
            severity=AuditSeverity.WARNING,
            actor_type="user",
            actor_id=reporter_id,
            actor_email=reporter_email,
            target_type="analysis",
            target_id=job_id,
            verdict=original_verdict,
            details={"feedback": feedback}
        )
    
    # ═══════════════════════════════════════════════════════════════════════
    # SYSTEM EVENTS
    # ═══════════════════════════════════════════════════════════════════════
    
    async def log_system_error(
        self,
        job_id: str,
        error: str,
        component: str,
        recoverable: bool
    ) -> Mode1AuditLog:
        """Log system error"""
        return await self._log(
            event_type=AuditEventType.SYSTEM_ERROR,
            job_id=job_id,
            message=f"System error in {component}: {error[:100]}",
            severity=AuditSeverity.ERROR if recoverable else AuditSeverity.CRITICAL,
            target_type="system",
            target_id=component,
            details={
                "error": error,
                "component": component,
                "recoverable": recoverable
            }
        )
    
    async def log_rate_limit(
        self,
        job_id: str,
        service: str,
        limit_type: str,
        retry_after: Optional[int] = None
    ) -> Mode1AuditLog:
        """Log rate limit hit"""
        return await self._log(
            event_type=AuditEventType.RATE_LIMIT_HIT,
            job_id=job_id,
            message=f"Rate limit hit on {service} ({limit_type})",
            severity=AuditSeverity.WARNING,
            target_type="external_service",
            target_id=service,
            details={
                "service": service,
                "limit_type": limit_type,
                "retry_after_seconds": retry_after
            }
        )
    
    # ═══════════════════════════════════════════════════════════════════════
    # QUERY METHODS
    # ═══════════════════════════════════════════════════════════════════════
    
    async def get_job_audit_trail(self, job_id: str) -> List[Mode1AuditLog]:
        """Get complete audit trail for a job"""
        return await Mode1AuditLog.find(
            Mode1AuditLog.job_id == job_id
        ).sort("+sequence_id").to_list()
    
    async def get_tenant_audit_trail(
        self,
        tenant_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[AuditEventType]] = None,
        limit: int = 1000
    ) -> List[Mode1AuditLog]:
        """Get audit trail for a tenant with filters"""
        query = {"tenant_id": tenant_id}
        
        if start_time or end_time:
            query["timestamp"] = {}
            if start_time:
                query["timestamp"]["$gte"] = start_time
            if end_time:
                query["timestamp"]["$lte"] = end_time
        
        if event_types:
            query["event_type"] = {"$in": [e.value for e in event_types]}
        
        return await Mode1AuditLog.find(query).sort("-sequence_id").limit(limit).to_list()
    
    async def verify_chain_integrity(self, limit: int = 1000) -> Dict[str, Any]:
        """Verify hash chain integrity (tamper detection)"""
        entries = await Mode1AuditLog.find().sort("+sequence_id").limit(limit).to_list()
        
        if not entries:
            return {"verified": True, "entries_checked": 0, "errors": []}
        
        errors = []
        expected_prev_hash = "GENESIS"
        
        for entry in entries:
            # Check previous hash chain
            if entry.previous_hash != expected_prev_hash:
                errors.append({
                    "sequence_id": entry.sequence_id,
                    "error": "previous_hash_mismatch",
                    "expected": expected_prev_hash,
                    "actual": entry.previous_hash
                })
            
            # Recompute and verify entry hash
            computed_hash = self._compute_entry_hash(entry)
            if entry.entry_hash != computed_hash:
                errors.append({
                    "sequence_id": entry.sequence_id,
                    "error": "entry_hash_mismatch",
                    "expected": computed_hash,
                    "actual": entry.entry_hash
                })
            
            expected_prev_hash = entry.entry_hash
        
        return {
            "verified": len(errors) == 0,
            "entries_checked": len(entries),
            "errors": errors
        }


# Singleton instance
_audit_logger: Optional[Mode1AuditLogger] = None


def get_mode1_audit_logger() -> Mode1AuditLogger:
    """Get singleton audit logger"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = Mode1AuditLogger()
    return _audit_logger
