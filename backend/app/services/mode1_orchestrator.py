"""
Enterprise Mode 1 Orchestrator
==============================
The complete enterprise-grade automatic email processing pipeline.

This is the MAIN orchestrator for Mode 1 (automatic IMAP ingestion).

Pipeline Flow:
1. IMAP Polling (per-tenant mailboxes)
2. Deduplication Check
3. Parse & Normalize
4. Analysis (5 parallel modules)
5. Threat Aggregation
6. Verdict Arbitration
7. Policy Evaluation
8. Action Execution
9. Audit Logging
10. Notification/Response

Enterprise Features:
- Multi-tenant isolation
- Deduplication (hash-based)
- Policy-driven actions
- Immutable audit trail
- Circuit breakers & rate limiting
- Backpressure handling
"""

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, Optional, List, Tuple

from app.config.logging import get_logger
from app.config.settings import get_settings

# Core services
from app.services.quick_imap import QuickIMAPService
from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer, ComprehensivePhishingAnalysis
from app.services.gemini import GeminiClient
from app.services.email_sender import send_email

# Enterprise services
from app.services.deduplication import (
    get_deduplication_service, 
    DedupResult, 
    DedupCheckResult
)
from app.services.mode1_audit import (
    get_mode1_audit_logger,
    AuditEventType
)
from app.services.tenant_mailbox import (
    get_tenant_mailbox_service,
    MailboxConfig,
    MailboxStatus
)
from app.services.policy_engine import (
    get_policy_engine,
    PolicyEvalMode
)
from app.services.worker_resilience import (
    get_resilience_manager,
    CircuitBreakerOpen,
    RateLimitExceeded,
    BackpressureFull,
    BulkheadFull,
    retry_with_backoff,
    RetryConfig
)

# Models
from app.models.mongodb_models import ForwardedEmailAnalysis
from app.models.tenant import Tenant, PolicyAction

settings = get_settings()
logger = get_logger(__name__)


class Mode1JobStatus(str, Enum):
    """Job status for Mode 1 pipeline"""
    QUEUED = "queued"
    DEDUP_CHECK = "dedup_check"
    PARSING = "parsing"
    ANALYZING = "analyzing"
    AGGREGATING = "aggregating"
    POLICY_EVAL = "policy_eval"
    EXECUTING = "executing"
    COMPLETED = "completed"
    SKIPPED = "skipped"       # Deduplicated
    FAILED = "failed"


@dataclass
class Mode1Job:
    """Represents a single email processing job"""
    job_id: str
    tenant_id: str
    mail_uid: str
    
    # Email metadata (populated after parsing)
    message_id: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    
    # Status tracking
    status: Mode1JobStatus = Mode1JobStatus.QUEUED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    
    # Results
    dedup_result: Optional[DedupCheckResult] = None
    analysis_result: Optional[ComprehensivePhishingAnalysis] = None
    policy_actions: List[str] = field(default_factory=list)
    
    # Timing
    timing: Dict[str, float] = field(default_factory=dict)
    
    # Error tracking
    error: Optional[str] = None
    error_stage: Optional[str] = None
    
    @property
    def total_duration_ms(self) -> float:
        return sum(self.timing.values())


class Mode1Orchestrator:
    """
    Enterprise Mode 1 Orchestrator.
    
    Coordinates the complete automatic email processing pipeline
    with enterprise-grade reliability and multi-tenant support.
    """
    
    def __init__(self):
        # Core services
        self.phishing_analyzer = EnhancedPhishingAnalyzer()
        self.gemini_client = GeminiClient()
        
        # Enterprise services
        self.dedup_service = get_deduplication_service()
        self.audit_logger = get_mode1_audit_logger()
        self.mailbox_service = get_tenant_mailbox_service()
        self.policy_engine = get_policy_engine()
        self.resilience = get_resilience_manager()
        
        # Job tracking
        self._active_jobs: Dict[str, Mode1Job] = {}
        
        # Polling state
        self._is_running = False
        self._poll_tasks: Dict[str, asyncio.Task] = {}
    
    # ═══════════════════════════════════════════════════════════════════════
    # MAIN ENTRY POINT
    # ═══════════════════════════════════════════════════════════════════════
    
    async def start_all_mailbox_polling(self):
        """Start polling all active tenant mailboxes"""
        if self._is_running:
            logger.warning("Mode1 Orchestrator already running")
            return
        
        self._is_running = True
        logger.info("Starting Mode 1 Enterprise Orchestrator")
        
        # Get all active mailboxes
        mailboxes = await self.mailbox_service.get_all_active_mailboxes()
        
        if not mailboxes:
            # Fallback to default IMAP if no tenant mailboxes configured
            logger.info("No tenant mailboxes configured, using default IMAP settings")
            await self._poll_default_mailbox()
        else:
            # Start a polling task for each tenant
            for mailbox in mailboxes:
                task = asyncio.create_task(
                    self._poll_tenant_mailbox(mailbox)
                )
                self._poll_tasks[mailbox.tenant_id] = task
                logger.info(f"Started polling for tenant: {mailbox.tenant_id}")
    
    async def stop_all_polling(self):
        """Stop all polling tasks"""
        self._is_running = False
        
        for tenant_id, task in self._poll_tasks.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            logger.info(f"Stopped polling for tenant: {tenant_id}")
        
        self._poll_tasks.clear()
        logger.info("Mode 1 Orchestrator stopped")
    
    # ═══════════════════════════════════════════════════════════════════════
    # MAILBOX POLLING
    # ═══════════════════════════════════════════════════════════════════════
    
    async def _poll_default_mailbox(self):
        """Poll the default IMAP mailbox (non-multi-tenant mode)"""
        if not getattr(settings, 'IMAP_ENABLED', False):
            logger.info("IMAP disabled in settings")
            return
        
        poll_interval = getattr(settings, 'IMAP_POLL_INTERVAL', 60)
        
        while self._is_running:
            try:
                await self._execute_poll_cycle(
                    tenant_id="default",
                    imap_service=QuickIMAPService()
                )
            except Exception as e:
                logger.error(f"Error in default mailbox polling: {e}")
            
            await asyncio.sleep(poll_interval)
    
    async def _poll_tenant_mailbox(self, mailbox: MailboxConfig):
        """Poll a specific tenant's mailbox"""
        while self._is_running:
            try:
                # Check circuit breaker for IMAP
                cb = self.resilience.get_circuit_breaker("imap")
                if cb.is_open:
                    logger.warning(f"IMAP circuit open for {mailbox.tenant_id}, skipping poll")
                    await asyncio.sleep(mailbox.poll_interval_seconds)
                    continue
                
                # Create tenant-specific IMAP service
                imap_service = self._create_tenant_imap(mailbox)
                
                start_time = time.monotonic()
                
                await self._execute_poll_cycle(
                    tenant_id=mailbox.tenant_id,
                    imap_service=imap_service
                )
                
                # Record success
                elapsed_ms = (time.monotonic() - start_time) * 1000
                await self.mailbox_service.record_poll_success(
                    mailbox.tenant_id,
                    emails_processed=0,  # Updated in execute
                    processing_time_ms=elapsed_ms
                )
                
            except Exception as e:
                logger.error(f"Error polling {mailbox.tenant_id}: {e}")
                await self.mailbox_service.record_poll_error(
                    mailbox.tenant_id,
                    str(e)
                )
            
            await asyncio.sleep(mailbox.poll_interval_seconds)
    
    def _create_tenant_imap(self, mailbox: MailboxConfig) -> QuickIMAPService:
        """Create IMAP service for a specific tenant"""
        # Create a custom IMAP service with tenant credentials
        service = QuickIMAPService()
        service.host = mailbox.imap_host
        service.user = mailbox.imap_user
        service.password = mailbox.imap_password
        service.folder = mailbox.imap_folder
        return service
    
    # ═══════════════════════════════════════════════════════════════════════
    # POLL CYCLE EXECUTION
    # ═══════════════════════════════════════════════════════════════════════
    
    async def _execute_poll_cycle(
        self, 
        tenant_id: str, 
        imap_service: QuickIMAPService
    ):
        """Execute a single poll cycle for a tenant"""
        
        # Check backpressure
        if not await self.resilience.backpressure.try_acquire():
            logger.warning(f"Backpressure active, skipping poll for {tenant_id}")
            return
        
        try:
            # Acquire tenant bulkhead
            try:
                await self.resilience.bulkhead.acquire(tenant_id, timeout=5.0)
            except BulkheadFull:
                logger.warning(f"Tenant {tenant_id} bulkhead full, skipping")
                return
            
            try:
                # Fetch recent emails with circuit breaker
                cb = self.resilience.get_circuit_breaker("imap")
                emails = await cb.execute(
                    asyncio.to_thread,
                    imap_service.get_recent_emails,
                    getattr(settings, 'IMAP_BATCH_SIZE', 50)
                )
                
                if not emails:
                    return
                
                logger.info(f"[{tenant_id}] Found {len(emails)} emails to check")
                
                # Process each email
                for email_meta in emails:
                    try:
                        job = await self.process_email(
                            tenant_id=tenant_id,
                            mail_uid=email_meta['uid'],
                            message_id=email_meta.get('message_id'),
                            imap_service=imap_service
                        )
                        
                        # Apply backpressure delay
                        delay = self.resilience.backpressure.get_delay()
                        if delay > 0:
                            await asyncio.sleep(delay)
                            
                    except Exception as e:
                        logger.error(f"Failed to process email {email_meta.get('uid')}: {e}")
                        
            finally:
                await self.resilience.bulkhead.release(tenant_id)
                
        finally:
            await self.resilience.backpressure.release()
    
    # ═══════════════════════════════════════════════════════════════════════
    # EMAIL PROCESSING PIPELINE
    # ═══════════════════════════════════════════════════════════════════════
    
    async def process_email(
        self,
        tenant_id: str,
        mail_uid: str,
        message_id: Optional[str],
        imap_service: QuickIMAPService
    ) -> Mode1Job:
        """
        Process a single email through the complete Mode 1 pipeline.
        
        Steps:
        1. Deduplication check
        2. Fetch & parse email
        3. Run analysis modules
        4. Evaluate policies
        5. Execute actions
        6. Audit logging
        """
        # Create job
        job = Mode1Job(
            job_id=self._generate_job_id(mail_uid),
            tenant_id=tenant_id,
            mail_uid=mail_uid,
            message_id=message_id
        )
        self._active_jobs[job.job_id] = job
        
        try:
            # ═══════════════════════════════════════════════════════════════
            # STEP 1: DEDUPLICATION CHECK
            # ═══════════════════════════════════════════════════════════════
            job.status = Mode1JobStatus.DEDUP_CHECK
            start = time.monotonic()
            
            if message_id:
                dedup_result = await self.dedup_service.check(
                    message_id=message_id,
                    tenant_id=tenant_id
                )
                job.dedup_result = dedup_result
                
                if dedup_result.status == DedupResult.DUPLICATE:
                    # Skip - already analyzed
                    job.status = Mode1JobStatus.SKIPPED
                    job.completed_at = datetime.now(timezone.utc)
                    
                    await self.audit_logger.log_email_deduplicated(
                        job_id=job.job_id,
                        message_id=message_id,
                        original_analysis_id=dedup_result.original_analysis_id or "",
                        match_type=dedup_result.match_type or "message_id",
                        cached_verdict=dedup_result.original_verdict or "UNKNOWN",
                        cached_score=dedup_result.original_score or 0.0
                    )
                    
                    logger.info(f"[Job {job.job_id}] Deduplicated via {dedup_result.match_type}")
                    return job
            
            job.timing["dedup"] = (time.monotonic() - start) * 1000
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 2: FETCH & PARSE EMAIL
            # ═══════════════════════════════════════════════════════════════
            job.status = Mode1JobStatus.PARSING
            start = time.monotonic()
            
            email_data = await asyncio.to_thread(
                imap_service.fetch_email_for_analysis, 
                mail_uid
            )
            
            if not email_data:
                raise ValueError(f"Could not fetch email {mail_uid}")
            
            job.message_id = email_data.get('message_id', message_id)
            job.subject = email_data.get('subject', 'No Subject')
            job.sender = email_data.get('from', 'Unknown')
            job.recipient = email_data.get('forwarded_by', '')
            
            job.timing["parse"] = (time.monotonic() - start) * 1000
            
            # Audit: Email received
            await self.audit_logger.log_email_received(
                job_id=job.job_id,
                tenant_id=tenant_id,
                tenant_domain=email_data.get('org_domain'),
                message_id=job.message_id or "",
                subject=job.subject,
                sender=job.sender,
                recipient=job.recipient,
                mail_uid=mail_uid
            )
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 3: ANALYSIS
            # ═══════════════════════════════════════════════════════════════
            job.status = Mode1JobStatus.ANALYZING
            start = time.monotonic()
            
            raw_email = email_data.get('raw_email')
            if not raw_email:
                raise ValueError("No raw email content for analysis")
            
            # Audit: Analysis started
            await self.audit_logger.log_analysis_started(
                job_id=job.job_id,
                tenant_id=tenant_id,
                message_id=job.message_id or ""
            )
            
            # Run analysis (thread pool for CPU-bound work)
            analysis_result = await asyncio.to_thread(
                self.phishing_analyzer.analyze_email,
                raw_email
            )
            job.analysis_result = analysis_result
            
            job.timing["analysis"] = (time.monotonic() - start) * 1000
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 4: THREAT INTEL ENHANCEMENT (with circuit breaker)
            # ═══════════════════════════════════════════════════════════════
            start = time.monotonic()
            
            try:
                vt_cb = self.resilience.get_circuit_breaker("virustotal")
                vt_limiter = self.resilience.get_rate_limiter("virustotal")
                
                await vt_limiter.acquire(timeout=5.0)
                
                await vt_cb.execute(
                    self.phishing_analyzer.enhance_with_threat_intel,
                    analysis_result
                )
            except (CircuitBreakerOpen, RateLimitExceeded) as e:
                logger.warning(f"[Job {job.job_id}] Threat intel skipped: {e}")
            except Exception as e:
                logger.warning(f"[Job {job.job_id}] Threat intel failed: {e}")
            
            job.timing["threat_intel"] = (time.monotonic() - start) * 1000
            
            # Audit: Analysis completed
            module_scores = {
                "sender": analysis_result.sender.score,
                "content": analysis_result.content.score,
                "links": analysis_result.links.overall_score,
                "authentication": analysis_result.authentication.overall_score,
                "attachments": analysis_result.attachments.score
            }
            
            await self.audit_logger.log_analysis_completed(
                job_id=job.job_id,
                tenant_id=tenant_id,
                message_id=job.message_id or "",
                verdict=analysis_result.final_verdict,
                score=float(analysis_result.total_score),
                confidence=analysis_result.confidence,
                risk_factors=analysis_result.risk_factors,
                module_scores=module_scores
            )
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 5: STORE ANALYSIS & DEDUP ENTRY
            # ═══════════════════════════════════════════════════════════════
            start = time.monotonic()
            
            # Create analysis document
            analysis_doc = ForwardedEmailAnalysis(
                user_id=job.recipient,
                forwarded_by=job.recipient,
                org_domain=email_data.get('org_domain', tenant_id),
                original_sender=job.sender,
                original_subject=job.subject,
                threat_score=float(analysis_result.total_score) / 100.0,
                risk_level=analysis_result.final_verdict,
                analysis_result={
                    "verdict": analysis_result.final_verdict,
                    "score": analysis_result.total_score,
                    "confidence": analysis_result.confidence,
                    "risk_factors": analysis_result.risk_factors,
                    "module_scores": module_scores
                },
                email_metadata={
                    "uid": mail_uid,
                    "message_id": job.message_id,
                    "subject": job.subject
                },
                reply_sent=False
            )
            await analysis_doc.save()
            
            # Store in dedup cache
            urls = [link.get('url', '') for link in email_data.get('links', [])]
            body_text = email_data.get('body_text', '')
            
            await self.dedup_service.store(
                analysis_id=str(analysis_doc.id),
                verdict=analysis_result.final_verdict,
                score=float(analysis_result.total_score),
                confidence=analysis_result.confidence,
                message_id=job.message_id,
                urls=urls if urls else None,
                content=body_text if body_text else None,
                tenant_id=tenant_id,
                subject=job.subject,
                sender=job.sender
            )
            
            job.timing["storage"] = (time.monotonic() - start) * 1000
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 6: POLICY EVALUATION
            # ═══════════════════════════════════════════════════════════════
            job.status = Mode1JobStatus.POLICY_EVAL
            start = time.monotonic()
            
            # Resolve tenant
            tenant = await self._resolve_tenant(tenant_id, email_data.get('org_domain'))
            
            # Evaluate policies
            policy_decisions = await self.policy_engine.evaluate(
                tenant=tenant,
                analysis=analysis_doc,
                job_id=job.job_id
            )
            
            # Collect all actions
            all_actions = set()
            for decision in policy_decisions:
                for action in decision.actions_taken:
                    all_actions.add(action)
                
                # Audit each policy evaluation
                await self.audit_logger.log_policy_evaluated(
                    job_id=job.job_id,
                    tenant_id=tenant_id,
                    policy_name=decision.rule_name,
                    matched=True,
                    conditions={}  # Simplified for now
                )
            
            job.policy_actions = list(all_actions)
            job.timing["policy"] = (time.monotonic() - start) * 1000
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 7: EXECUTE ACTIONS
            # ═══════════════════════════════════════════════════════════════
            job.status = Mode1JobStatus.EXECUTING
            start = time.monotonic()
            
            action_results = {}
            
            for action in job.policy_actions:
                try:
                    if action == PolicyAction.REPLY_USER.value:
                        success = await self._send_analysis_reply(job, analysis_result)
                        action_results["reply_user"] = success
                        
                        if success:
                            analysis_doc.reply_sent = True
                            analysis_doc.reply_sent_at = datetime.now(timezone.utc)
                            await analysis_doc.save()
                            
                            await self.audit_logger.log_reply_sent(
                                job_id=job.job_id,
                                tenant_id=tenant_id,
                                recipient=job.recipient,
                                verdict=analysis_result.final_verdict,
                                success=True
                            )
                    
                    elif action == PolicyAction.NOTIFY_SOC.value:
                        # TODO: Implement SOC notification
                        logger.info(f"[Job {job.job_id}] SOC notification triggered")
                        action_results["notify_soc"] = True
                        
                        await self.audit_logger.log_soc_notified(
                            job_id=job.job_id,
                            tenant_id=tenant_id,
                            notification_channel="pending",
                            recipient="soc@tenant.com",
                            success=True
                        )
                    
                    elif action == PolicyAction.QUARANTINE.value:
                        # TODO: Implement quarantine
                        logger.info(f"[Job {job.job_id}] Quarantine triggered")
                        action_results["quarantine"] = True
                        
                        await self.audit_logger.log_quarantine(
                            job_id=job.job_id,
                            tenant_id=tenant_id,
                            message_id=job.message_id or "",
                            success=True
                        )
                        
                except Exception as e:
                    logger.error(f"[Job {job.job_id}] Action {action} failed: {e}")
                    action_results[action] = False
            
            # Audit policy execution
            await self.audit_logger.log_policy_executed(
                job_id=job.job_id,
                tenant_id=tenant_id,
                policy_name="aggregated",
                actions=job.policy_actions,
                action_results=action_results
            )
            
            job.timing["actions"] = (time.monotonic() - start) * 1000
            
            # ═══════════════════════════════════════════════════════════════
            # COMPLETE
            # ═══════════════════════════════════════════════════════════════
            job.status = Mode1JobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            
            logger.info(
                f"[Job {job.job_id}] Completed: "
                f"verdict={analysis_result.final_verdict}, "
                f"score={analysis_result.total_score}, "
                f"duration={job.total_duration_ms:.0f}ms"
            )
            
            return job
            
        except Exception as e:
            job.status = Mode1JobStatus.FAILED
            job.error = str(e)
            job.error_stage = job.status.value
            job.completed_at = datetime.now(timezone.utc)
            
            # Audit failure
            await self.audit_logger.log_analysis_failed(
                job_id=job.job_id,
                tenant_id=tenant_id,
                message_id=job.message_id or "",
                error=str(e),
                error_type=type(e).__name__
            )
            
            logger.error(f"[Job {job.job_id}] Failed at {job.error_stage}: {e}")
            raise
        
        finally:
            # Cleanup
            if job.job_id in self._active_jobs:
                del self._active_jobs[job.job_id]
    
    # ═══════════════════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════════════════
    
    def _generate_job_id(self, mail_uid: str) -> str:
        """Generate unique job ID"""
        timestamp = datetime.now(timezone.utc).isoformat()
        return hashlib.sha256(f"{mail_uid}:{timestamp}".encode()).hexdigest()[:16]
    
    async def _resolve_tenant(self, tenant_id: str, domain: Optional[str]) -> Tenant:
        """Resolve tenant from ID or domain"""
        if tenant_id != "default":
            tenant = await Tenant.find_one(Tenant.domain == tenant_id)
            if tenant:
                return tenant
        
        if domain:
            tenant = await Tenant.find_one(Tenant.domain == domain)
            if tenant:
                return tenant
        
        # Return default tenant
        return Tenant(
            name="Default",
            domain="default",
            admin_email="admin@phishnet.ai"
        )
    
    async def _send_analysis_reply(
        self, 
        job: Mode1Job, 
        analysis: ComprehensivePhishingAnalysis
    ) -> bool:
        """Send analysis reply email to user"""
        try:
            # Rate limit email sending
            limiter = self.resilience.get_rate_limiter("email_send")
            await limiter.acquire(timeout=10.0)
            
            # Build email content
            verdict_display = {
                "PHISHING": "🚨 PHISHING DETECTED",
                "SUSPICIOUS": "⚠️ SUSPICIOUS",
                "SAFE": "✅ SAFE"
            }
            
            verdict = analysis.final_verdict
            
            body = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHISHNET ANALYSIS REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUBJECT: {job.subject}
FROM: {job.sender}

VERDICT: {verdict_display.get(verdict, verdict)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TECHNICAL DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Risk Score: {analysis.total_score}/100 (lower = more dangerous)
Confidence: {analysis.confidence:.0%}

Module Scores:
  • Sender Analysis:     {analysis.sender.score}/100
  • Content Analysis:    {analysis.content.score}/100
  • Link Analysis:       {analysis.links.overall_score}/100
  • Authentication:      {analysis.authentication.overall_score}/100
  • Attachment Analysis: {analysis.attachments.score}/100

Authentication Results:
  • SPF:   {analysis.authentication.spf_result.upper()}
  • DKIM:  {analysis.authentication.dkim_result.upper()}
  • DMARC: {analysis.authentication.dmarc_result.upper()}

Risk Factors:
{chr(10).join(['  • ' + rf for rf in analysis.risk_factors]) if analysis.risk_factors else '  • None identified'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This is an automated analysis by PhishNet.
Job ID: {job.job_id}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            
            subject = f"PhishNet Analysis: {verdict_display.get(verdict, verdict)} — {job.subject[:50]}"
            
            success = await send_email(
                to=job.recipient,
                subject=subject,
                body=body
            )
            
            return success
            
        except Exception as e:
            logger.error(f"[Job {job.job_id}] Failed to send reply: {e}")
            return False
    
    # ═══════════════════════════════════════════════════════════════════════
    # STATUS & MONITORING
    # ═══════════════════════════════════════════════════════════════════════
    
    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        return {
            "running": self._is_running,
            "active_jobs": len(self._active_jobs),
            "polling_tasks": list(self._poll_tasks.keys()),
            "resilience": self.resilience.get_health_status()
        }
    
    async def get_stats(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Get processing statistics"""
        dedup_stats = await self.dedup_service.get_stats(tenant_id)
        policy_stats = await self.policy_engine.get_policy_summary(
            tenant_id or "default"
        ) if tenant_id else {}
        
        return {
            "deduplication": dedup_stats,
            "policy": policy_stats,
            "resilience": self.resilience.get_health_status()
        }


# Singleton instance
_mode1_orchestrator: Optional[Mode1Orchestrator] = None


def get_mode1_orchestrator() -> Mode1Orchestrator:
    """Get singleton Mode 1 orchestrator"""
    global _mode1_orchestrator
    if _mode1_orchestrator is None:
        _mode1_orchestrator = Mode1Orchestrator()
    return _mode1_orchestrator
