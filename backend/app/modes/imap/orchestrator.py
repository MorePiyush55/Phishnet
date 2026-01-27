"""
IMAP Mode Orchestrator - Mode 1 (Bulk Forward)
==============================================
Coordinates the complete IMAP email processing pipeline.

This orchestrator handles the automatic email processing workflow:
1. Poll IMAP inbox for new emails
2. Check for duplicates
3. Parse and normalize email
4. Run phishing analysis
5. Apply organizational policies
6. Store results
7. Send notification/response to user

Enterprise Features:
- Multi-tenant support
- Deduplication (hash-based)
- Policy-driven actions
- Audit logging
- Circuit breakers & rate limiting
"""

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from enum import Enum

from app.modes.base import (
    ModeOrchestrator,
    AnalysisRequest,
    AnalysisResult,
    AnalysisStatus,
    Verdict,
    EmailMetadata,
    ModeType,
)
from app.modes.imap.service import IMAPEmailService, get_imap_service
from app.config.settings import get_settings
from app.config.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)


class IMAPJobStatus(str, Enum):
    """Status of an IMAP processing job."""
    QUEUED = "queued"
    DEDUP_CHECK = "dedup_check"
    FETCHING = "fetching"
    PARSING = "parsing"
    ANALYZING = "analyzing"
    POLICY_EVAL = "policy_eval"
    STORING = "storing"
    NOTIFYING = "notifying"
    COMPLETED = "completed"
    SKIPPED = "skipped"  # Deduplicated
    FAILED = "failed"


@dataclass
class IMAPJob:
    """Represents a single IMAP email processing job."""
    job_id: str
    mail_uid: str
    tenant_id: str = "default"
    
    # Email metadata (populated after parsing)
    message_id: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    forwarded_by: Optional[str] = None
    
    # Status tracking
    status: IMAPJobStatus = IMAPJobStatus.QUEUED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    
    # Results
    verdict: Optional[Verdict] = None
    score: float = 0.0
    confidence: float = 0.0
    analysis_details: Dict[str, Any] = field(default_factory=dict)
    
    # Timing
    timing: Dict[str, float] = field(default_factory=dict)
    
    # Error tracking
    error: Optional[str] = None
    error_stage: Optional[str] = None
    
    def to_result(self) -> AnalysisResult:
        """Convert job to AnalysisResult."""
        return AnalysisResult(
            request_id=self.job_id,
            mode=ModeType.IMAP_BULK,
            status=self._map_status(),
            verdict=self.verdict or Verdict.UNKNOWN,
            score=self.score,
            confidence=self.confidence,
            email_metadata=EmailMetadata(
                message_id=self.message_id or "",
                subject=self.subject or "",
                sender=self.sender or "",
                recipients=[],
            ) if self.message_id else None,
            details=self.analysis_details,
            started_at=self.created_at,
            completed_at=self.completed_at,
            duration_ms=int(sum(self.timing.values()) * 1000),
            error=self.error,
            error_stage=self.error_stage,
        )
    
    def _map_status(self) -> AnalysisStatus:
        """Map IMAP job status to generic AnalysisStatus."""
        status_map = {
            IMAPJobStatus.QUEUED: AnalysisStatus.PENDING,
            IMAPJobStatus.DEDUP_CHECK: AnalysisStatus.PENDING,
            IMAPJobStatus.FETCHING: AnalysisStatus.FETCHING,
            IMAPJobStatus.PARSING: AnalysisStatus.FETCHING,
            IMAPJobStatus.ANALYZING: AnalysisStatus.ANALYZING,
            IMAPJobStatus.POLICY_EVAL: AnalysisStatus.ANALYZING,
            IMAPJobStatus.STORING: AnalysisStatus.ANALYZING,
            IMAPJobStatus.NOTIFYING: AnalysisStatus.ANALYZING,
            IMAPJobStatus.COMPLETED: AnalysisStatus.COMPLETED,
            IMAPJobStatus.SKIPPED: AnalysisStatus.SKIPPED,
            IMAPJobStatus.FAILED: AnalysisStatus.FAILED,
        }
        return status_map.get(self.status, AnalysisStatus.PENDING)


class IMAPOrchestrator(ModeOrchestrator):
    """
    Orchestrator for Mode 1 (IMAP Bulk Forward).
    
    This class coordinates the complete automatic email processing pipeline
    with enterprise-grade reliability.
    
    Pipeline Steps:
    1. Receive email UID (from poll or manual trigger)
    2. Check deduplication (skip if already processed)
    3. Fetch email from IMAP
    4. Parse and extract content
    5. Run phishing analysis
    6. Apply organizational policies
    7. Store analysis results
    8. Send notification to user who forwarded
    """
    
    def __init__(self, imap_service: IMAPEmailService = None):
        """
        Initialize IMAP orchestrator.
        
        Args:
            imap_service: Optional IMAP service instance (uses singleton if not provided)
        """
        self.imap_service = imap_service or get_imap_service()
        
        # Lazy load dependencies to avoid circular imports
        self._analyzer = None
        self._dedup_service = None
        self._policy_engine = None
        self._gemini_client = None
        
        # Job tracking
        self._active_jobs: Dict[str, IMAPJob] = {}
        
        # Polling state
        self._is_running = False
        self._poll_task: Optional[asyncio.Task] = None
        self._poll_interval = getattr(settings, 'IMAP_POLL_INTERVAL', 60)
        self._batch_size = getattr(settings, 'IMAP_BATCH_SIZE', 50)
        
        # Metrics
        self._metrics = {
            'total_processed': 0,
            'total_skipped': 0,
            'total_errors': 0,
            'verdicts': {v.value: 0 for v in Verdict},
        }
    
    @property
    def mode(self) -> ModeType:
        """Return the mode type this orchestrator handles."""
        return ModeType.IMAP_BULK
    
    @property
    def analyzer(self):
        """Lazy load phishing analyzer."""
        if self._analyzer is None:
            try:
                from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer
                self._analyzer = EnhancedPhishingAnalyzer()
            except ImportError:
                logger.warning("EnhancedPhishingAnalyzer not available")
        return self._analyzer
    
    @property
    def dedup_service(self):
        """Lazy load deduplication service."""
        if self._dedup_service is None:
            try:
                from app.services.deduplication import get_deduplication_service
                self._dedup_service = get_deduplication_service()
            except ImportError:
                logger.warning("Deduplication service not available")
        return self._dedup_service
    
    @property
    def policy_engine(self):
        """Lazy load policy engine."""
        if self._policy_engine is None:
            try:
                from app.services.policy_engine import get_policy_engine
                self._policy_engine = get_policy_engine()
            except ImportError:
                logger.warning("Policy engine not available")
        return self._policy_engine
    
    @property
    def gemini_client(self):
        """Lazy load Gemini client."""
        if self._gemini_client is None:
            try:
                from app.services.gemini import GeminiClient
                self._gemini_client = GeminiClient()
            except ImportError:
                logger.warning("Gemini client not available")
        return self._gemini_client
    
    async def process_email(self, request: AnalysisRequest) -> AnalysisResult:
        """
        Process a single email through the IMAP analysis pipeline.
        
        Args:
            request: AnalysisRequest with email UID
            
        Returns:
            AnalysisResult with verdict and details
        """
        # Create job
        job = IMAPJob(
            job_id=request.request_id,
            mail_uid=request.email_identifier,
            tenant_id=request.tenant_id or "default",
        )
        self._active_jobs[job.job_id] = job
        
        try:
            # Step 1: Deduplication check
            job.status = IMAPJobStatus.DEDUP_CHECK
            start_time = time.time()
            
            if await self._check_duplicate(job):
                job.status = IMAPJobStatus.SKIPPED
                job.completed_at = datetime.now(timezone.utc)
                self._metrics['total_skipped'] += 1
                logger.info(f"[{job.job_id}] Skipped duplicate email")
                return job.to_result()
            
            job.timing['dedup_check'] = time.time() - start_time
            
            # Step 2: Fetch email
            job.status = IMAPJobStatus.FETCHING
            start_time = time.time()
            
            fetched_email = await self.imap_service.fetch_email(job.mail_uid)
            if not fetched_email:
                raise ValueError(f"Email {job.mail_uid} not found or could not be fetched")
            
            job.timing['fetch'] = time.time() - start_time
            
            # Update job metadata
            job.message_id = fetched_email.metadata.message_id
            job.subject = fetched_email.metadata.subject
            job.sender = fetched_email.metadata.sender
            job.forwarded_by = fetched_email.forwarded_by
            
            logger.info(f"[{job.job_id}] Fetched email: {job.subject[:50]}...")
            
            # Step 3: Run analysis
            job.status = IMAPJobStatus.ANALYZING
            start_time = time.time()
            
            analysis_result = await self._run_analysis(fetched_email)
            
            job.timing['analysis'] = time.time() - start_time
            
            # Update job with results
            job.verdict = analysis_result.get('verdict', Verdict.UNKNOWN)
            job.score = analysis_result.get('score', 0.0)
            job.confidence = analysis_result.get('confidence', 0.0)
            job.analysis_details = analysis_result
            
            logger.info(f"[{job.job_id}] Analysis complete: {job.verdict.value} ({job.score}%)")
            
            # Step 4: Apply policies (optional)
            job.status = IMAPJobStatus.POLICY_EVAL
            start_time = time.time()
            
            await self._apply_policies(job)
            
            job.timing['policy'] = time.time() - start_time
            
            # Step 5: Store results
            job.status = IMAPJobStatus.STORING
            start_time = time.time()
            
            await self._store_results(job, fetched_email)
            
            job.timing['store'] = time.time() - start_time
            
            # Step 6: Send notification
            job.status = IMAPJobStatus.NOTIFYING
            start_time = time.time()
            
            await self._send_notification(job, fetched_email)
            
            job.timing['notify'] = time.time() - start_time
            
            # Complete
            job.status = IMAPJobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            self._metrics['total_processed'] += 1
            self._metrics['verdicts'][job.verdict.value] += 1
            
            logger.info(
                f"[{job.job_id}] Completed in {sum(job.timing.values()):.2f}s - "
                f"Verdict: {job.verdict.value}, Score: {job.score}%"
            )
            
            return job.to_result()
            
        except Exception as e:
            job.status = IMAPJobStatus.FAILED
            job.error = str(e)
            job.error_stage = job.status.value
            job.completed_at = datetime.now(timezone.utc)
            self._metrics['total_errors'] += 1
            
            logger.error(f"[{job.job_id}] Failed at {job.error_stage}: {e}")
            return job.to_result()
            
        finally:
            # Cleanup
            if job.job_id in self._active_jobs:
                del self._active_jobs[job.job_id]
    
    async def _check_duplicate(self, job: IMAPJob) -> bool:
        """Check if email has already been processed."""
        if not self.dedup_service:
            return False
        
        try:
            # Use mail UID for initial check
            # After fetch, we'll use message_id for proper dedup
            result = await self.dedup_service.check(job.mail_uid, job.tenant_id)
            return result.is_duplicate
        except Exception as e:
            logger.warning(f"Dedup check failed: {e}")
            return False
    
    async def _run_analysis(self, fetched_email) -> Dict[str, Any]:
        """Run phishing analysis on fetched email."""
        if not self.analyzer:
            logger.warning("No analyzer available, using default scores")
            return {
                'verdict': Verdict.UNKNOWN,
                'score': 0.0,
                'confidence': 0.0,
            }
        
        try:
            # Run the enhanced phishing analyzer
            result = self.analyzer.analyze_email(fetched_email.raw_email)
            
            # Map verdict
            verdict_map = {
                'SAFE': Verdict.SAFE,
                'SUSPICIOUS': Verdict.SUSPICIOUS,
                'PHISHING': Verdict.PHISHING,
                'MALICIOUS': Verdict.MALICIOUS,
            }
            verdict = verdict_map.get(result.final_verdict, Verdict.UNKNOWN)
            
            return {
                'verdict': verdict,
                'score': result.total_score,
                'confidence': result.confidence,
                'sender_analysis': result.sender_analysis.__dict__ if hasattr(result, 'sender_analysis') else {},
                'content_analysis': result.content_analysis.__dict__ if hasattr(result, 'content_analysis') else {},
                'link_analysis': result.link_analysis.__dict__ if hasattr(result, 'link_analysis') else {},
                'auth_analysis': result.authentication_analysis.__dict__ if hasattr(result, 'authentication_analysis') else {},
                'attachment_analysis': result.attachment_analysis.__dict__ if hasattr(result, 'attachment_analysis') else {},
                'indicators': result.indicators if hasattr(result, 'indicators') else [],
            }
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {
                'verdict': Verdict.UNKNOWN,
                'score': 0.0,
                'confidence': 0.0,
                'error': str(e),
            }
    
    async def _apply_policies(self, job: IMAPJob):
        """Apply organizational policies based on analysis."""
        if not self.policy_engine:
            return
        
        try:
            # TODO: Implement policy evaluation
            pass
        except Exception as e:
            logger.warning(f"Policy evaluation failed: {e}")
    
    async def _store_results(self, job: IMAPJob, fetched_email):
        """Store analysis results in database."""
        try:
            from app.models.mongodb_models import ForwardedEmailAnalysis
            
            analysis_doc = ForwardedEmailAnalysis(
                user_id=job.forwarded_by or "unknown",
                forwarded_by=job.forwarded_by or "unknown",
                org_domain=job.analysis_details.get('org_domain', 'unknown'),
                original_sender=job.sender or "",
                original_subject=job.subject or "",
                threat_score=job.score / 100.0,  # Normalize to 0-1
                risk_level=job.verdict.value if job.verdict else "UNKNOWN",
                analysis_result=job.analysis_details,
                email_metadata={
                    'message_id': job.message_id,
                    'uid': job.mail_uid,
                    'subject': job.subject,
                    'from': job.sender,
                },
            )
            
            await analysis_doc.insert()
            logger.debug(f"[{job.job_id}] Stored analysis result")
            
        except Exception as e:
            logger.error(f"Failed to store results: {e}")
    
    async def _send_notification(self, job: IMAPJob, fetched_email):
        """Send notification email to user who forwarded."""
        if not job.forwarded_by:
            return
        
        try:
            from app.services.email_sender import send_email
            
            # Build report
            subject = f"PhishNet Analysis: {job.verdict.value} - {job.subject[:50]}"
            body = self._build_report_body(job)
            
            await send_email(
                to_email=job.forwarded_by,
                subject=subject,
                body=body,
                html=True,
            )
            
            logger.info(f"[{job.job_id}] Sent notification to {job.forwarded_by}")
            
        except Exception as e:
            logger.warning(f"Failed to send notification: {e}")
    
    def _build_report_body(self, job: IMAPJob) -> str:
        """Build HTML report body for notification email."""
        verdict_colors = {
            Verdict.SAFE: "#28a745",
            Verdict.SUSPICIOUS: "#ffc107",
            Verdict.PHISHING: "#dc3545",
            Verdict.MALICIOUS: "#dc3545",
            Verdict.UNKNOWN: "#6c757d",
        }
        color = verdict_colors.get(job.verdict, "#6c757d")
        
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>PhishNet Analysis Report</h2>
            <div style="background: {color}; color: white; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3 style="margin: 0;">Verdict: {job.verdict.value if job.verdict else 'UNKNOWN'}</h3>
                <p style="margin: 5px 0 0 0;">Threat Score: {job.score}%</p>
            </div>
            <h4>Email Details</h4>
            <ul>
                <li><strong>Subject:</strong> {job.subject}</li>
                <li><strong>Sender:</strong> {job.sender}</li>
            </ul>
            <p style="color: #666; font-size: 12px;">
                This report was generated automatically by PhishNet.
            </p>
        </body>
        </html>
        """
    
    async def start(self) -> None:
        """Start background polling."""
        if self._is_running:
            logger.warning("IMAP orchestrator already running")
            return
        
        if not getattr(settings, 'IMAP_ENABLED', False):
            logger.info("IMAP polling disabled in settings")
            return
        
        self._is_running = True
        self._poll_task = asyncio.create_task(self._poll_loop())
        logger.info(f"Started IMAP polling (interval: {self._poll_interval}s)")
    
    async def stop(self) -> None:
        """Stop background polling gracefully."""
        if not self._is_running:
            return
        
        self._is_running = False
        
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        
        # Wait for active jobs to complete
        if self._active_jobs:
            logger.info(f"Waiting for {len(self._active_jobs)} active jobs to complete...")
            await asyncio.sleep(5)  # Give jobs time to finish
        
        logger.info("IMAP orchestrator stopped")
    
    async def _poll_loop(self):
        """Background polling loop."""
        while self._is_running:
            try:
                await self._poll_once()
            except Exception as e:
                logger.error(f"Poll cycle error: {e}")
            
            await asyncio.sleep(self._poll_interval)
    
    async def _poll_once(self):
        """Execute a single poll cycle."""
        try:
            # Get recent emails
            emails = await self.imap_service.list_pending(limit=self._batch_size)
            
            if not emails:
                return
            
            logger.info(f"Found {len(emails)} emails to check")
            
            for email_meta in emails:
                uid = email_meta['uid']
                message_id = email_meta.get('message_id', '')
                
                # Check if already processed (by message_id)
                if message_id:
                    try:
                        from app.models.mongodb_models import ForwardedEmailAnalysis
                        exists = await ForwardedEmailAnalysis.find_one({
                            "email_metadata.message_id": message_id
                        })
                        if exists:
                            continue  # Already analyzed
                    except Exception:
                        pass
                
                # Process this email
                request = AnalysisRequest(
                    request_id=self._generate_job_id(uid),
                    mode=ModeType.IMAP_BULK,
                    email_identifier=uid,
                )
                
                await self.process_email(request)
                
        except Exception as e:
            logger.error(f"Poll error: {e}")
    
    def _generate_job_id(self, uid: str) -> str:
        """Generate unique job ID."""
        timestamp = datetime.now(timezone.utc).isoformat()
        return hashlib.sha256(f"{uid}:{timestamp}".encode()).hexdigest()[:16]
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the orchestrator."""
        return {
            "mode": self.mode.value,
            "running": self._is_running,
            "poll_interval": self._poll_interval,
            "batch_size": self._batch_size,
            "active_jobs": len(self._active_jobs),
            "metrics": self._metrics,
            "imap_configured": self.imap_service.is_configured,
        }


# Singleton instance factory
_instance: Optional[IMAPOrchestrator] = None

def get_imap_orchestrator() -> IMAPOrchestrator:
    """Get singleton IMAP orchestrator instance."""
    global _instance
    if _instance is None:
        _instance = IMAPOrchestrator()
    return _instance
