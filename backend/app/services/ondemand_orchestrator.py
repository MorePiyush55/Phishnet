"""
On-Demand Phishing Detection Orchestrator
==========================================
Coordinates the complete workflow for on-demand email analysis:
1. Email intake (IMAP polling)
2. Normalization & parsing  
3. Detection (EnhancedPhishingAnalyzer)
4. Interpretation (Gemini - explanation only, NOT verdict)
5. Client response (SMTP reply)

Architecture: Backend decides verdict → Gemini only translates findings to plain language.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, List
import hashlib
try:
    import redis.asyncio as redis
except ImportError:
    import redis

from app.config.logging import get_logger
from app.services.quick_imap import QuickIMAPService
from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer, ComprehensivePhishingAnalysis
from app.services.gemini import GeminiClient
from app.services.email_sender import send_email
from app.models.mongodb_models import ForwardedEmailAnalysis
from app.config.settings import get_settings

settings = get_settings()

logger = get_logger(__name__)


class JobStatus(str, Enum):
    """Analysis job states"""
    RECEIVED = "received"
    PARSED = "parsed"
    ANALYZING = "analyzing"
    INTERPRETING = "interpreting"
    RESPONDING = "responding"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class InterpretationResult:
    """Result from Gemini interpretation layer"""
    verdict: str  # Same as backend verdict (passed through)
    reasons: List[str]  # Plain-language explanations
    guidance: List[str]  # Actionable safety tips
    threat_score: float = 0.5


@dataclass
class AnalysisJob:
    """Tracks an email analysis job through the pipeline"""
    job_id: str
    mail_uid: str
    forwarded_by: str
    original_subject: str
    org_domain: Optional[str] = None
    status: JobStatus = JobStatus.RECEIVED
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    
    # Analysis results
    detection_result: Optional[ComprehensivePhishingAnalysis] = None
    interpretation: Optional[InterpretationResult] = None
    
    # Error tracking
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dictionary for API response"""
        return {
            "job_id": self.job_id,
            "mail_uid": self.mail_uid,
            "forwarded_by": self.forwarded_by,
            "original_subject": self.original_subject,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error
        }


class OnDemandOrchestrator:
    """
    Orchestrates the complete on-demand phishing detection workflow.
    
    Key Design Principles:
    - Backend detection logic is AUTHORITATIVE (decides verdict)
    - Gemini is ONLY for interpretation (converts technical → plain language)
    - Never pass raw email body to Gemini (prompt injection risk)
    - Sanitize all output in client response
    """
    
    def __init__(self):
        self.imap_service = QuickIMAPService()
        self.phishing_analyzer = EnhancedPhishingAnalyzer()
        self.gemini_client = GeminiClient()
        
        # In-memory job tracking (use Redis/DB in production)
        self._active_jobs: Dict[str, AnalysisJob] = {}
        
        # Redis for distributed locking
        self.redis = None
        if hasattr(settings, 'REDIS_URL') and settings.REDIS_URL:
            try:
                self.redis = redis.from_url(settings.REDIS_URL)
                logger.info("Orchestrator: Redis connection for locking initialized")
            except Exception as e:
                logger.warning(f"Orchestrator: Redis initialization failed: {e}")
    
    def _generate_job_id(self, mail_uid: str) -> str:
        """Generate unique job ID"""
        timestamp = datetime.utcnow().isoformat()
        return hashlib.sha256(f"{mail_uid}:{timestamp}".encode()).hexdigest()[:16]
    
    async def process_single_email(self, mail_uid: str) -> AnalysisJob:
        """
        Process a single forwarded email through the complete pipeline.
        
        Steps:
        1. Fetch & parse email from IMAP
        2. Run detection modules
        3. Get Gemini interpretation
        4. Send response to user
        
        Args:
            mail_uid: IMAP UID of the email to process
            
        Returns:
            AnalysisJob with complete results
        """
        job = AnalysisJob(
            job_id=self._generate_job_id(mail_uid),
            mail_uid=mail_uid,
            forwarded_by="",
            original_subject=""
        )
        self._active_jobs[job.job_id] = job
        
        try:
            # ═══════════════════════════════════════════════════════════════
            # STEP 1: Email Intake & Normalization
            # ═══════════════════════════════════════════════════════════════
            logger.info(f"[Job {job.job_id}] Starting analysis of email {mail_uid}")
            
            email_data = self.imap_service.fetch_email_for_analysis(mail_uid)
            if not email_data:
                raise ValueError(f"Email {mail_uid} not found or could not be parsed")
            
            job.forwarded_by = email_data.get('forwarded_by', '')
            job.org_domain = email_data.get('org_domain', 'unknown')
            job.original_subject = email_data.get('subject', 'No Subject')
            job.status = JobStatus.PARSED
            
            logger.info(f"[Job {job.job_id}] Parsed email from {job.forwarded_by} (Org: {job.org_domain}): {job.original_subject}")
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 2: Detection Phase (Backend is authoritative)
            # ═══════════════════════════════════════════════════════════════
            job.status = JobStatus.ANALYZING
            
            raw_email = email_data.get('raw_email')
            if not raw_email:
                raise ValueError("No raw email content available for analysis")
            
            detection_result = self.phishing_analyzer.analyze_email(raw_email)
            job.detection_result = detection_result
            
            logger.info(
                f"[Job {job.job_id}] Detection complete: "
                f"Verdict={detection_result.final_verdict}, "
                f"Score={detection_result.total_score}%, "
                f"Confidence={detection_result.confidence:.1%}"
            )
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 2.5: Enhanced Threat Intel (VirusTotal + AbuseIPDB)
            # ═══════════════════════════════════════════════════════════════
            try:
                await self.phishing_analyzer.enhance_with_threat_intel(detection_result)
                logger.info(f"[Job {job.job_id}] Threat intel enhancement complete")
            except Exception as ti_error:
                logger.warning(f"[Job {job.job_id}] Threat intel enhancement skipped: {ti_error}")
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 2.6: ThreatAggregator (Rules Engine + Multi-source Analysis)
            # ═══════════════════════════════════════════════════════════════
            try:
                from app.services.email_threat_adapter import (
                    aggregate_email_threat, 
                    enrich_analysis_with_aggregation
                )
                
                # Run aggregation with all available data
                threat_result = await aggregate_email_threat(
                    analysis=detection_result,
                    gemini_result=None,  # Will add Gemini after interpretation
                    email_id=job.job_id
                )
                
                # Enrich analysis with aggregator insights (may upgrade verdict)
                detection_result = enrich_analysis_with_aggregation(
                    analysis=detection_result,
                    threat_result=threat_result
                )
                
                logger.info(
                    f"[Job {job.job_id}] ThreatAggregator: "
                    f"score={threat_result.score:.2f}, "
                    f"level={threat_result.level.value}, "
                    f"rules_triggered={len([r for r in threat_result.rule_overrides if r.triggered])}"
                )
                
            except Exception as agg_error:
                logger.warning(f"[Job {job.job_id}] ThreatAggregator skipped: {agg_error}")
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 3: Interpretation Phase (Gemini translates, NOT decides)
            # ═══════════════════════════════════════════════════════════════
            job.status = JobStatus.INTERPRETING
            
            interpretation = await self._get_gemini_interpretation(
                detection_result, 
                job.original_subject
            )
            job.interpretation = interpretation
            
            logger.info(f"[Job {job.job_id}] Interpretation complete: {len(interpretation.reasons)} reasons")
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 4: Client Response (SMTP)
            # ═══════════════════════════════════════════════════════════════
            job.status = JobStatus.RESPONDING
            
            await self._send_analysis_response(job)
            
            # ═══════════════════════════════════════════════════════════════
            # Complete
            # ═══════════════════════════════════════════════════════════════
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.utcnow()

            # ═══════════════════════════════════════════════════════════════
            # STEP 5: Persist to Database (Critical for Deduplication)
            # ═══════════════════════════════════════════════════════════════
            try:
                # Provide a message_id if available, otherwise it might be missing
                # We need to re-fetch or pass it down. 
                # Ideally email_data has it.
                message_id = email_data.get('message_id')
                
                # Prepare email metadata, excluding message_id if None to avoid unique index violation
                email_metadata = {
                    "uid": mail_uid,
                    "subject": job.original_subject,
                    "date": email_data.get('received_date').isoformat() if email_data.get('received_date') else None
                }
                if message_id:
                    email_metadata["message_id"] = message_id
                
                analysis_doc = ForwardedEmailAnalysis(
                    user_id=job.forwarded_by,
                    forwarded_by=job.forwarded_by,
                    org_domain=job.org_domain,
                    original_sender=email_data.get('from', 'Unknown'),
                    original_subject=job.original_subject,
                    threat_score=float(detection_result.total_score) / 100.0,
                    risk_level=detection_result.final_verdict,
                    analysis_result={
                        "verdict": detection_result.final_verdict,
                        "score": detection_result.total_score,
                        "confidence": detection_result.confidence,
                        "risk_factors": detection_result.risk_factors
                    },
                    email_metadata=email_metadata,
                    reply_sent=True,
                    reply_sent_at=datetime.utcnow()
                )
                await analysis_doc.save()
                logger.info(f"[Job {job.job_id}] Analysis persisted to MongoDB for deduplication")
            except Exception as e:
                import traceback
                logger.error(f"[Job {job.job_id}] Failed to persist to MongoDB: {repr(e)}")
                logger.error(f"Traceback: {traceback.format_exc()}")
            
            return job
            
        except Exception as e:
            job.status = JobStatus.FAILED
            job.error = str(e)
            job.completed_at = datetime.utcnow()
            logger.error(f"[Job {job.job_id}] Analysis failed: {e}")
            raise
    
    async def _get_gemini_interpretation(
        self, 
        detection_result: ComprehensivePhishingAnalysis,
        subject: str
    ) -> InterpretationResult:
        """
        Get Gemini to interpret technical findings into plain language.
        
        CRITICAL: Gemini does NOT decide the verdict. The verdict from
        detection_result.final_verdict is passed through unchanged.
        Gemini only rewrites the findings for non-technical users.
        
        Args:
            detection_result: Complete analysis from EnhancedPhishingAnalyzer
            subject: Original email subject (for context)
            
        Returns:
            InterpretationResult with plain-language explanation
        """
        try:
            # Build structured summary for Gemini (no raw email content!)
            technical_report = self._build_technical_report(detection_result, subject)
            
            # Call Gemini interpretation
            gemini_result = await self.gemini_client.interpret_technical_findings(technical_report)
            
            if not gemini_result:
                raise ValueError("Gemini interpretation returned None (service unavailable or rate limited)")
            
            # Map to InterpretationResult
            # The verdict from Gemini should match backend, but we use backend as authority
            return InterpretationResult(
                verdict=detection_result.final_verdict,  # Always use backend verdict!
                reasons=gemini_result.explanation_snippets or self._default_reasons(detection_result),
                guidance=gemini_result.detected_techniques or self._default_guidance(detection_result),
                threat_score=gemini_result.llm_score
            )
            
        except Exception as e:
            logger.warning(f"Gemini interpretation failed, using fallback: {e}")
            # Fallback to rule-based interpretation
            return InterpretationResult(
                verdict=detection_result.final_verdict,
                reasons=self._default_reasons(detection_result),
                guidance=self._default_guidance(detection_result),
                threat_score=1.0 - (detection_result.total_score / 100)
            )
    
    async def _enhance_with_virustotal(
        self, 
        detection_result: ComprehensivePhishingAnalysis
    ) -> None:
        """
        Enhance detection with VirusTotal link scanning.
        
        Only scans suspicious URLs (encoded, redirects, http-only) to save API quota.
        Modifies detection_result in-place if malicious URLs found.
        """
        from app.services.virustotal import create_virustotal_client
        
        vt_client = create_virustotal_client()
        if not vt_client.is_available:
            logger.debug("VirusTotal not available, skipping enhancement")
            return
        
        # Identify suspicious URLs worth scanning
        suspicious_urls = []
        for link_info in detection_result.links.link_details[:10]:  # Limit to 10
            url = link_info.get('url', '')
            is_suspicious = (
                link_info.get('is_encoded', False) or
                link_info.get('is_redirect', False) or
                link_info.get('protocol') == 'http'
            )
            if is_suspicious and url.startswith(('http://', 'https://')):
                suspicious_urls.append(url)
        
        if not suspicious_urls:
            return
        
        logger.info(f"Scanning {len(suspicious_urls)} suspicious URLs with VirusTotal")
        
        # Scan URLs (limit to 3 to respect rate limits)
        malicious_urls = []
        for url in suspicious_urls[:3]:
            try:
                result = await vt_client.scan(url)
                if result.get('verdict') in ('malicious', 'suspicious'):
                    malicious_urls.append({
                        'url': url,
                        'verdict': result.get('verdict'),
                        'score': result.get('threat_score', 0)
                    })
            except Exception as e:
                logger.warning(f"VT scan failed for {url[:50]}: {e}")
        
        # If malicious URLs found, upgrade severity
        if malicious_urls:
            detection_result.risk_factors.append(
                f"VirusTotal flagged {len(malicious_urls)} URL(s) as malicious"
            )
            detection_result.links.indicators.append(
                f"🚨 {len(malicious_urls)} link(s) flagged by VirusTotal"
            )
            
            # Upgrade verdict if currently SAFE
            if detection_result.final_verdict == "SAFE":
                detection_result.final_verdict = "SUSPICIOUS"
                detection_result.confidence = max(detection_result.confidence, 0.8)
                logger.info(f"Verdict upgraded to SUSPICIOUS based on VirusTotal findings")
    
    def _build_technical_report(
        self, 
        result: ComprehensivePhishingAnalysis, 
        subject: str
    ) -> Dict[str, Any]:
        """
        Build sanitized technical report for Gemini.
        
        Only includes structured findings, NOT raw email content.
        This prevents prompt injection attacks.
        """
        return {
            "subject": subject[:100],  # Truncate for safety
            "verdict": result.final_verdict,
            "total_score": result.total_score,
            "confidence": result.confidence,
            "risk_factors": result.risk_factors[:10],  # Top 10
            "sections": {
                "sender": {
                    "score": result.sender.score,
                    "indicators": result.sender.indicators[:5]
                },
                "content": {
                    "score": result.content.score,
                    "urgency_level": result.content.urgency_level,
                    "keyword_count": result.content.keyword_count,
                    "indicators": result.content.indicators[:5]
                },
                "links": {
                    "score": result.links.overall_score,
                    "total_links": result.links.total_links,
                    "http_links": result.links.http_links,
                    "redirect_links": result.links.redirect_links,
                    "suspicious_tlds": result.links.suspicious_tlds[:3],
                    "indicators": result.links.indicators[:5]
                },
                "authentication": {
                    "score": result.authentication.overall_score,
                    "spf": result.authentication.spf_result,
                    "dkim": result.authentication.dkim_result,
                    "dmarc": result.authentication.dmarc_result,
                    "indicators": result.authentication.indicators[:5]
                },
                "attachments": {
                    "score": result.attachments.score,
                    "count": result.attachments.total_attachments,
                    "dangerous_types": result.attachments.dangerous_extensions[:3],
                    "indicators": result.attachments.indicators[:5]
                }
            }
        }
    
    def _default_reasons(self, result: ComprehensivePhishingAnalysis) -> List[str]:
        """Generate default plain-language reasons when Gemini unavailable"""
        reasons = []
        
        if result.authentication.spf_result in ['fail', 'softfail']:
            reasons.append("The sender's email address may be spoofed (failed SPF check).")
        if result.authentication.dkim_result == 'fail':
            reasons.append("The email signature could not be verified (failed DKIM).")
        if result.content.urgency_level == 'HIGH':
            reasons.append("The message uses urgent language to pressure you into acting quickly.")
        
        # PHASE 0: Alignment-aware HTTP messaging
        if result.links.http_links > 0:
            # Check if links are aligned with sender
            if hasattr(result.links, 'aligned_links') and result.links.aligned_links > 0:
                if result.links.aligned_links == result.links.http_links:
                    # All HTTP links are aligned - not alarming
                    reasons.append(f"Contains {result.links.http_links} HTTP link(s) to sender-aligned domains (verified).")
                elif result.links.unrelated_links > 0:
                    # Some unrelated links - mention those specifically
                    reasons.append(f"Contains {result.links.unrelated_links} HTTP link(s) to unrelated domains.")
            else:
                # No alignment data or all unrelated - original warning
                reasons.append(f"Contains {result.links.http_links} unencrypted HTTP link(s) (verify before clicking).")
        
        if result.links.redirect_links > 0:
            reasons.append("Contains links that redirect through other websites.")
        if len(result.attachments.dangerous_extensions) > 0:
            reasons.append(f"Contains potentially dangerous attachment(s): {', '.join(result.attachments.dangerous_extensions)}")
        if result.sender.score < 50:
            reasons.append("The sender's display name doesn't match their email address.")
        if len(result.links.suspicious_tlds) > 0:
            reasons.append(f"Contains links to suspicious domains ({', '.join(result.links.suspicious_tlds[:2])}).")
        
        # Ensure at least one reason
        if not reasons:
            if result.final_verdict == "PHISHING":
                reasons.append("Multiple indicators suggest this email is attempting to deceive you.")
            elif result.final_verdict == "SUSPICIOUS":
                reasons.append("Some elements of this email raise concerns.")
            else:
                reasons.append("No major security concerns were detected.")
        
        return reasons[:6]  # Max 6 reasons
    
    def _default_guidance(self, result: ComprehensivePhishingAnalysis) -> List[str]:
        """Generate default safety guidance when Gemini unavailable"""
        verdict = result.final_verdict
        
        if verdict == "PHISHING":
            return [
                "Delete this email immediately.",
                "Do NOT click any links or open attachments.",
                "If you clicked a link, change your password immediately.",
                "Report this email to your IT/Security team."
            ]
        elif verdict == "SUSPICIOUS":
            return [
                "Do not click links or open attachments.",
                "Verify the sender through a known, trusted channel.",
                "If unsure, forward to your IT/Security team for review."
            ]
        else:
            return [
                "This email appears safe, but always stay vigilant.",
                "Verify unexpected requests through official channels."
            ]
    
    async def _send_analysis_response(self, job: AnalysisJob) -> bool:
        """
        Send analysis results back to the user who forwarded the email.
        
        Security considerations:
        - Never include clickable links from the original email
        - Sanitize all content before including in response
        - Use plain text to avoid HTML injection
        """
        if not job.forwarded_by:
            logger.warning(f"[Job {job.job_id}] No recipient email, skipping response")
            return False
        
        if not job.detection_result or not job.interpretation:
            logger.warning(f"[Job {job.job_id}] Incomplete results, skipping response")
            return False
        
        verdict = job.detection_result.final_verdict
        interpretation = job.interpretation
        detection = job.detection_result
        
        # Verdict emoji mapping
        verdict_display = {
            "PHISHING": "🚨 PHISHING",
            "SUSPICIOUS": "⚠️ SUSPICIOUS", 
            "SAFE": "✅ LIKELY SAFE"
        }
        
        # Format reasons as bullets
        reasons_text = "\n".join(f"  • {reason}" for reason in interpretation.reasons)
        
        # Format guidance as bullets
        guidance_text = "\n".join(f"  👉 {tip}" for tip in interpretation.guidance)
        
        # Build email body (plain text for security)
        email_body = f"""
════════════════════════════════════════════════════════════
                    PhishNet Analysis Report
════════════════════════════════════════════════════════════

ANALYZED EMAIL
Subject: {self._sanitize_text(job.original_subject)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: {verdict_display.get(verdict, verdict)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

KEY FINDINGS:
{reasons_text}

RECOMMENDED ACTIONS:
{guidance_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TECHNICAL DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk Score: {detection.total_score}/100 (lower = more dangerous)
Confidence: {detection.confidence:.0%}

Section Scores:
  • Sender Analysis:     {detection.sender.score}/100
  • Content Analysis:    {detection.content.score}/100
  • Link Analysis:       {detection.links.overall_score}/100
  • Authentication:      {detection.authentication.overall_score}/100
  • Attachment Analysis: {detection.attachments.score}/100

Authentication Results:
  • SPF:   {detection.authentication.spf_result.upper()}
  • DKIM:  {detection.authentication.dkim_result.upper()}
  • DMARC: {detection.authentication.dmarc_result.upper()}

════════════════════════════════════════════════════════════
This is an automated analysis by PhishNet.
For questions, contact your IT/Security team.
════════════════════════════════════════════════════════════
"""
        
        # Send email
        subject = f"PhishNet Analysis: {verdict_display.get(verdict, verdict)} — {self._sanitize_text(job.original_subject)[:50]}"
        
        success = await send_email(
            to_email=job.forwarded_by,
            subject=subject,
            body=email_body,
            html=False  # Plain text for security
        )
        
        if success:
            logger.info(f"[Job {job.job_id}] Response sent to {job.forwarded_by}")
        else:
            logger.error(f"[Job {job.job_id}] Failed to send response to {job.forwarded_by}")
        
        return success
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitize text for safe inclusion in response email"""
        if not text:
            return ""
        # Remove potentially dangerous characters, limit length
        sanitized = text.replace('\r', '').replace('\n', ' ')
        # Remove any HTML-like content
        sanitized = sanitized.replace('<', '&lt;').replace('>', '&gt;')
        return sanitized[:200]
    
    async def process_all_pending(self) -> List[AnalysisJob]:
        """
        Process all pending emails in the inbox.
        
        Using ROBUST strategy:
        1. Fetch recent emails (read OR unread)
        2. Filter out ones already in MongoDB
        3. Process only new ones
        
        Returns:
            List of completed AnalysisJob objects
        """
        # robust polling settings
        email_limit = getattr(settings, 'IMAP_BATCH_SIZE', 50)
        recent_emails = self.imap_service.get_recent_emails(limit=email_limit)
        
        if not recent_emails:
            return []
            
        logger.info(f"Checking {len(recent_emails)} recent emails for new submissions...")
        
        completed_jobs = []
        skipped_count = 0
        
        for email_info in recent_emails:
            try:
                # FORCE STRING & TRIM UID (Critical for deduplication consistency)
                raw_uid = email_info.get('uid')
                mail_uid = str(raw_uid).strip() if raw_uid else None
                
                message_id = email_info.get('message_id')
                subject = email_info.get('subject', 'No Subject')
                
                if not mail_uid:
                    logger.warning(f"Email missing UID, skipping: {subject}")
                    continue
                
                # DEDUPLICATION CHECK
                exists = None
                if message_id:
                     # Check if already processed by Message-ID
                    exists = await ForwardedEmailAnalysis.find_one({"email_metadata.message_id": message_id})
                elif mail_uid:
                    # Fallback: Check by UID
                    # Force string for query consistency
                    query_uid = str(mail_uid).strip()
                    logger.debug(f"🔍 Checking duplicate by UID: '{query_uid}'")
                    exists = await ForwardedEmailAnalysis.find_one({"email_metadata.uid": query_uid})
                    if exists:
                        logger.info(f"✅ Found duplicate by UID: {query_uid} (Job {exists.id})")
                    else:
                        logger.debug(f"❌ UID {query_uid} not found in DB")
                
                if exists:
                    # Already analyzed - Skip
                    skipped_count += 1
                    logger.info(f"⏭️ Skipping already-processed email: {subject} (UID={mail_uid})")
                    continue
                
                # DISTRIBUTED LOCK (Prevention for multi-instance races)
                lock_acquired = False
                if self.redis and message_id:
                    lock_key = f"lock:analysis:{message_id}"
                    # Try to acquire lock for 10 minutes (sufficient for analysis)
                    lock_acquired = await self.redis.set(lock_key, "processing", ex=600, nx=True)
                    if not lock_acquired:
                        logger.info(f"⏭️ Skipping: Another instance is already processing email {message_id[:10]}...")
                        continue
                
                try:
                    # If we are here, it is NOT in DB - process it!
                    logger.info(f"🆕 Found NEW unanalyzed email: {subject} (UID {mail_uid})")
                    
                    job = await self.process_single_email(mail_uid)
                    completed_jobs.append(job)
                finally:
                    # Release lock if we acquired it
                    if self.redis and lock_acquired and message_id:
                        await self.redis.delete(f"lock:analysis:{message_id}")
                
            except Exception as e:
                logger.error(f"Failed to process email {email_info.get('uid')}: {e}")
                continue
        
        logger.info(f"Poll summary: {len(completed_jobs)} new, {skipped_count} already processed, {len(recent_emails)} total checked")
        
        if completed_jobs:
            logger.info(f"✅ Completed {len(completed_jobs)} new email analyses")
        return completed_jobs
    
    def get_job_status(self, job_id: str) -> Optional[AnalysisJob]:
        """Get status of a specific job"""
        return self._active_jobs.get(job_id)
    
    def get_active_jobs(self) -> List[AnalysisJob]:
        """Get all active/recent jobs"""
        return list(self._active_jobs.values())


# Singleton instance for dependency injection
_orchestrator_instance: Optional[OnDemandOrchestrator] = None


def get_ondemand_orchestrator() -> OnDemandOrchestrator:
    """Get or create the singleton orchestrator instance"""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = OnDemandOrchestrator()
    return _orchestrator_instance
