"""
Gmail Mode Orchestrator - Mode 2 (On-Demand Check)
===================================================
Coordinates the on-demand email analysis flow.

This orchestrator handles user-initiated email checks:
1. Receive check request with Message ID
2. Validate/refresh OAuth token
3. Fetch email via Gmail API
4. Run phishing analysis
5. Return results (store only if user consents)

Privacy Features:
- No background scanning
- User explicitly selects which emails to check
- Results not stored without consent
- Short-lived tokens (1 hour)
"""

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from app.modes.base import (
    ModeOrchestrator,
    AnalysisRequest,
    AnalysisResult,
    AnalysisStatus,
    Verdict,
    EmailMetadata,
    ModeType,
)
from app.modes.gmail.service import GmailAPIService, get_gmail_service
from app.config.settings import get_settings
from app.config.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)


@dataclass
class GmailCheckResult:
    """Result of a Gmail on-demand check."""
    success: bool
    message_id: str
    verdict: Verdict = Verdict.UNKNOWN
    score: float = 0.0
    confidence: float = 0.0
    analysis: Dict[str, Any] = field(default_factory=dict)
    need_oauth: bool = False
    oauth_url: Optional[str] = None
    error: Optional[str] = None
    stored: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "message_id": self.message_id,
            "verdict": self.verdict.value,
            "score": self.score,
            "confidence": self.confidence,
            "analysis": self.analysis,
            "need_oauth": self.need_oauth,
            "oauth_url": self.oauth_url,
            "error": self.error,
            "stored": self.stored,
        }


class GmailOrchestrator(ModeOrchestrator):
    """
    Orchestrator for Mode 2 (Gmail On-Demand).
    
    This class handles user-initiated email checks with privacy as the
    primary concern. No background processing, no automatic storage.
    
    Pipeline Steps:
    1. Validate request has valid access token
    2. Fetch specific email via Gmail API
    3. Run phishing analysis
    4. Return results to user
    5. Store results ONLY if user consented
    """
    
    def __init__(self, gmail_service: GmailAPIService = None):
        """
        Initialize Gmail orchestrator.
        
        Args:
            gmail_service: Optional Gmail service instance
        """
        self.gmail_service = gmail_service or get_gmail_service()
        
        # Lazy load dependencies
        self._analyzer = None
        self._gemini_client = None
        
        # Metrics (for status reporting)
        self._metrics = {
            'total_checks': 0,
            'total_stored': 0,
            'total_errors': 0,
            'verdicts': {v.value: 0 for v in Verdict},
        }
    
    @property
    def mode(self) -> ModeType:
        """Return the mode type this orchestrator handles."""
        return ModeType.GMAIL_ONDEMAND
    
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
        Process a single email through the Gmail on-demand pipeline.
        
        Args:
            request: AnalysisRequest with Gmail Message ID and access token
            
        Returns:
            AnalysisResult with verdict and details
        """
        start_time = time.time()
        
        # Validate access token
        access_token = request.access_token
        if not access_token:
            return AnalysisResult(
                request_id=request.request_id,
                mode=ModeType.GMAIL_ONDEMAND,
                status=AnalysisStatus.FAILED,
                error="Access token required for Gmail API",
                error_stage="validation",
            )
        
        try:
            # Step 1: Fetch email
            logger.info(f"[{request.request_id}] Fetching Gmail message {request.email_identifier}")
            
            fetched_email = await self.gmail_service.fetch_email(
                request.email_identifier,
                access_token=access_token
            )
            
            if not fetched_email:
                return AnalysisResult(
                    request_id=request.request_id,
                    mode=ModeType.GMAIL_ONDEMAND,
                    status=AnalysisStatus.FAILED,
                    error=f"Message {request.email_identifier} not found",
                    error_stage="fetch",
                )
            
            fetch_time = time.time() - start_time
            
            # Step 2: Run analysis
            logger.info(f"[{request.request_id}] Analyzing email: {fetched_email.metadata.subject[:50]}...")
            
            analysis_start = time.time()
            analysis_result = await self._run_analysis(fetched_email)
            analysis_time = time.time() - analysis_start
            
            # Step 3: Get AI interpretation (optional)
            ai_summary = None
            ai_explanation = None
            
            if self.gemini_client and analysis_result.get('verdict') != Verdict.SAFE:
                try:
                    interpretation = await self._get_ai_interpretation(analysis_result)
                    ai_summary = interpretation.get('summary')
                    ai_explanation = interpretation.get('explanation')
                except Exception as e:
                    logger.warning(f"AI interpretation failed: {e}")
            
            # Step 4: Store results if consented
            stored = False
            if request.store_consent:
                try:
                    await self._store_results(request, fetched_email, analysis_result)
                    stored = True
                    self._metrics['total_stored'] += 1
                except Exception as e:
                    logger.error(f"Failed to store results: {e}")
            
            # Build result
            verdict = analysis_result.get('verdict', Verdict.UNKNOWN)
            self._metrics['total_checks'] += 1
            self._metrics['verdicts'][verdict.value] += 1
            
            total_time = time.time() - start_time
            
            logger.info(
                f"[{request.request_id}] Completed in {total_time:.2f}s - "
                f"Verdict: {verdict.value}, Score: {analysis_result.get('score', 0)}%"
            )
            
            return AnalysisResult(
                request_id=request.request_id,
                mode=ModeType.GMAIL_ONDEMAND,
                status=AnalysisStatus.COMPLETED,
                verdict=verdict,
                score=analysis_result.get('score', 0.0),
                confidence=analysis_result.get('confidence', 0.0),
                email_metadata=fetched_email.metadata,
                details=analysis_result,
                indicators=analysis_result.get('indicators', []),
                ai_summary=ai_summary,
                ai_explanation=ai_explanation,
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                duration_ms=int(total_time * 1000),
            )
            
        except ValueError as e:
            # Token expired or invalid
            if "expired" in str(e).lower() or "invalid" in str(e).lower():
                return AnalysisResult(
                    request_id=request.request_id,
                    mode=ModeType.GMAIL_ONDEMAND,
                    status=AnalysisStatus.FAILED,
                    error="Access token expired. Please re-authenticate.",
                    error_stage="auth",
                )
            raise
            
        except Exception as e:
            self._metrics['total_errors'] += 1
            logger.error(f"[{request.request_id}] Failed: {e}")
            
            return AnalysisResult(
                request_id=request.request_id,
                mode=ModeType.GMAIL_ONDEMAND,
                status=AnalysisStatus.FAILED,
                error=str(e),
                error_stage="analysis",
            )
    
    async def check_email_on_demand(
        self,
        user_id: str,
        message_id: str,
        access_token: Optional[str] = None,
        store_consent: bool = False,
    ) -> GmailCheckResult:
        """
        Convenience method for on-demand email checking.
        
        This is the main entry point for the on-demand check feature.
        
        Args:
            user_id: User ID requesting the check
            message_id: Gmail Message ID to analyze
            access_token: Gmail access token (optional, will prompt if missing)
            store_consent: Whether user consents to storing results
            
        Returns:
            GmailCheckResult with analysis or OAuth prompt
        """
        # Check if we have a valid token
        if not access_token:
            # Need OAuth flow
            oauth_url, _ = self._build_oauth_url(user_id)
            return GmailCheckResult(
                success=False,
                message_id=message_id,
                need_oauth=True,
                oauth_url=oauth_url,
                error="Gmail access required. Please authenticate.",
            )
        
        # Create analysis request
        request = AnalysisRequest(
            request_id=self._generate_request_id(message_id),
            mode=ModeType.GMAIL_ONDEMAND,
            email_identifier=message_id,
            user_id=user_id,
            access_token=access_token,
            store_consent=store_consent,
        )
        
        # Run analysis
        result = await self.process_email(request)
        
        if not result.is_success:
            # Check if it's an auth error
            if result.error_stage == "auth":
                oauth_url, _ = self._build_oauth_url(user_id)
                return GmailCheckResult(
                    success=False,
                    message_id=message_id,
                    need_oauth=True,
                    oauth_url=oauth_url,
                    error=result.error,
                )
            
            return GmailCheckResult(
                success=False,
                message_id=message_id,
                error=result.error,
            )
        
        return GmailCheckResult(
            success=True,
            message_id=message_id,
            verdict=result.verdict,
            score=result.score,
            confidence=result.confidence,
            analysis=result.details,
            stored=store_consent,
        )
    
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
            result = self.analyzer.analyze_email(fetched_email.raw_email)
            
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
    
    async def _get_ai_interpretation(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Get AI-generated interpretation of analysis results."""
        if not self.gemini_client:
            return {}
        
        try:
            # Build prompt from analysis results
            prompt = f"""
            Explain this phishing analysis result in simple terms:
            - Verdict: {analysis.get('verdict', 'Unknown')}
            - Score: {analysis.get('score', 0)}%
            - Key indicators: {analysis.get('indicators', [])}
            
            Provide a brief summary and actionable guidance.
            """
            
            response = await self.gemini_client.generate(prompt)
            
            return {
                'summary': response.get('summary', ''),
                'explanation': response.get('text', ''),
            }
            
        except Exception as e:
            logger.warning(f"AI interpretation failed: {e}")
            return {}
    
    async def _store_results(self, request: AnalysisRequest, fetched_email, analysis: Dict[str, Any]):
        """Store analysis results (only with user consent)."""
        try:
            from app.models.mongodb_models import OnDemandAnalysis
            from datetime import timedelta
            
            doc = OnDemandAnalysis(
                user_id=request.user_id,
                gmail_message_id=request.email_identifier,
                threat_score=analysis.get('score', 0) / 100.0,
                risk_level=analysis.get('verdict', Verdict.UNKNOWN).value,
                analysis_result=analysis,
                email_metadata={
                    'message_id': fetched_email.metadata.message_id,
                    'subject': fetched_email.metadata.subject,
                    'sender': fetched_email.metadata.sender,
                    'date': fetched_email.metadata.date.isoformat() if fetched_email.metadata.date else None,
                },
                consent_given=True,
                retention_until=datetime.now(timezone.utc) + timedelta(days=30),
            )
            
            await doc.insert()
            logger.debug(f"Stored on-demand analysis for {request.email_identifier}")
            
        except Exception as e:
            logger.error(f"Failed to store on-demand results: {e}")
            raise
    
    def _build_oauth_url(self, user_id: str) -> tuple:
        """Build OAuth URL for Gmail authentication."""
        try:
            from app.modes.gmail.oauth import GmailOAuthHandler
            handler = GmailOAuthHandler()
            return handler.build_auth_url(user_id)
        except ImportError:
            # Fallback to basic URL construction
            from urllib.parse import urlencode
            import secrets
            
            base_url = getattr(settings, 'BASE_URL', 'http://localhost:8002')
            redirect_uri = f"{base_url}/api/v2/gmail/oauth/callback"
            
            state = secrets.token_urlsafe(32)
            
            params = {
                "client_id": getattr(settings, 'GMAIL_CLIENT_ID', ''),
                "redirect_uri": redirect_uri,
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
                "response_type": "code",
                "state": state,
                "access_type": "online",
                "prompt": "consent",
            }
            
            url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
            return url, state
    
    def _generate_request_id(self, message_id: str) -> str:
        """Generate unique request ID."""
        timestamp = datetime.now(timezone.utc).isoformat()
        return hashlib.sha256(f"{message_id}:{timestamp}".encode()).hexdigest()[:16]
    
    async def start(self) -> None:
        """
        Start the orchestrator.
        
        For Gmail on-demand mode, this is a no-op since there's
        no background processing. The orchestrator is always "ready".
        """
        logger.info("Gmail on-demand orchestrator ready")
    
    async def stop(self) -> None:
        """
        Stop the orchestrator.
        
        For Gmail on-demand mode, this is a no-op.
        """
        logger.info("Gmail on-demand orchestrator stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the orchestrator."""
        return {
            "mode": self.mode.value,
            "running": True,  # Always ready for on-demand
            "gmail_configured": self.gmail_service.is_configured,
            "metrics": self._metrics,
        }


# Singleton instance factory
_instance: Optional[GmailOrchestrator] = None

def get_gmail_orchestrator() -> GmailOrchestrator:
    """Get singleton Gmail orchestrator instance."""
    global _instance
    if _instance is None:
        _instance = GmailOrchestrator()
    return _instance
