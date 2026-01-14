"""
Enterprise Link Analysis Orchestrator for PhishNet
===================================================
Unified orchestration of all 10 phases for enterprise-grade email analysis.

Phase Summary:
- Phase 0: Hard Stop Fixes (HTTP critical flag removal)
- Phase 1: Domain Identity Resolution
- Phase 2: Sender-Link Alignment
- Phase 3: Redirect Chain Intelligence
- Phase 4: Multi-Dimensional Link Scoring
- Phase 5: Verdict Arbitration Layer
- Phase 6: Explainability Engine
- Phase 7: Feedback Loop
- Phase 8: Hardening & Security
- Phase 9: VirusTotal Integration
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.services.domain_identity import (
    get_registrable_domain,
    SenderLinkAlignment,
)
from app.services.domain_intelligence import (
    DomainIntelligenceService,
    RedirectResolver,
    LinkFeatureExtractor,
    LinkFeatureVector,
    RedirectChainResult,
)
from app.services.verdict_arbitrator import (
    VerdictArbitrator,
    ArbitrationContext,
    ModuleResult,
    ArbitrationResult,
    VerdictLevel,
)
from app.services.virustotal_intelligence import (
    VirusTotalService,
    VTResult,
    VTRiskLevel,
    ExplainabilityEngine,
)
from app.services.feedback_security import (
    FeedbackLoopService,
    SecurityGuard,
    get_domain_trust_weight,
    is_url_safe_to_fetch,
)
from app.services.enhanced_phishing_analyzer import (
    EnhancedPhishingAnalyzer,
    ComprehensivePhishingAnalysis,
)

logger = logging.getLogger(__name__)


@dataclass
class EnterpriseAnalysisResult:
    """Complete enterprise-grade analysis result"""
    # Core analysis (Phase 0)
    base_analysis: ComprehensivePhishingAnalysis
    
    # Enhanced link features (Phase 4)
    link_features: List[LinkFeatureVector] = field(default_factory=list)
    
    # Redirect chains (Phase 3)
    redirect_chains: List[RedirectChainResult] = field(default_factory=list)
    
    # VirusTotal results (Phase 9)
    vt_results: List[VTResult] = field(default_factory=list)
    
    # Arbitrated verdict (Phase 5)
    arbitration: Optional[ArbitrationResult] = None
    
    # Final outputs
    final_verdict: str = "SAFE"
    final_score: float = 100.0
    final_confidence: float = 0.5
    
    # Explainability (Phase 6)
    explanations: Dict[str, str] = field(default_factory=dict)
    
    # Metadata
    analysis_time_ms: float = 0.0
    phases_executed: List[str] = field(default_factory=list)


class EnterpriseAnalysisOrchestrator:
    """
    Orchestrates all 10 phases of enterprise link analysis.
    """
    
    def __init__(self):
        self.base_analyzer = EnhancedPhishingAnalyzer()
        self.domain_service = DomainIntelligenceService()
        self.vt_service = VirusTotalService()
        self.arbitrator = VerdictArbitrator()
        self.feedback_service = FeedbackLoopService()
        self.explainer = ExplainabilityEngine()
    
    async def analyze_email(
        self, 
        email_content: bytes,
        enable_redirect_resolution: bool = False,
        enable_virustotal: bool = True
    ) -> EnterpriseAnalysisResult:
        """
        Perform full enterprise analysis on an email.
        
        Args:
            email_content: Raw email bytes
            enable_redirect_resolution: Whether to resolve redirects (slower)
            enable_virustotal: Whether to check VT (requires API key)
        """
        start_time = datetime.utcnow()
        result = EnterpriseAnalysisResult(
            base_analysis=None
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # PHASE 0: Base Analysis (includes sender-link alignment)
        # ═══════════════════════════════════════════════════════════════════
        base_analysis = self.base_analyzer.analyze_email(email_content)
        result.base_analysis = base_analysis
        result.phases_executed.append("Phase 0: Base Analysis")
        
        # Extract sender domain for subsequent phases
        sender_domain = base_analysis.sender.email_address
        if '@' in sender_domain:
            sender_domain = sender_domain.split('@')[-1]
        
        # ═══════════════════════════════════════════════════════════════════
        # PHASE 1-4: Link Feature Extraction
        # ═══════════════════════════════════════════════════════════════════
        extractor = LinkFeatureExtractor(sender_domain)
        
        links_to_analyze = [
            d['url'] for d in base_analysis.links.link_details
            if d.get('url', '').startswith(('http://', 'https://'))
        ][:10]  # Limit to 10 links
        
        if links_to_analyze:
            features = await asyncio.gather(*[
                extractor.extract_features(url) for url in links_to_analyze
            ], return_exceptions=True)
            
            result.link_features = [
                f for f in features if isinstance(f, LinkFeatureVector)
            ]
            result.phases_executed.append("Phase 1-4: Link Feature Extraction")
        
        # ═══════════════════════════════════════════════════════════════════
        # PHASE 3: Redirect Resolution (optional, slower)
        # ═══════════════════════════════════════════════════════════════════
        if enable_redirect_resolution and links_to_analyze:
            resolver = RedirectResolver(sender_domain)
            
            # Only resolve suspicious links
            suspicious_urls = [
                f.url for f in result.link_features
                if f.alignment == "unrelated" or f.url_entropy > 4.0
            ][:3]  # Limit to 3
            
            if suspicious_urls:
                chains = await asyncio.gather(*[
                    resolver.resolve_chain(url) for url in suspicious_urls
                ], return_exceptions=True)
                
                result.redirect_chains = [
                    c for c in chains if isinstance(c, RedirectChainResult)
                ]
                result.phases_executed.append("Phase 3: Redirect Resolution")
        
        # ═══════════════════════════════════════════════════════════════════
        # PHASE 9: VirusTotal Integration (conditional)
        # ═══════════════════════════════════════════════════════════════════
        if enable_virustotal and self.vt_service.is_available:
            # Only query VT for suspicious links
            links_for_vt = [
                f.url for f in result.link_features
                if self.vt_service.should_query(
                    f.url,
                    alignment=f.alignment,
                    has_redirect=f.has_external_redirect,
                    url_entropy=f.url_entropy
                )
            ][:2]  # Limit to 2 VT queries
            
            if links_for_vt:
                vt_results = await asyncio.gather(*[
                    self.vt_service.check_url(url) for url in links_for_vt
                ], return_exceptions=True)
                
                result.vt_results = [
                    r for r in vt_results if isinstance(r, VTResult)
                ]
                result.phases_executed.append("Phase 9: VirusTotal")
        
        # ═══════════════════════════════════════════════════════════════════
        # PHASE 5: Verdict Arbitration
        # ═══════════════════════════════════════════════════════════════════
        context = self._build_arbitration_context(result)
        module_results = self._build_module_results(result)
        
        arbitration = self.arbitrator.arbitrate(context, module_results)
        result.arbitration = arbitration
        result.final_verdict = arbitration.verdict.value
        result.final_score = arbitration.final_score
        result.final_confidence = arbitration.confidence
        result.phases_executed.append("Phase 5: Verdict Arbitration")
        
        # ═══════════════════════════════════════════════════════════════════
        # PHASE 6: Explainability
        # ═══════════════════════════════════════════════════════════════════
        result.explanations = self._generate_explanations(result)
        result.phases_executed.append("Phase 6: Explainability")
        
        # Calculate timing
        result.analysis_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        return result
    
    def _build_arbitration_context(
        self, 
        result: EnterpriseAnalysisResult
    ) -> ArbitrationContext:
        """Build context for verdict arbitration"""
        base = result.base_analysis
        
        context = ArbitrationContext(
            spf_pass=base.authentication.spf_result.lower() == 'pass',
            dkim_pass=base.authentication.dkim_result.lower() == 'pass',
            dmarc_pass=base.authentication.dmarc_result.lower() == 'pass',
            alignment_score=base.links.sender_alignment_score,
            sender_link_aligned=base.links.sender_alignment_score >= 0.7,
            has_external_redirects=any(
                c.has_external_redirect for c in result.redirect_chains
            )
        )
        
        return context
    
    def _build_module_results(
        self, 
        result: EnterpriseAnalysisResult
    ) -> List[ModuleResult]:
        """Build module results for arbitration"""
        base = result.base_analysis
        modules = []
        
        # Authentication module
        modules.append(ModuleResult(
            module_name='authentication',
            score=float(base.authentication.overall_score),
            verdict_suggestion=self._score_to_verdict(base.authentication.overall_score),
            confidence=0.9,
            indicators=base.authentication.indicators,
            can_force_verdict=base.authentication.spf_result.lower() == 'fail'
        ))
        
        # Sender module
        modules.append(ModuleResult(
            module_name='sender',
            score=float(base.sender.score),
            verdict_suggestion=self._score_to_verdict(base.sender.score),
            confidence=0.7,
            indicators=base.sender.indicators
        ))
        
        # Content module
        modules.append(ModuleResult(
            module_name='content',
            score=float(base.content.score),
            verdict_suggestion=self._score_to_verdict(base.content.score),
            confidence=0.8,
            indicators=base.content.indicators
        ))
        
        # Links module
        modules.append(ModuleResult(
            module_name='links',
            score=float(base.links.overall_score),
            verdict_suggestion=self._score_to_verdict(base.links.overall_score),
            confidence=0.75,
            indicators=base.links.indicators
        ))
        
        # Attachments module
        modules.append(ModuleResult(
            module_name='attachments',
            score=float(base.attachments.score),
            verdict_suggestion=self._score_to_verdict(base.attachments.score),
            confidence=0.85,
            indicators=base.attachments.indicators,
            can_force_verdict=len(base.attachments.dangerous_extensions) > 0
        ))
        
        # VirusTotal module (if results available)
        if result.vt_results:
            # Aggregate VT scores
            vt_scores = [r.score for r in result.vt_results if not r.error]
            if vt_scores:
                avg_vt_score = sum(vt_scores) / len(vt_scores) * 100
                
                # Check for high-confidence malicious
                has_high_conf = any(
                    r.risk_level == VTRiskLevel.HIGH_CONFIDENCE 
                    for r in result.vt_results
                )
                
                modules.append(ModuleResult(
                    module_name='virustotal',
                    score=avg_vt_score,
                    verdict_suggestion=VerdictLevel.PHISHING if has_high_conf else self._score_to_verdict(avg_vt_score),
                    confidence=0.8,
                    indicators=[self.explainer.explain_vt_result(r) for r in result.vt_results[:2]],
                    can_force_verdict=False  # VT alone can't force verdict per Phase 9
                ))
        
        return modules
    
    def _score_to_verdict(self, score: float) -> VerdictLevel:
        """Convert score to verdict suggestion"""
        if score < 30:
            return VerdictLevel.PHISHING
        elif score < 60:
            return VerdictLevel.SUSPICIOUS
        else:
            return VerdictLevel.SAFE
    
    def _generate_explanations(
        self, 
        result: EnterpriseAnalysisResult
    ) -> Dict[str, str]:
        """Generate SOC-grade explanations"""
        base = result.base_analysis
        
        explanations = {
            'verdict': result.arbitration.primary_reason if result.arbitration else "Analysis complete",
            'authentication': self.explainer.explain_authentication(
                base.authentication.spf_result,
                base.authentication.dkim_result,
                base.authentication.dmarc_result
            ),
            'links': self.explainer.explain_link_score(
                base.links.https_links,
                base.links.http_links,
                base.links.aligned_links,
                base.links.unrelated_links
            )
        }
        
        # Add VT explanations
        if result.vt_results:
            explanations['virustotal'] = "; ".join([
                self.explainer.explain_vt_result(r) 
                for r in result.vt_results[:2]
            ])
        
        # Add redirect explanations
        if result.redirect_chains:
            chain = result.redirect_chains[0]
            explanations['redirects'] = self.explainer.explain_redirect(
                chain.hop_count,
                chain.chain_type,
                chain.has_external_redirect
            )
        
        return explanations


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Singleton orchestrator
_orchestrator: Optional[EnterpriseAnalysisOrchestrator] = None


def get_enterprise_orchestrator() -> EnterpriseAnalysisOrchestrator:
    """Get singleton orchestrator instance"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = EnterpriseAnalysisOrchestrator()
    return _orchestrator


async def analyze_email_enterprise(
    email_content: bytes,
    enable_redirects: bool = False,
    enable_vt: bool = True
) -> EnterpriseAnalysisResult:
    """Convenience function for enterprise email analysis"""
    orchestrator = get_enterprise_orchestrator()
    return await orchestrator.analyze_email(
        email_content,
        enable_redirect_resolution=enable_redirects,
        enable_virustotal=enable_vt
    )
