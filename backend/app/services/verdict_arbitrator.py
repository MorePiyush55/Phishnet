"""
Verdict Arbitration Layer for PhishNet
=======================================
Phase 5 Implementation: Context-aware final decision making.

Key Principle: NO single module can override context.
The verdict is decided AFTER all modules report.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class VerdictLevel(str, Enum):
    """Verdict levels with severity ordering"""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"


@dataclass
class ModuleResult:
    """Result from a single analysis module"""
    module_name: str
    score: float  # 0-100, higher = safer
    verdict_suggestion: VerdictLevel
    confidence: float  # 0-1
    indicators: List[str] = field(default_factory=list)
    can_force_verdict: bool = False  # Only critical modules can force


@dataclass
class ArbitrationContext:
    """Context for verdict arbitration"""
    # Authentication status
    spf_pass: bool = False
    dkim_pass: bool = False
    dmarc_pass: bool = False
    
    # Link alignment
    sender_link_aligned: bool = False
    alignment_score: float = 0.0
    has_external_redirects: bool = False
    
    # Module results
    module_results: Dict[str, ModuleResult] = field(default_factory=dict)
    
    @property
    def is_fully_authenticated(self) -> bool:
        return self.spf_pass and self.dkim_pass and self.dmarc_pass
    
    @property
    def is_well_aligned(self) -> bool:
        return self.alignment_score >= 0.7


@dataclass
class ArbitrationResult:
    """Final arbitrated verdict"""
    verdict: VerdictLevel
    confidence: float
    final_score: float
    
    # Explanation
    primary_reason: str
    contributing_factors: List[str] = field(default_factory=list)
    mitigating_factors: List[str] = field(default_factory=list)
    
    # Override tracking
    was_overridden: bool = False
    original_verdict: Optional[VerdictLevel] = None
    override_reason: Optional[str] = None


class VerdictArbitrator:
    """
    Phase 5: Verdict Arbitration Layer
    
    Implements hard guardrails that prevent single modules
    from overriding contextual signals.
    """
    
    # Module weights for score aggregation
    DEFAULT_WEIGHTS = {
        'authentication': 0.25,
        'sender': 0.15,
        'content': 0.15,
        'links': 0.20,
        'attachments': 0.15,
        'virustotal': 0.10
    }
    
    def arbitrate(
        self, 
        context: ArbitrationContext,
        module_results: List[ModuleResult]
    ) -> ArbitrationResult:
        """
        Perform final verdict arbitration.
        
        Hard Guardrails:
        1. If fully authenticated + aligned + no external redirects
           → Link module CANNOT produce SUSPICIOUS alone
        2. VT malicious + authenticated + aligned
           → DOWNGRADE to SUSPICIOUS (not PHISHING)
        """
        # Store module results in context
        for result in module_results:
            context.module_results[result.module_name] = result
        
        # Calculate weighted aggregate score
        total_weight = 0.0
        weighted_score = 0.0
        
        for result in module_results:
            weight = self.DEFAULT_WEIGHTS.get(result.module_name, 0.1)
            weighted_score += result.score * weight
            total_weight += weight
        
        final_score = weighted_score / total_weight if total_weight > 0 else 50.0
        
        # Initial verdict based on score
        if final_score < 30:
            initial_verdict = VerdictLevel.PHISHING
        elif final_score < 60:
            initial_verdict = VerdictLevel.SUSPICIOUS
        else:
            initial_verdict = VerdictLevel.SAFE
        
        # Check for module-forced verdicts (critical findings)
        forced_verdict = None
        for result in module_results:
            if result.can_force_verdict and result.verdict_suggestion == VerdictLevel.PHISHING:
                forced_verdict = VerdictLevel.PHISHING
                break
        
        # Apply hard guardrails
        arbitration_result = self._apply_guardrails(
            context, 
            forced_verdict or initial_verdict, 
            final_score,
            module_results
        )
        
        return arbitration_result
    
    def _apply_guardrails(
        self,
        context: ArbitrationContext,
        proposed_verdict: VerdictLevel,
        score: float,
        module_results: List[ModuleResult]
    ) -> ArbitrationResult:
        """Apply hard guardrails to proposed verdict"""
        
        final_verdict = proposed_verdict
        was_overridden = False
        override_reason = None
        mitigating_factors = []
        contributing_factors = []
        
        # Collect contributing factors
        for result in module_results:
            if result.score < 50:
                contributing_factors.extend(result.indicators[:2])
        
        # ═══════════════════════════════════════════════════════════════════
        # GUARDRAIL 1: Authenticated + Aligned Protection
        # ═══════════════════════════════════════════════════════════════════
        if context.is_fully_authenticated and context.is_well_aligned:
            mitigating_factors.append("Email is fully authenticated (SPF+DKIM+DMARC=PASS)")
            mitigating_factors.append(f"Links aligned with sender (score: {context.alignment_score:.0%})")
            
            # Check if only links module is causing SUSPICIOUS
            links_result = context.module_results.get('links')
            other_results = [r for r in module_results if r.module_name != 'links']
            other_scores = [r.score for r in other_results]
            
            if (proposed_verdict == VerdictLevel.SUSPICIOUS and 
                links_result and links_result.score < 50 and
                all(s >= 60 for s in other_scores) and
                not context.has_external_redirects):
                
                # Override: Links alone can't cause SUSPICIOUS when authenticated + aligned
                final_verdict = VerdictLevel.SAFE
                was_overridden = True
                override_reason = "Links module overridden: email is authenticated and aligned"
        
        # ═══════════════════════════════════════════════════════════════════
        # GUARDRAIL 2: VirusTotal Context Arbitration
        # ═══════════════════════════════════════════════════════════════════
        vt_result = context.module_results.get('virustotal')
        if vt_result and vt_result.verdict_suggestion == VerdictLevel.PHISHING:
            if context.is_fully_authenticated and context.is_well_aligned:
                # Downgrade VT-triggered PHISHING to SUSPICIOUS when authenticated + aligned
                if proposed_verdict == VerdictLevel.PHISHING:
                    final_verdict = VerdictLevel.SUSPICIOUS
                    was_overridden = True
                    override_reason = "VT finding downgraded: email is authenticated and aligned"
                    mitigating_factors.append("VirusTotal flagged but sender is authenticated")
        
        # ═══════════════════════════════════════════════════════════════════
        # GUARDRAIL 3: Authentication Failure Override
        # ═══════════════════════════════════════════════════════════════════
        auth_result = context.module_results.get('authentication')
        if auth_result and auth_result.score < 30:
            # Auth failure can upgrade verdict
            if final_verdict == VerdictLevel.SAFE:
                final_verdict = VerdictLevel.SUSPICIOUS
                contributing_factors.append("Email authentication failed")
        
        # Determine primary reason
        primary_reason = self._determine_primary_reason(final_verdict, contributing_factors, mitigating_factors)
        
        # Calculate confidence
        confidence = self._calculate_confidence(module_results, was_overridden)
        
        return ArbitrationResult(
            verdict=final_verdict,
            confidence=confidence,
            final_score=score,
            primary_reason=primary_reason,
            contributing_factors=contributing_factors[:5],
            mitigating_factors=mitigating_factors[:3],
            was_overridden=was_overridden,
            original_verdict=proposed_verdict if was_overridden else None,
            override_reason=override_reason
        )
    
    def _determine_primary_reason(
        self, 
        verdict: VerdictLevel, 
        contributing: List[str],
        mitigating: List[str]
    ) -> str:
        """Determine the primary reason for the verdict"""
        if verdict == VerdictLevel.SAFE:
            if mitigating:
                return mitigating[0]
            return "No significant security concerns detected"
        elif verdict == VerdictLevel.SUSPICIOUS:
            if contributing:
                return contributing[0]
            return "Some elements of this email raise concerns"
        else:  # PHISHING
            if contributing:
                return contributing[0]
            return "Multiple indicators suggest this email is attempting to deceive you"
    
    def _calculate_confidence(
        self, 
        module_results: List[ModuleResult],
        was_overridden: bool
    ) -> float:
        """Calculate confidence in the verdict"""
        # Base confidence from module agreement
        verdicts = [r.verdict_suggestion for r in module_results]
        most_common = max(set(verdicts), key=verdicts.count)
        agreement_ratio = verdicts.count(most_common) / len(verdicts)
        
        # Average module confidence
        avg_confidence = sum(r.confidence for r in module_results) / len(module_results)
        
        confidence = (agreement_ratio * 0.5 + avg_confidence * 0.5)
        
        # Reduce confidence if overridden
        if was_overridden:
            confidence *= 0.85
        
        return min(0.95, confidence)


# Singleton instance
verdict_arbitrator = VerdictArbitrator()


def arbitrate_verdict(
    context: ArbitrationContext,
    module_results: List[ModuleResult]
) -> ArbitrationResult:
    """Convenience function for verdict arbitration"""
    return verdict_arbitrator.arbitrate(context, module_results)
