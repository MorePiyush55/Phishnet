"""
PhishNet Calibration, Confidence Scoring & Explainability
============================================================
Production-grade post-processing for the 5-node phishing analyzer.

Three responsibilities:
    1. **Probability calibration** — convert raw 0-100 threat scores into
       well-calibrated probabilities via Platt scaling or isotonic regression.
    2. **Confidence scoring** — express how *certain* we are in a verdict
       based on inter-node agreement (all nodes flag → high, single node → low).
    3. **Explainability** — produce human-readable explanations:
       top-3 risk factors, matched detection rules, threat-intel attribution.

All components are lightweight (no external ML libraries required) and
designed to work with the ``EnhancedPhishingAnalyzer`` result objects.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("phishnet.testing.calibration")

# ═══════════════════════════════════════════════════════════════
# DATACLASSES
# ═══════════════════════════════════════════════════════════════


@dataclass
class CalibrationPoint:
    """A single (raw_score, observed_positive_rate) pair used for fitting."""
    raw_score: float
    positive_rate: float
    sample_count: int = 1


@dataclass
class CalibrationResult:
    """Output of a calibration model."""
    raw_score: float
    calibrated_probability: float
    method: str  # "platt" | "isotonic" | "identity"


@dataclass
class ConfidenceAssessment:
    """Confidence assessment based on node agreement."""
    confidence_level: str  # "HIGH" | "MEDIUM" | "LOW"
    confidence_score: float  # 0.0 – 1.0
    agreeing_nodes: List[str]
    dissenting_nodes: List[str]
    verdict_strength: str  # "UNANIMOUS" | "MAJORITY" | "SPLIT" | "MINORITY"
    explanation: str


@dataclass
class ExplainabilityReport:
    """Human-readable explanation of an analysis result."""
    verdict: str
    threat_score: float
    top_reasons: List[str]  # top-3 risk factors
    matched_rules: List[str]  # which detection rules fired
    node_summaries: Dict[str, str]  # per-node one-liner
    contributing_signals: List[Dict[str, Any]]
    threat_intel_sources: List[str]
    recommendation: str


# ═══════════════════════════════════════════════════════════════
# PLATT SCALING
# ═══════════════════════════════════════════════════════════════


class PlattScaler:
    """
    Platt scaling (logistic calibration) for threat scores.

    Fits  P(phishing | score) = 1 / (1 + exp(A * score + B))
    via maximum-likelihood using Newton's method on a set of
    (score, label) pairs collected from evaluation runs.

    Reference: Platt (1999), *Probabilistic outputs for support
    vector machines and comparisons to regularized likelihood methods.*
    """

    def __init__(self):
        self.A: float = 0.0
        self.B: float = 0.0
        self.fitted: bool = False

    def fit(
        self,
        scores: List[float],
        labels: List[int],
        max_iter: int = 100,
        min_step: float = 1e-10,
    ) -> None:
        """
        Fit Platt parameters A, B.

        Args:
            scores: Raw threat scores (0–100, where low = phishing).
            labels: Ground truth binary labels (1 = phishing, 0 = safe).
            max_iter: Maximum Newton iterations.
            min_step: Convergence step threshold.
        """
        if len(scores) != len(labels) or len(scores) < 5:
            logger.warning("Platt scaling requires >= 5 labeled samples")
            return

        # Target probabilities with Bayes prior smoothing (Platt's recipe)
        n_pos = sum(labels)
        n_neg = len(labels) - n_pos
        if n_pos == 0 or n_neg == 0:
            logger.warning("Platt scaling: need both positive and negative samples")
            return

        hi_target = (n_pos + 1.0) / (n_pos + 2.0)
        lo_target = 1.0 / (n_neg + 2.0)
        targets = [hi_target if lbl == 1 else lo_target for lbl in labels]

        A, B = 0.0, math.log((n_neg + 1.0) / (n_pos + 1.0))
        lambda_reg = 1e-3  # L2 regularisation to avoid numerical blow-up

        for iteration in range(max_iter):
            d1A, d1B = 0.0, 0.0
            d2A, d2B, d2AB = 0.0, 0.0, 0.0

            for s, t in zip(scores, targets):
                fval = A * s + B
                # Numerically stable sigmoid
                if fval >= 0:
                    p = 1.0 / (1.0 + math.exp(-fval))
                else:
                    ef = math.exp(fval)
                    p = ef / (1.0 + ef)
                p = max(min(p, 1.0 - 1e-15), 1e-15)

                d = p - t
                d1A += s * d
                d1B += d
                q = p * (1.0 - p)
                d2A += s * s * q
                d2B += q
                d2AB += s * q

            # Regularise Hessian diagonal
            d2A += lambda_reg
            d2B += lambda_reg

            det = d2A * d2B - d2AB * d2AB
            if abs(det) < 1e-15:
                break
            stepA = -(d2B * d1A - d2AB * d1B) / det
            stepB = -(d2A * d1B - d2AB * d1A) / det

            A += stepA
            B += stepB

            if abs(stepA) < min_step and abs(stepB) < min_step:
                logger.debug(f"Platt scaling converged at iteration {iteration + 1}")
                break

        self.A = A
        self.B = B
        self.fitted = True
        logger.info(f"Platt scaling fitted: A={A:.6f}, B={B:.6f}")

    def predict(self, score: float) -> float:
        """Return calibrated probability P(phishing | score)."""
        if not self.fitted:
            # Identity fallback: invert and normalise
            return max(0.0, min(1.0, (100.0 - score) / 100.0))
        fval = self.A * score + self.B
        if fval >= 0:
            return 1.0 / (1.0 + math.exp(-fval))
        ef = math.exp(fval)
        return ef / (1.0 + ef)


# ═══════════════════════════════════════════════════════════════
# ISOTONIC REGRESSION (PAV algorithm)
# ═══════════════════════════════════════════════════════════════


class IsotonicCalibrator:
    """
    Isotonic regression calibrator using the Pool Adjacent Violators
    (PAV) algorithm.  Non-parametric — makes no assumptions about the
    functional form of the mapping.

    Stores a stepwise non-decreasing function mapping raw scores to
    calibrated probabilities.
    """

    def __init__(self):
        self._thresholds: List[float] = []
        self._values: List[float] = []
        self.fitted: bool = False

    def fit(self, scores: List[float], labels: List[int]) -> None:
        """
        Fit an isotonic regression model.

        Because *lower* scores mean *more phishing* in the PhishNet
        scale (0-40 = phishing), we invert the scores for fitting
        so that the isotonic function is correctly non-decreasing
        with respect to phishing probability.
        """
        if len(scores) < 3:
            logger.warning("Isotonic calibration needs >= 3 samples")
            return

        # Sort by inverted score (ascending = more phishing first)
        inverted = [(100.0 - s, lbl) for s, lbl in zip(scores, labels)]
        inverted.sort(key=lambda x: x[0])

        # PAV
        n = len(inverted)
        block_values = [float(lbl) for _, lbl in inverted]
        block_weights = [1.0] * n
        block_keys = [inv for inv, _ in inverted]

        i = 0
        while i < len(block_values) - 1:
            if block_values[i] > block_values[i + 1]:
                # Merge adjacent blocks
                merged_val = (
                    block_values[i] * block_weights[i]
                    + block_values[i + 1] * block_weights[i + 1]
                ) / (block_weights[i] + block_weights[i + 1])
                merged_weight = block_weights[i] + block_weights[i + 1]
                merged_key = block_keys[i + 1]

                block_values[i] = merged_val
                block_weights[i] = merged_weight
                block_keys[i] = merged_key

                del block_values[i + 1]
                del block_weights[i + 1]
                del block_keys[i + 1]

                # Step back to check previous pair
                if i > 0:
                    i -= 1
            else:
                i += 1

        # Store thresholds (in original score space) and values
        self._thresholds = [100.0 - k for k in reversed(block_keys)]
        self._values = list(reversed(block_values))
        self.fitted = True
        logger.info(
            f"Isotonic calibration fitted with {len(self._thresholds)} knot points"
        )

    def predict(self, score: float) -> float:
        """Return calibrated probability P(phishing | score)."""
        if not self.fitted or not self._thresholds:
            return max(0.0, min(1.0, (100.0 - score) / 100.0))

        # Binary search for the right interval
        if score <= self._thresholds[0]:
            return self._values[0]
        if score >= self._thresholds[-1]:
            return self._values[-1]

        lo, hi = 0, len(self._thresholds) - 1
        while lo < hi - 1:
            mid = (lo + hi) // 2
            if self._thresholds[mid] <= score:
                lo = mid
            else:
                hi = mid

        # Linear interpolation between knots
        t = (score - self._thresholds[lo]) / max(
            self._thresholds[hi] - self._thresholds[lo], 1e-9
        )
        return self._values[lo] + t * (self._values[hi] - self._values[lo])


# ═══════════════════════════════════════════════════════════════
# UNIFIED PROBABILITY CALIBRATOR
# ═══════════════════════════════════════════════════════════════


class ProbabilityCalibrator:
    """
    Unified calibrator that supports both Platt scaling and isotonic
    regression, with automatic method selection.

    Usage::

        calibrator = ProbabilityCalibrator(method="platt")
        calibrator.fit(scores, labels)
        p = calibrator.predict(raw_score)
    """

    def __init__(self, method: str = "platt"):
        """
        Args:
            method: "platt", "isotonic", or "auto" (try both, pick best).
        """
        self.method = method
        self.platt = PlattScaler()
        self.isotonic = IsotonicCalibrator()
        self._active: str = method

    def fit(self, scores: List[float], labels: List[int]) -> None:
        """Fit on labeled evaluation data."""
        if self.method in ("platt", "auto"):
            self.platt.fit(scores, labels)
        if self.method in ("isotonic", "auto"):
            self.isotonic.fit(scores, labels)

        if self.method == "auto":
            self._active = self._select_best(scores, labels)
            logger.info(f"Auto-selected calibration method: {self._active}")

    def _select_best(self, scores: List[float], labels: List[int]) -> str:
        """Select calibrator with lowest Brier score."""
        brier_platt = self._brier(
            [self.platt.predict(s) for s in scores], labels
        )
        brier_iso = self._brier(
            [self.isotonic.predict(s) for s in scores], labels
        )
        logger.info(f"Brier scores — Platt: {brier_platt:.4f}, Isotonic: {brier_iso:.4f}")
        return "platt" if brier_platt <= brier_iso else "isotonic"

    @staticmethod
    def _brier(probs: List[float], labels: List[int]) -> float:
        """Brier score (lower is better)."""
        if not probs:
            return 1.0
        return sum((p - l) ** 2 for p, l in zip(probs, labels)) / len(probs)

    def predict(self, score: float) -> CalibrationResult:
        """Return calibrated probability."""
        if self._active == "isotonic" and self.isotonic.fitted:
            prob = self.isotonic.predict(score)
            method = "isotonic"
        elif self.platt.fitted:
            prob = self.platt.predict(score)
            method = "platt"
        else:
            prob = max(0.0, min(1.0, (100.0 - score) / 100.0))
            method = "identity"
        return CalibrationResult(
            raw_score=score,
            calibrated_probability=round(prob, 4),
            method=method,
        )

    def brier_score(self, scores: List[float], labels: List[int]) -> float:
        """Compute Brier score for the active calibrator."""
        probs = [self.predict(s).calibrated_probability for s in scores]
        return self._brier(probs, labels)


# ═══════════════════════════════════════════════════════════════
# CONFIDENCE SCORING
# ═══════════════════════════════════════════════════════════════


# Node score thresholds — below this score the node flags "suspicious"
_NODE_FLAG_THRESHOLDS = {
    "sender": 50,
    "content": 50,
    "link": 50,
    "authentication": 50,
    "attachment": 50,
}


class ConfidenceScorer:
    """
    Computes a confidence level based on inter-node agreement.

    Agreement semantics:
        - UNANIMOUS: all 5 nodes agree on the verdict direction.
        - MAJORITY: 4 of 5 agree.
        - SPLIT: 3 vs 2.
        - MINORITY: only 1 or 2 nodes flag.

    Mapped to confidence scores:
        - UNANIMOUS → HIGH (0.90 – 1.00)
        - MAJORITY  → HIGH (0.75 – 0.89)
        - SPLIT     → MEDIUM (0.50 – 0.74)
        - MINORITY  → LOW (0.25 – 0.49)
    """

    def __init__(
        self,
        thresholds: Optional[Dict[str, int]] = None,
    ):
        self.thresholds = thresholds or _NODE_FLAG_THRESHOLDS

    def assess(
        self,
        node_scores: Dict[str, float],
        final_verdict: str,
    ) -> ConfidenceAssessment:
        """
        Assess confidence in a verdict based on node agreement.

        Args:
            node_scores: Mapping of node name → score (0–100).
            final_verdict: The assigned verdict ("PHISHING", "SUSPICIOUS", "SAFE").

        Returns:
            ConfidenceAssessment.
        """
        flagging_nodes: List[str] = []
        non_flagging_nodes: List[str] = []

        for node, score in node_scores.items():
            threshold = self.thresholds.get(node, 50)
            if score < threshold:
                flagging_nodes.append(node)
            else:
                non_flagging_nodes.append(node)

        n_flagging = len(flagging_nodes)
        n_total = len(node_scores)

        is_threat_verdict = final_verdict in ("PHISHING", "SUSPICIOUS")

        if is_threat_verdict:
            agreeing = flagging_nodes
            dissenting = non_flagging_nodes
        else:
            agreeing = non_flagging_nodes
            dissenting = flagging_nodes

        agreement_ratio = len(agreeing) / max(n_total, 1)

        # Determine strength and score
        if agreement_ratio >= 1.0:
            strength = "UNANIMOUS"
            conf_score = 0.95
        elif agreement_ratio >= 0.8:
            strength = "MAJORITY"
            conf_score = 0.80
        elif agreement_ratio >= 0.6:
            strength = "SPLIT"
            conf_score = 0.55
        else:
            strength = "MINORITY"
            conf_score = 0.35

        # Fine-tune: boost if scores are extreme (far from threshold)
        avg_distance = 0.0
        for node in agreeing:
            s = node_scores[node]
            thresh = self.thresholds.get(node, 50)
            avg_distance += abs(s - thresh)
        if agreeing:
            avg_distance /= len(agreeing)
        boost = min(avg_distance / 100.0, 0.05)
        conf_score = min(conf_score + boost, 1.0)

        if conf_score >= 0.75:
            level = "HIGH"
        elif conf_score >= 0.50:
            level = "MEDIUM"
        else:
            level = "LOW"

        explanation = (
            f"{strength} agreement ({len(agreeing)}/{n_total} nodes align with "
            f"'{final_verdict}' verdict). "
            f"Agreeing: {', '.join(agreeing) if agreeing else 'none'}. "
            f"Dissenting: {', '.join(dissenting) if dissenting else 'none'}."
        )

        return ConfidenceAssessment(
            confidence_level=level,
            confidence_score=round(conf_score, 3),
            agreeing_nodes=agreeing,
            dissenting_nodes=dissenting,
            verdict_strength=strength,
            explanation=explanation,
        )


# ═══════════════════════════════════════════════════════════════
# EXPLAINABILITY ENGINE
# ═══════════════════════════════════════════════════════════════

# Detection rule catalogue — each maps a condition to a human label
_DETECTION_RULES = [
    ("sender_score_below_30", "Sender score critically low — likely spoofed or unknown sender"),
    ("sender_score_below_50", "Sender reputation below normal"),
    ("content_score_below_30", "Email body contains strong phishing indicators"),
    ("content_score_below_50", "Content shows suspicious language patterns"),
    ("link_score_below_30", "Embedded URLs are highly suspicious"),
    ("link_score_below_50", "One or more links flagged as risky"),
    ("auth_score_below_30", "Email authentication (SPF/DKIM/DMARC) failed significantly"),
    ("auth_score_below_50", "Incomplete or weak email authentication"),
    ("attachment_score_below_30", "Dangerous attachment type detected"),
    ("attachment_score_below_50", "Attachment warrants caution"),
]


class ExplainabilityEngine:
    """
    Produces human-readable explanations for each phishing analysis.

    Output includes:
        - Top-3 risk factors (from the analyzer's own risk_factors list).
        - Matched detection rules (based on node scores).
        - Per-node one-liner summaries.
        - Threat-intel source attribution (if available).
        - Actionable recommendation.
    """

    def explain(
        self,
        node_scores: Dict[str, float],
        final_verdict: str,
        threat_score: float,
        risk_factors: Optional[List[str]] = None,
        threat_intel_sources: Optional[List[str]] = None,
        extra_signals: Optional[List[Dict[str, Any]]] = None,
    ) -> ExplainabilityReport:
        """
        Generate an explainability report.

        Args:
            node_scores: Mapping of node name → score (0–100).
            final_verdict: "PHISHING", "SUSPICIOUS", or "SAFE".
            threat_score: Total threat score (0–100).
            risk_factors: Optional list of risk factor strings from the analyzer.
            threat_intel_sources: Optional list of threat intel sources that contributed.
            extra_signals: Optional list of additional signal dicts.

        Returns:
            ExplainabilityReport.
        """
        risk_factors = risk_factors or []
        threat_intel_sources = threat_intel_sources or []
        extra_signals = extra_signals or []

        # ── Top 3 reasons ──
        top_reasons = risk_factors[:3] if risk_factors else self._infer_reasons(node_scores)

        # ── Matched rules ──
        matched_rules = self._match_rules(node_scores)

        # ── Node summaries ──
        node_summaries = self._summarize_nodes(node_scores)

        # ── Contributing signals ──
        signals = list(extra_signals)
        for node, score in sorted(node_scores.items(), key=lambda x: x[1]):
            signals.append({
                "source": node,
                "score": score,
                "impact": "high" if score < 30 else ("medium" if score < 50 else "low"),
            })

        # ── Recommendation ──
        recommendation = self._recommendation(final_verdict, threat_score, matched_rules)

        return ExplainabilityReport(
            verdict=final_verdict,
            threat_score=threat_score,
            top_reasons=top_reasons,
            matched_rules=matched_rules,
            node_summaries=node_summaries,
            contributing_signals=signals,
            threat_intel_sources=threat_intel_sources,
            recommendation=recommendation,
        )

    def _infer_reasons(self, node_scores: Dict[str, float]) -> List[str]:
        """Infer top reasons from node scores when risk_factors are unavailable."""
        reasons = []
        sorted_nodes = sorted(node_scores.items(), key=lambda x: x[1])
        for node, score in sorted_nodes[:3]:
            if score < 30:
                reasons.append(f"Critical: {node} analysis returned very low score ({score:.0f}/100)")
            elif score < 50:
                reasons.append(f"Warning: {node} analysis flagged concerns ({score:.0f}/100)")
            else:
                reasons.append(f"Note: {node} analysis score is {score:.0f}/100")
        return reasons

    def _match_rules(self, node_scores: Dict[str, float]) -> List[str]:
        """Match detection rules based on node scores."""
        matched = []
        for rule_id, description in _DETECTION_RULES:
            # Parse rule: node_score_below_N
            parts = rule_id.rsplit("_below_", 1)
            if len(parts) != 2:
                continue
            node_prefix = parts[0].replace("_score", "")
            threshold = int(parts[1])

            # Find matching node
            for node, score in node_scores.items():
                if node.startswith(node_prefix) or node_prefix.startswith(node[:4]):
                    if score < threshold:
                        matched.append(description)
                    break

        return matched

    def _summarize_nodes(self, node_scores: Dict[str, float]) -> Dict[str, str]:
        """Generate one-liner summaries per node."""
        summaries = {}
        for node, score in node_scores.items():
            if score >= 80:
                summaries[node] = f"Passed ({score:.0f}/100) — no concerns detected"
            elif score >= 50:
                summaries[node] = f"Marginal ({score:.0f}/100) — minor indicators present"
            elif score >= 30:
                summaries[node] = f"Suspicious ({score:.0f}/100) — significant risk signals"
            else:
                summaries[node] = f"Critical ({score:.0f}/100) — strong phishing indicators"
        return summaries

    def _recommendation(
        self,
        verdict: str,
        threat_score: float,
        matched_rules: List[str],
    ) -> str:
        """Generate an actionable recommendation."""
        if verdict == "PHISHING":
            if threat_score < 20:
                return (
                    "BLOCK IMMEDIATELY. This email exhibits strong phishing characteristics "
                    f"across {len(matched_rules)} detection rules. Quarantine and notify "
                    "the security team."
                )
            return (
                "QUARANTINE. High confidence phishing detection. Review before "
                "releasing to the user."
            )
        elif verdict == "SUSPICIOUS":
            return (
                "FLAG FOR REVIEW. This email triggered some detection rules but "
                "does not conclusively appear malicious. Consider user notification "
                "with caution banner."
            )
        else:
            if matched_rules:
                return (
                    "DELIVER with monitoring. Email appears safe but triggered minor "
                    f"rules ({len(matched_rules)}). No action required unless user reports."
                )
            return "DELIVER. Email passed all detection checks."
