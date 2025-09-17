"""ThreatAggregator used by unit tests.

Provides aggregation across AnalysisResult items: weighted averaging,
consensus detection, indicator aggregation, and basic configuration of
service weights.
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from app.services.interfaces import AnalysisResult


@dataclass
class AggregatedResult:
    final_threat_score: float
    confidence: float
    verdict: str
    contributing_results: List[AnalysisResult]
    aggregated_indicators: List[str]
    explanation: str
    aggregation_time_ms: int


class ThreatAggregator:
    def __init__(self):
        # service weight mapping (default to 1.0)
        self._weights: Dict[str, float] = {}
        self._aggregation_method = 'weighted_average'

    def set_aggregation_method(self, method: str) -> None:
        self._aggregation_method = method

    def set_service_weights(self, weights: Dict[str, float]) -> None:
        self._weights.update(weights)

    def get_service_weight(self, service_name: str) -> float:
        return float(self._weights.get(service_name, 1.0))

    def aggregate_results(self, results: List[AnalysisResult]) -> AggregatedResult:
        start = 0
        # handle empty
        if not results:
            return AggregatedResult(
                final_threat_score=0.0,
                confidence=0.0,
                verdict='unknown',
                contributing_results=[],
                aggregated_indicators=[],
                explanation='No analysis results provided',
                aggregation_time_ms=0
            )

        # collect scores and weights
        scores = []
        weights = []
        indicators = []
        for r in results:
            w = self.get_service_weight(getattr(r, 'service_name', ''))
            scores.append(getattr(r, 'threat_score', 0.0))
            weights.append(w)
            inds = getattr(r, 'indicators', None) or []
            indicators.extend(inds)

        # delegate score calculation to helper for clearer logic and testing
        final_score, confidence, explanation = self.calculate_final_score(results)

        # determine verdict
        if final_score >= 0.7:
            verdict = 'malicious'
        elif final_score >= 0.3:
            verdict = 'suspicious'
        else:
            verdict = 'clean'

        aggregated_indicators = list(dict.fromkeys(indicators))

        # build AggregatedResult
        return AggregatedResult(
            final_threat_score=final_score,
            confidence=confidence,
            verdict=verdict,
            contributing_results=results,
            aggregated_indicators=aggregated_indicators,
            explanation=explanation,
            aggregation_time_ms=1
        )

    def calculate_final_score(self, results: List[AnalysisResult]):
        """Calculate a final threat score and confidence with heuristics.

        Uses configured service weights combined with each result's reported
        confidence to form effective weights. Detects conflicts and single
        result scenarios to adjust explanations and confidence.
        Returns tuple: (final_score: float, confidence: float, explanation: str)
        """
        if not results:
            return 0.0, 0.0, 'No analysis results provided'

        scores = [getattr(r, 'threat_score', 0.0) for r in results]
        confidences = [getattr(r, 'confidence', 1.0) for r in results]

        # build effective weights using service weights * reported confidence
        eff_weights = []
        for r, conf in zip(results, confidences):
            svc = getattr(r, 'service_name', '')
            base_w = self.get_service_weight(svc)
            eff_weights.append(base_w * (conf if conf is not None else 0.0))

        # single-result shortcut
        if len(results) == 1:
            single_score = scores[0]
            confidence_out = confidences[0] * 0.95
            explanation = 'Single service result — limited analysis'
            return single_score, confidence_out, explanation

        # compute final score by aggregation method
        if self._aggregation_method == 'max_score':
            final_score = max(scores)
        elif self._aggregation_method == 'consensus':
            avg = sum(scores) / len(scores)
            variance = sum((s - avg) ** 2 for s in scores) / len(scores)
            # consensus penalizes high variance
            final_score = max(0.0, avg - variance)
        else:
            total_w = sum(eff_weights) if sum(eff_weights) > 0 else len(eff_weights)
            final_score = sum(s * w for s, w in zip(scores, eff_weights)) / total_w

        # base confidence is average reported confidence
        confidence_out = sum(confidences) / len(confidences)

        # detect conflict (large spread) and annotate
        spread = max(scores) - min(scores)
        variance = 0.0
        if len(scores) > 0:
            avg = sum(scores) / len(scores)
            variance = sum((s - avg) ** 2 for s in scores) / len(scores)

        explanation = 'Aggregated result'
        if spread > 0.5 or variance > 0.04:
            explanation = 'Conflict detected between sources — disagreement in results'
            # reduce confidence for conflicting inputs
            confidence_out = max(0.0, confidence_out * 0.8)
        else:
            # note strong consensus when scores cluster and are high
            if all(s >= 0.6 for s in scores) and variance < 0.02:
                explanation = 'Consensus reached across sources'

        return float(final_score), float(confidence_out), explanation


__all__ = ["ThreatAggregator"]
