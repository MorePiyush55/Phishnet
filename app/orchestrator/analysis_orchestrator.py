"""Analysis orchestrator used by unit tests.

Provides analyzer registration, concurrent execution, basic caching,
aggregation helpers and simple statistics tracking. This is a lightweight
implementation intended to satisfy test contracts; production systems
may replace this with a more sophisticated implementation.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

from app.services.interfaces import AnalysisResult, AnalysisType, ThreatVerdict


class OrchestratorResult:
    def __init__(self, target: str):
        self.target = target
        self.individual_results: List[AnalysisResult] = []
        self.aggregated_threat_score: float = 0.0
        self.final_verdict: ThreatVerdict = ThreatVerdict.CLEAN
        self.aggregated_indicators: List[str] = []
        self.errors: Dict[str, Any] = {}
        self.filtered_results: Optional[List[AnalysisResult]] = None


class AnalysisOrchestrator:
    def __init__(self):
        # name -> analyzer object
        self.analyzers: Dict[str, Any] = {}
        self._cache: Dict[str, OrchestratorResult] = {}
        self.default_timeout: float = 10.0
        self.max_analyzers: int = 50

        # simple statistics
        self._stats = {
            'total_analyses': 0,
            'successful_analyses': 0,
            'failed_analyses': 0,
            'total_duration_seconds': 0.0,
        }

    def add_analyzer(self, name: str, analyzer: Any) -> None:
        if len(self.analyzers) >= self.max_analyzers:
            raise RuntimeError("max analyzers reached")
        self.analyzers[name] = analyzer

    def remove_analyzer(self, name: str) -> None:
        if name in self.analyzers:
            del self.analyzers[name]

    async def _run_analyzer(self, name: str, analyzer: Any, url: str, timeout: Optional[float]) -> Optional[AnalysisResult]:
        coro = analyzer.analyze_url(url)
        try:
            t = timeout if timeout is not None else self.default_timeout
            res = await asyncio.wait_for(coro, timeout=t)
            return res
        except asyncio.TimeoutError as e:
            self._last_errors = (name, e)
            raise

    async def analyze_url(self, url: str, timeout: Optional[float] = None, min_confidence: Optional[float] = None) -> OrchestratorResult:
        # Return cached
        if url in self._cache:
            return self._cache[url]

        start = time.time()
        result = OrchestratorResult(target=url)

        # run analyzers concurrently
        tasks = {}
        for name, analyzer in self.analyzers.items():
            tasks[name] = asyncio.create_task(self._safe_execute(name, analyzer, url, timeout))

        # gather results
        for name, task in tasks.items():
            try:
                r = await task
            except Exception as e:
                # record error and continue
                result.errors[name] = e
                continue

            if r is None:
                continue

            result.individual_results.append(r)

        # Aggregations
        scores = [getattr(r, 'threat_score', 0.0) for r in result.individual_results]
        confidences = [getattr(r, 'confidence', 1.0) for r in result.individual_results]
        verdicts = [getattr(r, 'verdict', ThreatVerdict.CLEAN) for r in result.individual_results]
        indicators = []
        for r in result.individual_results:
            inds = getattr(r, 'indicators', None)
            if inds:
                indicators.extend(inds)

        # determine if any analyzers expose priority and compute weighted average
        priorities = [getattr(getattr(self.analyzers.get(name, None), 'priority', None), '__int__', None) for name in self.analyzers]
        use_weighted = any(p is not None for p in priorities)

        if scores:
            if use_weighted:
                # compute weights based on priority attr if present
                weights = []
                i = 0
                for name in self.analyzers:
                    analyzer = self.analyzers[name]
                    p = getattr(analyzer, 'priority', None)
                    # lower number -> higher priority, convert to weight
                    weights.append((max(1, (5 - (p or 0)))))
                    i += 1
                # align weights length to scores length (only for analyzers that produced results)
                weights = weights[:len(scores)]
                total_w = sum(weights) if sum(weights) > 0 else 1
                weighted = sum(s * w for s, w in zip(scores, weights)) / total_w
                result.aggregated_threat_score = weighted
            else:
                result.aggregated_threat_score = self._aggregate_threat_scores_average(scores)

        result.aggregated_indicators = list(dict.fromkeys(indicators))
        result.final_verdict = self._aggregate_verdicts(verdicts)

        # filtered results by confidence
        if min_confidence is not None:
            result.filtered_results = [r for r in result.individual_results if getattr(r, 'confidence', 1.0) >= min_confidence]

        # update stats
        duration = time.time() - start
        self._stats['total_analyses'] += 1
        if result.individual_results:
            self._stats['successful_analyses'] += 1
        if result.errors:
            self._stats['failed_analyses'] += len(result.errors)
        self._stats['total_duration_seconds'] += duration

        # cache
        self._cache[url] = result

        return result

    async def _safe_execute(self, name: str, analyzer: Any, url: str, timeout: Optional[float]):
        try:
            return await asyncio.wait_for(analyzer.analyze_url(url), timeout=timeout if timeout is not None else self.default_timeout)
        except asyncio.TimeoutError as e:
            raise e
        except Exception as e:
            raise e

    # Aggregation helpers
    def _aggregate_threat_scores_average(self, scores: List[float]) -> float:
        if not scores:
            return 0.0
        return sum(scores) / len(scores)

    def _aggregate_threat_scores_max(self, scores: List[float]) -> float:
        if not scores:
            return 0.0
        return max(scores)

    def _aggregate_threat_scores_weighted(self, scores: List[float], weights: List[float]) -> float:
        if not scores:
            return 0.0
        total = sum(weights)
        if total == 0:
            return self._aggregate_threat_scores_average(scores)
        return sum(s * w for s, w in zip(scores, weights)) / total

    def _aggregate_verdicts(self, verdicts: List[ThreatVerdict]) -> ThreatVerdict:
        # MALICIOUS > SUSPICIOUS > CLEAN
        if any(v == ThreatVerdict.MALICIOUS for v in verdicts):
            return ThreatVerdict.MALICIOUS
        if any(v == ThreatVerdict.SUSPICIOUS for v in verdicts):
            return ThreatVerdict.SUSPICIOUS
        return ThreatVerdict.CLEAN

    # Health checks
    async def check_analyzer_health(self) -> Dict[str, bool]:
        results = {}
        for name, analyzer in self.analyzers.items():
            if hasattr(analyzer, 'health_check'):
                try:
                    ok = await analyzer.health_check()
                except Exception:
                    ok = False
                results[name] = bool(ok)
            else:
                results[name] = True
        return results

    def get_statistics(self) -> Dict[str, Any]:
        avg = 0.0
        if self._stats['total_analyses'] > 0:
            avg = self._stats['total_duration_seconds'] / self._stats['total_analyses']
        return {
            'total_analyses': self._stats['total_analyses'],
            'successful_analyses': self._stats['successful_analyses'],
            'failed_analyses': self._stats['failed_analyses'],
            'average_duration': avg,
        }


__all__ = ["AnalysisOrchestrator"]

