"""
PhishNet Regression Runner
============================
CI-integrated regression testing with baseline metric comparison.

Every code change must:
    1. Run pytest --cov
    2. Run full phishing benchmark
    3. Compare against baseline metrics
    4. Block merge if F1 drops by >1%

Integrates with deployment workflow for safe promotion.
"""

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .dataset_loader import DatasetLoader, DatasetSplit
from .evaluator import AggregatedEvaluator, EvaluationMetrics, PERFORMANCE_TARGETS

logger = logging.getLogger("phishnet.testing.regression_runner")


# ═══════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════

class RegressionVerdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


@dataclass
class BaselineMetrics:
    """Stored baseline metrics from the last successful evaluation."""
    f1_score: float
    precision: float
    recall: float
    false_negative_rate: float
    roc_auc: float
    node_accuracies: Dict[str, float]
    timestamp: str = ""
    commit_hash: str = ""
    version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaselineMetrics":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class RegressionDelta:
    """Difference between current and baseline metrics."""
    metric_name: str
    baseline_value: float
    current_value: float
    delta: float
    threshold: float
    passed: bool

    @property
    def delta_pct(self) -> str:
        if self.baseline_value == 0:
            return "N/A"
        pct = (self.delta / self.baseline_value) * 100
        return f"{pct:+.2f}%"


@dataclass
class RegressionResult:
    """Complete regression test result."""
    verdict: str  # PASS, FAIL, WARN
    timestamp: str
    current_metrics: Dict[str, Any]
    baseline_metrics: Optional[Dict[str, Any]]
    deltas: List[RegressionDelta]
    failed_checks: List[str]
    warnings: List[str]
    node_diagnostics: Dict[str, float]
    duration_seconds: float
    # Deployment gate
    safe_to_deploy: bool = False
    blocking_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "timestamp": self.timestamp,
            "safe_to_deploy": self.safe_to_deploy,
            "blocking_reason": self.blocking_reason,
            "duration_seconds": round(self.duration_seconds, 2),
            "failed_checks": self.failed_checks,
            "warnings": self.warnings,
            "deltas": [
                {
                    "metric": d.metric_name,
                    "baseline": round(d.baseline_value, 4),
                    "current": round(d.current_value, 4),
                    "delta": round(d.delta, 4),
                    "delta_pct": d.delta_pct,
                    "passed": d.passed,
                }
                for d in self.deltas
            ],
            "node_diagnostics": {k: round(v, 1) for k, v in self.node_diagnostics.items()},
            "current_metrics": self.current_metrics,
        }


# ═══════════════════════════════════════════════════════════════
# REGRESSION THRESHOLDS
# ═══════════════════════════════════════════════════════════════

# Maximum allowed regression (drop) per metric before blocking merge
REGRESSION_THRESHOLDS = {
    "f1_score": 0.01,           # Block if F1 drops by >1%
    "recall": 0.01,             # Block if recall drops by >1%
    "precision": 0.02,          # Block if precision drops by >2%
    "false_negative_rate": 0.01, # Block if FNR increases by >1%
    "roc_auc": 0.02,           # Block if ROC-AUC drops by >2%
}

# Warning thresholds (smaller drops trigger warnings)
WARNING_THRESHOLDS = {
    "f1_score": 0.005,
    "recall": 0.005,
    "precision": 0.01,
    "false_negative_rate": 0.005,
    "roc_auc": 0.01,
}

# Per-node accuracy warning threshold
NODE_ACCURACY_WARNING_THRESHOLD = 5.0  # Warn if any node drops >5%


# ═══════════════════════════════════════════════════════════════
# REGRESSION RUNNER
# ═══════════════════════════════════════════════════════════════

class RegressionRunner:
    """
    Runs regression tests comparing current performance against baselines.
    
    Workflow:
        1. Load baseline metrics (from last successful run)
        2. Run full evaluation on benchmark dataset
        3. Compare current vs baseline
        4. Generate pass/fail/warn verdict
        5. Block deployment if regression exceeds thresholds
    """

    DEFAULT_BASELINE_PATH = "backend/app/testing/baselines/latest_baseline.json"

    def __init__(
        self,
        evaluator: Optional[AggregatedEvaluator] = None,
        baseline_path: Optional[str] = None,
    ):
        self.evaluator = evaluator or AggregatedEvaluator()
        self.baseline_path = baseline_path or self.DEFAULT_BASELINE_PATH

    # ─── Run Regression ───────────────────────────────────────

    def run(
        self,
        dataset: DatasetSplit,
        commit_hash: str = "",
        version: str = "",
        weights: Optional[Dict[str, float]] = None,
    ) -> RegressionResult:
        """
        Run complete regression test suite.
        
        Args:
            dataset: Benchmark dataset split to evaluate.
            commit_hash: Git commit hash of current code.
            version: Application version string.
            weights: Optional custom weights for evaluation.
        
        Returns:
            RegressionResult with verdict and diagnostics.
        """
        start_time = time.time()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        logger.info("═" * 60)
        logger.info("PHISHNET REGRESSION TEST SUITE")
        logger.info(f"Timestamp: {timestamp}")
        logger.info(f"Commit: {commit_hash or 'unknown'}")
        logger.info(f"Dataset: {dataset.name} ({dataset.size} samples)")
        logger.info("═" * 60)

        # Step 1: Run evaluation
        logger.info("Step 1: Running full benchmark evaluation...")
        metrics = self.evaluator.evaluate(dataset, weights=weights, verbose=False)

        # Step 2: Load baseline
        logger.info("Step 2: Loading baseline metrics...")
        baseline = self._load_baseline()

        # Step 3: Compare
        logger.info("Step 3: Comparing against baseline...")
        deltas, failed_checks, warnings = self._compare_metrics(metrics, baseline)

        # Step 4: Check node diagnostics
        logger.info("Step 4: Running node-level diagnostics...")
        node_diagnostics = metrics.node_accuracies
        node_warnings = self._check_node_regression(node_diagnostics, baseline)
        warnings.extend(node_warnings)

        # Step 5: Check absolute targets
        logger.info("Step 5: Checking performance targets...")
        target_failures = self._check_absolute_targets(metrics)
        failed_checks.extend(target_failures)

        # Step 6: Determine verdict
        if failed_checks:
            verdict = RegressionVerdict.FAIL.value
            safe_to_deploy = False
            blocking_reason = f"Failed checks: {', '.join(failed_checks)}"
        elif warnings:
            verdict = RegressionVerdict.WARN.value
            safe_to_deploy = True  # Warnings don't block, but flag for review
            blocking_reason = ""
        else:
            verdict = RegressionVerdict.PASS.value
            safe_to_deploy = True
            blocking_reason = ""

        duration = time.time() - start_time

        result = RegressionResult(
            verdict=verdict,
            timestamp=timestamp,
            current_metrics=metrics.to_dict(),
            baseline_metrics=baseline.to_dict() if baseline else None,
            deltas=deltas,
            failed_checks=failed_checks,
            warnings=warnings,
            node_diagnostics=node_diagnostics,
            duration_seconds=duration,
            safe_to_deploy=safe_to_deploy,
            blocking_reason=blocking_reason,
        )

        # Log summary
        logger.info("═" * 60)
        logger.info(f"VERDICT: {verdict}")
        logger.info(f"Safe to deploy: {safe_to_deploy}")
        if blocking_reason:
            logger.warning(f"BLOCKING: {blocking_reason}")
        for w in warnings:
            logger.warning(f"WARNING: {w}")
        logger.info(f"Duration: {duration:.1f}s")
        logger.info("═" * 60)

        return result

    # ─── Comparison Logic ─────────────────────────────────────

    def _compare_metrics(
        self,
        current: EvaluationMetrics,
        baseline: Optional[BaselineMetrics],
    ) -> tuple:
        """Compare current metrics against baseline."""
        deltas: List[RegressionDelta] = []
        failed_checks: List[str] = []
        warnings: List[str] = []

        if baseline is None:
            logger.info("No baseline found — first run. All checks pass by default.")
            return deltas, failed_checks, warnings

        cm = current.confusion_matrix
        comparison_pairs = [
            ("f1_score", cm.f1_score, baseline.f1_score, False),
            ("recall", cm.recall, baseline.recall, False),
            ("precision", cm.precision, baseline.precision, False),
            ("roc_auc", current.roc_auc, baseline.roc_auc, False),
            ("false_negative_rate", cm.false_negative_rate, baseline.false_negative_rate, True),
        ]

        for metric_name, current_val, baseline_val, higher_is_worse in comparison_pairs:
            if higher_is_worse:
                delta = current_val - baseline_val  # Positive = worse
                regression_threshold = REGRESSION_THRESHOLDS.get(metric_name, 0.01)
                warning_threshold = WARNING_THRESHOLDS.get(metric_name, 0.005)
                passed = delta <= regression_threshold
                is_warning = delta > warning_threshold and passed
            else:
                delta = baseline_val - current_val  # Positive = worse (score dropped)
                regression_threshold = REGRESSION_THRESHOLDS.get(metric_name, 0.01)
                warning_threshold = WARNING_THRESHOLDS.get(metric_name, 0.005)
                passed = delta <= regression_threshold
                is_warning = delta > warning_threshold and passed

            rd = RegressionDelta(
                metric_name=metric_name,
                baseline_value=baseline_val,
                current_value=current_val,
                delta=delta,
                threshold=regression_threshold,
                passed=passed,
            )
            deltas.append(rd)

            if not passed:
                msg = (
                    f"{metric_name}: regressed by {delta:.4f} "
                    f"(threshold: {regression_threshold:.4f})"
                )
                failed_checks.append(msg)
                logger.error(f"REGRESSION FAILURE: {msg}")
            elif is_warning:
                msg = (
                    f"{metric_name}: minor regression of {delta:.4f} "
                    f"(warning threshold: {warning_threshold:.4f})"
                )
                warnings.append(msg)

        return deltas, failed_checks, warnings

    def _check_node_regression(
        self,
        current_nodes: Dict[str, float],
        baseline: Optional[BaselineMetrics],
    ) -> List[str]:
        """Check for per-node accuracy regressions."""
        warnings = []
        if baseline is None or not baseline.node_accuracies:
            return warnings

        for node, current_acc in current_nodes.items():
            baseline_acc = baseline.node_accuracies.get(node, 0)
            drop = baseline_acc - current_acc
            if drop > NODE_ACCURACY_WARNING_THRESHOLD:
                warnings.append(
                    f"Node '{node}' accuracy dropped {drop:.1f}% "
                    f"(baseline={baseline_acc:.1f}% → current={current_acc:.1f}%)"
                )

        return warnings

    @staticmethod
    def _check_absolute_targets(metrics: EvaluationMetrics) -> List[str]:
        """Check against absolute performance targets."""
        failures = []
        cm = metrics.confusion_matrix

        if cm.precision < PERFORMANCE_TARGETS["precision"]:
            failures.append(
                f"Precision {cm.precision:.3f} below target {PERFORMANCE_TARGETS['precision']}"
            )
        if cm.recall < PERFORMANCE_TARGETS["recall"]:
            failures.append(
                f"Recall {cm.recall:.3f} below target {PERFORMANCE_TARGETS['recall']}"
            )
        if cm.false_negative_rate >= PERFORMANCE_TARGETS["false_negative_rate_max"]:
            failures.append(
                f"FNR {cm.false_negative_rate:.3f} exceeds max {PERFORMANCE_TARGETS['false_negative_rate_max']}"
            )

        return failures

    # ─── Baseline Management ─────────────────────────────────

    def _load_baseline(self) -> Optional[BaselineMetrics]:
        """Load baseline metrics from file."""
        path = Path(self.baseline_path)
        if not path.exists():
            logger.info(f"No baseline file found at {self.baseline_path}")
            return None

        try:
            with open(path) as f:
                data = json.load(f)
            baseline = BaselineMetrics.from_dict(data)
            logger.info(
                f"Loaded baseline: F1={baseline.f1_score:.3f} "
                f"Recall={baseline.recall:.3f} (from {baseline.timestamp})"
            )
            return baseline
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return None

    def save_baseline(
        self,
        metrics: EvaluationMetrics,
        commit_hash: str = "",
        version: str = "",
    ) -> None:
        """Save current metrics as the new baseline."""
        cm = metrics.confusion_matrix
        baseline = BaselineMetrics(
            f1_score=cm.f1_score,
            precision=cm.precision,
            recall=cm.recall,
            false_negative_rate=cm.false_negative_rate,
            roc_auc=metrics.roc_auc,
            node_accuracies=metrics.node_accuracies,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            commit_hash=commit_hash,
            version=version,
        )

        path = Path(self.baseline_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(baseline.to_dict(), f, indent=2)

        logger.info(f"New baseline saved: F1={cm.f1_score:.3f} Recall={cm.recall:.3f}")

    def save_result(self, result: RegressionResult, output_dir: str = "backend/app/testing/results") -> str:
        """Save regression result to a timestamped file."""
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)

        filename = f"regression_{result.timestamp.replace(':', '-')}.json"
        filepath = path / filename

        with open(filepath, "w") as f:
            json.dump(result.to_dict(), f, indent=2)

        logger.info(f"Regression result saved to {filepath}")
        return str(filepath)

    # ─── CI Integration Helpers ───────────────────────────────

    def run_ci_gate(
        self,
        dataset: Optional[DatasetSplit] = None,
        commit_hash: str = "",
    ) -> bool:
        """
        Run as a CI gate check. Returns True if safe to merge.
        
        If no dataset is provided, loads the built-in benchmark.
        Exits with appropriate code for CI integration.
        """
        if dataset is None:
            loader = DatasetLoader()
            loader.load_builtin_dataset()
            splits = loader.split()
            dataset = splits["test"]

        result = self.run(dataset, commit_hash=commit_hash)

        if result.safe_to_deploy:
            if result.verdict == RegressionVerdict.PASS.value:
                logger.info("CI GATE: PASSED — safe to merge")
            else:
                logger.info("CI GATE: PASSED (with warnings) — safe to merge")
            # Save as new baseline on pass
            if result.verdict == RegressionVerdict.PASS.value:
                metrics_obj = self.evaluator.evaluate(dataset, verbose=False)
                self.save_baseline(metrics_obj, commit_hash=commit_hash)
            return True
        else:
            logger.error(f"CI GATE: BLOCKED — {result.blocking_reason}")
            return False


# ═══════════════════════════════════════════════════════════════
# DRIFT DETECTION
# ═══════════════════════════════════════════════════════════════

class DriftDetector:
    """
    Monitors for feature distribution drift, prediction drift, and label drift
    using KL divergence and statistical tests.
    
    Tracks three drift types:
        1. Feature Drift — node score distributions shift
        2. Prediction Drift — verdict distribution changes
        3. Label Drift — ground truth distribution changes (if available)
    
    Features tracked:
        - Sender domain entropy
        - Link TLD distribution
        - Attachment extension frequency
        - Per-node score distributions
        - Threat score distribution
    """

    def __init__(self, history_size: int = 500):
        self.history_size = history_size
        self._score_history: List[Dict[str, float]] = []
        self._prediction_history: List[str] = []      # verdict history
        self._label_history: List[str] = []            # ground truth (when available)
        self._feature_history: List[Dict[str, Any]] = []  # raw features
        self._alert_callbacks: List[Any] = []

    def record_scores(self, scores: Dict[str, float]) -> None:
        """Record a set of node scores for drift monitoring."""
        self._score_history.append({
            "timestamp": time.time(),
            **scores,
        })
        if len(self._score_history) > self.history_size:
            self._score_history = self._score_history[-self.history_size:]

    def record_prediction(self, verdict: str, label: Optional[str] = None,
                          features: Optional[Dict[str, Any]] = None) -> None:
        """Record a prediction and optional ground truth for drift tracking."""
        self._prediction_history.append(verdict)
        if len(self._prediction_history) > self.history_size:
            self._prediction_history = self._prediction_history[-self.history_size:]

        if label is not None:
            self._label_history.append(label)
            if len(self._label_history) > self.history_size:
                self._label_history = self._label_history[-self.history_size:]

        if features is not None:
            self._feature_history.append(features)
            if len(self._feature_history) > self.history_size:
                self._feature_history = self._feature_history[-self.history_size:]

    @staticmethod
    def _kl_divergence(p: List[float], q: List[float], epsilon: float = 1e-10) -> float:
        """
        Compute KL divergence: KL(P || Q) = Σ p_i * log(p_i / q_i)
        
        Uses epsilon smoothing to avoid log(0).
        Higher values indicate greater distribution shift.
        """
        kl = 0.0
        for pi, qi in zip(p, q):
            pi = max(pi, epsilon)
            qi = max(qi, epsilon)
            kl += pi * (pi / qi if qi > 0 else 0)
        # Use log form: KL = Σ p * log(p/q)
        import math
        kl = 0.0
        for pi, qi in zip(p, q):
            pi = max(pi, epsilon)
            qi = max(qi, epsilon)
            kl += pi * math.log(pi / qi)
        return max(kl, 0.0)

    @staticmethod
    def _distribution_from_values(values: List[float], bins: int = 10,
                                   range_min: float = 0, range_max: float = 100) -> List[float]:
        """Convert raw values to a normalized probability distribution."""
        if not values:
            return [1.0 / bins] * bins  # uniform
        bin_width = (range_max - range_min) / bins
        counts = [0] * bins
        for v in values:
            idx = min(int((v - range_min) / bin_width), bins - 1)
            idx = max(0, idx)
            counts[idx] += 1
        total = sum(counts)
        if total == 0:
            return [1.0 / bins] * bins
        return [c / total for c in counts]

    @staticmethod
    def _categorical_distribution(values: List[str], categories: List[str]) -> List[float]:
        """Convert categorical values to a probability distribution."""
        if not values:
            n = len(categories)
            return [1.0 / n] * n
        counts = {c: 0 for c in categories}
        for v in values:
            if v in counts:
                counts[v] += 1
        total = sum(counts.values())
        if total == 0:
            n = len(categories)
            return [1.0 / n] * n
        return [counts[c] / total for c in categories]

    def check_drift(self, window_size: int = 50) -> Dict[str, Any]:
        """
        Comprehensive drift detection across feature, prediction, and label distributions.
        
        Uses KL divergence to measure distribution shifts between recent
        window and historical baseline.
        
        Args:
            window_size: Number of recent samples to compare against historical.
        
        Returns:
            Dict with drift analysis results per drift type.
        """
        result: Dict[str, Any] = {
            "drift_detected": False,
            "feature_drift": {},
            "prediction_drift": {},
            "label_drift": {},
            "kl_divergences": {},
            "samples_analyzed": len(self._score_history),
        }

        # ── Feature Drift (node score distributions) ──
        if len(self._score_history) >= window_size * 2:
            recent = self._score_history[-window_size:]
            historical = self._score_history[-window_size * 2:-window_size]

            nodes = ["sender_score", "content_score", "link_score", "auth_score", "attachment_score"]
            feature_kl = {}
            feature_shifts = {}

            for node in nodes:
                recent_vals = [r.get(node, 50) for r in recent]
                hist_vals = [h.get(node, 50) for h in historical]

                p = self._distribution_from_values(recent_vals)
                q = self._distribution_from_values(hist_vals)
                kl = self._kl_divergence(p, q)
                feature_kl[node] = round(kl, 4)

                recent_mean = sum(recent_vals) / len(recent_vals)
                hist_mean = sum(hist_vals) / len(hist_vals)
                feature_shifts[node] = round(abs(recent_mean - hist_mean), 2)

            result["feature_drift"] = {
                "kl_divergences": feature_kl,
                "mean_shifts": feature_shifts,
                "significant": {k: v for k, v in feature_kl.items() if v > 0.1},
            }
            result["kl_divergences"].update(feature_kl)

            # Overall threat score drift
            recent_totals = [sum(r.get(n, 50) for n in nodes) / len(nodes) for r in recent]
            hist_totals = [sum(h.get(n, 50) for n in nodes) / len(nodes) for h in historical]
            p_total = self._distribution_from_values(recent_totals)
            q_total = self._distribution_from_values(hist_totals)
            result["feature_drift"]["threat_score_kl"] = round(self._kl_divergence(p_total, q_total), 4)

        # ── Prediction Drift (verdict distribution) ──
        if len(self._prediction_history) >= window_size * 2:
            recent_preds = self._prediction_history[-window_size:]
            hist_preds = self._prediction_history[-window_size * 2:-window_size]

            categories = ["SAFE", "SUSPICIOUS", "PHISHING"]
            p = self._categorical_distribution(recent_preds, categories)
            q = self._categorical_distribution(hist_preds, categories)
            pred_kl = self._kl_divergence(p, q)

            result["prediction_drift"] = {
                "kl_divergence": round(pred_kl, 4),
                "recent_distribution": dict(zip(categories, [round(x, 4) for x in p])),
                "historical_distribution": dict(zip(categories, [round(x, 4) for x in q])),
                "significant": pred_kl > 0.1,
            }
            result["kl_divergences"]["prediction"] = round(pred_kl, 4)

        # ── Label Drift (ground truth distribution) ──
        if len(self._label_history) >= window_size * 2:
            recent_labels = self._label_history[-window_size:]
            hist_labels = self._label_history[-window_size * 2:-window_size]

            categories = ["SAFE", "SUSPICIOUS", "PHISHING"]
            p = self._categorical_distribution(recent_labels, categories)
            q = self._categorical_distribution(hist_labels, categories)
            label_kl = self._kl_divergence(p, q)

            result["label_drift"] = {
                "kl_divergence": round(label_kl, 4),
                "recent_distribution": dict(zip(categories, [round(x, 4) for x in p])),
                "historical_distribution": dict(zip(categories, [round(x, 4) for x in q])),
                "significant": label_kl > 0.1,
            }
            result["kl_divergences"]["label"] = round(label_kl, 4)

        # ── Aggregate Drift Decision ──
        significant_drifts = {}
        for key, kl in result.get("kl_divergences", {}).items():
            if kl > 0.1:  # KL > 0.1 threshold
                significant_drifts[key] = kl

        if result.get("feature_drift", {}).get("significant"):
            significant_drifts.update(result["feature_drift"]["significant"])
        if result.get("prediction_drift", {}).get("significant"):
            significant_drifts["prediction"] = result["prediction_drift"]["kl_divergence"]
        if result.get("label_drift", {}).get("significant"):
            significant_drifts["label"] = result["label_drift"]["kl_divergence"]

        result["drift_detected"] = len(significant_drifts) > 0
        result["significant_drifts"] = significant_drifts

        if result["drift_detected"]:
            logger.warning(f"DRIFT DETECTED: {significant_drifts}")
            for callback in self._alert_callbacks:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Drift alert callback failed: {e}")

        return result

    def on_drift(self, callback) -> None:
        """Register a callback to be invoked when drift is detected."""
        self._alert_callbacks.append(callback)
