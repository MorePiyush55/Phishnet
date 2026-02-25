"""
PhishNet Evaluator
===================
Per-node and aggregate evaluation engine with enterprise-grade metrics.

Tracks:
    - Precision, Recall, F1 Score
    - False Positive Rate, False Negative Rate
    - ROC-AUC
    - Per-node accuracy diagnostics

Targets:
    - Precision >= 95%
    - Recall   >= 97%
    - FNR      <  2%
"""

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

from .dataset_loader import DatasetSplit, EmailSample

logger = logging.getLogger("phishnet.testing.evaluator")


# ═══════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════

@dataclass
class ConfusionMatrix:
    """Binary confusion matrix."""
    tp: int = 0  # True Positives (correctly detected phishing)
    fp: int = 0  # False Positives (legitimate flagged as phishing)
    tn: int = 0  # True Negatives (correctly passed legitimate)
    fn: int = 0  # False Negatives (phishing missed — CRITICAL)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        """Of all predicted phishing, how many are truly phishing."""
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        """Of all actual phishing, how many did we catch."""
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        """FPR = FP / (FP + TN)"""
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0

    @property
    def false_negative_rate(self) -> float:
        """FNR = FN / (FN + TP) — THE MOST CRITICAL METRIC."""
        return self.fn / (self.fn + self.tp) if (self.fn + self.tp) > 0 else 0.0

    @property
    def specificity(self) -> float:
        return self.tn / (self.tn + self.fp) if (self.tn + self.fp) > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "specificity": round(self.specificity, 4),
        }


@dataclass
class EvaluationMetrics:
    """Complete evaluation metrics for a single evaluation run."""
    confusion_matrix: ConfusionMatrix
    roc_auc: float = 0.0
    # Per-node accuracy
    node_accuracies: Dict[str, float] = field(default_factory=dict)
    # Per-category breakdown
    category_metrics: Dict[str, ConfusionMatrix] = field(default_factory=dict)
    # Per-difficulty breakdown
    difficulty_metrics: Dict[str, ConfusionMatrix] = field(default_factory=dict)
    # Misclassified samples for analysis
    misclassified: List[Dict[str, Any]] = field(default_factory=list)
    # Target compliance
    targets_met: Dict[str, bool] = field(default_factory=dict)
    # Per-node confusion matrices
    node_confusion_matrices: Dict[str, ConfusionMatrix] = field(default_factory=dict)
    # FN distribution by node (which nodes caused false negatives)
    fn_distribution: Dict[str, int] = field(default_factory=dict)
    # Node contribution importance scores
    node_importance: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall": self.confusion_matrix.to_dict(),
            "roc_auc": round(self.roc_auc, 4),
            "node_accuracies": {k: round(v, 4) for k, v in self.node_accuracies.items()},
            "category_metrics": {k: v.to_dict() for k, v in self.category_metrics.items()},
            "difficulty_metrics": {k: v.to_dict() for k, v in self.difficulty_metrics.items()},
            "misclassified_count": len(self.misclassified),
            "targets_met": self.targets_met,
            "node_confusion_matrices": {k: v.to_dict() for k, v in self.node_confusion_matrices.items()},
            "fn_distribution": self.fn_distribution,
            "node_importance": {k: round(v, 4) for k, v in self.node_importance.items()},
        }


@dataclass
class NodeScore:
    """Individual node score for a single email."""
    sender_score: int = 0
    content_score: int = 0
    link_score: int = 0
    auth_score: int = 0
    attachment_score: int = 0
    weighted_total: int = 0
    predicted_verdict: str = "SAFE"
    confidence: float = 0.0
    risk_factors: List[str] = field(default_factory=list)


@dataclass
class EvaluationRecord:
    """Full evaluation record for a single email sample."""
    sample_id: str
    ground_truth: str
    category: str
    difficulty: str
    node_scores: NodeScore
    correct: bool = False


# ═══════════════════════════════════════════════════════════════
# TARGET THRESHOLDS
# ═══════════════════════════════════════════════════════════════

PERFORMANCE_TARGETS = {
    "precision": 0.95,
    "recall": 0.97,
    "false_negative_rate_max": 0.02,  # < 2%
    "f1_score": 0.96,
}


# ═══════════════════════════════════════════════════════════════
# NODE-LEVEL EVALUATOR
# ═══════════════════════════════════════════════════════════════

class NodeEvaluator:
    """
    Evaluates each analysis node independently to diagnose weak modules.
    
    Runs each email through the EnhancedPhishingAnalyzer and captures
    individual node scores (sender, content, link, auth, attachment).
    """

    # Thresholds for per-node "correct" determination.
    # If ground_truth is PHISHING, a node scoring below this is "correct" (it detected risk).
    # If ground_truth is SAFE, a node scoring above this is "correct" (it cleared the email).
    NODE_PHISHING_THRESHOLD = 50  # Score below this → node flagged as risky
    NODE_SAFE_THRESHOLD = 50      # Score above this → node cleared it

    def __init__(self, analyzer=None):
        """
        Args:
            analyzer: An instance of EnhancedPhishingAnalyzer. If None, imported lazily.
        """
        self._analyzer = analyzer

    @property
    def analyzer(self):
        if self._analyzer is None:
            try:
                from ..services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer
                self._analyzer = EnhancedPhishingAnalyzer()
            except ImportError:
                from ..core.analysis.phishing_analyzer import EnhancedPhishingAnalyzer
                self._analyzer = EnhancedPhishingAnalyzer()
        return self._analyzer

    def analyze_sample(self, sample: EmailSample) -> NodeScore:
        """Run a single sample through the analyzer and return node-level scores."""
        try:
            raw_email = sample.to_raw_email_bytes()
            result = self.analyzer.analyze_email(raw_email)

            return NodeScore(
                sender_score=result.sender.score,
                content_score=result.content.score,
                link_score=result.links.overall_score,
                auth_score=result.authentication.overall_score,
                attachment_score=result.attachments.score,
                weighted_total=result.total_score,
                predicted_verdict=result.final_verdict,
                confidence=result.confidence,
                risk_factors=result.risk_factors,
            )
        except Exception as e:
            logger.error(f"Analysis failed for sample {sample.id}: {e}")
            return NodeScore(predicted_verdict="ERROR", risk_factors=[str(e)])

    def evaluate_node_accuracy(
        self, records: List[EvaluationRecord]
    ) -> Dict[str, float]:
        """
        Calculate per-node accuracy across all evaluation records.
        
        A node is "correct" if:
          - For PHISHING emails: node score < NODE_PHISHING_THRESHOLD (detected risk)
          - For SAFE emails: node score >= NODE_SAFE_THRESHOLD (cleared email)
        
        Returns:
            Dict mapping node name to accuracy percentage (0-100).
        """
        node_names = ["sender", "content", "link", "auth", "attachment"]
        correct_counts = {n: 0 for n in node_names}
        total = len(records)

        if total == 0:
            return {n: 0.0 for n in node_names}

        for rec in records:
            scores = rec.node_scores
            is_phishing_gt = rec.ground_truth in ("PHISHING", "SUSPICIOUS")

            node_scores_map = {
                "sender": scores.sender_score,
                "content": scores.content_score,
                "link": scores.link_score,
                "auth": scores.auth_score,
                "attachment": scores.attachment_score,
            }

            for node_name, score in node_scores_map.items():
                if is_phishing_gt:
                    if score < self.NODE_PHISHING_THRESHOLD:
                        correct_counts[node_name] += 1
                else:
                    if score >= self.NODE_SAFE_THRESHOLD:
                        correct_counts[node_name] += 1

        return {n: round((correct_counts[n] / total) * 100, 1) for n in node_names}

    def evaluate_node_confusion_matrices(
        self, records: List[EvaluationRecord]
    ) -> Dict[str, ConfusionMatrix]:
        """
        Build a per-node confusion matrix.
        
        Each node is treated as an independent binary classifier:
          - Predicts PHISHING if score < NODE_PHISHING_THRESHOLD
          - Predicts SAFE if score >= NODE_SAFE_THRESHOLD
        
        Returns:
            Dict mapping node name → ConfusionMatrix.
        """
        node_names = ["sender", "content", "link", "auth", "attachment"]
        node_cms: Dict[str, ConfusionMatrix] = {n: ConfusionMatrix() for n in node_names}

        for rec in records:
            scores = rec.node_scores
            gt_is_phishing = rec.ground_truth in ("PHISHING", "SUSPICIOUS")

            node_scores_map = {
                "sender": scores.sender_score,
                "content": scores.content_score,
                "link": scores.link_score,
                "auth": scores.auth_score,
                "attachment": scores.attachment_score,
            }

            for node_name, score in node_scores_map.items():
                node_pred_phishing = score < self.NODE_PHISHING_THRESHOLD

                if gt_is_phishing and node_pred_phishing:
                    node_cms[node_name].tp += 1
                elif gt_is_phishing and not node_pred_phishing:
                    node_cms[node_name].fn += 1
                elif not gt_is_phishing and node_pred_phishing:
                    node_cms[node_name].fp += 1
                else:
                    node_cms[node_name].tn += 1

        return node_cms

    def analyze_fn_distribution(
        self, records: List[EvaluationRecord]
    ) -> Dict[str, int]:
        """
        For each false negative (missed phishing), determine which nodes
        failed to flag the email. Returns count of FN contributions per node.
        
        A node "contributed to FN" if it scored >= NODE_SAFE_THRESHOLD
        (i.e., cleared the email) when ground truth was PHISHING.
        """
        node_names = ["sender", "content", "link", "auth", "attachment"]
        fn_counts = {n: 0 for n in node_names}

        for rec in records:
            # Only look at false negatives (GT=PHISHING but predicted SAFE)
            gt_is_phishing = rec.ground_truth in ("PHISHING", "SUSPICIOUS")
            pred_is_phishing = rec.node_scores.predicted_verdict in ("PHISHING", "SUSPICIOUS")
            if not gt_is_phishing or pred_is_phishing:
                continue  # Not a false negative

            node_scores_map = {
                "sender": rec.node_scores.sender_score,
                "content": rec.node_scores.content_score,
                "link": rec.node_scores.link_score,
                "auth": rec.node_scores.auth_score,
                "attachment": rec.node_scores.attachment_score,
            }

            for node_name, score in node_scores_map.items():
                if score >= self.NODE_SAFE_THRESHOLD:
                    fn_counts[node_name] += 1

        return fn_counts

    def compute_node_importance(
        self, records: List[EvaluationRecord]
    ) -> Dict[str, float]:
        """
        Compute feature importance by measuring how much each node's score
        correlates with correct classification (poor man's SHAP).
        
        Importance = |mean_score_correct - mean_score_incorrect| / total_range
        Higher = node matters more for correct classification.
        """
        node_names = ["sender", "content", "link", "auth", "attachment"]
        correct_scores = {n: [] for n in node_names}
        incorrect_scores = {n: [] for n in node_names}

        for rec in records:
            node_scores_map = {
                "sender": rec.node_scores.sender_score,
                "content": rec.node_scores.content_score,
                "link": rec.node_scores.link_score,
                "auth": rec.node_scores.auth_score,
                "attachment": rec.node_scores.attachment_score,
            }
            target = correct_scores if rec.correct else incorrect_scores
            for n, s in node_scores_map.items():
                target[n].append(s)

        importance = {}
        for n in node_names:
            if correct_scores[n] and incorrect_scores[n]:
                mean_correct = sum(correct_scores[n]) / len(correct_scores[n])
                mean_incorrect = sum(incorrect_scores[n]) / len(incorrect_scores[n])
                importance[n] = abs(mean_correct - mean_incorrect) / 100.0
            else:
                importance[n] = 0.0

        # Normalize to sum to 1.0
        total = sum(importance.values())
        if total > 0:
            importance = {n: v / total for n, v in importance.items()}

        return importance


# ═══════════════════════════════════════════════════════════════
# AGGREGATED EVALUATOR
# ═══════════════════════════════════════════════════════════════

class AggregatedEvaluator:
    """
    Runs full 5-node analysis on a dataset split and computes aggregate metrics.
    
    Flow:
        1. Run full analysis on each sample
        2. Store node scores individually
        3. Compare predicted verdict against ground truth
        4. Calculate confusion matrix, precision, recall, F1, FPR, FNR, ROC-AUC
        5. Compute per-node accuracy diagnostics
        6. Check against performance targets
    """

    def __init__(self, node_evaluator: Optional[NodeEvaluator] = None):
        self.node_evaluator = node_evaluator or NodeEvaluator()

    def evaluate(
        self,
        dataset: DatasetSplit,
        weights: Optional[Dict[str, float]] = None,
        verbose: bool = False,
    ) -> EvaluationMetrics:
        """
        Run full evaluation on a dataset split.
        
        Args:
            dataset: The DatasetSplit to evaluate.
            weights: Optional custom weights for score recalculation.
            verbose: If True, log per-sample results.
        
        Returns:
            EvaluationMetrics with full diagnostics.
        """
        records: List[EvaluationRecord] = []
        score_confidence_pairs: List[Tuple[float, int]] = []  # (confidence_score, is_phishing_gt)

        cm = ConfusionMatrix()
        category_cms: Dict[str, ConfusionMatrix] = defaultdict(ConfusionMatrix)
        difficulty_cms: Dict[str, ConfusionMatrix] = defaultdict(ConfusionMatrix)
        misclassified: List[Dict[str, Any]] = []

        for sample in dataset.samples:
            node_scores = self.node_evaluator.analyze_sample(sample)

            # Recalculate weighted total if custom weights provided
            if weights:
                node_scores.weighted_total = self._recalculate_total(node_scores, weights)
                node_scores.predicted_verdict = self._verdict_from_score(node_scores.weighted_total)

            # Determine correctness (binary: phishing vs non-phishing)
            gt_is_phishing = sample.ground_truth in ("PHISHING", "SUSPICIOUS")
            pred_is_phishing = node_scores.predicted_verdict in ("PHISHING", "SUSPICIOUS")
            correct = gt_is_phishing == pred_is_phishing

            # Update confusion matrices
            self._update_cm(cm, gt_is_phishing, pred_is_phishing)
            self._update_cm(category_cms[sample.category], gt_is_phishing, pred_is_phishing)
            self._update_cm(difficulty_cms[sample.difficulty], gt_is_phishing, pred_is_phishing)

            # Store ROC data (use inverted score as confidence for phishing)
            phishing_confidence = 1.0 - (node_scores.weighted_total / 100.0)
            score_confidence_pairs.append((phishing_confidence, 1 if gt_is_phishing else 0))

            record = EvaluationRecord(
                sample_id=sample.id,
                ground_truth=sample.ground_truth,
                category=sample.category,
                difficulty=sample.difficulty,
                node_scores=node_scores,
                correct=correct,
            )
            records.append(record)

            if not correct:
                misclassified.append({
                    "sample_id": sample.id,
                    "ground_truth": sample.ground_truth,
                    "predicted": node_scores.predicted_verdict,
                    "category": sample.category,
                    "difficulty": sample.difficulty,
                    "total_score": node_scores.weighted_total,
                    "node_scores": {
                        "sender": node_scores.sender_score,
                        "content": node_scores.content_score,
                        "link": node_scores.link_score,
                        "auth": node_scores.auth_score,
                        "attachment": node_scores.attachment_score,
                    },
                    "risk_factors": node_scores.risk_factors,
                })

            if verbose:
                status = "✓" if correct else "✗"
                logger.info(
                    f"  {status} [{sample.id}] GT={sample.ground_truth} "
                    f"PRED={node_scores.predicted_verdict} SCORE={node_scores.weighted_total}"
                )

        # Per-node accuracy
        node_accuracies = self.node_evaluator.evaluate_node_accuracy(records)

        # Per-node confusion matrices
        node_cms = self.node_evaluator.evaluate_node_confusion_matrices(records)

        # FN distribution by node
        fn_distribution = self.node_evaluator.analyze_fn_distribution(records)

        # Node importance scores
        node_importance = self.node_evaluator.compute_node_importance(records)

        # ROC-AUC
        roc_auc = self._calculate_roc_auc(score_confidence_pairs)

        # Check targets
        targets_met = self._check_targets(cm)

        metrics = EvaluationMetrics(
            confusion_matrix=cm,
            roc_auc=roc_auc,
            node_accuracies=node_accuracies,
            category_metrics=dict(category_cms),
            difficulty_metrics=dict(difficulty_cms),
            misclassified=misclassified,
            targets_met=targets_met,
            node_confusion_matrices=node_cms,
            fn_distribution=fn_distribution,
            node_importance=node_importance,
        )

        logger.info(
            f"Evaluation complete: {dataset.name} | "
            f"Precision={cm.precision:.3f} Recall={cm.recall:.3f} "
            f"F1={cm.f1_score:.3f} FNR={cm.false_negative_rate:.3f} "
            f"ROC-AUC={roc_auc:.3f}"
        )

        return metrics

    # ─── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _update_cm(cm: ConfusionMatrix, gt_positive: bool, pred_positive: bool) -> None:
        if gt_positive and pred_positive:
            cm.tp += 1
        elif gt_positive and not pred_positive:
            cm.fn += 1  # MISSED PHISHING — worst case
        elif not gt_positive and pred_positive:
            cm.fp += 1
        else:
            cm.tn += 1

    @staticmethod
    def _recalculate_total(scores: NodeScore, weights: Dict[str, float]) -> int:
        """Recalculate weighted total from individual node scores."""
        total = (
            scores.sender_score * weights.get("sender", 0.20) +
            scores.content_score * weights.get("content", 0.25) +
            scores.link_score * weights.get("link", 0.25) +
            scores.auth_score * weights.get("auth", 0.15) +
            scores.attachment_score * weights.get("attachment", 0.15)
        )
        return int(total)

    @staticmethod
    def _verdict_from_score(score: int) -> str:
        """Derive verdict from weighted total score.

        Scoring convention (matches production scoring.py):
            low score  = low risk  = SAFE
            high score = high risk = PHISHING
        """
        if score >= 70:
            return "PHISHING"
        elif score >= 40:
            return "SUSPICIOUS"
        else:
            return "SAFE"

    @staticmethod
    def _check_targets(cm: ConfusionMatrix) -> Dict[str, bool]:
        """Check against performance targets."""
        return {
            "precision_ge_95": cm.precision >= PERFORMANCE_TARGETS["precision"],
            "recall_ge_97": cm.recall >= PERFORMANCE_TARGETS["recall"],
            "fnr_lt_2": cm.false_negative_rate < PERFORMANCE_TARGETS["false_negative_rate_max"],
            "f1_ge_96": cm.f1_score >= PERFORMANCE_TARGETS["f1_score"],
        }

    @staticmethod
    def _calculate_roc_auc(pairs: List[Tuple[float, int]]) -> float:
        """
        Calculate ROC-AUC from (predicted_score, ground_truth_label) pairs.
        Uses the trapezoidal rule on sorted thresholds.
        """
        if not pairs:
            return 0.0

        # Sort by score descending
        sorted_pairs = sorted(pairs, key=lambda x: -x[0])
        
        total_pos = sum(1 for _, label in sorted_pairs if label == 1)
        total_neg = sum(1 for _, label in sorted_pairs if label == 0)

        if total_pos == 0 or total_neg == 0:
            return 0.0

        tp = 0
        fp = 0
        prev_tpr = 0.0
        prev_fpr = 0.0
        auc = 0.0

        for score, label in sorted_pairs:
            if label == 1:
                tp += 1
            else:
                fp += 1
            
            tpr = tp / total_pos
            fpr = fp / total_neg

            # Trapezoidal rule
            auc += (fpr - prev_fpr) * (tpr + prev_tpr) / 2.0
            prev_tpr = tpr
            prev_fpr = fpr

        return min(auc, 1.0)
