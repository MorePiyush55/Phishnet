"""
PhishNet Report Generator
===========================
Generates human-readable and machine-parseable evaluation reports.

Output Formats:
    - Console summary (colored)
    - JSON (for CI pipelines)
    - Markdown (for PR comments / docs)
    - HTML (for dashboards)

Reports include:
    - Overall metrics (precision, recall, F1, FNR, ROC-AUC)
    - Per-node accuracy diagnostics
    - Per-category breakdown
    - Per-difficulty breakdown
    - Misclassification analysis
    - Weight optimization results
    - Regression comparison
    - AI feedback prompts for misclassified emails
"""

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .evaluator import EvaluationMetrics, PERFORMANCE_TARGETS
from .regression_runner import RegressionResult
from .weight_optimizer import OptimizationResult

logger = logging.getLogger("phishnet.testing.report_generator")


# ═══════════════════════════════════════════════════════════════
# AI FEEDBACK PROMPT TEMPLATE
# ═══════════════════════════════════════════════════════════════

AI_REVIEW_PROMPT_TEMPLATE = """You are a phishing detection expert.

The system classified the following email as {predicted_verdict}.
Ground truth label is {ground_truth}.

Email Details:
- Sample ID: {sample_id}
- Category: {category}
- Difficulty: {difficulty}
- Total Score: {total_score}/100

Node Scores:
- Sender Analysis:     {sender_score}/100
- Content Analysis:    {content_score}/100
- Link Analysis:       {link_score}/100
- Authentication:      {auth_score}/100
- Attachment Analysis: {attachment_score}/100

Risk Factors Detected: {risk_factors}

Analyze why the detection {failure_description}.
Return:
1. Key missed indicators (if any)
2. Which node failed or underperformed
3. Suggested new detection rule
4. Suggested feature improvement
5. Confidence in your assessment (high/medium/low)
"""


# ═══════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════

class ReportGenerator:
    """
    Generates comprehensive evaluation reports in multiple formats.
    """

    def __init__(self, output_dir: str = "backend/app/testing/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ─── Console Report ──────────────────────────────────────

    def print_console_report(
        self,
        metrics: EvaluationMetrics,
        title: str = "PhishNet Evaluation Report",
        optimization: Optional[OptimizationResult] = None,
        regression: Optional[RegressionResult] = None,
    ) -> str:
        """Generate and print a formatted console report. Returns the report string."""
        lines = []
        cm = metrics.confusion_matrix

        lines.append("")
        lines.append("=" * 70)
        lines.append(f"  {title}")
        lines.append(f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("=" * 70)

        # -- Overall Metrics --
        lines.append("")
        lines.append("+-- OVERALL METRICS --------------------------------------------+")
        lines.append(f"|  Precision:           {cm.precision:.4f}  {'[PASS]' if cm.precision >= 0.95 else '[FAIL]'} (target >= 0.95)  |")
        lines.append(f"|  Recall:              {cm.recall:.4f}  {'[PASS]' if cm.recall >= 0.97 else '[FAIL]'} (target >= 0.97)  |")
        lines.append(f"|  F1 Score:            {cm.f1_score:.4f}  {'[PASS]' if cm.f1_score >= 0.96 else '[FAIL]'} (target >= 0.96)  |")
        lines.append(f"|  Accuracy:            {cm.accuracy:.4f}                              |")
        lines.append(f"|  False Positive Rate: {cm.false_positive_rate:.4f}                              |")
        lines.append(f"|  False Negative Rate: {cm.false_negative_rate:.4f}  {'[PASS]' if cm.false_negative_rate < 0.02 else '[FAIL]'} (target < 0.02)  |")
        lines.append(f"|  ROC-AUC:             {metrics.roc_auc:.4f}                              |")
        lines.append("+---------------------------------------------------------------+")

        # ── Confusion Matrix ──
        lines.append("")
        lines.append("+-- CONFUSION MATRIX -------------------------------------------+")
        lines.append(f"|                     Predicted PHISH  Predicted SAFE           |")
        lines.append(f"|  Actual PHISH       TP = {cm.tp:>5}        FN = {cm.fn:>5}  <- CRITICAL   |")
        lines.append(f"|  Actual SAFE        FP = {cm.fp:>5}        TN = {cm.tn:>5}              |")
        lines.append(f"|  Total samples: {cm.total}                                     |")
        lines.append("+---------------------------------------------------------------+")

        # ── Node-Level Diagnostics ──
        if metrics.node_accuracies:
            lines.append("")
            lines.append("+-- NODE-LEVEL DIAGNOSTICS -------------------------------------+")
            for node, acc in sorted(metrics.node_accuracies.items()):
                bar = "#" * int(acc / 5) + "-" * (20 - int(acc / 5))
                status = "[PASS]" if acc >= 80 else "[WARN]" if acc >= 60 else "[FAIL]"
                lines.append(f"|  {node:<12} {acc:>5.1f}% {bar} {status}  |")
            lines.append("+---------------------------------------------------------------+")

        # ── Per-Category Breakdown ──
        if metrics.category_metrics:
            lines.append("")
            lines.append("+-- PER-CATEGORY BREAKDOWN ------------------------------------+")
            for cat, cat_cm in metrics.category_metrics.items():
                lines.append(f"|  {cat:<30} F1={cat_cm.f1_score:.3f}  Recall={cat_cm.recall:.3f} |")
            lines.append("+---------------------------------------------------------------+")

        # ── Per-Difficulty Breakdown ──
        if metrics.difficulty_metrics:
            lines.append("")
            lines.append("+-- PER-DIFFICULTY BREAKDOWN -----------------------------------+")
            for diff, diff_cm in metrics.difficulty_metrics.items():
                lines.append(f"|  {diff:<15} F1={diff_cm.f1_score:.3f}  Recall={diff_cm.recall:.3f}  FNR={diff_cm.false_negative_rate:.3f}  |")
            lines.append("+---------------------------------------------------------------+")

        # ── Misclassified Samples ──
        if metrics.misclassified:
            lines.append("")
            lines.append(f"+-- MISCLASSIFIED SAMPLES ({len(metrics.misclassified)}) ---------------------------------+")
            for mc in metrics.misclassified[:10]:
                lines.append(
                    f"|  [{mc['sample_id']}] GT={mc['ground_truth']:<10} "
                    f"PRED={mc['predicted']:<12} SCORE={mc['total_score']:>3} |"
                )
            if len(metrics.misclassified) > 10:
                lines.append(f"|  ... and {len(metrics.misclassified) - 10} more                                    |")
            lines.append("+---------------------------------------------------------------+")

        # ── Target Compliance ──
        lines.append("")
        lines.append("+-- TARGET COMPLIANCE -----------------------------------------+")
        all_met = True
        for target, met in metrics.targets_met.items():
            status = "PASS" if met else "FAIL"
            lines.append(f"|  {target:<25} {status:<10}                     |")
            if not met:
                all_met = False
        overall = "ALL TARGETS MET" if all_met else "TARGETS NOT MET"
        lines.append(f"|  {'-' * 40}                 |")
        lines.append(f"|  {overall:<55}|")
        lines.append("+---------------------------------------------------------------+")

        # ── Weight Optimization ──
        if optimization:
            lines.append("")
            lines.append("+-- WEIGHT OPTIMIZATION RESULTS --------------------------------+")
            lines.append(f"|  Method: {optimization.method:<50}|")
            lines.append(f"|  Best F1: {optimization.best_f1:.4f}                                       |")
            lines.append(f"|  Best Recall: {optimization.best_recall:.4f}                                   |")
            w = optimization.best_weights.to_dict()
            for k, v in w.items():
                lines.append(f"|    {k:<12} = {v:.4f}                                    |")
            lines.append(f"|  Iterations: {optimization.iterations_run}                                       |")
            lines.append(f"|  Time: {optimization.total_time_seconds:.1f}s                                           |")
            lines.append("+---------------------------------------------------------------+")

        # ── Regression Results ──
        if regression:
            lines.append("")
            lines.append("+-- REGRESSION TEST RESULTS ------------------------------------+")
            lines.append(f"|  Verdict: {regression.verdict:<50}|")
            lines.append(f"|  Safe to Deploy: {'YES' if regression.safe_to_deploy else 'NO':<44}|")
            if regression.blocking_reason:
                lines.append(f"|  Blocking: {regression.blocking_reason[:48]:<48}|")
            for delta in regression.deltas:
                status = "[PASS]" if delta.passed else "[FAIL]"
                lines.append(
                    f"|  {status} {delta.metric_name:<20} "
                    f"{delta.baseline_value:.4f} -> {delta.current_value:.4f} "
                    f"(d {delta.delta:+.4f})  |"
                )
            lines.append("+---------------------------------------------------------------+")

        lines.append("")
        lines.append("=" * 70)

        report = "\n".join(lines)
        print(report)
        return report

    # ─── JSON Report ──────────────────────────────────────────

    def generate_json_report(
        self,
        metrics: EvaluationMetrics,
        optimization: Optional[OptimizationResult] = None,
        regression: Optional[RegressionResult] = None,
        filename: Optional[str] = None,
    ) -> str:
        """Generate a JSON report. Returns filepath."""
        report = {
            "report_type": "phishnet_evaluation",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "version": "1.0.0",
            "metrics": metrics.to_dict(),
        }

        if optimization:
            report["optimization"] = optimization.to_dict()
        if regression:
            report["regression"] = regression.to_dict()

        if filename is None:
            filename = f"report_{time.strftime('%Y%m%d_%H%M%S')}.json"

        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        logger.info(f"JSON report saved to {filepath}")
        return str(filepath)

    # ─── Markdown Report ──────────────────────────────────────

    def generate_markdown_report(
        self,
        metrics: EvaluationMetrics,
        optimization: Optional[OptimizationResult] = None,
        regression: Optional[RegressionResult] = None,
        filename: Optional[str] = None,
    ) -> str:
        """Generate a Markdown report for PR comments. Returns filepath."""
        cm = metrics.confusion_matrix
        lines = []

        lines.append("# PhishNet Evaluation Report")
        lines.append(f"*Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}*")
        lines.append("")

        # Overall Metrics Table
        lines.append("## Overall Metrics")
        lines.append("")
        lines.append("| Metric | Value | Target | Status |")
        lines.append("|--------|-------|--------|--------|")
        lines.append(f"| Precision | {cm.precision:.4f} | ≥ 0.95 | {'✅' if cm.precision >= 0.95 else '❌'} |")
        lines.append(f"| Recall | {cm.recall:.4f} | ≥ 0.97 | {'✅' if cm.recall >= 0.97 else '❌'} |")
        lines.append(f"| F1 Score | {cm.f1_score:.4f} | ≥ 0.96 | {'✅' if cm.f1_score >= 0.96 else '❌'} |")
        lines.append(f"| False Negative Rate | {cm.false_negative_rate:.4f} | < 0.02 | {'✅' if cm.false_negative_rate < 0.02 else '❌'} |")
        lines.append(f"| ROC-AUC | {metrics.roc_auc:.4f} | — | — |")
        lines.append(f"| Accuracy | {cm.accuracy:.4f} | — | — |")
        lines.append("")

        # Confusion Matrix
        lines.append("## Confusion Matrix")
        lines.append("")
        lines.append("| | Predicted PHISHING | Predicted SAFE |")
        lines.append("|---|---|---|")
        lines.append(f"| **Actual PHISHING** | TP = {cm.tp} | FN = {cm.fn} ⚠️ |")
        lines.append(f"| **Actual SAFE** | FP = {cm.fp} | TN = {cm.tn} |")
        lines.append("")

        # Node Diagnostics
        if metrics.node_accuracies:
            lines.append("## Node-Level Diagnostics")
            lines.append("")
            lines.append("| Node | Accuracy | Status |")
            lines.append("|------|----------|--------|")
            for node, acc in sorted(metrics.node_accuracies.items()):
                status = "✅" if acc >= 80 else "⚠️" if acc >= 60 else "❌"
                lines.append(f"| {node.title()} | {acc:.1f}% | {status} |")
            lines.append("")

        # Per-Category
        if metrics.category_metrics:
            lines.append("## Per-Category Performance")
            lines.append("")
            lines.append("| Category | F1 | Recall | FNR |")
            lines.append("|----------|-----|--------|-----|")
            for cat, cat_cm in metrics.category_metrics.items():
                lines.append(f"| {cat} | {cat_cm.f1_score:.3f} | {cat_cm.recall:.3f} | {cat_cm.false_negative_rate:.3f} |")
            lines.append("")

        # Misclassified
        if metrics.misclassified:
            lines.append(f"## Misclassified Samples ({len(metrics.misclassified)})")
            lines.append("")
            lines.append("| Sample ID | Ground Truth | Predicted | Score | Category |")
            lines.append("|-----------|-------------|-----------|-------|----------|")
            for mc in metrics.misclassified[:20]:
                lines.append(
                    f"| {mc['sample_id']} | {mc['ground_truth']} | {mc['predicted']} "
                    f"| {mc['total_score']} | {mc['category']} |"
                )
            lines.append("")

        # Optimization
        if optimization:
            lines.append("## Weight Optimization")
            lines.append("")
            lines.append(f"- **Method**: {optimization.method}")
            lines.append(f"- **Best F1**: {optimization.best_f1:.4f}")
            lines.append(f"- **Best Recall**: {optimization.best_recall:.4f}")
            lines.append(f"- **Iterations**: {optimization.iterations_run}")
            lines.append("")
            lines.append("**Optimized Weights:**")
            lines.append("")
            lines.append("| Node | Weight |")
            lines.append("|------|--------|")
            for k, v in optimization.best_weights.to_dict().items():
                lines.append(f"| {k.title()} | {v:.4f} |")
            lines.append("")

        # Regression
        if regression:
            lines.append("## Regression Test")
            lines.append("")
            verdict_icon = "✅" if regression.verdict == "PASS" else "⚠️" if regression.verdict == "WARN" else "❌"
            lines.append(f"**Verdict**: {verdict_icon} {regression.verdict}")
            lines.append(f"**Safe to Deploy**: {'Yes' if regression.safe_to_deploy else 'No'}")
            lines.append("")
            if regression.deltas:
                lines.append("| Metric | Baseline | Current | Delta | Status |")
                lines.append("|--------|----------|---------|-------|--------|")
                for d in regression.deltas:
                    status = "✅" if d.passed else "❌"
                    lines.append(
                        f"| {d.metric_name} | {d.baseline_value:.4f} | {d.current_value:.4f} "
                        f"| {d.delta:+.4f} | {status} |"
                    )
                lines.append("")

        if filename is None:
            filename = f"report_{time.strftime('%Y%m%d_%H%M%S')}.md"

        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info(f"Markdown report saved to {filepath}")
        return str(filepath)

    # ─── AI Feedback Prompts ──────────────────────────────────

    def generate_ai_feedback_prompts(
        self,
        metrics: EvaluationMetrics,
        max_samples: int = 10,
    ) -> List[str]:
        """
        Generate LLM review prompts for misclassified emails.
        
        These prompts can be sent to an AI model for analysis of
        why detection failed, following the template from Section 8.
        """
        prompts = []

        for mc in metrics.misclassified[:max_samples]:
            node_scores = mc.get("node_scores", {})
            prompt = AI_REVIEW_PROMPT_TEMPLATE.format(
                predicted_verdict=mc["predicted"],
                ground_truth=mc["ground_truth"],
                sample_id=mc["sample_id"],
                category=mc["category"],
                difficulty=mc["difficulty"],
                total_score=mc["total_score"],
                sender_score=node_scores.get("sender", "N/A"),
                content_score=node_scores.get("content", "N/A"),
                link_score=node_scores.get("link", "N/A"),
                auth_score=node_scores.get("auth", "N/A"),
                attachment_score=node_scores.get("attachment", "N/A"),
                risk_factors=", ".join(mc.get("risk_factors", [])) or "None",
                failure_description="failed",
            )
            prompts.append(prompt)

        logger.info(f"Generated {len(prompts)} AI feedback prompts for misclassified samples")
        return prompts

    def save_ai_feedback_prompts(
        self,
        prompts: List[str],
        filename: Optional[str] = None,
    ) -> str:
        """Save AI feedback prompts to a file for processing."""
        if filename is None:
            filename = f"ai_feedback_{time.strftime('%Y%m%d_%H%M%S')}.json"

        filepath = self.output_dir / filename
        data = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_prompts": len(prompts),
            "prompts": prompts,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"AI feedback prompts saved to {filepath}")
        return str(filepath)
