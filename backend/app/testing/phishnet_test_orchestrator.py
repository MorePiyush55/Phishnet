"""
PhishNet Test Orchestrator
============================
Master orchestrator that ties all testing components together into
a unified evaluation, optimization, and self-improvement pipeline.

Flow:
    1. Load labeled dataset
    2. Run full 5-node analysis
    3. Store node scores individually
    4. Calculate weighted final score
    5. Compare against ground truth label
    6. Calculate metrics (precision, recall, F1, FNR, ROC-AUC)
    7. Adjust weights via optimization
    8. Re-run evaluation with optimized weights
    9. Repeat until convergence or iteration limit
    10. Run adversarial stress test
    11. Run regression comparison
    12. Generate comprehensive reports
    13. Version model state

This orchestrator transforms PhishNet from a phishing detector into an
enterprise-grade adaptive security engine that:
    - Diagnoses itself
    - Stress tests itself
    - Adjusts itself
    - Blocks bad deployments
    - Learns from mistakes
    - Resists adversarial phishing
"""

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .dataset_loader import DatasetLoader, DatasetSplit
from .evaluator import (
    AggregatedEvaluator,
    EvaluationMetrics,
    NodeEvaluator,
    PERFORMANCE_TARGETS,
)
from .weight_optimizer import WeightOptimizer, OptimizationResult, WeightConfiguration
from .adversarial_generator import AdversarialGenerator
from .regression_runner import RegressionRunner, RegressionResult, DriftDetector
from .report_generator import ReportGenerator

logger = logging.getLogger("phishnet.testing.orchestrator")


# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR CONFIG
# ═══════════════════════════════════════════════════════════════

@dataclass
class OrchestratorConfig:
    """Configuration for the test orchestrator."""
    # Dataset
    dataset_path: Optional[str] = None
    use_builtin_dataset: bool = True
    
    # Optimization
    optimization_method: str = "bayesian"  # "grid", "bayesian", "differential_evolution"
    optimization_iterations: int = 50
    grid_step: int = 5
    convergence_threshold: float = 0.001  # Stop if F1 improvement < this
    max_convergence_rounds: int = 5
    
    # Adversarial
    adversarial_count_per_type: int = 3
    include_adversarial: bool = True
    
    # Regression
    baseline_path: str = "backend/app/testing/baselines/latest_baseline.json"
    
    # Reporting
    report_output_dir: str = "backend/app/testing/reports"
    generate_json: bool = True
    generate_markdown: bool = True
    generate_ai_prompts: bool = True
    
    # Model versioning
    versioned_models_dir: str = "backend/app/models/versioned_models"
    locked_weights_path: str = "backend/app/testing/baselines/locked_weights.json"
    
    # Self-improvement
    auto_lock_weights: bool = True
    min_f1_for_lock: float = 0.90

    # ── Deployment Safeguards ──
    # Model freeze window: block weight updates for N hours after last deploy
    freeze_window_hours: float = 48.0
    freeze_state_path: str = "backend/app/testing/baselines/freeze_state.json"
    # Canary deployment: require N consecutive passing evaluations before promoting
    canary_required_passes: int = 3
    canary_max_fnr: float = 0.03  # Max FNR during canary window
    canary_max_fpr: float = 0.10  # Max FPR during canary window
    # Shadow evaluation: run new weights in parallel for N hours without deploying
    shadow_eval_hours: float = 48.0
    shadow_max_divergence: float = 0.05  # Max allowed divergence from production


# ═══════════════════════════════════════════════════════════════
# ORCHESTRATION RESULT
# ═══════════════════════════════════════════════════════════════

@dataclass
class OrchestratorResult:
    """Complete result from an orchestration run."""
    # Status
    success: bool
    timestamp: str
    duration_seconds: float
    
    # Initial evaluation
    initial_metrics: Optional[Dict[str, Any]] = None
    
    # Optimization
    optimization_result: Optional[Dict[str, Any]] = None
    optimized_metrics: Optional[Dict[str, Any]] = None
    
    # Adversarial
    adversarial_metrics: Optional[Dict[str, Any]] = None
    
    # Regression
    regression_result: Optional[Dict[str, Any]] = None
    
    # Convergence
    convergence_rounds: int = 0
    converged: bool = False
    
    # Deployment gate
    safe_to_deploy: bool = False
    deployment_blockers: List[str] = field(default_factory=list)
    
    # Reports
    report_paths: List[str] = field(default_factory=list)
    
    # Model versioning
    model_version: str = ""
    weights_locked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "timestamp": self.timestamp,
            "duration_seconds": round(self.duration_seconds, 2),
            "convergence_rounds": self.convergence_rounds,
            "converged": self.converged,
            "safe_to_deploy": self.safe_to_deploy,
            "deployment_blockers": self.deployment_blockers,
            "model_version": self.model_version,
            "weights_locked": self.weights_locked,
            "report_paths": self.report_paths,
            "initial_metrics": self.initial_metrics,
            "optimization_result": self.optimization_result,
            "optimized_metrics": self.optimized_metrics,
            "adversarial_metrics": self.adversarial_metrics,
            "regression_result": self.regression_result,
        }


# ═══════════════════════════════════════════════════════════════
# PHISHNET TEST ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

class PhishNetTestOrchestrator:
    """
    Master orchestrator for the PhishNet Ultimate Testing Suite.
    
    This is the single entry point that coordinates:
        1. Dataset loading and splitting
        2. Full 5-node evaluation
        3. Weight optimization with convergence loop
        4. Adversarial stress testing
        5. Regression comparison
        6. Report generation
        7. Model versioning
        8. Deployment gate checking
    """

    def __init__(self, config: Optional[OrchestratorConfig] = None):
        self.config = config or OrchestratorConfig()
        
        # Initialize components
        self.node_evaluator = NodeEvaluator()
        self.evaluator = AggregatedEvaluator(self.node_evaluator)
        self.optimizer = WeightOptimizer(self.evaluator)
        self.adversarial = AdversarialGenerator()
        self.regression = RegressionRunner(self.evaluator, self.config.baseline_path)
        self.reporter = ReportGenerator(self.config.report_output_dir)
        self.drift_detector = DriftDetector()
        
        # State
        self._dataset_loader: Optional[DatasetLoader] = None
        self._splits: Optional[Dict[str, DatasetSplit]] = None
        self._current_weights: Optional[WeightConfiguration] = None

    # ─── Main Orchestration ───────────────────────────────────

    def run(
        self,
        commit_hash: str = "",
        version: str = "",
        verbose: bool = True,
    ) -> OrchestratorResult:
        """
        Run the complete testing, optimization, and evaluation pipeline.
        
        This is the primary entry point for the entire testing suite.
        
        Args:
            commit_hash: Git commit hash for traceability.
            version: Application version string.
            verbose: If True, print detailed progress.
        
        Returns:
            OrchestratorResult with full diagnostics.
        """
        start_time = time.time()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        report_paths: List[str] = []
        deployment_blockers: List[str] = []

        logger.info("+============================================================+")
        logger.info("|       PhishNet Ultimate Testing Suite - Orchestrator        |")
        logger.info("+============================================================+")
        logger.info(f"Timestamp: {timestamp}")
        logger.info(f"Commit: {commit_hash or 'N/A'}")
        logger.info(f"Version: {version or 'N/A'}")

        try:
            # ── PHASE 1: Dataset Loading ─────────────────────
            logger.info("")
            logger.info("═══ PHASE 1: DATASET LOADING ═══")
            
            self._load_dataset()
            train_set = self._splits["train"]
            val_set = self._splits["validation"]
            test_set = self._splits["test"]
            
            logger.info(f"Train: {train_set.size}, Validation: {val_set.size}, Test: {test_set.size}")

            # ── PHASE 2: Initial Baseline Evaluation ─────────
            logger.info("")
            logger.info("═══ PHASE 2: INITIAL EVALUATION (Default Weights) ═══")
            
            initial_metrics = self.evaluator.evaluate(val_set, verbose=verbose)
            initial_dict = initial_metrics.to_dict()
            
            logger.info(
                f"Initial: F1={initial_metrics.confusion_matrix.f1_score:.3f} "
                f"Recall={initial_metrics.confusion_matrix.recall:.3f} "
                f"FNR={initial_metrics.confusion_matrix.false_negative_rate:.3f}"
            )

            # ── PHASE 3: Weight Optimization Loop ────────────
            logger.info("")
            logger.info("═══ PHASE 3: WEIGHT OPTIMIZATION ═══")
            
            opt_result, optimized_metrics, convergence_rounds, converged = (
                self._optimization_convergence_loop(val_set, verbose)
            )
            
            optimization_dict = opt_result.to_dict() if opt_result else None
            optimized_dict = optimized_metrics.to_dict() if optimized_metrics else None

            # ── PHASE 4: Adversarial Stress Test ─────────────
            adversarial_dict = None
            if self.config.include_adversarial:
                logger.info("")
                logger.info("═══ PHASE 4: ADVERSARIAL STRESS TEST ═══")
                
                adversarial_metrics = self._run_adversarial_test(test_set)
                adversarial_dict = adversarial_metrics.to_dict() if adversarial_metrics else None
                
                if adversarial_metrics:
                    adv_fnr = adversarial_metrics.confusion_matrix.false_negative_rate
                    if adv_fnr > 0.05:
                        deployment_blockers.append(
                            f"Adversarial FNR too high: {adv_fnr:.3f} (max 0.05)"
                        )

            # ── PHASE 5: Regression Testing ──────────────────
            logger.info("")
            logger.info("═══ PHASE 5: REGRESSION TESTING ═══")
            
            weights_dict = None
            if opt_result and self._current_weights:
                weights_dict = self._current_weights.to_dict()
            
            reg_result = self.regression.run(
                test_set,
                commit_hash=commit_hash,
                version=version,
                weights=weights_dict,
            )
            regression_dict = reg_result.to_dict()
            
            if not reg_result.safe_to_deploy:
                deployment_blockers.append(f"Regression: {reg_result.blocking_reason}")

            # ── PHASE 6: Model Versioning ────────────────────
            logger.info("")
            logger.info("═══ PHASE 6: MODEL VERSIONING ═══")
            
            model_version = f"v{version or '1.0.0'}_{timestamp.replace(':', '-')}"
            weights_locked = False
            
            if opt_result and self.config.auto_lock_weights:
                if opt_result.best_f1 >= self.config.min_f1_for_lock:
                    self.optimizer.lock_weights(opt_result, self.config.locked_weights_path)
                    weights_locked = True
                    logger.info(f"Weights locked: F1={opt_result.best_f1:.3f}")
                else:
                    logger.warning(
                        f"Weights NOT locked: F1={opt_result.best_f1:.3f} "
                        f"below threshold {self.config.min_f1_for_lock}"
                    )

            self._save_model_version(model_version, opt_result, initial_metrics)

            # ── PHASE 7: Report Generation ───────────────────
            logger.info("")
            logger.info("═══ PHASE 7: REPORT GENERATION ═══")
            
            final_metrics = optimized_metrics or initial_metrics
            
            # Console report
            self.reporter.print_console_report(
                final_metrics,
                title=f"PhishNet Evaluation - {model_version}",
                optimization=opt_result,
                regression=reg_result,
            )

            # File reports
            if self.config.generate_json:
                path = self.reporter.generate_json_report(
                    final_metrics, opt_result, reg_result
                )
                report_paths.append(path)

            if self.config.generate_markdown:
                path = self.reporter.generate_markdown_report(
                    final_metrics, opt_result, reg_result
                )
                report_paths.append(path)

            if self.config.generate_ai_prompts and final_metrics.misclassified:
                prompts = self.reporter.generate_ai_feedback_prompts(final_metrics)
                path = self.reporter.save_ai_feedback_prompts(prompts)
                report_paths.append(path)

            # ── PHASE 8: Save Baseline ───────────────────────
            if not deployment_blockers:
                logger.info("")
                logger.info("═══ PHASE 8: SAVING BASELINE ═══")
                self.regression.save_baseline(
                    final_metrics,
                    commit_hash=commit_hash,
                    version=version,
                )

            # ── Final Result ─────────────────────────────────
            duration = time.time() - start_time
            safe_to_deploy = len(deployment_blockers) == 0

            result = OrchestratorResult(
                success=True,
                timestamp=timestamp,
                duration_seconds=duration,
                initial_metrics=initial_dict,
                optimization_result=optimization_dict,
                optimized_metrics=optimized_dict,
                adversarial_metrics=adversarial_dict,
                regression_result=regression_dict,
                convergence_rounds=convergence_rounds,
                converged=converged,
                safe_to_deploy=safe_to_deploy,
                deployment_blockers=deployment_blockers,
                report_paths=report_paths,
                model_version=model_version,
                weights_locked=weights_locked,
            )

            # Save orchestration result
            result_path = Path(self.config.report_output_dir) / "orchestration_result.json"
            result_path.parent.mkdir(parents=True, exist_ok=True)
            with open(result_path, "w") as f:
                json.dump(result.to_dict(), f, indent=2)
            report_paths.append(str(result_path))

            logger.info("")
            logger.info("+============================================================+")
            logger.info(f"|  ORCHESTRATION COMPLETE - {'PASS' if safe_to_deploy else 'FAIL':>33}  |")
            logger.info(f"|  Duration: {duration:.1f}s{'':>47} |")
            logger.info(f"|  Safe to Deploy: {'YES' if safe_to_deploy else 'NO':>42} |")
            logger.info(f"|  Model Version: {model_version:>43} |")
            logger.info("+============================================================+")

            return result

        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Orchestration failed: {e}", exc_info=True)
            return OrchestratorResult(
                success=False,
                timestamp=timestamp,
                duration_seconds=duration,
                deployment_blockers=[f"Orchestration error: {str(e)}"],
            )

    # ─── Dataset Loading ──────────────────────────────────────

    def _load_dataset(self) -> None:
        """Load and split dataset according to configuration."""
        self._dataset_loader = DatasetLoader()
        
        if self.config.dataset_path:
            self._dataset_loader.load_from_json(self.config.dataset_path)
        
        if self.config.use_builtin_dataset:
            self._dataset_loader.load_builtin_dataset()
        
        if self._dataset_loader.total_samples == 0:
            raise ValueError("No samples loaded. Provide a dataset path or enable builtin dataset.")
        
        self._splits = self._dataset_loader.split(stratify=True)
        
        summary = self._dataset_loader.summary()
        logger.info(f"Dataset summary: {json.dumps(summary, indent=2)}")

    # ─── Optimization Convergence Loop ────────────────────────

    def _optimization_convergence_loop(
        self,
        val_set: DatasetSplit,
        verbose: bool,
    ) -> tuple:
        """
        Run optimization in a convergence loop:
            1. Optimize weights
            2. Evaluate with new weights
            3. If F1 improved by > threshold, repeat
            4. Stop when converged or max rounds reached
        """
        best_f1 = 0.0
        best_opt_result: Optional[OptimizationResult] = None
        best_metrics: Optional[EvaluationMetrics] = None
        convergence_rounds = 0
        converged = False

        for round_num in range(1, self.config.max_convergence_rounds + 1):
            logger.info(f"  Convergence round {round_num}/{self.config.max_convergence_rounds}")
            
            # Run optimization
            method = self.config.optimization_method
            if method == "grid":
                opt_result = self.optimizer.grid_search(
                    val_set, step=self.config.grid_step
                )
            elif method == "bayesian":
                opt_result = self.optimizer.bayesian_optimize(
                    val_set, n_iterations=self.config.optimization_iterations
                )
            elif method == "differential_evolution":
                opt_result = self.optimizer.differential_evolution(val_set)
            else:
                raise ValueError(f"Unknown optimization method: {method}")

            current_f1 = opt_result.best_f1
            improvement = current_f1 - best_f1
            convergence_rounds = round_num

            logger.info(
                f"  Round {round_num}: F1={current_f1:.4f} "
                f"(improvement={improvement:+.4f})"
            )

            if current_f1 > best_f1:
                best_f1 = current_f1
                best_opt_result = opt_result
                self._current_weights = opt_result.best_weights
                
                # Re-evaluate with optimized weights
                best_metrics = self.evaluator.evaluate(
                    val_set,
                    weights=opt_result.best_weights.to_dict(),
                    verbose=verbose,
                )

            if improvement < self.config.convergence_threshold and round_num > 1:
                converged = True
                logger.info(
                    f"  Converged at round {round_num} "
                    f"(improvement {improvement:.6f} < threshold {self.config.convergence_threshold})"
                )
                break

        return best_opt_result, best_metrics, convergence_rounds, converged

    # ─── Adversarial Testing ──────────────────────────────────

    def _run_adversarial_test(
        self, base_test_set: DatasetSplit
    ) -> Optional[EvaluationMetrics]:
        """Run adversarial stress test with generated attack samples."""
        try:
            adversarial_samples = self.adversarial.generate_full_adversarial_suite(
                count_per_type=self.config.adversarial_count_per_type
            )
            
            # Create adversarial-only dataset
            adv_dataset = DatasetSplit(
                name="adversarial_stress_test",
                samples=adversarial_samples,
            )
            
            # Evaluate with current best weights
            weights = self._current_weights.to_dict() if self._current_weights else None
            metrics = self.evaluator.evaluate(adv_dataset, weights=weights, verbose=False)
            
            logger.info(
                f"Adversarial results: F1={metrics.confusion_matrix.f1_score:.3f} "
                f"Recall={metrics.confusion_matrix.recall:.3f} "
                f"FNR={metrics.confusion_matrix.false_negative_rate:.3f} "
                f"({len(adversarial_samples)} attack samples)"
            )
            
            return metrics
        except Exception as e:
            logger.error(f"Adversarial test failed: {e}")
            return None

    # ─── Model Versioning ─────────────────────────────────────

    def _save_model_version(
        self,
        version: str,
        opt_result: Optional[OptimizationResult],
        metrics: EvaluationMetrics,
    ) -> None:
        """Save versioned model state for rollback support."""
        version_dir = Path(self.config.versioned_models_dir)
        version_dir.mkdir(parents=True, exist_ok=True)

        model_state = {
            "version": version,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "weights": opt_result.best_weights.to_dict() if opt_result else None,
            "metrics": {
                "f1": metrics.confusion_matrix.f1_score,
                "recall": metrics.confusion_matrix.recall,
                "precision": metrics.confusion_matrix.precision,
                "fnr": metrics.confusion_matrix.false_negative_rate,
                "roc_auc": metrics.roc_auc,
            },
            "node_accuracies": metrics.node_accuracies,
            "targets_met": metrics.targets_met,
        }

        filepath = version_dir / f"{version}.json"
        with open(filepath, "w") as f:
            json.dump(model_state, f, indent=2)

        logger.info(f"Model version saved: {filepath}")

    # ═══════════════════════════════════════════════════════════
    # DEPLOYMENT SAFEGUARDS
    # ═══════════════════════════════════════════════════════════

    def check_freeze_window(self) -> bool:
        """
        Check if we are within the model freeze window.

        After any weight deployment, updates are blocked for
        ``freeze_window_hours`` to prevent thrashing and allow
        stability observation.

        Returns:
            True if frozen (updates blocked), False if clear.
        """
        freeze_path = Path(self.config.freeze_state_path)
        if not freeze_path.exists():
            return False

        try:
            with open(freeze_path) as f:
                state = json.load(f)
            last_deploy = state.get("last_deploy_timestamp", 0)
            elapsed_hours = (time.time() - last_deploy) / 3600.0
            frozen = elapsed_hours < self.config.freeze_window_hours
            if frozen:
                remaining = self.config.freeze_window_hours - elapsed_hours
                logger.warning(
                    f"MODEL FREEZE ACTIVE: {remaining:.1f} hours remaining. "
                    f"Weight updates blocked."
                )
            return frozen
        except Exception as e:
            logger.error(f"Failed to check freeze state: {e}")
            return False

    def set_freeze_window(self) -> None:
        """Set the model freeze window timestamp after a deployment."""
        freeze_path = Path(self.config.freeze_state_path)
        freeze_path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "last_deploy_timestamp": time.time(),
            "freeze_until": time.time() + (self.config.freeze_window_hours * 3600),
            "set_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        with open(freeze_path, "w") as f:
            json.dump(state, f, indent=2)
        logger.info(f"Freeze window set for {self.config.freeze_window_hours} hours")

    def canary_evaluation(
        self,
        dataset: DatasetSplit,
        weights: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """
        Run canary evaluation: N consecutive passes must all meet
        FNR / FPR thresholds before weights can be promoted.

        Returns:
            Dict with per-pass results and promotion decision.
        """
        logger.info(
            f"Starting canary evaluation: {self.config.canary_required_passes} passes required"
        )
        results: List[Dict[str, Any]] = []
        all_passed = True

        for i in range(self.config.canary_required_passes):
            metrics = self.evaluator.evaluate(dataset, weights=weights, verbose=False)
            cm = metrics.confusion_matrix
            fnr = cm.false_negative_rate
            fpr = cm.false_positive_rate

            passed = fnr <= self.config.canary_max_fnr and fpr <= self.config.canary_max_fpr
            results.append({
                "pass_number": i + 1,
                "fnr": round(fnr, 4),
                "fpr": round(fpr, 4),
                "f1": round(cm.f1_score, 4),
                "passed": passed,
            })

            if not passed:
                all_passed = False
                logger.warning(
                    f"Canary pass {i + 1} FAILED: FNR={fnr:.4f} FPR={fpr:.4f}"
                )

            logger.info(
                f"  Canary pass {i + 1}/{self.config.canary_required_passes}: "
                f"FNR={fnr:.4f} FPR={fpr:.4f} {'PASS' if passed else 'FAIL'}"
            )

        canary_result = {
            "promote": all_passed,
            "passes": results,
            "required_passes": self.config.canary_required_passes,
            "thresholds": {
                "max_fnr": self.config.canary_max_fnr,
                "max_fpr": self.config.canary_max_fpr,
            },
        }

        if all_passed:
            logger.info("CANARY: All passes succeeded — safe to promote")
        else:
            logger.warning("CANARY: Failed — blocking promotion")

        return canary_result

    def shadow_evaluation(
        self,
        dataset: DatasetSplit,
        production_weights: Optional[Dict[str, float]],
        candidate_weights: Dict[str, float],
    ) -> Dict[str, Any]:
        """
        Shadow evaluation: compare candidate weights against production
        weights on the same dataset.  Blocks promotion if divergence
        exceeds ``shadow_max_divergence``.

        Returns:
            Dict with divergence details and promotion decision.
        """
        logger.info("Starting shadow evaluation: candidate vs production weights")

        prod_metrics = self.evaluator.evaluate(
            dataset, weights=production_weights, verbose=False
        )
        cand_metrics = self.evaluator.evaluate(
            dataset, weights=candidate_weights, verbose=False
        )

        prod_cm = prod_metrics.confusion_matrix
        cand_cm = cand_metrics.confusion_matrix

        divergences = {
            "f1_delta": round(abs(cand_cm.f1_score - prod_cm.f1_score), 4),
            "fnr_delta": round(
                abs(cand_cm.false_negative_rate - prod_cm.false_negative_rate), 4
            ),
            "fpr_delta": round(
                abs(cand_cm.false_positive_rate - prod_cm.false_positive_rate), 4
            ),
            "recall_delta": round(abs(cand_cm.recall - prod_cm.recall), 4),
            "precision_delta": round(abs(cand_cm.precision - prod_cm.precision), 4),
        }

        max_divergence = max(divergences.values())
        acceptable = max_divergence <= self.config.shadow_max_divergence

        candidate_loss = 5.0 * cand_cm.false_negative_rate + 1.0 * cand_cm.false_positive_rate
        production_loss = 5.0 * prod_cm.false_negative_rate + 1.0 * prod_cm.false_positive_rate
        candidate_is_better = candidate_loss < production_loss

        shadow_result = {
            "acceptable_divergence": acceptable,
            "candidate_is_better": candidate_is_better,
            "promote": acceptable and candidate_is_better,
            "max_divergence": max_divergence,
            "threshold": self.config.shadow_max_divergence,
            "divergences": divergences,
            "production_metrics": {
                "f1": round(prod_cm.f1_score, 4),
                "fnr": round(prod_cm.false_negative_rate, 4),
                "fpr": round(prod_cm.false_positive_rate, 4),
                "loss": round(production_loss, 4),
            },
            "candidate_metrics": {
                "f1": round(cand_cm.f1_score, 4),
                "fnr": round(cand_cm.false_negative_rate, 4),
                "fpr": round(cand_cm.false_positive_rate, 4),
                "loss": round(candidate_loss, 4),
            },
        }

        logger.info(
            f"Shadow eval: prod_loss={production_loss:.4f} cand_loss={candidate_loss:.4f} "
            f"divergence={max_divergence:.4f} promote={'YES' if shadow_result['promote'] else 'NO'}"
        )
        return shadow_result

    # ─── Self-Improvement API ─────────────────────────────────

    def nightly_improvement_cycle(
        self,
        new_labeled_emails: Optional[List[Dict]] = None,
        commit_hash: str = "",
    ) -> OrchestratorResult:
        """
        Nightly self-improvement cycle with deployment safeguards:
            1. Check freeze window — abort if frozen
            2. Pull new labeled emails
            3. Run full evaluation + optimization
            4. Canary: N consecutive passes must meet FNR/FPR thresholds
            5. Shadow: compare candidate vs production weights
            6. Only promote if canary + shadow both pass
            7. Set new freeze window upon promotion

        Args:
            new_labeled_emails: Optional new labeled data to incorporate.
            commit_hash: Current deployment commit.

        Returns:
            OrchestratorResult
        """
        logger.info("Starting nightly self-improvement cycle...")

        # ── Freeze window guard ──
        if self.check_freeze_window():
            logger.warning("Nightly cycle aborted: model freeze window is active")
            return OrchestratorResult(
                success=False,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                duration_seconds=0.0,
                deployment_blockers=["Model freeze window is active"],
            )

        if new_labeled_emails:
            if self._dataset_loader is None:
                self._dataset_loader = DatasetLoader()
            self._dataset_loader.load_from_list(new_labeled_emails)
            logger.info(f"Incorporated {len(new_labeled_emails)} new labeled emails")

        # Run full orchestration
        result = self.run(commit_hash=commit_hash, version="nightly")

        # ── Post-run safeguards ──
        if result.success and result.safe_to_deploy and self._current_weights:
            self._load_dataset()
            test_set = self._splits["test"]

            # Canary
            canary = self.canary_evaluation(test_set, weights=self._current_weights.to_dict())
            if not canary["promote"]:
                result.safe_to_deploy = False
                result.deployment_blockers.append("Canary evaluation failed")
                logger.warning("Promotion blocked by canary evaluation")
            else:
                # Shadow
                shadow = self.shadow_evaluation(
                    test_set,
                    production_weights=None,  # current production = default weights
                    candidate_weights=self._current_weights.to_dict(),
                )
                if not shadow["promote"]:
                    result.safe_to_deploy = False
                    result.deployment_blockers.append(
                        f"Shadow evaluation rejected: divergence={shadow['max_divergence']:.4f}"
                    )
                    logger.warning("Promotion blocked by shadow evaluation")
                else:
                    # Promote succeeded — set freeze window
                    self.set_freeze_window()
                    logger.info("Weights promoted. Freeze window activated.")

        return result

    # ─── Quick Evaluation (No Optimization) ───────────────────

    def quick_evaluate(
        self,
        dataset: Optional[DatasetSplit] = None,
        verbose: bool = True,
    ) -> EvaluationMetrics:
        """
        Run a quick evaluation without optimization or adversarial testing.
        
        Useful for fast feedback during development.
        """
        if dataset is None:
            self._load_dataset()
            dataset = self._splits["test"]
        
        metrics = self.evaluator.evaluate(dataset, verbose=verbose)
        self.reporter.print_console_report(metrics, title="Quick Evaluation")
        return metrics

    # ─── Drift Monitoring ─────────────────────────────────────

    def check_production_drift(
        self,
        recent_scores: List[Dict[str, float]],
    ) -> Dict[str, Any]:
        """
        Check for score distribution drift in production data.
        
        Integrates with threat model controls — if anomaly spike detected,
        triggers investigation.
        """
        for scores in recent_scores:
            self.drift_detector.record_scores(scores)
        
        result = self.drift_detector.check_drift()
        
        if result.get("drift_detected"):
            logger.warning("PRODUCTION DRIFT DETECTED — triggering investigation")
            logger.warning(f"Significant shifts: {result.get('significant_drifts')}")
        
        return result
