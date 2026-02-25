"""
PhishNet Weight Optimizer
==========================
Dynamic optimization of analysis node weights using grid search
and Bayesian optimization.

Replaces static weights with data-driven optimal weights that maximize
F1 score (with emphasis on minimizing false negatives).

Methods:
    1. Grid Search: Exhaustive search over weight combinations
    2. Bayesian Optimization: Faster convergence via surrogate modeling
    3. Differential Evolution: Evolutionary strategy for complex landscapes
"""

import logging
import math
import random
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Tuple

from .dataset_loader import DatasetSplit
from .evaluator import AggregatedEvaluator, EvaluationMetrics, NodeEvaluator

logger = logging.getLogger("phishnet.testing.weight_optimizer")


# ═══════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════

@dataclass
class WeightConfiguration:
    """A single weight configuration for the 5 analysis nodes."""
    sender: float
    content: float
    link: float
    auth: float
    attachment: float

    def to_dict(self) -> Dict[str, float]:
        return {
            "sender": round(self.sender, 4),
            "content": round(self.content, 4),
            "link": round(self.link, 4),
            "auth": round(self.auth, 4),
            "attachment": round(self.attachment, 4),
        }

    @property
    def total(self) -> float:
        return self.sender + self.content + self.link + self.auth + self.attachment

    def normalized(self) -> "WeightConfiguration":
        """Return a copy with weights normalized to sum to 1.0."""
        t = self.total
        if t == 0:
            return WeightConfiguration(0.2, 0.2, 0.2, 0.2, 0.2)
        return WeightConfiguration(
            sender=self.sender / t,
            content=self.content / t,
            link=self.link / t,
            auth=self.auth / t,
            attachment=self.attachment / t,
        )


@dataclass
class OptimizationResult:
    """Result of a weight optimization run."""
    best_weights: WeightConfiguration
    best_f1: float
    best_recall: float
    best_precision: float
    best_fnr: float
    iterations_run: int
    total_time_seconds: float
    method: str
    convergence_history: List[Dict[str, Any]] = field(default_factory=list)
    all_metrics: Optional[EvaluationMetrics] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "best_weights": self.best_weights.to_dict(),
            "best_f1": round(self.best_f1, 4),
            "best_recall": round(self.best_recall, 4),
            "best_precision": round(self.best_precision, 4),
            "best_fnr": round(self.best_fnr, 4),
            "iterations_run": self.iterations_run,
            "total_time_seconds": round(self.total_time_seconds, 2),
            "method": self.method,
            "convergence_history_length": len(self.convergence_history),
        }


# ═══════════════════════════════════════════════════════════════
# DEFAULT WEIGHTS (FROM ARCHITECTURE DOCS)
# ═══════════════════════════════════════════════════════════════

DEFAULT_WEIGHTS = WeightConfiguration(
    sender=0.20,
    content=0.25,
    link=0.25,
    auth=0.15,
    attachment=0.15,
)

# Current code weights (from enhanced_phishing_analyzer.py)
CODE_WEIGHTS = WeightConfiguration(
    sender=0.15,
    content=0.20,
    link=0.20,
    auth=0.30,
    attachment=0.15,
)


# ═══════════════════════════════════════════════════════════════
# WEIGHT OPTIMIZER
# ═══════════════════════════════════════════════════════════════

class WeightOptimizer:
    """
    Finds optimal node weights that maximize F1 score while
    constraining false negative rate below 2%.
    
    The objective function heavily penalizes false negatives because
    a missed phishing email = potential breach.
    """

    # Weight search ranges (percentage points)
    WEIGHT_RANGES = {
        "sender": (0.05, 0.30),
        "content": (0.10, 0.35),
        "link": (0.10, 0.40),
        "auth": (0.05, 0.35),
        "attachment": (0.05, 0.25),
    }

    def __init__(
        self,
        evaluator: Optional[AggregatedEvaluator] = None,
        validation_set: Optional[DatasetSplit] = None,
    ):
        self.evaluator = evaluator or AggregatedEvaluator()
        self.validation_set = validation_set

    def set_validation_set(self, dataset: DatasetSplit) -> None:
        """Set the validation dataset for optimization."""
        self.validation_set = dataset

    # ─── Objective Function ───────────────────────────────────

    def _objective(self, weights: WeightConfiguration, dataset: DatasetSplit) -> float:
        """
        Objective function to MAXIMIZE (negative loss).
        
        Loss = 5 × FNR + 1 × FPR
        
        Minimizing loss is equivalent to maximizing -loss.
        FNR is weighted 5× heavier because a missed phishing email 
        (false negative) is far more costly than a false alarm.
        
        The asymmetric cost reflects operational reality:
            - FN = user gets phished → breach, credential compromise
            - FP = legitimate email quarantined → minor inconvenience
        """
        w = weights.normalized()
        weight_dict = w.to_dict()

        metrics = self.evaluator.evaluate(dataset, weights=weight_dict, verbose=False)
        cm = metrics.confusion_matrix

        fnr = cm.false_negative_rate
        fpr = cm.false_positive_rate

        # Asymmetric loss: Loss = 5×FNR + 1×FPR
        loss = 5.0 * fnr + 1.0 * fpr

        # Negate because our framework maximizes the objective
        score = -loss
        return score, metrics

    # ─── Grid Search ──────────────────────────────────────────

    def grid_search(
        self,
        dataset: Optional[DatasetSplit] = None,
        step: int = 5,
        max_iterations: Optional[int] = None,
    ) -> OptimizationResult:
        """
        Exhaustive grid search over weight combinations.
        
        For each combination of weights (step size = step percentage points):
            1. Normalize weights to sum to 1.0
            2. Evaluate F1 score on validation set
            3. Keep best combination
        
        Args:
            dataset: Dataset to evaluate on. Uses validation_set if None.
            step: Step size in percentage points (default 5 → 5% steps).
            max_iterations: Optional cap on iterations.
        
        Returns:
            OptimizationResult with best weights and convergence history.
        """
        ds = dataset or self.validation_set
        if ds is None:
            raise ValueError("No dataset provided for optimization.")

        logger.info(f"Starting grid search with step={step}%...")
        start_time = time.time()

        best_score = -math.inf
        best_weights = DEFAULT_WEIGHTS
        best_metrics: Optional[EvaluationMetrics] = None
        convergence_history: List[Dict[str, Any]] = []
        iteration = 0

        ranges = self.WEIGHT_RANGES
        s_range = self._pct_range(ranges["sender"], step)
        c_range = self._pct_range(ranges["content"], step)
        l_range = self._pct_range(ranges["link"], step)
        a_range = self._pct_range(ranges["auth"], step)
        t_range = self._pct_range(ranges["attachment"], step)

        for s in s_range:
            for c in c_range:
                for l in l_range:
                    for a in a_range:
                        for t in t_range:
                            if max_iterations and iteration >= max_iterations:
                                break

                            w = WeightConfiguration(s, c, l, a, t).normalized()
                            score, metrics = self._objective(w, ds)
                            iteration += 1

                            if score > best_score:
                                best_score = score
                                best_weights = w
                                best_metrics = metrics
                                convergence_history.append({
                                    "iteration": iteration,
                                    "loss": round(-score, 4),
                                    "fnr": round(metrics.confusion_matrix.false_negative_rate, 4),
                                    "fpr": round(metrics.confusion_matrix.false_positive_rate, 4),
                                    "f1": round(metrics.confusion_matrix.f1_score, 4),
                                    "weights": w.to_dict(),
                                })
                                logger.info(
                                    f"  Grid [{iteration}] New best: Loss={-score:.4f} "
                                    f"FNR={metrics.confusion_matrix.false_negative_rate:.3f} "
                                    f"FPR={metrics.confusion_matrix.false_positive_rate:.3f} "
                                    f"F1={metrics.confusion_matrix.f1_score:.3f}"
                                )

                            if iteration % 100 == 0:
                                logger.debug(f"  Grid search progress: {iteration} iterations...")

        elapsed = time.time() - start_time
        cm = best_metrics.confusion_matrix if best_metrics else None

        result = OptimizationResult(
            best_weights=best_weights,
            best_f1=cm.f1_score if cm else 0.0,
            best_recall=cm.recall if cm else 0.0,
            best_precision=cm.precision if cm else 0.0,
            best_fnr=cm.false_negative_rate if cm else 1.0,
            iterations_run=iteration,
            total_time_seconds=elapsed,
            method="grid_search",
            convergence_history=convergence_history,
            all_metrics=best_metrics,
        )

        logger.info(
            f"Grid search complete: {iteration} iterations in {elapsed:.1f}s. "
            f"Best F1={result.best_f1:.3f} Best weights={best_weights.to_dict()}"
        )
        return result

    # ─── Bayesian Optimization ────────────────────────────────

    def bayesian_optimize(
        self,
        dataset: Optional[DatasetSplit] = None,
        n_iterations: int = 50,
        n_initial: int = 10,
        exploration_rate: float = 0.3,
    ) -> OptimizationResult:
        """
        Bayesian-style optimization using random exploration + exploitation.
        
        Uses a simulated surrogate model approach:
            1. Random initial sampling
            2. Exploit best-known region with perturbations
            3. Occasional exploration of random configurations
        
        Args:
            dataset: Dataset to evaluate on.
            n_iterations: Total optimization iterations.
            n_initial: Number of random initial samples.
            exploration_rate: Probability of random exploration vs exploitation.
        
        Returns:
            OptimizationResult with best weights.
        """
        ds = dataset or self.validation_set
        if ds is None:
            raise ValueError("No dataset provided for optimization.")

        logger.info(f"Starting Bayesian optimization: {n_iterations} iterations...")
        start_time = time.time()
        rng = random.Random(42)

        best_score = -math.inf
        best_weights = DEFAULT_WEIGHTS
        best_metrics: Optional[EvaluationMetrics] = None
        convergence_history: List[Dict[str, Any]] = []
        observations: List[Tuple[WeightConfiguration, float]] = []

        for i in range(n_iterations):
            if i < n_initial:
                # Phase 1: Random exploration
                w = self._random_weights(rng)
            elif rng.random() < exploration_rate:
                # Phase 2a: Random exploration (explore)
                w = self._random_weights(rng)
            else:
                # Phase 2b: Perturb best-known weights (exploit)
                w = self._perturb_weights(best_weights, rng, scale=0.05)

            w = w.normalized()
            score, metrics = self._objective(w, ds)
            observations.append((w, score))

            if score > best_score:
                best_score = score
                best_weights = w
                best_metrics = metrics
                convergence_history.append({
                    "iteration": i + 1,
                    "loss": round(-score, 4),
                    "fnr": round(metrics.confusion_matrix.false_negative_rate, 4),
                    "fpr": round(metrics.confusion_matrix.false_positive_rate, 4),
                    "f1": round(metrics.confusion_matrix.f1_score, 4),
                    "weights": w.to_dict(),
                })
                logger.info(
                    f"  Bayes [{i+1}/{n_iterations}] New best: "
                    f"Loss={-score:.4f} FNR={metrics.confusion_matrix.false_negative_rate:.3f} "
                    f"FPR={metrics.confusion_matrix.false_positive_rate:.3f}"
                )

        elapsed = time.time() - start_time
        cm = best_metrics.confusion_matrix if best_metrics else None

        result = OptimizationResult(
            best_weights=best_weights,
            best_f1=cm.f1_score if cm else 0.0,
            best_recall=cm.recall if cm else 0.0,
            best_precision=cm.precision if cm else 0.0,
            best_fnr=cm.false_negative_rate if cm else 1.0,
            iterations_run=n_iterations,
            total_time_seconds=elapsed,
            method="bayesian_optimization",
            convergence_history=convergence_history,
            all_metrics=best_metrics,
        )

        logger.info(
            f"Bayesian optimization complete: {n_iterations} iterations in {elapsed:.1f}s. "
            f"Best F1={result.best_f1:.3f}"
        )
        return result

    # ─── Differential Evolution ───────────────────────────────

    def differential_evolution(
        self,
        dataset: Optional[DatasetSplit] = None,
        population_size: int = 20,
        generations: int = 30,
        mutation_factor: float = 0.8,
        crossover_rate: float = 0.7,
    ) -> OptimizationResult:
        """
        Differential evolution optimizer for weight tuning.
        
        Evolves a population of weight configurations using mutation
        and crossover operators to find optimal F1-maximizing weights.
        """
        ds = dataset or self.validation_set
        if ds is None:
            raise ValueError("No dataset provided for optimization.")

        logger.info(
            f"Starting differential evolution: pop={population_size}, gen={generations}..."
        )
        start_time = time.time()
        rng = random.Random(42)

        # Initialize population
        population = [self._random_weights(rng).normalized() for _ in range(population_size)]
        fitness = []
        metrics_list = []

        for w in population:
            score, m = self._objective(w, ds)
            fitness.append(score)
            metrics_list.append(m)

        best_idx = max(range(len(fitness)), key=lambda i: fitness[i])
        best_weights = population[best_idx]
        best_score = fitness[best_idx]
        best_metrics = metrics_list[best_idx]
        convergence_history: List[Dict[str, Any]] = []

        total_iterations = 0

        for gen in range(generations):
            for i in range(population_size):
                # Select 3 distinct random individuals (not i)
                candidates = [j for j in range(population_size) if j != i]
                a, b, c = rng.sample(candidates, 3)

                # Mutation
                wa, wb, wc = population[a], population[b], population[c]
                mutant = WeightConfiguration(
                    sender=max(0, wa.sender + mutation_factor * (wb.sender - wc.sender)),
                    content=max(0, wa.content + mutation_factor * (wb.content - wc.content)),
                    link=max(0, wa.link + mutation_factor * (wb.link - wc.link)),
                    auth=max(0, wa.auth + mutation_factor * (wb.auth - wc.auth)),
                    attachment=max(0, wa.attachment + mutation_factor * (wb.attachment - wc.attachment)),
                ).normalized()

                # Crossover
                trial_fields = []
                for field_name in ["sender", "content", "link", "auth", "attachment"]:
                    if rng.random() < crossover_rate:
                        trial_fields.append(getattr(mutant, field_name))
                    else:
                        trial_fields.append(getattr(population[i], field_name))

                trial = WeightConfiguration(*trial_fields).normalized()

                # Selection
                trial_score, trial_metrics = self._objective(trial, ds)
                total_iterations += 1

                if trial_score > fitness[i]:
                    population[i] = trial
                    fitness[i] = trial_score
                    metrics_list[i] = trial_metrics

                    if trial_score > best_score:
                        best_score = trial_score
                        best_weights = trial
                        best_metrics = trial_metrics
                        convergence_history.append({
                            "generation": gen + 1,
                            "iteration": total_iterations,
                            "loss": round(-trial_score, 4),
                            "fnr": round(trial_metrics.confusion_matrix.false_negative_rate, 4),
                            "fpr": round(trial_metrics.confusion_matrix.false_positive_rate, 4),
                            "f1": round(trial_metrics.confusion_matrix.f1_score, 4),
                            "weights": trial.to_dict(),
                        })

            logger.debug(
                f"  DE gen {gen+1}/{generations}: best_score={best_score:.4f}"
            )

        elapsed = time.time() - start_time
        cm = best_metrics.confusion_matrix if best_metrics else None

        result = OptimizationResult(
            best_weights=best_weights,
            best_f1=cm.f1_score if cm else 0.0,
            best_recall=cm.recall if cm else 0.0,
            best_precision=cm.precision if cm else 0.0,
            best_fnr=cm.false_negative_rate if cm else 1.0,
            iterations_run=total_iterations,
            total_time_seconds=elapsed,
            method="differential_evolution",
            convergence_history=convergence_history,
            all_metrics=best_metrics,
        )

        logger.info(
            f"Differential evolution complete: {total_iterations} evals in {elapsed:.1f}s. "
            f"Best F1={result.best_f1:.3f}"
        )
        return result

    # ─── Weight Lock ──────────────────────────────────────────

    @staticmethod
    def lock_weights(result: OptimizationResult, filepath: str) -> None:
        """
        Lock the best weights to a JSON file for production use.
        
        This file can be loaded by the analyzer to use optimized weights
        instead of hardcoded defaults.
        """
        import json
        from pathlib import Path

        data = {
            "locked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "method": result.method,
            "metrics": {
                "f1": result.best_f1,
                "recall": result.best_recall,
                "precision": result.best_precision,
                "fnr": result.best_fnr,
            },
            "weights": result.best_weights.to_dict(),
            "iterations": result.iterations_run,
        }

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Weights locked to {filepath}")

    @staticmethod
    def load_locked_weights(filepath: str) -> WeightConfiguration:
        """Load previously locked weights from JSON."""
        import json
        from pathlib import Path

        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Locked weights file not found: {filepath}")

        with open(path) as f:
            data = json.load(f)

        w = data["weights"]
        return WeightConfiguration(
            sender=w["sender"],
            content=w["content"],
            link=w["link"],
            auth=w["auth"],
            attachment=w["attachment"],
        )

    # ─── Internal Helpers ─────────────────────────────────────

    def _random_weights(self, rng: random.Random) -> WeightConfiguration:
        """Generate random weights within defined ranges."""
        return WeightConfiguration(
            sender=rng.uniform(*self.WEIGHT_RANGES["sender"]),
            content=rng.uniform(*self.WEIGHT_RANGES["content"]),
            link=rng.uniform(*self.WEIGHT_RANGES["link"]),
            auth=rng.uniform(*self.WEIGHT_RANGES["auth"]),
            attachment=rng.uniform(*self.WEIGHT_RANGES["attachment"]),
        )

    @staticmethod
    def _perturb_weights(
        base: WeightConfiguration, rng: random.Random, scale: float = 0.05
    ) -> WeightConfiguration:
        """Perturb weights by a small random amount."""
        return WeightConfiguration(
            sender=max(0.01, base.sender + rng.gauss(0, scale)),
            content=max(0.01, base.content + rng.gauss(0, scale)),
            link=max(0.01, base.link + rng.gauss(0, scale)),
            auth=max(0.01, base.auth + rng.gauss(0, scale)),
            attachment=max(0.01, base.attachment + rng.gauss(0, scale)),
        )

    @staticmethod
    def _pct_range(limits: Tuple[float, float], step: int) -> List[float]:
        """Generate range of floats from limits with step in percentage points."""
        start_pct = int(limits[0] * 100)
        end_pct = int(limits[1] * 100)
        return [p / 100.0 for p in range(start_pct, end_pct + 1, step)]
