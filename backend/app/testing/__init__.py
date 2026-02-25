"""
PhishNet Ultimate Testing Suite
================================
Enterprise-grade adaptive testing, evaluation, and self-improvement engine
for the PhishNet phishing detection platform.

Modules:
    - dataset_loader: Load and split labeled datasets for training/validation/test
    - evaluator: Per-node and aggregate evaluation with precision/recall/F1/ROC-AUC
    - weight_optimizer: Grid search and Bayesian optimization for node weights
    - adversarial_generator: Generate adversarial phishing emails to stress-test
    - regression_runner: CI-integrated regression testing with baseline comparison
    - report_generator: Human and machine-readable evaluation reports
    - calibration: Platt/isotonic calibration, confidence scoring, explainability
    - phishnet_test_orchestrator: Master orchestrator tying all components together
"""

__version__ = "2.0.0"

from .dataset_loader import DatasetLoader, EmailSample, DatasetSplit
from .evaluator import NodeEvaluator, AggregatedEvaluator, EvaluationMetrics
from .weight_optimizer import WeightOptimizer, OptimizationResult
from .adversarial_generator import AdversarialGenerator
from .regression_runner import RegressionRunner, RegressionResult, DriftDetector
from .report_generator import ReportGenerator
from .calibration import (
    ProbabilityCalibrator,
    PlattScaler,
    IsotonicCalibrator,
    CalibrationResult,
    ConfidenceScorer,
    ConfidenceAssessment,
    ExplainabilityEngine,
    ExplainabilityReport,
)
from .phishnet_test_orchestrator import PhishNetTestOrchestrator

__all__ = [
    # Dataset
    "DatasetLoader",
    "EmailSample",
    "DatasetSplit",
    # Evaluation
    "NodeEvaluator",
    "AggregatedEvaluator",
    "EvaluationMetrics",
    # Optimization
    "WeightOptimizer",
    "OptimizationResult",
    # Adversarial
    "AdversarialGenerator",
    # Regression & Drift
    "RegressionRunner",
    "RegressionResult",
    "DriftDetector",
    # Reports
    "ReportGenerator",
    # Calibration & Confidence & Explainability
    "ProbabilityCalibrator",
    "PlattScaler",
    "IsotonicCalibrator",
    "CalibrationResult",
    "ConfidenceScorer",
    "ConfidenceAssessment",
    "ExplainabilityEngine",
    "ExplainabilityReport",
    # Orchestrator
    "PhishNetTestOrchestrator",
]
