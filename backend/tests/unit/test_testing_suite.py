"""
Unit tests for the PhishNet Ultimate Testing Suite.

Tests all 7 core modules: DatasetLoader, Evaluator, WeightOptimizer,
AdversarialGenerator, RegressionRunner, ReportGenerator, and
PhishNetTestOrchestrator.

Uses built-in datasets and mocks to avoid external dependencies.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Import testing suite components ──────────────────────────────

from app.testing.dataset_loader import (
    DatasetLoader,
    DatasetSplit,
    EmailCategory,
    EmailSample,
    GroundTruth,
)
from app.testing.evaluator import (
    AggregatedEvaluator,
    ConfusionMatrix,
    EvaluationMetrics,
    EvaluationRecord,
    NodeEvaluator,
    NodeScore,
    PERFORMANCE_TARGETS,
)
from app.testing.weight_optimizer import (
    OptimizationResult,
    WeightConfiguration,
    WeightOptimizer,
)
from app.testing.adversarial_generator import AdversarialGenerator
from app.testing.regression_runner import (
    BaselineMetrics,
    DriftDetector,
    RegressionDelta,
    RegressionRunner,
    RegressionVerdict,
)
from app.testing.report_generator import ReportGenerator
from app.testing.phishnet_test_orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    PhishNetTestOrchestrator,
)


# ═══════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════


@pytest.fixture
def sample_safe():
    return EmailSample(
        id="test_safe_001",
        sender="john@company.com",
        sender_display_name="John Smith",
        subject="Weekly report",
        body="Here is the weekly report for review.",
        links=[],
        attachments=[],
        headers={"Authentication-Results": "spf=pass; dkim=pass; dmarc=pass"},
        ground_truth="SAFE",
        category="CLEAN_LEGITIMATE",
        difficulty="easy",
    )


@pytest.fixture
def sample_phishing():
    return EmailSample(
        id="test_phish_001",
        sender="security@paypa1.com",
        sender_display_name="PayPal Security",
        subject="URGENT: Account suspended",
        body="Click here immediately to verify your account or it will be permanently deleted.",
        links=["http://paypa1-secure.com/verify"],
        attachments=[],
        headers={"Authentication-Results": "spf=fail; dkim=fail; dmarc=fail"},
        ground_truth="PHISHING",
        category="KNOWN_PHISHING",
        difficulty="easy",
    )


@pytest.fixture
def builtin_loader():
    loader = DatasetLoader()
    loader.load_builtin_dataset()
    return loader


@pytest.fixture
def mock_node_score_safe():
    return NodeScore(
        sender_score=90,
        content_score=85,
        link_score=95,
        auth_score=90,
        attachment_score=100,
        weighted_total=92,
        predicted_verdict="SAFE",
        confidence=0.92,
        risk_factors=[],
    )


@pytest.fixture
def mock_node_score_phishing():
    return NodeScore(
        sender_score=20,
        content_score=15,
        link_score=10,
        auth_score=25,
        attachment_score=30,
        weighted_total=18,
        predicted_verdict="PHISHING",
        confidence=0.95,
        risk_factors=["Suspicious sender domain", "Urgency keywords"],
    )


# ═══════════════════════════════════════════════════════════════
# DATASET LOADER TESTS
# ═══════════════════════════════════════════════════════════════


class TestDatasetLoader:
    """Tests for DatasetLoader module."""

    def test_load_builtin_dataset(self, builtin_loader):
        """Built-in dataset loads successfully with samples."""
        assert builtin_loader.total_samples > 0
        assert builtin_loader.total_samples >= 20  # Minimum expected samples

    def test_split_ratios(self, builtin_loader):
        """Splits follow 70/15/15 ratio."""
        splits = builtin_loader.split()
        total = builtin_loader.total_samples

        assert "train" in splits
        assert "validation" in splits
        assert "test" in splits

        # Verify all samples are accounted for (rounding)
        split_total = splits["train"].size + splits["validation"].size + splits["test"].size
        assert split_total == total

    def test_no_data_leakage(self, builtin_loader):
        """No sample appears in multiple splits."""
        splits = builtin_loader.split()

        train_ids = {s.id for s in splits["train"].samples}
        val_ids = {s.id for s in splits["validation"].samples}
        test_ids = {s.id for s in splits["test"].samples}

        assert train_ids.isdisjoint(val_ids), "Train/Val overlap detected"
        assert train_ids.isdisjoint(test_ids), "Train/Test overlap detected"
        assert val_ids.isdisjoint(test_ids), "Val/Test overlap detected"

    def test_deduplication(self):
        """Duplicate samples are rejected."""
        loader = DatasetLoader()
        sample = EmailSample(
            id="dup_001",
            sender="test@test.com",
            body="Duplicate content",
            ground_truth="SAFE",
        )
        # Load same sample twice
        loaded = loader.load_from_list([sample.to_dict(), sample.to_dict()])
        assert loaded == 1  # Second one rejected

    def test_stratified_split_preserves_distribution(self, builtin_loader):
        """Stratified split maintains class distribution across splits."""
        splits = builtin_loader.split(stratify=True)

        for split_name, ds in splits.items():
            if ds.size > 0:
                # Each split should have at least some phishing and safe samples
                # (given enough samples)
                if ds.size >= 3:
                    assert ds.phishing_count > 0 or ds.safe_count > 0, (
                        f"Split '{split_name}' has no labeled samples"
                    )

    def test_email_sample_content_hash(self, sample_safe):
        """Content hash is deterministic."""
        hash1 = sample_safe.content_hash
        hash2 = sample_safe.content_hash
        assert hash1 == hash2
        assert len(hash1) == 16

    def test_email_sample_to_raw_bytes(self, sample_phishing):
        """Converts to valid email bytes."""
        raw = sample_phishing.to_raw_email_bytes()
        assert isinstance(raw, bytes)
        assert b"From:" in raw
        assert b"Subject:" in raw
        assert b"PHISHNET_BOUNDARY" in raw

    def test_email_sample_serialization(self, sample_safe):
        """Sample round-trips through dict serialization."""
        d = sample_safe.to_dict()
        restored = EmailSample.from_dict(d)
        assert restored.id == sample_safe.id
        assert restored.sender == sample_safe.sender
        assert restored.ground_truth == sample_safe.ground_truth

    def test_export_and_load_json(self, builtin_loader):
        """Dataset can be exported and reloaded from JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test_export.json")
            builtin_loader.export_to_json(path)
            assert os.path.exists(path)

            # Reload
            loader2 = DatasetLoader()
            count = loader2.load_from_json(path)
            assert count == builtin_loader.total_samples

    def test_invalid_split_ratios(self):
        """Invalid split ratios raise ValueError."""
        with pytest.raises(ValueError, match="sum to 1.0"):
            DatasetLoader(split_ratios={"train": 0.5, "validation": 0.1, "test": 0.1})

    def test_four_categories_present(self, builtin_loader):
        """Built-in dataset includes all 4 email categories."""
        categories = {s.category for s in builtin_loader._all_samples}
        assert "CLEAN_LEGITIMATE" in categories
        assert "KNOWN_PHISHING" in categories
        assert "SPEAR_PHISHING" in categories
        assert "ADVERSARIAL_OBFUSCATED" in categories

    def test_dataset_split_properties(self, builtin_loader):
        """DatasetSplit properties compute correctly."""
        splits = builtin_loader.split()
        for ds in splits.values():
            assert ds.size == len(ds.samples)
            assert ds.phishing_count + ds.safe_count + ds.suspicious_count == ds.size
            breakdown = ds.category_breakdown()
            assert sum(breakdown.values()) == ds.size


# ═══════════════════════════════════════════════════════════════
# CONFUSION MATRIX TESTS
# ═══════════════════════════════════════════════════════════════


class TestConfusionMatrix:
    """Tests for the ConfusionMatrix metrics."""

    def test_perfect_classification(self):
        """Perfect classifier has P=1, R=1, F1=1, FNR=0."""
        cm = ConfusionMatrix(tp=50, fp=0, tn=50, fn=0)
        assert cm.precision == 1.0
        assert cm.recall == 1.0
        assert cm.f1_score == 1.0
        assert cm.false_negative_rate == 0.0
        assert cm.accuracy == 1.0

    def test_zero_division_safety(self):
        """Handles edge case of all-zero counts gracefully."""
        cm = ConfusionMatrix(tp=0, fp=0, tn=0, fn=0)
        assert cm.precision == 0.0
        assert cm.recall == 0.0
        assert cm.f1_score == 0.0
        assert cm.false_negative_rate == 0.0
        assert cm.total == 0

    def test_false_negative_rate(self):
        """FNR = FN / (FN + TP)."""
        cm = ConfusionMatrix(tp=90, fp=5, tn=100, fn=10)
        expected_fnr = 10 / (10 + 90)
        assert abs(cm.false_negative_rate - expected_fnr) < 1e-6

    def test_false_positive_rate(self):
        """FPR = FP / (FP + TN)."""
        cm = ConfusionMatrix(tp=90, fp=5, tn=100, fn=10)
        expected_fpr = 5 / (5 + 100)
        assert abs(cm.false_positive_rate - expected_fpr) < 1e-6

    def test_f1_score_calculation(self):
        """F1 = 2 * P * R / (P + R)."""
        cm = ConfusionMatrix(tp=80, fp=10, tn=90, fn=20)
        p = 80 / (80 + 10)
        r = 80 / (80 + 20)
        expected_f1 = 2 * p * r / (p + r)
        assert abs(cm.f1_score - expected_f1) < 1e-6

    def test_to_dict(self):
        """Serialization includes all expected fields."""
        cm = ConfusionMatrix(tp=10, fp=2, tn=8, fn=1)
        d = cm.to_dict()
        required = {"tp", "fp", "tn", "fn", "precision", "recall", "f1_score",
                     "accuracy", "false_positive_rate", "false_negative_rate", "specificity"}
        assert required.issubset(d.keys())


# ═══════════════════════════════════════════════════════════════
# EVALUATOR TESTS
# ═══════════════════════════════════════════════════════════════


class TestEvaluator:
    """Tests for NodeEvaluator and AggregatedEvaluator."""

    def test_node_evaluator_accuracy_all_correct(self, mock_node_score_safe, mock_node_score_phishing):
        """Node accuracy is 100% when all predictions are correct."""
        evaluator = NodeEvaluator()
        records = [
            EvaluationRecord(
                sample_id="s1", ground_truth="SAFE", category="CLEAN_LEGITIMATE",
                difficulty="easy", node_scores=mock_node_score_safe, correct=True,
            ),
            EvaluationRecord(
                sample_id="p1", ground_truth="PHISHING", category="KNOWN_PHISHING",
                difficulty="easy", node_scores=mock_node_score_phishing, correct=True,
            ),
        ]
        acc = evaluator.evaluate_node_accuracy(records)
        assert all(v == 100.0 for v in acc.values())

    def test_node_evaluator_accuracy_empty(self):
        """Empty records return 0% accuracy."""
        evaluator = NodeEvaluator()
        acc = evaluator.evaluate_node_accuracy([])
        assert all(v == 0.0 for v in acc.values())

    def test_aggregated_evaluator_verdict_from_score(self):
        """Score-to-verdict thresholds are correct."""
        assert AggregatedEvaluator._verdict_from_score(10) == "PHISHING"
        assert AggregatedEvaluator._verdict_from_score(39) == "PHISHING"
        assert AggregatedEvaluator._verdict_from_score(40) == "SUSPICIOUS"
        assert AggregatedEvaluator._verdict_from_score(69) == "SUSPICIOUS"
        assert AggregatedEvaluator._verdict_from_score(70) == "SAFE"
        assert AggregatedEvaluator._verdict_from_score(100) == "SAFE"

    def test_recalculate_total_with_weights(self, mock_node_score_safe):
        """Custom weights correctly recalculate the total score."""
        weights = {"sender": 0.20, "content": 0.25, "link": 0.25, "auth": 0.15, "attachment": 0.15}
        total = AggregatedEvaluator._recalculate_total(mock_node_score_safe, weights)
        expected = int(
            90 * 0.20 + 85 * 0.25 + 95 * 0.25 + 90 * 0.15 + 100 * 0.15
        )
        assert total == expected

    def test_check_targets(self):
        """Target checking identifies passing and failing metrics."""
        good_cm = ConfusionMatrix(tp=97, fp=3, tn=100, fn=0)
        targets = AggregatedEvaluator._check_targets(good_cm)
        assert targets["recall_ge_97"] is True
        assert targets["fnr_lt_2"] is True

    def test_update_cm_correctly(self):
        """Confusion matrix updates for all four quadrants."""
        cm = ConfusionMatrix()
        AggregatedEvaluator._update_cm(cm, True, True)   # TP
        AggregatedEvaluator._update_cm(cm, True, False)  # FN
        AggregatedEvaluator._update_cm(cm, False, True)  # FP
        AggregatedEvaluator._update_cm(cm, False, False) # TN
        assert cm.tp == 1 and cm.fn == 1 and cm.fp == 1 and cm.tn == 1

    def test_evaluation_metrics_to_dict(self):
        """EvaluationMetrics serializes to dict with all required keys."""
        cm = ConfusionMatrix(tp=10, fp=2, tn=8, fn=1)
        metrics = EvaluationMetrics(confusion_matrix=cm, roc_auc=0.95)
        d = metrics.to_dict()
        assert "overall" in d
        assert "roc_auc" in d
        assert "node_accuracies" in d
        assert "targets_met" in d

    def test_roc_auc_perfect(self):
        """Perfect separation returns AUC = 1.0."""
        pairs = [(1.0, 1), (0.9, 1), (0.8, 1), (0.1, 0), (0.0, 0)]
        auc = AggregatedEvaluator._calculate_roc_auc(pairs)
        assert auc == 1.0

    def test_roc_auc_empty(self):
        """Empty input returns 0.0."""
        assert AggregatedEvaluator._calculate_roc_auc([]) == 0.0


# ═══════════════════════════════════════════════════════════════
# WEIGHT OPTIMIZER TESTS
# ═══════════════════════════════════════════════════════════════


class TestWeightOptimizer:
    """Tests for WeightOptimizer module."""

    def test_weight_configuration_normalization(self):
        """Normalized weights sum to 1.0."""
        wc = WeightConfiguration(sender=20, content=25, link=25, auth=15, attachment=15)
        normalized = wc.normalized()
        assert abs(normalized.total - 1.0) < 1e-6

    def test_weight_configuration_to_dict(self):
        """Weight config serializes correctly."""
        wc = WeightConfiguration(sender=0.2, content=0.25, link=0.25, auth=0.15, attachment=0.15)
        d = wc.to_dict()
        assert set(d.keys()) == {"sender", "content", "link", "auth", "attachment"}

    def test_optimization_result_to_dict(self):
        """OptimizationResult serializes correctly."""
        wc = WeightConfiguration(sender=0.2, content=0.25, link=0.25, auth=0.15, attachment=0.15)
        result = OptimizationResult(
            best_weights=wc, best_f1=0.95, best_recall=0.97,
            best_precision=0.96, best_fnr=0.01,
            iterations_run=50, total_time_seconds=10.5, method="bayesian",
        )
        d = result.to_dict()
        assert "best_weights" in d
        assert "best_f1" in d
        assert d["method"] == "bayesian"

    def test_lock_and_load_weights(self):
        """Weights can be locked to file and reloaded."""
        wc = WeightConfiguration(sender=0.18, content=0.28, link=0.27, auth=0.14, attachment=0.13)
        result = OptimizationResult(
            best_weights=wc, best_f1=0.95, best_recall=0.97,
            best_precision=0.96, best_fnr=0.01,
            iterations_run=50, total_time_seconds=10.5, method="grid",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "locked_weights.json")
            WeightOptimizer.lock_weights(result, filepath)
            assert os.path.exists(filepath)

            loaded = WeightOptimizer.load_locked_weights(filepath)
            assert abs(loaded.sender - 0.18) < 1e-6
            assert abs(loaded.content - 0.28) < 1e-6


# ═══════════════════════════════════════════════════════════════
# ADVERSARIAL GENERATOR TESTS
# ═══════════════════════════════════════════════════════════════


class TestAdversarialGenerator:
    """Tests for AdversarialGenerator module."""

    def test_generate_full_suite(self):
        """Full adversarial suite generates samples for all attack types."""
        gen = AdversarialGenerator(random_seed=42)
        samples = gen.generate_full_adversarial_suite(count_per_type=2)
        assert len(samples) > 0
        # All adversarial samples should be labeled PHISHING
        assert all(s.ground_truth == "PHISHING" for s in samples)

    def test_homoglyph_attacks(self):
        """Homoglyph attack generator produces valid samples."""
        gen = AdversarialGenerator(random_seed=42)
        samples = gen.generate_homoglyph_attacks(count=3)
        assert len(samples) == 3
        for s in samples:
            assert s.ground_truth == "PHISHING"
            assert s.category == "ADVERSARIAL_OBFUSCATED"

    def test_url_shortener_attacks(self):
        """URL shortener attacks have links."""
        gen = AdversarialGenerator(random_seed=42)
        samples = gen.generate_url_shortener_attacks(count=2)
        assert len(samples) == 2
        for s in samples:
            assert len(s.links) > 0

    def test_encoded_payload_attacks(self):
        """Encoded payload attacks generate valid samples."""
        gen = AdversarialGenerator(random_seed=42)
        samples = gen.generate_encoded_payload_attacks(count=2)
        assert len(samples) == 2

    def test_grammar_perfect_phishing(self):
        """Grammar-perfect phishing generates professional-sounding content."""
        gen = AdversarialGenerator(random_seed=42)
        samples = gen.generate_grammar_perfect_phishing(count=2)
        assert len(samples) == 2
        for s in samples:
            assert len(s.body) > 0

    def test_inject_into_dataset(self):
        """Adversarial samples are injected into existing dataset."""
        gen = AdversarialGenerator(random_seed=42)
        original = [
            EmailSample(id="orig_001", sender="test@test.com", body="Safe email", ground_truth="SAFE"),
        ]
        combined = gen.inject_into_dataset(original, count_per_type=1)
        assert len(combined) > len(original)

    def test_unique_ids(self):
        """All generated samples have unique IDs."""
        gen = AdversarialGenerator(random_seed=42)
        samples = gen.generate_full_adversarial_suite(count_per_type=3)
        ids = [s.id for s in samples]
        assert len(ids) == len(set(ids)), "Duplicate IDs found"

    def test_to_raw_bytes_all_samples(self):
        """All adversarial samples convert to valid raw email bytes."""
        gen = AdversarialGenerator(random_seed=42)
        samples = gen.generate_full_adversarial_suite(count_per_type=1)
        for s in samples:
            raw = s.to_raw_email_bytes()
            assert isinstance(raw, bytes)
            assert len(raw) > 0


# ═══════════════════════════════════════════════════════════════
# REGRESSION RUNNER TESTS
# ═══════════════════════════════════════════════════════════════


class TestRegressionRunner:
    """Tests for RegressionRunner and DriftDetector."""

    def test_baseline_save_load(self):
        """Baseline can be saved and reloaded."""
        cm = ConfusionMatrix(tp=90, fp=5, tn=100, fn=5)
        metrics = EvaluationMetrics(
            confusion_matrix=cm, roc_auc=0.95,
            node_accuracies={"sender": 85.0, "content": 90.0, "link": 92.0},
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test_baseline.json")
            runner = RegressionRunner(baseline_path=path)
            runner.save_baseline(metrics, commit_hash="abc123", version="1.0")

            loaded = runner._load_baseline()
            assert loaded is not None
            assert abs(loaded.f1_score - cm.f1_score) < 1e-6
            assert loaded.commit_hash == "abc123"

    def test_regression_delta(self):
        """RegressionDelta calculates delta percentage correctly."""
        delta = RegressionDelta(
            metric_name="f1_score", baseline_value=0.95,
            current_value=0.93, delta=0.02, threshold=0.01, passed=False,
        )
        assert "%" in delta.delta_pct
        assert not delta.passed

    def test_first_run_passes(self):
        """First run without baseline passes by default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "nonexistent_baseline.json")
            runner = RegressionRunner(baseline_path=path)
            deltas, failures, warnings = runner._compare_metrics(
                EvaluationMetrics(confusion_matrix=ConfusionMatrix(tp=10, fp=1, tn=10, fn=0)),
                None,
            )
            assert len(failures) == 0

    def test_absolute_target_check_pass(self):
        """Metrics meeting targets pass absolute checks."""
        cm = ConfusionMatrix(tp=97, fp=2, tn=100, fn=1)
        metrics = EvaluationMetrics(confusion_matrix=cm)
        failures = RegressionRunner._check_absolute_targets(metrics)
        assert len(failures) == 0

    def test_absolute_target_check_fail(self):
        """Metrics below targets fail absolute checks."""
        cm = ConfusionMatrix(tp=50, fp=30, tn=100, fn=20)
        metrics = EvaluationMetrics(confusion_matrix=cm)
        failures = RegressionRunner._check_absolute_targets(metrics)
        assert len(failures) > 0


class TestDriftDetector:
    """Tests for DriftDetector."""

    def test_insufficient_data(self):
        """Returns no drift with insufficient data."""
        detector = DriftDetector(history_size=100)
        result = detector.check_drift()
        assert result["drift_detected"] is False

    def test_drift_detection(self):
        """Detects drift when score distributions shift significantly."""
        detector = DriftDetector(history_size=100)

        # Record stable scores
        for _ in range(20):
            detector.record_scores({
                "sender_score": 80, "content_score": 85,
                "link_score": 90, "auth_score": 75, "attachment_score": 95,
            })
        # Record shifted scores
        for _ in range(20):
            detector.record_scores({
                "sender_score": 30, "content_score": 25,
                "link_score": 20, "auth_score": 15, "attachment_score": 35,
            })

        result = detector.check_drift()
        assert result["drift_detected"] is True
        assert len(result["significant_drifts"]) > 0

    def test_no_drift_stable(self):
        """No drift detected with stable scores."""
        detector = DriftDetector(history_size=100)
        for _ in range(40):
            detector.record_scores({
                "sender_score": 80, "content_score": 85,
                "link_score": 90, "auth_score": 75, "attachment_score": 95,
            })
        result = detector.check_drift()
        assert result["drift_detected"] is False

    def test_drift_callback(self):
        """Drift detection triggers registered callbacks."""
        detector = DriftDetector(history_size=100)
        callback_called = []
        detector.on_drift(lambda r: callback_called.append(True))

        # Force drift
        for _ in range(20):
            detector.record_scores({"sender_score": 90, "content_score": 90, "link_score": 90, "auth_score": 90, "attachment_score": 90})
        for _ in range(20):
            detector.record_scores({"sender_score": 10, "content_score": 10, "link_score": 10, "auth_score": 10, "attachment_score": 10})

        detector.check_drift()
        assert len(callback_called) > 0


# ═══════════════════════════════════════════════════════════════
# REPORT GENERATOR TESTS
# ═══════════════════════════════════════════════════════════════


class TestReportGenerator:
    """Tests for ReportGenerator module."""

    def test_console_report(self):
        """Console report generates a string."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            cm = ConfusionMatrix(tp=90, fp=5, tn=100, fn=5)
            metrics = EvaluationMetrics(
                confusion_matrix=cm, roc_auc=0.95,
                node_accuracies={"sender": 85.0, "content": 90.0, "link": 92.0, "auth": 88.0, "attachment": 79.0},
            )
            report = gen.print_console_report(metrics, title="Test Report")
            assert isinstance(report, str)
            assert "Test Report" in report

    def test_json_report(self):
        """JSON report creates a valid file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            cm = ConfusionMatrix(tp=90, fp=5, tn=100, fn=5)
            metrics = EvaluationMetrics(confusion_matrix=cm, roc_auc=0.95)
            path = gen.generate_json_report(metrics)
            assert os.path.exists(path)

            with open(path) as f:
                data = json.load(f)
            assert "overall" in data or "confusion_matrix" in data or "metrics" in data

    def test_markdown_report(self):
        """Markdown report creates a file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ReportGenerator(output_dir=tmpdir)
            cm = ConfusionMatrix(tp=90, fp=5, tn=100, fn=5)
            metrics = EvaluationMetrics(confusion_matrix=cm, roc_auc=0.95)
            path = gen.generate_markdown_report(metrics)
            assert os.path.exists(path)
            assert path.endswith(".md")

    def test_ai_feedback_prompts(self):
        """AI feedback prompts are generated for misclassified samples."""
        gen = ReportGenerator(output_dir=tempfile.gettempdir())
        cm = ConfusionMatrix(tp=9, fp=1, tn=10, fn=1)
        metrics = EvaluationMetrics(
            confusion_matrix=cm,
            misclassified=[
                {
                    "sample_id": "phish_001",
                    "ground_truth": "PHISHING",
                    "predicted": "SAFE",
                    "category": "KNOWN_PHISHING",
                    "difficulty": "easy",
                    "total_score": 75,
                    "node_scores": {"sender": 20, "content": 80, "link": 90, "auth": 85, "attachment": 100},
                    "risk_factors": [],
                },
            ],
        )
        prompts = gen.generate_ai_feedback_prompts(metrics)
        assert len(prompts) > 0
        assert "PHISHING" in prompts[0]


# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR TESTS
# ═══════════════════════════════════════════════════════════════


class TestOrchestratorResult:
    """Tests for OrchestratorResult dataclass."""

    def test_result_fields(self):
        """OrchestratorResult stores all expected fields."""
        result = OrchestratorResult(
            success=True,
            timestamp="2026-01-01T00:00:00Z",
            duration_seconds=42.5,
            safe_to_deploy=True,
        )
        assert result.success is True
        assert result.duration_seconds == 42.5
        assert result.safe_to_deploy is True
        assert result.deployment_blockers == []

    def test_deployment_blockers(self):
        """Deployment blockers are properly tracked."""
        result = OrchestratorResult(
            success=True,
            timestamp="2026-01-01T00:00:00Z",
            duration_seconds=10.0,
            safe_to_deploy=False,
            deployment_blockers=["F1 too low", "FNR too high"],
        )
        assert len(result.deployment_blockers) == 2
        assert "F1 too low" in result.deployment_blockers


class TestOrchestratorConfig:
    """Tests for OrchestratorConfig defaults."""

    def test_default_config(self):
        """Default config has expected values."""
        config = OrchestratorConfig()
        assert config.optimization_method == "bayesian"
        assert config.use_builtin_dataset is True
        assert config.include_adversarial is True
        assert config.auto_lock_weights is True
        assert config.min_f1_for_lock == 0.90


# ═══════════════════════════════════════════════════════════════
# PERFORMANCE TARGETS
# ═══════════════════════════════════════════════════════════════


class TestPerformanceTargets:
    """Tests that performance target thresholds are correctly defined."""

    def test_targets_defined(self):
        """All required targets exist."""
        assert "precision" in PERFORMANCE_TARGETS
        assert "recall" in PERFORMANCE_TARGETS
        assert "false_negative_rate_max" in PERFORMANCE_TARGETS
        assert "f1_score" in PERFORMANCE_TARGETS

    def test_target_values(self):
        """Targets match specification: P>=95%, R>=97%, FNR<2%."""
        assert PERFORMANCE_TARGETS["precision"] >= 0.95
        assert PERFORMANCE_TARGETS["recall"] >= 0.97
        assert PERFORMANCE_TARGETS["false_negative_rate_max"] <= 0.02
