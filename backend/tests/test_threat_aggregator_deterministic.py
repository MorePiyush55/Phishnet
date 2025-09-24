"""
Test cases for ThreatAggregator deterministic behavior and explainability.

Validates that same inputs produce identical outputs and that explanations
are consistent and meaningful for analyst trust.
"""

import pytest
from datetime import datetime, timezone
from typing import List, Dict, Any

from app.services.threat_aggregator import (
    ThreatAggregator,
    ThreatAggregatorConfig,
    ComponentScore,
    ComponentType,
    ThresholdProfile,
    ThreatLevel,
    RecommendedAction,
    AggregatedThreatResult
)


class TestThreatAggregatorDeterministic:
    """Test deterministic behavior of ThreatAggregator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = ThreatAggregatorConfig(ThresholdProfile.BALANCED)
        self.aggregator = ThreatAggregator(self.config)
        
        # Create sample component scores for testing
        self.sample_components = [
            ComponentScore(
                component_type=ComponentType.GEMINI_LLM,
                score=0.8,
                confidence=0.9,
                signals=["phishing_content", "social_engineering", "urgency_tactics"],
                metadata={"analysis_time": 1.2, "model_version": "gemini-1.5"},
                processing_time=1.2,
                timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
                version="1.0"
            ),
            ComponentScore(
                component_type=ComponentType.VIRUS_TOTAL,
                score=0.7,
                confidence=0.85,
                signals=["malicious_url", "blacklisted_domain"],
                metadata={"detections": 5, "total_engines": 70},
                processing_time=0.8,
                timestamp=datetime(2024, 1, 15, 10, 30, 1, tzinfo=timezone.utc),
                version="1.0"
            ),
            ComponentScore(
                component_type=ComponentType.LINK_REDIRECT,
                score=0.6,
                confidence=0.75,
                signals=["suspicious_redirect", "url_shortener"],
                metadata={"redirect_chain_length": 3, "final_domain": "suspicious.com"},
                processing_time=2.1,
                timestamp=datetime(2024, 1, 15, 10, 30, 2, tzinfo=timezone.utc),
                version="1.0"
            )
        ]
        
        self.target_identifier = "email_123456789"
    
    def test_deterministic_scoring(self):
        """Test that identical inputs produce identical scores."""
        
        # Run aggregation multiple times
        results = []
        for i in range(5):
            result = self.aggregator.aggregate_threat_scores(
                self.sample_components, self.target_identifier
            )
            results.append(result.threat_score)
        
        # All scores should be identical
        assert all(score == results[0] for score in results), \
            f"Scores are not deterministic: {results}"
    
    def test_deterministic_hash_consistency(self):
        """Test that deterministic hash is consistent across runs."""
        
        results = []
        for i in range(3):
            result = self.aggregator.aggregate_threat_scores(
                self.sample_components, self.target_identifier
            )
            results.append(result.deterministic_hash)
        
        # All hashes should be identical
        assert all(hash_val == results[0] for hash_val in results), \
            f"Deterministic hashes are not consistent: {results}"
    
    def test_deterministic_hash_changes_with_input(self):
        """Test that hash changes when inputs change."""
        
        # Get baseline result
        result1 = self.aggregator.aggregate_threat_scores(
            self.sample_components, self.target_identifier
        )
        
        # Modify component score slightly
        modified_components = self.sample_components.copy()
        modified_components[0] = ComponentScore(
            component_type=ComponentType.GEMINI_LLM,
            score=0.81,  # Changed from 0.8
            confidence=0.9,
            signals=["phishing_content", "social_engineering", "urgency_tactics"],
            metadata={"analysis_time": 1.2, "model_version": "gemini-1.5"},
            processing_time=1.2,
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            version="1.0"
        )
        
        result2 = self.aggregator.aggregate_threat_scores(
            modified_components, self.target_identifier
        )
        
        # Hashes should be different
        assert result1.deterministic_hash != result2.deterministic_hash, \
            "Hash should change when input changes"
    
    def test_validate_deterministic_behavior_method(self):
        """Test the built-in deterministic validation method."""
        
        is_deterministic = self.aggregator.validate_deterministic_behavior(
            self.sample_components, self.target_identifier, iterations=5
        )
        
        assert is_deterministic, "Aggregator should pass deterministic validation"
    
    def test_threshold_profiles_produce_different_scores(self):
        """Test that different threshold profiles produce different results."""
        
        strict_aggregator = ThreatAggregator(ThreatAggregatorConfig(ThresholdProfile.STRICT))
        balanced_aggregator = ThreatAggregator(ThreatAggregatorConfig(ThresholdProfile.BALANCED))
        lenient_aggregator = ThreatAggregator(ThreatAggregatorConfig(ThresholdProfile.LENIENT))
        
        strict_result = strict_aggregator.aggregate_threat_scores(
            self.sample_components, self.target_identifier
        )
        balanced_result = balanced_aggregator.aggregate_threat_scores(
            self.sample_components, self.target_identifier
        )
        lenient_result = lenient_aggregator.aggregate_threat_scores(
            self.sample_components, self.target_identifier
        )
        
        # Scores might be different due to different weights
        # But each profile should be deterministic
        assert strict_result.deterministic_hash != balanced_result.deterministic_hash
        assert balanced_result.deterministic_hash != lenient_result.deterministic_hash
        
        # Each should have different recommended actions for same input
        # (Due to different thresholds)
        actions = {strict_result.recommended_action, balanced_result.recommended_action, lenient_result.recommended_action}
        
        # At least strict should be more aggressive than lenient
        assert strict_result.recommended_action != lenient_result.recommended_action, \
            "Strict and lenient profiles should produce different actions"


class TestThreatExplanation:
    """Test explainability features of ThreatAggregator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.aggregator = ThreatAggregator()
        
        # Create components with clear signals for testing explanations
        self.test_components = [
            ComponentScore(
                component_type=ComponentType.GEMINI_LLM,
                score=0.9,
                confidence=0.95,
                signals=["credential_theft", "phishing_content", "impersonation"],
                metadata={"confidence_score": 0.95, "risk_indicators": ["login_request", "urgent_action"]},
                processing_time=1.5,
                timestamp=datetime.now(timezone.utc),
                version="1.0"
            ),
            ComponentScore(
                component_type=ComponentType.VIRUS_TOTAL,
                score=0.8,
                confidence=0.9,
                signals=["malicious_url", "blacklisted_ip"],
                metadata={"positive_detections": 8, "total_scanners": 70},
                processing_time=0.5,
                timestamp=datetime.now(timezone.utc),
                version="1.0"
            ),
            ComponentScore(
                component_type=ComponentType.ABUSEIPDB,
                score=0.6,
                confidence=0.8,
                signals=["ip_reputation", "abuse_reports"],
                metadata={"abuse_confidence": 75, "usage_type": "datacenter"},
                processing_time=0.3,
                timestamp=datetime.now(timezone.utc),
                version="1.0"
            )
        ]
    
    def test_explanation_contains_top_signals(self):
        """Test that explanation includes top contributing signals."""
        
        result = self.aggregator.aggregate_threat_scores(
            self.test_components, "test_email"
        )
        
        explanation = result.explanation
        
        # Should have top signals
        assert len(explanation.top_signals) > 0, "Should have top contributing signals"
        assert len(explanation.top_signals) <= 5, "Should limit to top 5 signals"
        
        # Top signals should be sorted by contribution
        if len(explanation.top_signals) > 1:
            for i in range(len(explanation.top_signals) - 1):
                assert explanation.top_signals[i].contribution >= explanation.top_signals[i + 1].contribution, \
                    "Signals should be sorted by contribution"
    
    def test_explanation_has_component_breakdown(self):
        """Test that explanation includes component contribution breakdown."""
        
        result = self.aggregator.aggregate_threat_scores(
            self.test_components, "test_email"
        )
        
        explanation = result.explanation
        
        # Should have component breakdown
        assert len(explanation.component_breakdown) > 0, "Should have component breakdown"
        
        # All processed components should be in breakdown
        processed_types = {cs.component_type.value for cs in self.test_components}
        breakdown_types = set(explanation.component_breakdown.keys())
        
        assert processed_types.issubset(breakdown_types), \
            f"All components should be in breakdown. Processed: {processed_types}, Breakdown: {breakdown_types}"
    
    def test_explanation_has_confidence_band(self):
        """Test that explanation includes confidence interval."""
        
        result = self.aggregator.aggregate_threat_scores(
            self.test_components, "test_email"
        )
        
        confidence_band = result.explanation.confidence_band
        
        # Confidence band should be valid
        assert 0.0 <= confidence_band.lower_bound <= 1.0, "Lower bound should be in valid range"
        assert 0.0 <= confidence_band.upper_bound <= 1.0, "Upper bound should be in valid range"
        assert confidence_band.lower_bound <= confidence_band.upper_bound, "Lower bound should be <= upper bound"
        assert 0.0 <= confidence_band.confidence_level <= 1.0, "Confidence level should be in valid range"
        
        # The actual score should be within the confidence band
        assert confidence_band.lower_bound <= result.threat_score <= confidence_band.upper_bound, \
            "Threat score should be within confidence band"
    
    def test_explanation_reasoning_is_meaningful(self):
        """Test that human-readable reasoning is generated."""
        
        result = self.aggregator.aggregate_threat_scores(
            self.test_components, "test_email"
        )
        
        reasoning = result.explanation.reasoning
        
        # Reasoning should be non-empty and contain relevant content
        assert len(reasoning) > 20, "Reasoning should be substantial"
        assert any(level.value in reasoning.lower() for level in ThreatLevel), \
            "Reasoning should mention threat level"
        
        # Should mention key factors for high-threat content
        if result.threat_score > 0.7:
            assert any(keyword in reasoning.lower() for keyword in 
                      ["threat", "risk", "malicious", "suspicious", "factors"]), \
                "High-threat reasoning should mention relevant keywords"
    
    def test_explanation_certainty_factors(self):
        """Test that certainty factors are calculated."""
        
        result = self.aggregator.aggregate_threat_scores(
            self.test_components, "test_email"
        )
        
        certainty_factors = result.explanation.certainty_factors
        
        # Should have expected certainty factor types
        expected_factors = {
            "component_agreement",
            "data_coverage",
            "signal_strength",
            "confidence_consistency"
        }
        
        assert expected_factors.issubset(set(certainty_factors.keys())), \
            f"Missing certainty factors. Expected: {expected_factors}, Got: {set(certainty_factors.keys())}"
        
        # All factors should be in valid range
        for factor_name, factor_value in certainty_factors.items():
            assert 0.0 <= factor_value <= 1.0, \
                f"Certainty factor {factor_name} should be in range [0,1], got {factor_value}"
    
    def test_risk_factors_extraction(self):
        """Test that key risk factors are extracted."""
        
        result = self.aggregator.aggregate_threat_scores(
            self.test_components, "test_email"
        )
        
        risk_factors = result.explanation.risk_factors
        
        # Should extract risk factors from high-scoring components
        if result.threat_score > 0.5:
            assert len(risk_factors) > 0, "Should extract risk factors for high-threat content"
            
            # Risk factors should come from the signals
            all_signals = set()
            for cs in self.test_components:
                all_signals.update(cs.signals)
            
            for risk_factor in risk_factors:
                assert risk_factor in all_signals, \
                    f"Risk factor '{risk_factor}' should come from component signals"


class TestComponentScoreConversion:
    """Test conversion from legacy analysis results to ComponentScore format."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.aggregator = ThreatAggregator()
    
    def test_legacy_to_component_score_conversion(self):
        """Test conversion from legacy format to ComponentScore."""
        
        # Sample legacy analysis results
        legacy_results = {
            "virustotal": {
                "threat_score": 0.8,
                "confidence": 0.9,
                "verdict": "malicious",
                "indicators": ["malicious_url", "blacklisted_domain"],
                "raw_data": {"positive_detections": 5, "total": 70}
            },
            "gemini": {
                "threat_score": 0.75,
                "confidence": 0.85,
                "verdict": "suspicious",
                "indicators": ["phishing_content", "social_engineering"],
                "raw_data": {"analysis_confidence": 0.85}
            }
        }
        
        # Convert to ComponentScore format
        component_scores = self.aggregator._convert_legacy_results(legacy_results)
        
        # Should have created appropriate ComponentScore objects
        assert len(component_scores) == 2, "Should create ComponentScore for each service"
        
        # Check VirusTotal conversion
        vt_component = next((cs for cs in component_scores if cs.component_type == ComponentType.VIRUS_TOTAL), None)
        assert vt_component is not None, "Should create VirusTotal component"
        assert vt_component.score == 0.8, "Should preserve threat score"
        assert vt_component.confidence == 0.9, "Should preserve confidence"
        assert "malicious_url" in vt_component.signals, "Should preserve indicators as signals"
        
        # Check Gemini conversion
        gemini_component = next((cs for cs in component_scores if cs.component_type == ComponentType.GEMINI_LLM), None)
        assert gemini_component is not None, "Should create Gemini component"
        assert gemini_component.score == 0.75, "Should preserve threat score"
        assert gemini_component.confidence == 0.85, "Should preserve confidence"
        assert "phishing_content" in gemini_component.signals, "Should preserve indicators as signals"
    
    def test_ml_score_conversion(self):
        """Test that ML scores are converted to ComponentScore."""
        
        legacy_results = {
            "virustotal": {
                "threat_score": 0.6,
                "confidence": 0.8,
                "verdict": "suspicious",
                "indicators": ["suspicious_url"]
            }
        }
        
        ml_score = 0.75
        
        component_scores = self.aggregator._convert_legacy_results(legacy_results, ml_score)
        
        # Should have ML component in addition to VT
        assert len(component_scores) == 2, "Should have VT and ML components"
        
        ml_component = next((cs for cs in component_scores if cs.component_type == ComponentType.ML_CONTENT), None)
        assert ml_component is not None, "Should create ML component"
        assert ml_component.score == 0.75, "Should use provided ML score"
        assert ml_component.confidence == 0.8, "Should have reasonable confidence for ML"
        assert "ml_prediction" in ml_component.signals, "Should have ML signal"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])