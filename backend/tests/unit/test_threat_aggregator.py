"""
Unit tests for ThreatAggregator and orchestrator logic.
Tests threat scoring, result aggregation, and decision making.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime
from typing import List, Dict, Any

from app.orchestrator.threat_aggregator import ThreatAggregator
from app.services.interfaces import AnalysisResult, AnalysisType
from app.orchestrator.real_threat_orchestrator import RealThreatOrchestrator


@pytest.fixture
def threat_aggregator():
    """Create ThreatAggregator instance for testing."""
    return ThreatAggregator()


@pytest.fixture
def mock_analysis_results():
    """Create mock analysis results for testing."""
    return [
        AnalysisResult(
            service_name="virustotal",
            analysis_type=AnalysisType.URL_SCAN,
            target="https://malicious.example.com",
            threat_score=0.8,
            confidence=0.9,
            verdict="malicious",
            explanation="Multiple engines detected threats",
            indicators=["Engine1: Malware", "Engine2: Phishing"],
            raw_response={"positives": 5, "total": 65},
            timestamp=datetime.now().timestamp(),
            execution_time_ms=1500
        ),
        AnalysisResult(
            service_name="gemini",
            analysis_type=AnalysisType.CONTENT_ANALYSIS,
            target="Email content",
            threat_score=0.6,
            confidence=0.7,
            verdict="suspicious",
            explanation="Suspicious language patterns detected",
            indicators=["urgency_keywords", "financial_request"],
            raw_response={"analysis": "suspicious_content"},
            timestamp=datetime.now().timestamp(),
            execution_time_ms=2000
        ),
        AnalysisResult(
            service_name="link_analyzer",
            analysis_type=AnalysisType.URL_SCAN,
            target="https://redirect.example.com",
            threat_score=0.3,
            confidence=0.8,
            verdict="suspicious",
            explanation="Multiple redirects detected",
            indicators=["redirect_chain", "suspicious_domain"],
            raw_response={"redirects": 3},
            timestamp=datetime.now().timestamp(),
            execution_time_ms=800
        )
    ]


@pytest.fixture
def clean_analysis_results():
    """Create clean analysis results for testing."""
    return [
        AnalysisResult(
            service_name="virustotal",
            analysis_type=AnalysisType.URL_SCAN,
            target="https://legitimate.example.com",
            threat_score=0.0,
            confidence=0.9,
            verdict="clean",
            explanation="No threats detected",
            indicators=[],
            raw_response={"positives": 0, "total": 65},
            timestamp=datetime.now().timestamp(),
            execution_time_ms=1200
        ),
        AnalysisResult(
            service_name="gemini",
            analysis_type=AnalysisType.CONTENT_ANALYSIS,
            target="Email content",
            threat_score=0.1,
            confidence=0.8,
            verdict="clean",
            explanation="Normal business communication",
            indicators=[],
            raw_response={"analysis": "clean_content"},
            timestamp=datetime.now().timestamp(),
            execution_time_ms=1800
        )
    ]


class TestThreatAggregator:
    """Test suite for ThreatAggregator."""
    
    def test_aggregator_initialization(self, threat_aggregator):
        """Test aggregator initializes correctly."""
        assert threat_aggregator is not None
        assert hasattr(threat_aggregator, 'aggregate_results')
        assert hasattr(threat_aggregator, 'calculate_final_score')
    
    def test_simple_aggregation(self, threat_aggregator, mock_analysis_results):
        """Test basic threat aggregation."""
        final_result = threat_aggregator.aggregate_results(mock_analysis_results)
        
        assert final_result is not None
        assert final_result.final_threat_score > 0.5  # Should be high due to malicious findings
        assert final_result.confidence > 0.0
        assert final_result.verdict in ["malicious", "suspicious"]
        assert len(final_result.contributing_results) == 3
    
    def test_clean_aggregation(self, threat_aggregator, clean_analysis_results):
        """Test aggregation of clean results."""
        final_result = threat_aggregator.aggregate_results(clean_analysis_results)
        
        assert final_result.final_threat_score < 0.3  # Should be low
        assert final_result.verdict == "clean"
        assert len(final_result.contributing_results) == 2
    
    def test_weighted_aggregation(self, threat_aggregator):
        """Test weighted aggregation based on service reliability."""
        # High confidence, high threat score from reliable service
        high_confidence_result = AnalysisResult(
            service_name="virustotal",
            analysis_type=AnalysisType.URL_SCAN,
            target="https://test.com",
            threat_score=0.9,
            confidence=0.95,
            verdict="malicious",
            explanation="High confidence detection",
            indicators=["multiple_detections"],
            raw_response={},
            timestamp=datetime.now().timestamp(),
            execution_time_ms=1000
        )
        
        # Low confidence, low threat score from less reliable source
        low_confidence_result = AnalysisResult(
            service_name="experimental_service",
            analysis_type=AnalysisType.CONTENT_ANALYSIS,
            target="Content",
            threat_score=0.2,
            confidence=0.3,
            verdict="clean",
            explanation="Low confidence assessment",
            indicators=[],
            raw_response={},
            timestamp=datetime.now().timestamp(),
            execution_time_ms=500
        )
        
        final_result = threat_aggregator.aggregate_results([
            high_confidence_result, 
            low_confidence_result
        ])
        
        # Should be heavily weighted toward high confidence result
        assert final_result.final_threat_score > 0.6
        assert final_result.verdict == "malicious"
    
    def test_consensus_building(self, threat_aggregator):
        """Test consensus building across multiple services."""
        # Multiple services agreeing on threat
        consensus_results = [
            AnalysisResult(
                service_name=f"service_{i}",
                analysis_type=AnalysisType.URL_SCAN,
                target="https://consensus-threat.com",
                threat_score=0.7 + (i * 0.1),
                confidence=0.8,
                verdict="malicious",
                explanation=f"Service {i} detected threat",
                indicators=[f"indicator_{i}"],
                raw_response={},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=1000
            )
            for i in range(3)
        ]
        
        final_result = threat_aggregator.aggregate_results(consensus_results)
        
        # Strong consensus should result in high confidence
        assert final_result.confidence > 0.8
        assert final_result.verdict == "malicious"
        assert "consensus" in final_result.explanation.lower()
    
    def test_conflicting_results_handling(self, threat_aggregator):
        """Test handling of conflicting analysis results."""
        conflicting_results = [
            AnalysisResult(
                service_name="service_a",
                analysis_type=AnalysisType.URL_SCAN,
                target="https://conflicting.com",
                threat_score=0.9,
                confidence=0.8,
                verdict="malicious",
                explanation="Detected as malicious",
                indicators=["malware"],
                raw_response={},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=1000
            ),
            AnalysisResult(
                service_name="service_b",
                analysis_type=AnalysisType.URL_SCAN,
                target="https://conflicting.com",
                threat_score=0.1,
                confidence=0.8,
                verdict="clean",
                explanation="Appears clean",
                indicators=[],
                raw_response={},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=1000
            )
        ]
        
        final_result = threat_aggregator.aggregate_results(conflicting_results)
        
        # Should handle conflict appropriately
        assert final_result.confidence < 0.9  # Lower confidence due to conflict
        assert final_result.verdict in ["suspicious", "malicious"]  # Conservative approach
        assert "conflict" in final_result.explanation.lower() or "disagreement" in final_result.explanation.lower()
    
    def test_missing_results_handling(self, threat_aggregator):
        """Test handling when some services fail to provide results."""
        partial_results = [
            AnalysisResult(
                service_name="working_service",
                analysis_type=AnalysisType.URL_SCAN,
                target="https://test.com",
                threat_score=0.5,
                confidence=0.8,
                verdict="suspicious",
                explanation="Single service assessment",
                indicators=["suspicious_pattern"],
                raw_response={},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=1000
            )
        ]
        
        final_result = threat_aggregator.aggregate_results(partial_results)
        
        # Should still provide result but with lower confidence
        assert final_result is not None
        assert final_result.confidence < 0.9  # Reduced confidence with fewer inputs
        assert "limited analysis" in final_result.explanation.lower() or "single service" in final_result.explanation.lower()
    
    def test_score_calculation_algorithms(self, threat_aggregator):
        """Test different score calculation algorithms."""
        test_results = [
            AnalysisResult(
                service_name="service_1",
                analysis_type=AnalysisType.URL_SCAN,
                target="https://test.com",
                threat_score=0.3,
                confidence=0.9,
                verdict="suspicious",
                explanation="Low threat",
                indicators=[],
                raw_response={},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=1000
            ),
            AnalysisResult(
                service_name="service_2",
                analysis_type=AnalysisType.CONTENT_ANALYSIS,
                target="Content",
                threat_score=0.7,
                confidence=0.8,
                verdict="suspicious",
                explanation="Medium threat",
                indicators=[],
                raw_response={},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=1000
            )
        ]
        
        # Test different aggregation methods
        methods = ["weighted_average", "max_score", "consensus"]
        
        for method in methods:
            if hasattr(threat_aggregator, 'set_aggregation_method'):
                threat_aggregator.set_aggregation_method(method)
            
            result = threat_aggregator.aggregate_results(test_results)
            assert result is not None
            assert 0.0 <= result.final_threat_score <= 1.0
    
    def test_indicator_aggregation(self, threat_aggregator, mock_analysis_results):
        """Test aggregation of threat indicators."""
        final_result = threat_aggregator.aggregate_results(mock_analysis_results)
        
        # Should collect indicators from all services
        all_indicators = final_result.aggregated_indicators
        
        assert "Engine1: Malware" in all_indicators
        assert "Engine2: Phishing" in all_indicators
        assert "urgency_keywords" in all_indicators
        assert "redirect_chain" in all_indicators
        assert len(all_indicators) >= 5
    
    def test_performance_metrics(self, threat_aggregator, mock_analysis_results):
        """Test performance metrics calculation."""
        import time
        
        start_time = time.time()
        final_result = threat_aggregator.aggregate_results(mock_analysis_results)
        end_time = time.time()
        
        # Should complete quickly
        assert (end_time - start_time) < 1.0
        
        # Should track timing information
        assert hasattr(final_result, 'aggregation_time_ms')
        assert final_result.aggregation_time_ms > 0
    
    def test_empty_results_handling(self, threat_aggregator):
        """Test handling of empty results list."""
        empty_result = threat_aggregator.aggregate_results([])
        
        assert empty_result is not None
        assert empty_result.final_threat_score == 0.0
        assert empty_result.verdict == "unknown"
        assert empty_result.confidence == 0.0
        assert "no analysis" in empty_result.explanation.lower()
    
    def test_single_result_handling(self, threat_aggregator):
        """Test handling of single analysis result."""
        single_result = [
            AnalysisResult(
                service_name="single_service",
                analysis_type=AnalysisType.URL_SCAN,
                target="https://test.com",
                threat_score=0.6,
                confidence=0.8,
                verdict="suspicious",
                explanation="Single analysis",
                indicators=["indicator1"],
                raw_response={},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=1000
            )
        ]
        
        final_result = threat_aggregator.aggregate_results(single_result)
        
        # Should pass through single result with appropriate confidence adjustment
        assert final_result.final_threat_score == 0.6
        assert final_result.verdict == "suspicious"
        assert final_result.confidence <= 0.8  # May be reduced for single source
    
    def test_verdict_determination_logic(self, threat_aggregator):
        """Test verdict determination logic."""
        # Test score ranges for different verdicts
        test_cases = [
            (0.0, "clean"),
            (0.1, "clean"),
            (0.3, "suspicious"),
            (0.5, "suspicious"),
            (0.7, "malicious"),
            (0.9, "malicious")
        ]
        
        for score, expected_verdict in test_cases:
            test_result = [
                AnalysisResult(
                    service_name="test_service",
                    analysis_type=AnalysisType.URL_SCAN,
                    target="https://test.com",
                    threat_score=score,
                    confidence=0.8,
                    verdict=expected_verdict,
                    explanation="Test",
                    indicators=[],
                    raw_response={},
                    timestamp=datetime.now().timestamp(),
                    execution_time_ms=1000
                )
            ]
            
            final_result = threat_aggregator.aggregate_results(test_result)
            assert final_result.verdict == expected_verdict, f"Score {score} should result in {expected_verdict}"
    
    def test_confidence_calculation(self, threat_aggregator):
        """Test confidence calculation logic."""
        # High confidence inputs should result in high confidence output
        high_confidence_results = [
            AnalysisResult(
                service_name=f"service_{i}",
                analysis_type=AnalysisType.URL_SCAN,
                target="https://test.com",
                threat_score=0.5,
                confidence=0.95,
                verdict="suspicious",
                explanation="High confidence",
                indicators=[],
                raw_response={},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=1000
            )
            for i in range(3)
        ]
        
        final_result = threat_aggregator.aggregate_results(high_confidence_results)
        assert final_result.confidence > 0.8
        
        # Low confidence inputs should result in low confidence output
        low_confidence_results = [
            AnalysisResult(
                service_name=f"service_{i}",
                analysis_type=AnalysisType.URL_SCAN,
                target="https://test.com",
                threat_score=0.5,
                confidence=0.3,
                verdict="suspicious",
                explanation="Low confidence",
                indicators=[],
                raw_response={},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=1000
            )
            for i in range(3)
        ]
        
        final_result = threat_aggregator.aggregate_results(low_confidence_results)
        assert final_result.confidence < 0.5
    
    def test_service_weight_configuration(self, threat_aggregator):
        """Test service weight configuration."""
        # Test that service weights can be configured
        if hasattr(threat_aggregator, 'set_service_weights'):
            weights = {
                "virustotal": 1.0,
                "gemini": 0.8,
                "link_analyzer": 0.6
            }
            threat_aggregator.set_service_weights(weights)
            
            # Verify weights are applied
            assert threat_aggregator.get_service_weight("virustotal") == 1.0
            assert threat_aggregator.get_service_weight("gemini") == 0.8
    
    def test_aggregation_with_errors(self, threat_aggregator):
        """Test aggregation with some results containing errors."""
        mixed_results = [
            AnalysisResult(
                service_name="good_service",
                analysis_type=AnalysisType.URL_SCAN,
                target="https://test.com",
                threat_score=0.5,
                confidence=0.8,
                verdict="suspicious",
                explanation="Normal result",
                indicators=[],
                raw_response={},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=1000
            ),
            AnalysisResult(
                service_name="error_service",
                analysis_type=AnalysisType.URL_SCAN,
                target="https://test.com",
                threat_score=0.0,
                confidence=0.0,
                verdict="error",
                explanation="Service error occurred",
                indicators=[],
                raw_response={"error": "Service unavailable"},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=0,
                error="Service unavailable"
            )
        ]
        
        final_result = threat_aggregator.aggregate_results(mixed_results)
        
        # Should still provide useful result despite errors
        assert final_result is not None
        assert final_result.final_threat_score >= 0.0
        assert "error" not in final_result.verdict
    
    @pytest.mark.parametrize("num_results", [1, 3, 5, 10])
    def test_scalability(self, threat_aggregator, num_results):
        """Test aggregation performance with varying numbers of results."""
        import time
        
        # Generate multiple results
        results = [
            AnalysisResult(
                service_name=f"service_{i}",
                analysis_type=AnalysisType.URL_SCAN,
                target="https://test.com",
                threat_score=0.5,
                confidence=0.8,
                verdict="suspicious",
                explanation=f"Result {i}",
                indicators=[],
                raw_response={},
                timestamp=datetime.now().timestamp(),
                execution_time_ms=1000
            )
            for i in range(num_results)
        ]
        
        start_time = time.time()
        final_result = threat_aggregator.aggregate_results(results)
        end_time = time.time()
        
        # Should scale reasonably
        assert (end_time - start_time) < 1.0  # Should complete within 1 second
        assert final_result is not None
        assert len(final_result.contributing_results) == num_results
