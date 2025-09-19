"""
Comprehensive unit tests for ThreatAggregator - unified threat analysis and scoring.
Tests cover threat aggregation logic, scoring algorithms, and verdict generation with mocked external services.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, List, Any
import json
from datetime import datetime

from app.services.threat_aggregator import (
    ThreatAggregator, ThreatLevel, AggregatedThreatResult
)
from app.services.interfaces import AnalysisResult, AnalysisType


class TestThreatAggregator:
    """Test suite for ThreatAggregator with comprehensive threat scoring testing."""
    
    @pytest.fixture
    def aggregator(self):
        """Create aggregator instance with mocked dependencies."""
        return ThreatAggregator()
    
    @pytest.fixture
    def mock_virustotal_result(self):
        """Mock VirusTotal analysis result."""
        return AnalysisResult(
            target="https://suspicious.com",
            analysis_type=AnalysisType.URL,
            threat_score=0.7,
            confidence=0.9,
            verdict="MALICIOUS",
            explanation="Detected by 5/67 security vendors",
            indicators=["malware_detected", "phishing_url"],
            data={
                "positives": 5,
                "total": 67,
                "scan_date": "2025-01-01 12:00:00",
                "vendors": ["Kaspersky", "Symantec", "McAfee", "Bitdefender", "Avira"]
            },
            timestamp=1704110400
        )
    
    @pytest.fixture
    def mock_gemini_result(self):
        """Mock Gemini AI analysis result."""
        return AnalysisResult(
            target="Suspicious email content with urgent action required",
            analysis_type=AnalysisType.TEXT,
            threat_score=0.8,
            confidence=0.85,
            verdict="PHISHING",
            explanation="Content shows typical phishing characteristics: urgency, credential requests",
            indicators=["urgency_language", "credential_request", "suspicious_links"],
            data={
                "content_analysis": {
                    "urgency_score": 0.9,
                    "credential_request_detected": True,
                    "suspicious_phrases": ["act now", "verify account", "click here"]
                },
                "ai_confidence": 0.85
            },
            timestamp=1704110400
        )
    
    @pytest.fixture
    def mock_redirect_analyzer_result(self):
        """Mock LinkRedirectAnalyzer result."""
        return AnalysisResult(
            target="https://bit.ly/suspicious123",
            analysis_type=AnalysisType.URL,
            threat_score=0.6,
            confidence=0.75,
            verdict="SUSPICIOUS",
            explanation="Multiple redirects leading to suspicious domain",
            indicators=["multiple_redirects", "suspicious_domain", "cloaking_detected"],
            data={
                "redirect_chain": [
                    {"url": "https://bit.ly/suspicious123", "status": 301},
                    {"url": "https://tracking.com/click", "status": 302},
                    {"url": "https://phishing-site.com", "status": 200}
                ],
                "final_url": "https://phishing-site.com",
                "cloaking_detected": True
            },
            timestamp=1704110400
        )
    
    @pytest.fixture
    def sample_component_results(self, mock_virustotal_result, mock_gemini_result, mock_redirect_analyzer_result):
        """Sample results from multiple analysis components."""
        return {
            "virustotal": mock_virustotal_result,
            "gemini": mock_gemini_result,
            "redirect_analyzer": mock_redirect_analyzer_result
        }
    
    @pytest.mark.asyncio
    async def test_basic_threat_aggregation(self, aggregator, sample_component_results):
        """Test basic threat aggregation from multiple components."""
        target = "https://suspicious.com"
        
        with patch.object(aggregator, '_collect_component_results') as mock_collect:
            mock_collect.return_value = sample_component_results
            
            result = await aggregator.aggregate_threats(target)
            
            assert isinstance(result, AggregatedThreatResult)
            assert result.threat_score > 0.5  # Should be high due to multiple threats
            assert result.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
            assert result.confidence > 0.7
            assert "MALICIOUS" in result.verdict or "PHISHING" in result.verdict
    
    @pytest.mark.asyncio
    async def test_threat_score_calculation(self, aggregator, sample_component_results):
        """Test threat score calculation algorithms."""
        target = "https://test.com"
        
        # Test weighted average calculation
        result = await aggregator._calculate_aggregated_score(sample_component_results)
        
        # Score should be weighted average considering confidence
        expected_components = len(sample_component_results)
        assert 0.0 <= result['threat_score'] <= 1.0
        assert 0.0 <= result['confidence'] <= 1.0
        
        # High-confidence results should influence score more
        assert result['threat_score'] > 0.6  # Given the high-threat inputs
        
        # Test score calculation with different component weights
        custom_weights = {
            "virustotal": 0.4,
            "gemini": 0.35,
            "redirect_analyzer": 0.25
        }
        
        weighted_result = await aggregator._calculate_weighted_score(
            sample_component_results, custom_weights
        )
        
        assert 0.0 <= weighted_result <= 1.0
    
    @pytest.mark.asyncio
    async def test_threat_level_classification(self, aggregator):
        """Test threat level classification based on scores."""
        test_cases = [
            (0.0, ThreatLevel.SAFE),
            (0.1, ThreatLevel.SAFE),
            (0.25, ThreatLevel.LOW),
            (0.45, ThreatLevel.MEDIUM),
            (0.7, ThreatLevel.HIGH),
            (0.9, ThreatLevel.CRITICAL),
            (1.0, ThreatLevel.CRITICAL)
        ]
        
        for score, expected_level in test_cases:
            level = aggregator._classify_threat_level(score)
            assert level == expected_level
    
    @pytest.mark.asyncio
    async def test_verdict_generation(self, aggregator, sample_component_results):
        """Test human-readable verdict generation."""
        target = "https://test-verdict.com"
        
        aggregated_result = await aggregator._generate_verdict(sample_component_results, 0.75, ThreatLevel.HIGH)
        
        assert isinstance(aggregated_result['verdict'], str)
        assert len(aggregated_result['verdict']) > 0
        
        # Should mention key threat types
        verdict_lower = aggregated_result['verdict'].lower()
        assert any(threat in verdict_lower for threat in ['malicious', 'phishing', 'suspicious'])
        
        # Should have explanation
        assert isinstance(aggregated_result['explanation'], str)
        assert len(aggregated_result['explanation']) > 10
        
        # Should have indicators
        assert isinstance(aggregated_result['indicators'], list)
        assert len(aggregated_result['indicators']) > 0
    
    @pytest.mark.asyncio
    async def test_safe_content_handling(self, aggregator):
        """Test handling of safe/clean content."""
        safe_results = {
            "virustotal": AnalysisResult(
                target="https://google.com",
                analysis_type=AnalysisType.URL,
                threat_score=0.0,
                confidence=0.95,
                verdict="CLEAN",
                explanation="No threats detected",
                indicators=[],
                data={"positives": 0, "total": 67},
                timestamp=1704110400
            ),
            "gemini": AnalysisResult(
                target="Welcome to our legitimate business website",
                analysis_type=AnalysisType.TEXT,
                threat_score=0.05,
                confidence=0.9,
                verdict="SAFE",
                explanation="Content appears legitimate",
                indicators=[],
                data={"content_analysis": {"legitimacy_score": 0.95}},
                timestamp=1704110400
            )
        }
        
        with patch.object(aggregator, '_collect_component_results') as mock_collect:
            mock_collect.return_value = safe_results
            
            result = await aggregator.aggregate_threats("https://google.com")
            
            assert result.threat_score < 0.2
            assert result.threat_level in [ThreatLevel.SAFE, ThreatLevel.LOW]
            assert "SAFE" in result.verdict or "CLEAN" in result.verdict
            assert result.confidence > 0.8
    
    @pytest.mark.asyncio
    async def test_confidence_calculation(self, aggregator):
        """Test confidence calculation based on component agreement."""
        
        # Test high agreement (all components agree on threat)
        high_agreement_results = {
            "virustotal": AnalysisResult(
                target="https://malware.com", analysis_type=AnalysisType.URL,
                threat_score=0.9, confidence=0.95, verdict="MALICIOUS",
                explanation="High threat", indicators=["malware"], data={}, timestamp=1704110400
            ),
            "gemini": AnalysisResult(
                target="Malicious content", analysis_type=AnalysisType.TEXT,
                threat_score=0.85, confidence=0.9, verdict="MALICIOUS", 
                explanation="High threat", indicators=["malicious_content"], data={}, timestamp=1704110400
            ),
            "redirect_analyzer": AnalysisResult(
                target="https://malware.com", analysis_type=AnalysisType.URL,
                threat_score=0.8, confidence=0.85, verdict="MALICIOUS",
                explanation="High threat", indicators=["suspicious_redirects"], data={}, timestamp=1704110400
            )
        }
        
        high_confidence = await aggregator._calculate_consensus_confidence(high_agreement_results)
        assert high_confidence > 0.85  # High agreement should yield high confidence
        
        # Test low agreement (components disagree)
        low_agreement_results = {
            "virustotal": AnalysisResult(
                target="https://mixed.com", analysis_type=AnalysisType.URL,
                threat_score=0.1, confidence=0.9, verdict="CLEAN",
                explanation="Clean", indicators=[], data={}, timestamp=1704110400
            ),
            "gemini": AnalysisResult(
                target="Mixed content", analysis_type=AnalysisType.TEXT,
                threat_score=0.9, confidence=0.8, verdict="MALICIOUS",
                explanation="Threat", indicators=["threat"], data={}, timestamp=1704110400
            )
        }
        
        low_confidence = await aggregator._calculate_consensus_confidence(low_agreement_results)
        assert low_confidence < 0.7  # Disagreement should reduce confidence
    
    @pytest.mark.asyncio
    async def test_indicator_aggregation(self, aggregator, sample_component_results):
        """Test aggregation and deduplication of threat indicators."""
        indicators = await aggregator._aggregate_indicators(sample_component_results)
        
        assert isinstance(indicators, list)
        assert len(indicators) > 0
        
        # Should include indicators from all components
        all_indicators = set()
        for result in sample_component_results.values():
            all_indicators.update(result.indicators)
        
        aggregated_set = set(indicators)
        assert len(aggregated_set.intersection(all_indicators)) > 0
        
        # Should not have duplicates
        assert len(indicators) == len(set(indicators))
    
    @pytest.mark.asyncio
    async def test_recommendation_generation(self, aggregator):
        """Test generation of actionable recommendations."""
        high_threat_result = AggregatedThreatResult(
            threat_score=0.85,
            threat_level=ThreatLevel.HIGH,
            confidence=0.9,
            verdict="MALICIOUS",
            explanation="Multiple threats detected",
            indicators=["malware_detected", "phishing_url", "suspicious_redirects"],
            recommendations=[],
            component_results={},
            metadata={},
            timestamp=1704110400
        )
        
        recommendations = await aggregator._generate_recommendations(high_threat_result)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        
        # Should have specific actionable recommendations
        rec_text = ' '.join(recommendations).lower()
        assert any(action in rec_text for action in [
            'block', 'quarantine', 'investigate', 'avoid', 'report'
        ])
    
    @pytest.mark.asyncio
    async def test_error_handling_and_partial_results(self, aggregator):
        """Test handling of errors and partial results from components."""
        
        # Simulate some components failing
        partial_results = {
            "virustotal": AnalysisResult(
                target="https://test.com", analysis_type=AnalysisType.URL,
                threat_score=0.3, confidence=0.8, verdict="SUSPICIOUS",
                explanation="Partial result", indicators=[], data={}, timestamp=1704110400
            ),
            # gemini and redirect_analyzer failed (not in results)
        }
        
        with patch.object(aggregator, '_collect_component_results') as mock_collect:
            mock_collect.return_value = partial_results
            
            result = await aggregator.aggregate_threats("https://test.com")
            
            # Should still provide a result with reduced confidence
            assert isinstance(result, AggregatedThreatResult)
            assert result.confidence < 0.9  # Should be lower due to missing components
            assert "partial" in result.explanation.lower() or result.confidence < 0.8
    
    @pytest.mark.asyncio
    async def test_temporal_analysis(self, aggregator):
        """Test temporal analysis and trend detection."""
        
        # Simulate historical results for the same target
        historical_results = [
            {"timestamp": 1704024000, "threat_score": 0.1, "verdict": "SAFE"},    # 1 day ago
            {"timestamp": 1704067200, "threat_score": 0.3, "verdict": "SUSPICIOUS"}, # 12 hours ago  
            {"timestamp": 1704110400, "threat_score": 0.7, "verdict": "MALICIOUS"},  # now
        ]
        
        with patch.object(aggregator, '_get_historical_results') as mock_history:
            mock_history.return_value = historical_results
            
            trend_analysis = await aggregator._analyze_temporal_trends("https://evolving-threat.com")
            
            assert 'trend_direction' in trend_analysis
            assert trend_analysis['trend_direction'] == 'increasing'  # Threat is escalating
            assert 'risk_velocity' in trend_analysis
            assert trend_analysis['risk_velocity'] > 0  # Positive velocity (worsening)
    
    @pytest.mark.asyncio
    async def test_component_weight_adjustment(self, aggregator):
        """Test dynamic adjustment of component weights based on performance."""
        
        # Test performance-based weight adjustment
        component_performance = {
            "virustotal": {"accuracy": 0.95, "false_positive_rate": 0.02},
            "gemini": {"accuracy": 0.87, "false_positive_rate": 0.08},
            "redirect_analyzer": {"accuracy": 0.82, "false_positive_rate": 0.15}
        }
        
        weights = await aggregator._calculate_dynamic_weights(component_performance)
        
        # VirusTotal should have highest weight due to best performance
        assert weights["virustotal"] > weights["gemini"]
        assert weights["gemini"] > weights["redirect_analyzer"]
        assert abs(sum(weights.values()) - 1.0) < 0.001  # Weights should sum to 1
    
    @pytest.mark.asyncio
    async def test_threat_context_enrichment(self, aggregator, sample_component_results):
        """Test enrichment of threat context with external intelligence."""
        
        with patch.object(aggregator, '_enrich_threat_context') as mock_enrich:
            mock_enrich.return_value = {
                "threat_family": "phishing_kit_v2",
                "attribution": "cybercrime_group_x", 
                "geographic_origin": "unknown",
                "first_seen": "2025-01-01",
                "related_campaigns": ["campaign_alpha", "campaign_beta"]
            }
            
            result = await aggregator.aggregate_threats("https://contextual-threat.com")
            
            assert 'threat_context' in result.metadata
            context = result.metadata['threat_context']
            assert 'threat_family' in context
            assert 'attribution' in context
    
    @pytest.mark.asyncio
    async def test_performance_optimization(self, aggregator):
        """Test performance optimization for concurrent aggregations."""
        
        targets = [
            "https://test1.com",
            "https://test2.com", 
            "https://test3.com"
        ]
        
        # Mock component results for concurrent processing
        async def mock_collect_fast(target):
            await asyncio.sleep(0.01)  # Simulate fast processing
            return {
                "virustotal": AnalysisResult(
                    target=target, analysis_type=AnalysisType.URL,
                    threat_score=0.1, confidence=0.9, verdict="CLEAN",
                    explanation="Clean", indicators=[], data={}, timestamp=1704110400
                )
            }
        
        with patch.object(aggregator, '_collect_component_results', side_effect=mock_collect_fast):
            start_time = asyncio.get_event_loop().time()
            
            # Process multiple targets concurrently
            tasks = [aggregator.aggregate_threats(target) for target in targets]
            results = await asyncio.gather(*tasks)
            
            end_time = asyncio.get_event_loop().time()
            processing_time = end_time - start_time
            
            assert len(results) == 3
            assert processing_time < 1.0  # Should complete quickly with concurrency
            
            # Each result should correspond to its target
            for i, result in enumerate(results):
                assert targets[i] in str(result.component_results)
    
    @pytest.mark.asyncio
    async def test_caching_and_result_reuse(self, aggregator):
        """Test caching of aggregation results for performance."""
        
        target = "https://cached-target.com"
        
        # First call should perform full analysis
        with patch.object(aggregator, '_collect_component_results') as mock_collect:
            mock_collect.return_value = {"test": Mock()}
            
            result1 = await aggregator.aggregate_threats(target)
            assert mock_collect.call_count == 1
            
            # Second call should use cache (if implemented)
            result2 = await aggregator.aggregate_threats(target)
            
            # Results should be consistent
            assert result1.target == result2.target
            assert result1.threat_score == result2.threat_score
    
    def test_configuration_and_thresholds(self, aggregator):
        """Test configuration of threat thresholds and parameters."""
        
        # Test custom threshold configuration
        custom_config = {
            'threat_thresholds': {
                'safe': 0.2,
                'low': 0.4,
                'medium': 0.6,
                'high': 0.8
            },
            'confidence_threshold': 0.7,
            'component_weights': {
                'virustotal': 0.5,
                'gemini': 0.3,
                'redirect_analyzer': 0.2
            }
        }
        
        aggregator.configure(custom_config)
        
        # Test that configuration affects classification
        assert aggregator._classify_threat_level(0.3) == ThreatLevel.LOW  # Above custom safe threshold
        assert aggregator._classify_threat_level(0.5) == ThreatLevel.MEDIUM
        
        # Test weight configuration
        assert aggregator.component_weights['virustotal'] == 0.5
        assert aggregator.component_weights['gemini'] == 0.3
    
    def test_logging_and_metrics_integration(self, aggregator):
        """Test integration with logging and metrics systems."""
        
        with patch('app.services.threat_aggregator.logger') as mock_logger, \
             patch.object(aggregator, '_record_metrics') as mock_metrics:
            
            # Simulate threat aggregation
            sample_result = AggregatedThreatResult(
                threat_score=0.8,
                threat_level=ThreatLevel.HIGH,
                confidence=0.9,
                verdict="MALICIOUS",
                explanation="High threat detected",
                indicators=["threat1", "threat2"],
                recommendations=["block_access"],
                component_results={},
                metadata={},
                timestamp=1704110400
            )
            
            aggregator._log_aggregation_result(sample_result)
            
            # Should log threat detection
            assert mock_logger.warning.called or mock_logger.error.called
            
            # Should record metrics
            mock_metrics.assert_called_once()
            
            metrics_call = mock_metrics.call_args[0][0]
            assert metrics_call['threat_level'] == 'HIGH'
            assert metrics_call['threat_score'] == 0.8
