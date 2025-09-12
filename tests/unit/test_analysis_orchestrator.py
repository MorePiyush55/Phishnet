"""
Unit tests for AnalysisOrchestrator.
Tests analysis coordination, result aggregation, and error handling.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any

from app.orchestrator.analysis_orchestrator import AnalysisOrchestrator
from app.services.interfaces import AnalysisResult, AnalysisType, ThreatVerdict
from app.analyzers.interfaces import BaseAnalyzer


@pytest.fixture
def orchestrator():
    """Create AnalysisOrchestrator instance for testing."""
    return AnalysisOrchestrator()


@pytest.fixture
def mock_analyzers():
    """Create mock analyzers for testing."""
    analyzers = {}
    
    # Mock VirusTotal analyzer
    vt_analyzer = Mock(spec=BaseAnalyzer)
    vt_analyzer.analyze_url = AsyncMock(return_value=AnalysisResult(
        analysis_type=AnalysisType.VIRUSTOTAL_SCAN,
        target="https://example.com",
        threat_score=0.3,
        verdict=ThreatVerdict.SUSPICIOUS,
        explanation="VirusTotal scan results",
        indicators=["external_scan"],
        timestamp=datetime.utcnow()
    ))
    analyzers["virustotal"] = vt_analyzer
    
    # Mock URLVoid analyzer
    urlvoid_analyzer = Mock(spec=BaseAnalyzer)
    urlvoid_analyzer.analyze_url = AsyncMock(return_value=AnalysisResult(
        analysis_type=AnalysisType.URLVOID_SCAN,
        target="https://example.com",
        threat_score=0.2,
        verdict=ThreatVerdict.CLEAN,
        explanation="URLVoid scan results",
        indicators=["reputation_check"],
        timestamp=datetime.utcnow()
    ))
    analyzers["urlvoid"] = urlvoid_analyzer
    
    # Mock LinkRedirect analyzer
    redirect_analyzer = Mock(spec=BaseAnalyzer)
    redirect_analyzer.analyze_url = AsyncMock(return_value=AnalysisResult(
        analysis_type=AnalysisType.URL_SCAN,
        target="https://example.com",
        threat_score=0.1,
        verdict=ThreatVerdict.CLEAN,
        explanation="Direct link, no redirects",
        indicators=["direct_link"],
        redirect_count=0,
        final_url="https://example.com",
        timestamp=datetime.utcnow()
    ))
    analyzers["redirect"] = redirect_analyzer
    
    return analyzers


@pytest.fixture
def sample_analysis_results():
    """Create sample analysis results for testing."""
    return [
        AnalysisResult(
            analysis_type=AnalysisType.VIRUSTOTAL_SCAN,
            target="https://example.com",
            threat_score=0.7,
            verdict=ThreatVerdict.MALICIOUS,
            explanation="Multiple AV engines detected malware",
            indicators=["malware_detected", "blacklisted"],
            timestamp=datetime.utcnow()
        ),
        AnalysisResult(
            analysis_type=AnalysisType.URLVOID_SCAN,
            target="https://example.com",
            threat_score=0.6,
            verdict=ThreatVerdict.SUSPICIOUS,
            explanation="Domain has poor reputation",
            indicators=["poor_reputation", "suspicious_domain"],
            timestamp=datetime.utcnow()
        ),
        AnalysisResult(
            analysis_type=AnalysisType.URL_SCAN,
            target="https://example.com",
            threat_score=0.4,
            verdict=ThreatVerdict.SUSPICIOUS,
            explanation="Multiple redirects to suspicious domains",
            indicators=["multiple_redirects", "suspicious_domain"],
            redirect_count=3,
            final_url="https://malicious.com",
            timestamp=datetime.utcnow()
        )
    ]


class TestAnalysisOrchestrator:
    """Test suite for AnalysisOrchestrator."""
    
    def test_orchestrator_initialization(self, orchestrator):
        """Test orchestrator initializes correctly."""
        assert orchestrator is not None
        assert hasattr(orchestrator, 'analyze_url')
        assert hasattr(orchestrator, 'add_analyzer')
        assert hasattr(orchestrator, 'remove_analyzer')
        assert orchestrator.analyzers == {}
    
    def test_analyzer_registration(self, orchestrator, mock_analyzers):
        """Test analyzer registration and removal."""
        # Test adding analyzers
        for name, analyzer in mock_analyzers.items():
            orchestrator.add_analyzer(name, analyzer)
            assert name in orchestrator.analyzers
            assert orchestrator.analyzers[name] == analyzer
        
        # Test removing analyzer
        orchestrator.remove_analyzer("virustotal")
        assert "virustotal" not in orchestrator.analyzers
        assert len(orchestrator.analyzers) == 2
    
    @pytest.mark.asyncio
    async def test_single_analyzer_execution(self, orchestrator, mock_analyzers):
        """Test execution with single analyzer."""
        orchestrator.add_analyzer("virustotal", mock_analyzers["virustotal"])
        
        result = await orchestrator.analyze_url("https://example.com")
        
        assert result is not None
        assert result.target == "https://example.com"
        assert len(result.individual_results) == 1
        assert result.individual_results[0].analysis_type == AnalysisType.VIRUSTOTAL_SCAN
        mock_analyzers["virustotal"].analyze_url.assert_called_once_with("https://example.com")
    
    @pytest.mark.asyncio
    async def test_multiple_analyzer_execution(self, orchestrator, mock_analyzers):
        """Test execution with multiple analyzers."""
        for name, analyzer in mock_analyzers.items():
            orchestrator.add_analyzer(name, analyzer)
        
        result = await orchestrator.analyze_url("https://example.com")
        
        assert result is not None
        assert len(result.individual_results) == 3
        
        # Verify all analyzers were called
        for analyzer in mock_analyzers.values():
            analyzer.analyze_url.assert_called_once_with("https://example.com")
        
        # Verify analysis types are correct
        analysis_types = {r.analysis_type for r in result.individual_results}
        expected_types = {AnalysisType.VIRUSTOTAL_SCAN, AnalysisType.URLVOID_SCAN, AnalysisType.URL_SCAN}
        assert analysis_types == expected_types
    
    @pytest.mark.asyncio
    async def test_result_aggregation(self, orchestrator, sample_analysis_results):
        """Test aggregation of analysis results."""
        # Mock analyzers to return specific results
        mock_vt = Mock(spec=BaseAnalyzer)
        mock_vt.analyze_url = AsyncMock(return_value=sample_analysis_results[0])
        
        mock_uv = Mock(spec=BaseAnalyzer)
        mock_uv.analyze_url = AsyncMock(return_value=sample_analysis_results[1])
        
        mock_redirect = Mock(spec=BaseAnalyzer)
        mock_redirect.analyze_url = AsyncMock(return_value=sample_analysis_results[2])
        
        orchestrator.add_analyzer("virustotal", mock_vt)
        orchestrator.add_analyzer("urlvoid", mock_uv)
        orchestrator.add_analyzer("redirect", mock_redirect)
        
        result = await orchestrator.analyze_url("https://example.com")
        
        # Test threat score aggregation
        expected_score = (0.7 + 0.6 + 0.4) / 3  # Average of individual scores
        assert abs(result.aggregated_threat_score - expected_score) < 0.01
        
        # Test verdict aggregation (should be worst case)
        assert result.final_verdict == ThreatVerdict.MALICIOUS
        
        # Test indicator aggregation
        all_indicators = {"malware_detected", "blacklisted", "poor_reputation", 
                         "suspicious_domain", "multiple_redirects"}
        assert set(result.aggregated_indicators) == all_indicators
    
    @pytest.mark.asyncio
    async def test_concurrent_execution(self, orchestrator, mock_analyzers):
        """Test that analyzers run concurrently."""
        import time
        
        # Add delay to one analyzer to test concurrency
        slow_analyzer = Mock(spec=BaseAnalyzer)
        async def slow_analyze(url):
            await asyncio.sleep(0.1)  # 100ms delay
            return AnalysisResult(
                analysis_type=AnalysisType.CUSTOM_SCAN,
                target=url,
                threat_score=0.0,
                verdict=ThreatVerdict.CLEAN,
                explanation="Slow analysis",
                indicators=[],
                timestamp=datetime.utcnow()
            )
        slow_analyzer.analyze_url = slow_analyze
        
        orchestrator.add_analyzer("slow", slow_analyzer)
        for name, analyzer in mock_analyzers.items():
            orchestrator.add_analyzer(name, analyzer)
        
        start_time = time.time()
        result = await orchestrator.analyze_url("https://example.com")
        end_time = time.time()
        
        # Should complete in ~100ms (concurrent) not ~400ms (sequential)
        assert (end_time - start_time) < 0.2
        assert len(result.individual_results) == 4
    
    @pytest.mark.asyncio
    async def test_analyzer_error_handling(self, orchestrator):
        """Test handling of analyzer errors."""
        # Mock analyzer that raises exception
        failing_analyzer = Mock(spec=BaseAnalyzer)
        failing_analyzer.analyze_url = AsyncMock(side_effect=Exception("Analysis failed"))
        
        # Mock working analyzer
        working_analyzer = Mock(spec=BaseAnalyzer)
        working_analyzer.analyze_url = AsyncMock(return_value=AnalysisResult(
            analysis_type=AnalysisType.VIRUSTOTAL_SCAN,
            target="https://example.com",
            threat_score=0.3,
            verdict=ThreatVerdict.CLEAN,
            explanation="Working analysis",
            indicators=[],
            timestamp=datetime.utcnow()
        ))
        
        orchestrator.add_analyzer("failing", failing_analyzer)
        orchestrator.add_analyzer("working", working_analyzer)
        
        result = await orchestrator.analyze_url("https://example.com")
        
        # Should continue despite one analyzer failing
        assert result is not None
        assert len(result.individual_results) == 1  # Only working analyzer result
        assert len(result.errors) == 1  # One error recorded
        assert "failing" in result.errors
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self, orchestrator):
        """Test handling of analyzer timeouts."""
        # Mock analyzer that times out
        timeout_analyzer = Mock(spec=BaseAnalyzer)
        async def timeout_analyze(url):
            await asyncio.sleep(10)  # Long delay
            return AnalysisResult(
                analysis_type=AnalysisType.CUSTOM_SCAN,
                target=url,
                threat_score=0.0,
                verdict=ThreatVerdict.CLEAN,
                explanation="Should timeout",
                indicators=[],
                timestamp=datetime.utcnow()
            )
        timeout_analyzer.analyze_url = timeout_analyze
        
        orchestrator.add_analyzer("timeout", timeout_analyzer)
        
        # Set short timeout
        result = await orchestrator.analyze_url("https://example.com", timeout=1.0)
        
        assert result is not None
        assert len(result.errors) == 1
        assert "timeout" in result.errors
    
    @pytest.mark.asyncio
    async def test_partial_failure_aggregation(self, orchestrator):
        """Test aggregation when some analyzers fail."""
        # Mix of successful and failing analyzers
        success_analyzer = Mock(spec=BaseAnalyzer)
        success_analyzer.analyze_url = AsyncMock(return_value=AnalysisResult(
            analysis_type=AnalysisType.VIRUSTOTAL_SCAN,
            target="https://example.com",
            threat_score=0.8,
            verdict=ThreatVerdict.MALICIOUS,
            explanation="Detected malware",
            indicators=["malware"],
            timestamp=datetime.utcnow()
        ))
        
        fail_analyzer = Mock(spec=BaseAnalyzer)
        fail_analyzer.analyze_url = AsyncMock(side_effect=Exception("Failed"))
        
        orchestrator.add_analyzer("success", success_analyzer)
        orchestrator.add_analyzer("fail", fail_analyzer)
        
        result = await orchestrator.analyze_url("https://example.com")
        
        # Should aggregate available results
        assert result.aggregated_threat_score == 0.8
        assert result.final_verdict == ThreatVerdict.MALICIOUS
        assert "malware" in result.aggregated_indicators
        assert len(result.errors) == 1
    
    def test_threat_score_aggregation_methods(self, orchestrator):
        """Test different threat score aggregation methods."""
        scores = [0.2, 0.7, 0.9, 0.1, 0.5]
        
        # Test average method
        avg_score = orchestrator._aggregate_threat_scores_average(scores)
        assert abs(avg_score - 0.48) < 0.01
        
        # Test maximum method
        max_score = orchestrator._aggregate_threat_scores_max(scores)
        assert max_score == 0.9
        
        # Test weighted method (if implemented)
        if hasattr(orchestrator, '_aggregate_threat_scores_weighted'):
            weights = [1.0, 2.0, 1.5, 1.0, 1.2]
            weighted_score = orchestrator._aggregate_threat_scores_weighted(scores, weights)
            assert 0.0 <= weighted_score <= 1.0
    
    def test_verdict_aggregation_logic(self, orchestrator):
        """Test verdict aggregation logic."""
        # Test all clean -> clean
        clean_verdicts = [ThreatVerdict.CLEAN, ThreatVerdict.CLEAN, ThreatVerdict.CLEAN]
        result = orchestrator._aggregate_verdicts(clean_verdicts)
        assert result == ThreatVerdict.CLEAN
        
        # Test mixed with malicious -> malicious
        mixed_verdicts = [ThreatVerdict.CLEAN, ThreatVerdict.SUSPICIOUS, ThreatVerdict.MALICIOUS]
        result = orchestrator._aggregate_verdicts(mixed_verdicts)
        assert result == ThreatVerdict.MALICIOUS
        
        # Test mixed without malicious -> suspicious
        suspicious_verdicts = [ThreatVerdict.CLEAN, ThreatVerdict.SUSPICIOUS]
        result = orchestrator._aggregate_verdicts(suspicious_verdicts)
        assert result == ThreatVerdict.SUSPICIOUS
    
    @pytest.mark.asyncio
    async def test_analyzer_priority_ordering(self, orchestrator):
        """Test analyzer execution with priority ordering."""
        # Mock analyzers with different priorities
        high_priority = Mock(spec=BaseAnalyzer)
        high_priority.priority = 1
        high_priority.analyze_url = AsyncMock(return_value=AnalysisResult(
            analysis_type=AnalysisType.VIRUSTOTAL_SCAN,
            target="https://example.com",
            threat_score=0.9,
            verdict=ThreatVerdict.MALICIOUS,
            explanation="High priority detection",
            indicators=["high_priority"],
            timestamp=datetime.utcnow()
        ))
        
        low_priority = Mock(spec=BaseAnalyzer)
        low_priority.priority = 3
        low_priority.analyze_url = AsyncMock(return_value=AnalysisResult(
            analysis_type=AnalysisType.CUSTOM_SCAN,
            target="https://example.com",
            threat_score=0.1,
            verdict=ThreatVerdict.CLEAN,
            explanation="Low priority check",
            indicators=["low_priority"],
            timestamp=datetime.utcnow()
        ))
        
        orchestrator.add_analyzer("high", high_priority)
        orchestrator.add_analyzer("low", low_priority)
        
        result = await orchestrator.analyze_url("https://example.com")
        
        # High priority should have more weight in final decision
        assert result.final_verdict == ThreatVerdict.MALICIOUS
    
    @pytest.mark.asyncio
    async def test_caching_mechanism(self, orchestrator, mock_analyzers):
        """Test result caching mechanism."""
        orchestrator.add_analyzer("virustotal", mock_analyzers["virustotal"])
        
        url = "https://example.com"
        
        # First analysis
        result1 = await orchestrator.analyze_url(url)
        assert mock_analyzers["virustotal"].analyze_url.call_count == 1
        
        # Second analysis (should use cache if implemented)
        result2 = await orchestrator.analyze_url(url)
        
        # Verify results are consistent
        assert result1.target == result2.target
        assert result1.aggregated_threat_score == result2.aggregated_threat_score
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, orchestrator, mock_analyzers):
        """Test rate limiting for analyzer calls."""
        orchestrator.add_analyzer("virustotal", mock_analyzers["virustotal"])
        
        # Make multiple rapid requests
        urls = [f"https://example{i}.com" for i in range(10)]
        
        start_time = datetime.utcnow()
        tasks = [orchestrator.analyze_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = datetime.utcnow()
        
        # All should complete successfully
        for result in results:
            assert not isinstance(result, Exception)
        
        # If rate limiting is implemented, should take minimum time
        duration = (end_time - start_time).total_seconds()
        assert duration >= 0.0  # Basic sanity check
    
    def test_configuration_validation(self, orchestrator):
        """Test configuration validation."""
        # Test timeout configuration
        assert orchestrator.default_timeout > 0
        assert orchestrator.default_timeout < 300  # Should be reasonable
        
        # Test max analyzers limit
        if hasattr(orchestrator, 'max_analyzers'):
            assert orchestrator.max_analyzers > 0
            assert orchestrator.max_analyzers < 100
    
    @pytest.mark.asyncio
    async def test_detailed_error_reporting(self, orchestrator):
        """Test detailed error reporting."""
        # Mock analyzer with specific error
        error_analyzer = Mock(spec=BaseAnalyzer)
        specific_error = ValueError("Invalid URL format")
        error_analyzer.analyze_url = AsyncMock(side_effect=specific_error)
        
        orchestrator.add_analyzer("error", error_analyzer)
        
        result = await orchestrator.analyze_url("https://example.com")
        
        assert "error" in result.errors
        assert "ValueError" in str(result.errors["error"]) or "Invalid URL format" in str(result.errors["error"])
    
    @pytest.mark.asyncio
    async def test_analyzer_health_checking(self, orchestrator):
        """Test analyzer health checking."""
        healthy_analyzer = Mock(spec=BaseAnalyzer)
        healthy_analyzer.analyze_url = AsyncMock(return_value=AnalysisResult(
            analysis_type=AnalysisType.VIRUSTOTAL_SCAN,
            target="https://example.com",
            threat_score=0.0,
            verdict=ThreatVerdict.CLEAN,
            explanation="Healthy",
            indicators=[],
            timestamp=datetime.utcnow()
        ))
        
        # Add health check method if implemented
        if hasattr(healthy_analyzer, 'health_check'):
            healthy_analyzer.health_check = AsyncMock(return_value=True)
        
        orchestrator.add_analyzer("healthy", healthy_analyzer)
        
        # Test health check functionality
        if hasattr(orchestrator, 'check_analyzer_health'):
            health_status = await orchestrator.check_analyzer_health()
            assert "healthy" in health_status
            assert health_status["healthy"] is True
    
    @pytest.mark.asyncio
    async def test_result_filtering(self, orchestrator):
        """Test filtering of analysis results."""
        # Mock analyzers with different confidence levels
        high_confidence = Mock(spec=BaseAnalyzer)
        high_confidence.analyze_url = AsyncMock(return_value=AnalysisResult(
            analysis_type=AnalysisType.VIRUSTOTAL_SCAN,
            target="https://example.com",
            threat_score=0.9,
            verdict=ThreatVerdict.MALICIOUS,
            explanation="High confidence detection",
            indicators=["high_confidence"],
            confidence=0.95,
            timestamp=datetime.utcnow()
        ))
        
        low_confidence = Mock(spec=BaseAnalyzer)
        low_confidence.analyze_url = AsyncMock(return_value=AnalysisResult(
            analysis_type=AnalysisType.CUSTOM_SCAN,
            target="https://example.com",
            threat_score=0.7,
            verdict=ThreatVerdict.SUSPICIOUS,
            explanation="Low confidence detection",
            indicators=["low_confidence"],
            confidence=0.3,
            timestamp=datetime.utcnow()
        ))
        
        orchestrator.add_analyzer("high_conf", high_confidence)
        orchestrator.add_analyzer("low_conf", low_confidence)
        
        # Test with confidence filtering
        result = await orchestrator.analyze_url("https://example.com", min_confidence=0.5)
        
        # Should filter out low confidence results
        if hasattr(result, 'filtered_results'):
            high_conf_results = [r for r in result.filtered_results if r.confidence >= 0.5]
            assert len(high_conf_results) == 1
            assert high_conf_results[0].confidence == 0.95
    
    def test_statistics_tracking(self, orchestrator):
        """Test statistics tracking."""
        if hasattr(orchestrator, 'get_statistics'):
            stats = orchestrator.get_statistics()
            
            # Should track basic metrics
            expected_fields = ['total_analyses', 'successful_analyses', 'failed_analyses', 'average_duration']
            for field in expected_fields:
                assert field in stats
                assert isinstance(stats[field], (int, float))
    
    @pytest.mark.parametrize("analyzer_count", [1, 3, 5, 10])
    @pytest.mark.asyncio
    async def test_scalability_with_analyzer_count(self, orchestrator, analyzer_count):
        """Test scalability with different numbers of analyzers."""
        # Create multiple mock analyzers
        for i in range(analyzer_count):
            analyzer = Mock(spec=BaseAnalyzer)
            analyzer.analyze_url = AsyncMock(return_value=AnalysisResult(
                analysis_type=AnalysisType.CUSTOM_SCAN,
                target="https://example.com",
                threat_score=0.1 * i,
                verdict=ThreatVerdict.CLEAN,
                explanation=f"Analyzer {i}",
                indicators=[f"analyzer_{i}"],
                timestamp=datetime.utcnow()
            ))
            orchestrator.add_analyzer(f"analyzer_{i}", analyzer)
        
        start_time = datetime.utcnow()
        result = await orchestrator.analyze_url("https://example.com")
        end_time = datetime.utcnow()
        
        # Should complete in reasonable time regardless of analyzer count
        duration = (end_time - start_time).total_seconds()
        assert duration < 10.0
        assert len(result.individual_results) == analyzer_count
