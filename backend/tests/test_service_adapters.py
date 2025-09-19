"""
Comprehensive tests for service adapters and analyzer interface conformance.
Tests unified outputs, error handling, and integration with factory.
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any

from app.services.interfaces import (
    IAnalyzer, AnalysisResult, AnalysisType, ServiceHealth, ServiceStatus,
    VirusTotalResult, AbuseIPDBResult, GeminiResult,
    ServiceUnavailableError, InvalidTargetError, AnalysisError, RateLimitError
)
from app.services.virustotal import VirusTotalClient
from app.services.abuseipdb import AbuseIPDBClient
from app.services.gemini import GeminiClient
from app.services.analyzer_factory import (
    AnalyzerFactory, FactoryConfig, AnalyzerMode, AnalyzerConfig,
    MockAnalyzer, get_analyzer_factory, analyze_with_best_available
)


class TestAnalyzerInterface:
    """Test analyzer interface conformance for all service adapters."""
    
    @pytest.fixture
    def mock_redis(self):
        """Mock Redis client for testing."""
        with patch('app.core.redis_client.redis_client') as mock:
            mock.get.return_value = None
            mock.setex.return_value = True
            yield mock
    
    @pytest.mark.asyncio
    async def test_virustotal_interface_conformance(self, mock_redis):
        """Test VirusTotal client conforms to IAnalyzer interface."""
        client = VirusTotalClient(api_key="test_key")
        
        # Test interface methods exist
        assert hasattr(client, 'analyze')
        assert hasattr(client, 'health_check')
        assert hasattr(client, 'is_available')
        assert hasattr(client, 'service_name')
        
        # Test service name
        assert client.service_name == "virustotal"
        
        # Test health property
        assert isinstance(client._health, ServiceHealth)
        
        # Test availability check
        assert isinstance(client.is_available, bool)
    
    @pytest.mark.asyncio
    async def test_abuseipdb_interface_conformance(self, mock_redis):
        """Test AbuseIPDB client conforms to IAnalyzer interface."""
        client = AbuseIPDBClient(api_key="test_key")
        
        # Test interface methods exist
        assert hasattr(client, 'analyze')
        assert hasattr(client, 'health_check')
        assert hasattr(client, 'is_available')
        assert hasattr(client, 'service_name')
        
        # Test service name
        assert client.service_name == "abuseipdb"
        
        # Test health property
        assert isinstance(client._health, ServiceHealth)
    
    @pytest.mark.asyncio
    async def test_gemini_interface_conformance(self, mock_redis):
        """Test Gemini client conforms to IAnalyzer interface."""
        client = GeminiClient(api_key="test_key")
        
        # Test interface methods exist
        assert hasattr(client, 'analyze')
        assert hasattr(client, 'health_check')
        assert hasattr(client, 'is_available')
        assert hasattr(client, 'service_name')
        
        # Test service name
        assert client.service_name == "gemini"
        
        # Test health property
        assert isinstance(client._health, ServiceHealth)


class TestAnalysisResultNormalization:
    """Test that all analyzers return normalized AnalysisResult objects."""
    
    @pytest.fixture
    def mock_http_response(self):
        """Mock HTTP response for testing."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "response_code": 1,
            "positives": 2,
            "total": 10,
            "scans": {
                "Engine1": {"detected": True, "result": "Malware"},
                "Engine2": {"detected": True, "result": "Phishing"}
            }
        }
        return mock_response
    
    @pytest.mark.asyncio
    async def test_virustotal_normalized_output(self, mock_redis):
        """Test VirusTotal returns properly normalized AnalysisResult."""
        client = VirusTotalClient(api_key="test_key")
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_context = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_context
            
            # Mock URL scan submission
            submit_response = AsyncMock()
            submit_response.status = 200
            submit_response.json.return_value = {"scan_id": "test_id"}
            
            # Mock URL report retrieval
            report_response = AsyncMock()
            report_response.status = 200
            report_response.json.return_value = {
                "response_code": 1,
                "positives": 3,
                "total": 15,
                "scan_date": "2025-09-11 10:00:00",
                "scans": {
                    "Engine1": {"detected": True, "result": "Malware"},
                    "Engine2": {"detected": True, "result": "Phishing"},
                    "Engine3": {"detected": True, "result": "Suspicious"}
                }
            }
            
            mock_context.post.return_value.__aenter__.return_value = submit_response
            mock_context.get.return_value.__aenter__.return_value = report_response
            
            # Test URL analysis
            result = await client.analyze("https://test.com", AnalysisType.URL_SCAN)
            
            # Verify normalized structure
            assert isinstance(result, AnalysisResult)
            assert result.service_name == "virustotal"
            assert result.analysis_type == AnalysisType.URL_SCAN
            assert result.target == "https://test.com"
            assert 0.0 <= result.threat_score <= 1.0
            assert 0.0 <= result.confidence <= 1.0
            assert isinstance(result.raw_response, dict)
            assert isinstance(result.timestamp, float)
            assert isinstance(result.execution_time_ms, int)
            assert result.verdict in ["malicious", "clean", "suspicious"]
            assert isinstance(result.explanation, str)
            assert isinstance(result.indicators, list)
    
    @pytest.mark.asyncio
    async def test_abuseipdb_normalized_output(self, mock_redis):
        """Test AbuseIPDB returns properly normalized AnalysisResult."""
        client = AbuseIPDBClient(api_key="test_key")
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_context = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_context
            
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {
                "data": {
                    "abuseConfidencePercentage": 75,
                    "totalReports": 10,
                    "countryCode": "US",
                    "usageType": "hosting",
                    "lastReportedAt": "2025-09-11T10:00:00Z"
                }
            }
            
            mock_context.get.return_value.__aenter__.return_value = mock_response
            
            # Test IP analysis
            result = await client.analyze("192.168.1.1", AnalysisType.IP_REPUTATION)
            
            # Should return error for private IP, but still normalized
            assert isinstance(result, AnalysisResult)
            assert result.service_name == "abuseipdb"
            assert result.analysis_type == AnalysisType.IP_REPUTATION
            assert 0.0 <= result.threat_score <= 1.0
            assert 0.0 <= result.confidence <= 1.0
    
    @pytest.mark.asyncio
    async def test_gemini_normalized_output(self, mock_redis):
        """Test Gemini returns properly normalized AnalysisResult."""
        client = GeminiClient(api_key="test_key")
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_context = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_context
            
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {
                "candidates": [{
                    "content": {
                        "parts": [{
                            "text": '{"threat_score": 0.8, "confidence": 0.9, "verdict": "phishing", "explanation": "Test analysis", "indicators": ["urgent language", "suspicious link"], "techniques": ["social engineering"]}'
                        }]
                    }
                }]
            }
            
            mock_context.post.return_value.__aenter__.return_value = mock_response
            
            # Test text analysis
            result = await client.analyze("Urgent! Click here to verify your account!", AnalysisType.TEXT_ANALYSIS)
            
            # Verify normalized structure
            assert isinstance(result, AnalysisResult)
            assert result.service_name == "gemini"
            assert result.analysis_type == AnalysisType.TEXT_ANALYSIS
            assert 0.0 <= result.threat_score <= 1.0
            assert 0.0 <= result.confidence <= 1.0
            assert isinstance(result.raw_response, dict)
            assert isinstance(result.explanation, str)
            assert isinstance(result.indicators, list)


class TestErrorHandling:
    """Test error handling and circuit breaker behavior."""
    
    @pytest.mark.asyncio
    async def test_rate_limiting_handling(self, mock_redis):
        """Test rate limit error handling."""
        client = VirusTotalClient(api_key="test_key")
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_context = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_context
            
            # Mock rate limit response
            rate_limit_response = AsyncMock()
            rate_limit_response.status = 429
            mock_context.post.return_value.__aenter__.return_value = rate_limit_response
            
            # Should handle rate limit gracefully
            result = await client.analyze("https://test.com", AnalysisType.URL_SCAN)
            
            # Should return error result, not raise exception
            assert isinstance(result, AnalysisResult)
            assert result.error is not None
            assert "rate limit" in result.error.lower() or "unavailable" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_behavior(self, mock_redis):
        """Test circuit breaker opens after consecutive failures."""
        client = AbuseIPDBClient(api_key="test_key")
        
        # Simulate multiple failures
        for i in range(4):  # More than threshold (3)
            client._update_health_failure()
        
        # Service should not be available due to circuit breaker
        assert not client.is_available
        assert client._health.status == ServiceStatus.CIRCUIT_OPEN
        assert client._health.circuit_breaker_until is not None
    
    @pytest.mark.asyncio
    async def test_invalid_target_validation(self, mock_redis):
        """Test target validation for different analysis types."""
        
        # Test VirusTotal URL validation
        vt_client = VirusTotalClient(api_key="test_key")
        result = await vt_client.analyze("invalid-url", AnalysisType.URL_SCAN)
        assert result.error is not None
        
        # Test AbuseIPDB IP validation
        abuse_client = AbuseIPDBClient(api_key="test_key")
        result = await abuse_client.analyze("invalid-ip", AnalysisType.IP_REPUTATION)
        assert result.error is not None
        
        # Test Gemini text validation
        gemini_client = GeminiClient(api_key="test_key")
        result = await gemini_client.analyze("", AnalysisType.TEXT_ANALYSIS)
        assert result.error is not None


class TestAnalyzerFactory:
    """Test analyzer factory functionality."""
    
    @pytest.mark.asyncio
    async def test_factory_initialization_modes(self):
        """Test factory initialization in different modes."""
        
        # Test production mode
        prod_config = FactoryConfig(mode=AnalyzerMode.PRODUCTION)
        prod_factory = AnalyzerFactory(prod_config)
        await prod_factory.initialize()
        
        analyzers = prod_factory.get_analyzers()
        assert isinstance(analyzers, dict)
        
        # Test mock mode
        mock_config = FactoryConfig(mode=AnalyzerMode.MOCK)
        mock_factory = AnalyzerFactory(mock_config)
        await mock_factory.initialize()
        
        mock_analyzers = mock_factory.get_analyzers()
        assert len(mock_analyzers) >= 3  # Should have VT, AbuseIPDB, Gemini mocks
        
        for analyzer in mock_analyzers.values():
            assert isinstance(analyzer, MockAnalyzer)
    
    @pytest.mark.asyncio
    async def test_analyzer_selection_by_type(self):
        """Test getting analyzers for specific analysis types."""
        config = FactoryConfig(mode=AnalyzerMode.MOCK)
        factory = AnalyzerFactory(config)
        await factory.initialize()
        
        # Test URL scan analyzers
        url_analyzers = factory.get_analyzers_for_type(AnalysisType.URL_SCAN)
        assert any(a.service_name == "virustotal" for a in url_analyzers)
        
        # Test IP reputation analyzers
        ip_analyzers = factory.get_analyzers_for_type(AnalysisType.IP_REPUTATION)
        analyzer_names = [a.service_name for a in ip_analyzers]
        assert "abuseipdb" in analyzer_names
        
        # Test text analysis analyzers
        text_analyzers = factory.get_analyzers_for_type(AnalysisType.TEXT_ANALYSIS)
        assert any(a.service_name == "gemini" for a in text_analyzers)
    
    @pytest.mark.asyncio
    async def test_factory_health_monitoring(self):
        """Test factory health monitoring capabilities."""
        config = FactoryConfig(mode=AnalyzerMode.MOCK)
        factory = AnalyzerFactory(config)
        await factory.initialize()
        
        # Get health status
        health_status = await factory.get_service_health()
        
        assert isinstance(health_status, dict)
        assert len(health_status) > 0
        
        for service_name, health in health_status.items():
            assert isinstance(health, ServiceHealth)
    
    @pytest.mark.asyncio
    async def test_parallel_analysis_execution(self):
        """Test parallel execution of multiple analyzers."""
        # Use convenience function with mocks
        with patch('app.services.analyzer_factory.get_analyzer_factory') as mock_factory_getter:
            mock_factory = AnalyzerFactory(FactoryConfig(mode=AnalyzerMode.MOCK))
            await mock_factory.initialize()
            mock_factory_getter.return_value = mock_factory
            
            # Test parallel analysis
            results = await analyze_with_best_available(
                "https://test.com", 
                AnalysisType.URL_SCAN
            )
            
            assert isinstance(results, dict)
            assert len(results) > 0
            
            # All results should be AnalysisResult objects
            for service_name, result in results.items():
                assert isinstance(result, AnalysisResult)
                assert result.service_name == service_name


class TestMockAnalyzer:
    """Test mock analyzer functionality."""
    
    @pytest.mark.asyncio
    async def test_mock_analyzer_interface(self):
        """Test mock analyzer conforms to interface."""
        mock_analyzer = MockAnalyzer("test_service", mock_score=0.5)
        
        # Test analysis
        result = await mock_analyzer.analyze("test_target", AnalysisType.URL_SCAN)
        
        assert isinstance(result, AnalysisResult)
        assert result.service_name == "test_service"
        assert result.threat_score == 0.5
        assert result.confidence == 0.8
        assert result.verdict == "mock"
        
        # Test health check
        health = await mock_analyzer.health_check()
        assert isinstance(health, ServiceHealth)
        assert health.status == ServiceStatus.AVAILABLE


class TestCacheIntegration:
    """Test caching behavior across analyzers."""
    
    @pytest.fixture
    def mock_redis_with_cache(self):
        """Mock Redis with cache simulation."""
        cache_store = {}
        
        async def mock_get(key):
            return cache_store.get(key)
        
        async def mock_setex(key, ttl, value):
            cache_store[key] = value
            return True
        
        with patch('app.core.redis_client.redis_client') as mock:
            mock.get.side_effect = mock_get
            mock.setex.side_effect = mock_setex
            yield mock, cache_store
    
    @pytest.mark.asyncio
    async def test_cache_behavior(self, mock_redis_with_cache):
        """Test that analyzers properly use caching."""
        mock_redis, cache_store = mock_redis_with_cache
        
        client = VirusTotalClient(api_key="test_key")
        
        with patch('aiohttp.ClientSession') as mock_session:
            # Setup mock HTTP responses
            mock_context = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_context
            
            submit_response = AsyncMock()
            submit_response.status = 200
            submit_response.json.return_value = {"scan_id": "test"}
            
            report_response = AsyncMock()
            report_response.status = 200
            report_response.json.return_value = {
                "response_code": 1,
                "positives": 1,
                "total": 10,
                "scans": {"Engine1": {"detected": True}}
            }
            
            mock_context.post.return_value.__aenter__.return_value = submit_response
            mock_context.get.return_value.__aenter__.return_value = report_response
            
            # First analysis should cache result
            result1 = await client.analyze("https://test.com", AnalysisType.URL_SCAN)
            
            # Verify cache was used (setex called)
            assert len(cache_store) > 0
            
            # Second analysis should hit cache
            # (In real implementation, this would return cached result)
            result2 = await client.analyze("https://test.com", AnalysisType.URL_SCAN)
            
            assert isinstance(result1, AnalysisResult)
            assert isinstance(result2, AnalysisResult)


# Integration test configurations
@pytest.fixture
def integration_test_config():
    """Configuration for integration tests."""
    return FactoryConfig(
        mode=AnalyzerMode.TESTING,
        parallel_execution=True,
        fallback_enabled=True
    )


class TestIntegrationScenarios:
    """Integration tests for real-world scenarios."""
    
    @pytest.mark.asyncio
    async def test_multi_service_analysis_workflow(self, integration_test_config):
        """Test complete analysis workflow with multiple services."""
        factory = AnalyzerFactory(integration_test_config)
        await factory.initialize()
        
        # Test different analysis types
        test_cases = [
            ("https://example.com", AnalysisType.URL_SCAN),
            ("8.8.8.8", AnalysisType.IP_REPUTATION),
            ("Click here to verify your account!", AnalysisType.TEXT_ANALYSIS)
        ]
        
        for target, analysis_type in test_cases:
            analyzers = factory.get_analyzers_for_type(analysis_type)
            
            if analyzers:  # Only test if analyzers are available
                results = {}
                for analyzer in analyzers:
                    try:
                        result = await analyzer.analyze(target, analysis_type)
                        results[analyzer.service_name] = result
                    except Exception as e:
                        # In production, errors should be handled gracefully
                        assert isinstance(e, (ServiceUnavailableError, AnalysisError))
                
                # Verify results structure
                for service_name, result in results.items():
                    assert isinstance(result, AnalysisResult)
                    assert result.service_name == service_name
                    assert 0.0 <= result.threat_score <= 1.0
                    assert 0.0 <= result.confidence <= 1.0


if __name__ == "__main__":
    # Run specific test for development
    pytest.main([__file__ + "::TestAnalyzerInterface::test_virustotal_interface_conformance", "-v"])
