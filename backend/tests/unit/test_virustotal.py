"""
Unit tests for VirusTotal API client.
Tests API integration, error handling, caching, and circuit breaker functionality.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
import aiohttp
import time
from typing import Dict, Any

from app.services.virustotal import VirusTotalClient
from app.services.interfaces import AnalysisType, ServiceStatus, ServiceUnavailableError
from app.resilience.circuit_breaker import CircuitBreakerOpenError


@pytest.fixture
def mock_api_key():
    """Mock API key for testing."""
    return "test_api_key_12345"


@pytest.fixture
def vt_client(mock_api_key):
    """Create VirusTotal client for testing."""
    return VirusTotalClient(api_key=mock_api_key)


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    redis_mock = AsyncMock()
    redis_mock.get.return_value = None
    redis_mock.set.return_value = True
    redis_mock.delete.return_value = True
    return redis_mock


class TestVirusTotalClient:
    """Test suite for VirusTotal API client."""
    
    def test_client_initialization(self, vt_client, mock_api_key):
        """Test client initializes correctly."""
        assert vt_client.api_key == mock_api_key
        assert vt_client.service_name == "virustotal"
        assert vt_client.is_available is True
    
    def test_client_initialization_without_api_key(self):
        """Test client initialization without API key."""
        client = VirusTotalClient(api_key=None)
        assert client._health.status == ServiceStatus.UNAVAILABLE
        assert client.is_available is False
    
    @pytest.mark.asyncio
    async def test_url_analysis_success(self, vt_client):
        """Test successful URL analysis."""
        mock_response = {
            "response_code": 1,
            "positives": 2,
            "total": 65,
            "scans": {
                "Engine1": {"detected": True, "result": "Malware"},
                "Engine2": {"detected": True, "result": "Phishing"}
            },
            "scan_date": "2023-01-01 12:00:00",
            "scan_id": "test_scan_id"
        }
        
        with patch.object(vt_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response
            
            result = await vt_client.analyze("https://malicious.example.com", AnalysisType.URL_SCAN)
            
            assert result is not None
            assert result.service_name == "virustotal"
            assert result.analysis_type == AnalysisType.URL_SCAN
            assert result.target == "https://malicious.example.com"
            assert result.threat_score > 0  # Should detect threat
            assert result.verdict == "malicious"
            assert "Engine1" in result.indicators
    
    @pytest.mark.asyncio
    async def test_url_analysis_clean(self, vt_client):
        """Test URL analysis with clean result."""
        mock_response = {
            "response_code": 1,
            "positives": 0,
            "total": 65,
            "scans": {},
            "scan_date": "2023-01-01 12:00:00",
            "scan_id": "test_scan_id"
        }
        
        with patch.object(vt_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response
            
            result = await vt_client.analyze("https://clean.example.com", AnalysisType.URL_SCAN)
            
            assert result.threat_score == 0.0
            assert result.verdict == "clean"
            assert len(result.indicators) == 0
    
    @pytest.mark.asyncio
    async def test_file_hash_analysis(self, vt_client):
        """Test file hash analysis."""
        test_hash = "e3b0c44298fc1c149afbf4c8996fb924"
        mock_response = {
            "response_code": 1,
            "positives": 5,
            "total": 70,
            "scans": {
                "Antivirus1": {"detected": True, "result": "Trojan.Win32.Test"},
                "Antivirus2": {"detected": True, "result": "Malware.Generic"}
            },
            "scan_date": "2023-01-01 12:00:00"
        }
        
        with patch.object(vt_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response
            
            result = await vt_client.analyze(test_hash, AnalysisType.FILE_HASH)
            
            assert result.analysis_type == AnalysisType.FILE_HASH
            assert result.target == test_hash
            assert result.threat_score > 0
            assert "Trojan" in str(result.indicators)
    
    @pytest.mark.asyncio
    async def test_ip_reputation_analysis(self, vt_client):
        """Test IP reputation analysis."""
        test_ip = "1.2.3.4"
        mock_response = {
            "response_code": 1,
            "positives": 1,
            "total": 25,
            "scans": {
                "ThreatIntel": {"detected": True, "result": "Suspicious"}
            }
        }
        
        with patch.object(vt_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response
            
            result = await vt_client.analyze(test_ip, AnalysisType.IP_REPUTATION)
            
            assert result.analysis_type == AnalysisType.IP_REPUTATION
            assert result.target == test_ip
    
    @pytest.mark.asyncio
    async def test_caching_functionality(self, vt_client, mock_redis):
        """Test result caching."""
        test_url = "https://example.com"
        mock_response = {
            "response_code": 1,
            "positives": 0,
            "total": 65,
            "scans": {},
            "scan_date": "2023-01-01 12:00:00"
        }
        
        # Mock cache miss then hit
        with patch('app.core.redis_client.get_redis_connection', return_value=mock_redis):
            with patch.object(vt_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
                mock_request.return_value = mock_response
                
                # First call - cache miss
                result1 = await vt_client.analyze(test_url, AnalysisType.URL_SCAN)
                
                # Second call - should use cache
                mock_redis.get.return_value = result1.json() if hasattr(result1, 'json') else None
                result2 = await vt_client.analyze(test_url, AnalysisType.URL_SCAN)
                
                # API should only be called once
                assert mock_request.call_count <= 1
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, vt_client):
        """Test rate limiting functionality."""
        start_time = time.time()
        
        # Mock multiple rapid requests
        mock_response = {"response_code": 1, "positives": 0, "total": 65, "scans": {}}
        
        with patch.object(vt_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response
            
            # Make multiple requests rapidly
            tasks = []
            for i in range(3):
                tasks.append(vt_client.analyze(f"https://test{i}.com", AnalysisType.URL_SCAN))
            
            results = await asyncio.gather(*tasks)
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Should take time due to rate limiting
            assert duration >= 2.0  # At least 2 seconds for 3 requests with rate limiting
            assert all(result is not None for result in results)
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_fallback(self, vt_client):
        """Test circuit breaker fallback behavior."""
        with patch.object(vt_client, '_make_api_request', side_effect=Exception("API Error")):
            # Should return fallback result instead of raising exception
            result = await vt_client.analyze("https://test.com", AnalysisType.URL_SCAN)
            
            assert result is not None
            assert result.raw_response.get("fallback") is True
            assert result.verdict == "suspicious"  # Conservative fallback
    
    @pytest.mark.asyncio
    async def test_service_unavailable_fallback(self, vt_client):
        """Test fallback when service is unavailable."""
        # Mark service as unavailable
        vt_client._health.status = ServiceStatus.UNAVAILABLE
        
        result = await vt_client.analyze("https://test.com", AnalysisType.URL_SCAN)
        
        assert result.raw_response.get("fallback") is True
        assert "service_unavailable" in result.indicators
    
    def test_target_validation(self, vt_client):
        """Test target validation for different analysis types."""
        # Valid targets
        valid_cases = [
            ("https://example.com", AnalysisType.URL_SCAN),
            ("http://test.com", AnalysisType.URL_SCAN),
            ("e3b0c44298fc1c149afbf4c8996fb924", AnalysisType.FILE_HASH),
            ("192.168.1.1", AnalysisType.IP_REPUTATION),
            ("8.8.8.8", AnalysisType.IP_REPUTATION)
        ]
        
        for target, analysis_type in valid_cases:
            # Should not raise exception
            vt_client._validate_target(target, analysis_type)
        
        # Invalid targets
        invalid_cases = [
            ("not-a-url", AnalysisType.URL_SCAN),
            ("invalid-hash", AnalysisType.FILE_HASH),
            ("not-an-ip", AnalysisType.IP_REPUTATION),
            ("", AnalysisType.URL_SCAN)
        ]
        
        for target, analysis_type in invalid_cases:
            with pytest.raises(Exception):
                vt_client._validate_target(target, analysis_type)
    
    def test_response_parsing(self, vt_client):
        """Test response parsing logic."""
        # Test various response formats
        responses = [
            {
                "response_code": 1,
                "positives": 3,
                "total": 65,
                "scans": {
                    "Engine1": {"detected": True, "result": "Malware"},
                    "Engine2": {"detected": False, "result": None},
                    "Engine3": {"detected": True, "result": "Phishing"}
                }
            },
            {
                "response_code": 0,
                "verbose_msg": "Resource does not exist in the dataset"
            },
            {
                "response_code": -2,
                "verbose_msg": "Scan request successfully queued"
            }
        ]
        
        for response in responses:
            result = vt_client._parse_response(response, AnalysisType.URL_SCAN)
            assert result is not None
            assert hasattr(result, 'vt_score')
            assert hasattr(result, 'positives')
            assert hasattr(result, 'total_engines')
    
    def test_health_monitoring(self, vt_client):
        """Test health monitoring functionality."""
        # Initial health should be healthy with API key
        assert vt_client.get_health().status == ServiceStatus.HEALTHY
        
        # Simulate failures
        vt_client._update_health_failure()
        vt_client._update_health_failure()
        vt_client._update_health_failure()
        
        # Health should degrade after multiple failures
        health = vt_client.get_health()
        assert health.status in [ServiceStatus.DEGRADED, ServiceStatus.UNAVAILABLE]
    
    @pytest.mark.asyncio
    async def test_error_handling(self, vt_client):
        """Test various error conditions."""
        error_scenarios = [
            (aiohttp.ClientError("Network error"), "Network error"),
            (aiohttp.ClientTimeout(), "Timeout"),
            (Exception("Generic error"), "Generic error")
        ]
        
        for exception, description in error_scenarios:
            with patch.object(vt_client, '_make_api_request', side_effect=exception):
                result = await vt_client.analyze("https://test.com", AnalysisType.URL_SCAN)
                
                # Should return fallback result, not raise exception
                assert result is not None
                assert result.raw_response.get("fallback") is True
    
    def test_explanation_generation(self, vt_client):
        """Test explanation generation for results."""
        from app.services.interfaces import VirusTotalResult
        
        # Test clean result explanation
        clean_result = VirusTotalResult(
            vt_score=0.0,
            positives=0,
            total_engines=65,
            engine_hits=[],
            last_seen=None,
            scan_id="test"
        )
        
        explanation = vt_client._generate_explanation(clean_result)
        assert "clean" in explanation.lower()
        assert "no threats" in explanation.lower()
        
        # Test malicious result explanation
        malicious_result = VirusTotalResult(
            vt_score=0.8,
            positives=5,
            total_engines=65,
            engine_hits=["Engine1: Malware", "Engine2: Phishing"],
            last_seen="2023-01-01",
            scan_id="test"
        )
        
        explanation = vt_client._generate_explanation(malicious_result)
        assert "threats detected" in explanation.lower()
        assert "5" in explanation
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self, vt_client):
        """Test handling of concurrent requests."""
        import asyncio
        
        mock_response = {"response_code": 1, "positives": 0, "total": 65, "scans": {}}
        
        with patch.object(vt_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response
            
            # Create multiple concurrent requests
            tasks = [
                vt_client.analyze(f"https://test{i}.com", AnalysisType.URL_SCAN)
                for i in range(5)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All should complete successfully
            for result in results:
                assert not isinstance(result, Exception)
                assert result is not None
    
    def test_configuration_validation(self, vt_client):
        """Test configuration validation."""
        # Test rate limits
        assert vt_client.PUBLIC_API_RATE_LIMIT > 0
        assert vt_client.PREMIUM_API_RATE_LIMIT > vt_client.PUBLIC_API_RATE_LIMIT
        
        # Test URLs
        assert vt_client.BASE_URL.startswith("https://")
        assert "virustotal.com" in vt_client.BASE_URL
    
    @pytest.mark.asyncio
    async def test_metrics_recording(self, vt_client):
        """Test that metrics are recorded during analysis."""
        mock_response = {"response_code": 1, "positives": 0, "total": 65, "scans": {}}
        
        with patch('app.observability.tracing.record_external_api_failure') as mock_record:
            with patch.object(vt_client, '_make_api_request', side_effect=Exception("Test error")):
                await vt_client.analyze("https://test.com", AnalysisType.URL_SCAN)
                
                # Should record the failure
                mock_record.assert_called_once_with("virustotal", "Exception")
    
    @pytest.mark.asyncio
    async def test_tracing_integration(self, vt_client):
        """Test OpenTelemetry tracing integration."""
        mock_response = {"response_code": 1, "positives": 0, "total": 65, "scans": {}}
        
        with patch('app.observability.tracing.traced_span') as mock_span:
            with patch.object(vt_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
                mock_request.return_value = mock_response
                
                await vt_client.analyze("https://test.com", AnalysisType.URL_SCAN)
                
                # Should create traced span
                mock_span.assert_called()
    
    def test_fallback_result_creation(self, vt_client):
        """Test fallback result creation."""
        fallback_result = vt_client._create_fallback_result(
            "https://test.com",
            AnalysisType.URL_SCAN,
            error="Service unavailable"
        )
        
        assert fallback_result.service_name == "virustotal"
        assert fallback_result.target == "https://test.com"
        assert fallback_result.verdict == "suspicious"
        assert fallback_result.raw_response["fallback"] is True
        assert "service_unavailable" in fallback_result.indicators
        assert "manual_review_required" in fallback_result.indicators
    
    @pytest.mark.parametrize("analysis_type", [
        AnalysisType.URL_SCAN,
        AnalysisType.FILE_HASH,
        AnalysisType.IP_REPUTATION
    ])
    @pytest.mark.asyncio
    async def test_analysis_types_support(self, vt_client, analysis_type):
        """Test support for different analysis types."""
        # Mock appropriate targets for each type
        targets = {
            AnalysisType.URL_SCAN: "https://example.com",
            AnalysisType.FILE_HASH: "e3b0c44298fc1c149afbf4c8996fb924",
            AnalysisType.IP_REPUTATION: "8.8.8.8"
        }
        
        mock_response = {"response_code": 1, "positives": 0, "total": 65, "scans": {}}
        
        with patch.object(vt_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response
            
            result = await vt_client.analyze(targets[analysis_type], analysis_type)
            
            assert result.analysis_type == analysis_type
            assert result.target == targets[analysis_type]
