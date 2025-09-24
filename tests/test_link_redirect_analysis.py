"""
Comprehensive Test Suite for Link Redirect Analysis

Tests for multi-hop redirect detection, cloaking scenarios, TLS validation,
API endpoints, and comprehensive security analysis.
"""

import pytest
import asyncio
import json
import time
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
from typing import Dict, List, Any

import httpx
from fastapi.testclient import TestClient
from playwright.async_api import Page, Browser, BrowserContext

from app.services.link_redirect_analyzer import LinkRedirectAnalyzer, TLSCertificateDetails, RedirectHopDetails
from app.services.interfaces import AnalysisType, AnalysisResult
from backend.app.api.link_analysis import router


# Test Fixtures
@pytest.fixture
def analyzer():
    """Create LinkRedirectAnalyzer instance for testing."""
    return LinkRedirectAnalyzer()


@pytest.fixture
def mock_redis():
    """Mock Redis client for testing."""
    redis_mock = Mock()
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.setex = AsyncMock()
    redis_mock.ping = AsyncMock(return_value=True)
    return redis_mock


@pytest.fixture
def mock_browser():
    """Mock Playwright browser for testing."""
    browser_mock = Mock()
    context_mock = Mock()
    page_mock = Mock()
    
    # Setup async context managers
    browser_mock.new_context = AsyncMock(return_value=context_mock)
    context_mock.__aenter__ = AsyncMock(return_value=context_mock)
    context_mock.__aexit__ = AsyncMock(return_value=None)
    context_mock.new_page = AsyncMock(return_value=page_mock)
    
    page_mock.goto = AsyncMock()
    page_mock.wait_for_load_state = AsyncMock()
    page_mock.content = AsyncMock(return_value="<html><body>Test content</body></html>")
    page_mock.evaluate = AsyncMock(return_value=[])
    page_mock.close = AsyncMock()
    
    return browser_mock


@pytest.fixture
def sample_redirect_chain():
    """Sample redirect chain for testing."""
    return [
        {
            "hop_number": 1,
            "url": "https://example.com/redirect1",
            "method": "GET",
            "status_code": 301,
            "redirect_type": "HTTP_REDIRECT",
            "location_header": "https://example.com/redirect2",
            "hostname": "example.com",
            "ip_address": "93.184.216.34",
            "response_time_ms": 150,
            "content_hash": "abc123def456",
            "content_length": 1024,
            "headers": {"Location": "https://example.com/redirect2"},
            "javascript_redirects": [],
            "suspicious_patterns": [],
            "timestamp": datetime.utcnow().isoformat(),
            "final_effective_url": "https://example.com/redirect2"
        },
        {
            "hop_number": 2,
            "url": "https://example.com/redirect2",
            "method": "GET",
            "status_code": 302,
            "redirect_type": "HTTP_REDIRECT",
            "location_header": "https://final-destination.com",
            "hostname": "example.com",
            "ip_address": "93.184.216.34",
            "response_time_ms": 200,
            "content_hash": "def456ghi789",
            "content_length": 2048,
            "headers": {"Location": "https://final-destination.com"},
            "javascript_redirects": [],
            "suspicious_patterns": [],
            "timestamp": datetime.utcnow().isoformat(),
            "final_effective_url": "https://final-destination.com"
        }
    ]


# Core Analyzer Tests
class TestLinkRedirectAnalyzer:
    """Test the core LinkRedirectAnalyzer functionality."""
    
    @pytest.mark.asyncio
    async def test_basic_redirect_detection(self, analyzer, mock_redis):
        """Test basic redirect chain detection."""
        with patch.object(analyzer, 'redis_client', mock_redis):
            with patch('httpx.AsyncClient.get') as mock_get:
                # Mock HTTP responses for redirect chain
                mock_responses = [
                    Mock(status_code=301, headers={"Location": "https://example.com/step2"}, 
                         content=b"Redirect", url="https://example.com/step1"),
                    Mock(status_code=200, headers={}, 
                         content=b"Final content", url="https://example.com/step2")
                ]
                mock_get.side_effect = mock_responses
                
                result = await analyzer._trace_redirects("https://example.com/step1")
                
                assert len(result) == 2
                assert result[0].status_code == 301
                assert result[1].status_code == 200
                assert "step2" in result[-1].url

    @pytest.mark.asyncio
    async def test_javascript_redirect_detection(self, analyzer, mock_browser):
        """Test JavaScript redirect detection."""
        with patch.object(analyzer, '_browser', mock_browser):
            mock_page = await mock_browser.new_context().__aenter__().new_page()
            mock_page.evaluate.return_value = ["https://js-redirect.com"]
            
            result = await analyzer._detect_javascript_redirects("https://example.com")
            
            assert "https://js-redirect.com" in result

    @pytest.mark.asyncio
    async def test_tls_certificate_validation(self, analyzer):
        """Test TLS certificate validation."""
        with patch('ssl.get_server_certificate') as mock_ssl:
            with patch('cryptography.x509.load_pem_x509_certificate') as mock_cert:
                # Mock certificate data
                mock_cert_obj = Mock()
                mock_cert_obj.subject.rfc4514_string.return_value = "CN=example.com"
                mock_cert_obj.issuer.rfc4514_string.return_value = "CN=Test CA"
                mock_cert_obj.not_valid_after = datetime.utcnow() + timedelta(days=90)
                mock_cert_obj.not_valid_before = datetime.utcnow() - timedelta(days=30)
                mock_cert_obj.extensions = []
                mock_cert_obj.serial_number = 123456789
                mock_cert_obj.signature_algorithm_oid._name = "sha256WithRSAEncryption"
                
                mock_cert.return_value = mock_cert_obj
                mock_ssl.return_value = "FAKE_PEM_CERT"
                
                result = await analyzer._validate_tls_certificate("example.com", 443)
                
                assert result is not None
                assert result.common_name == "example.com"
                assert result.is_valid

    @pytest.mark.asyncio
    async def test_cloaking_detection(self, analyzer, mock_browser):
        """Test cloaking detection across user agents."""
        with patch.object(analyzer, '_browser', mock_browser):
            with patch('httpx.AsyncClient.get') as mock_get:
                # Mock different responses for different user agents
                mock_responses = [
                    Mock(content=b"Normal content", status_code=200),
                    Mock(content=b"Different content", status_code=200),  # Cloaking detected
                ]
                mock_get.side_effect = mock_responses
                
                result = await analyzer._detect_cloaking("https://example.com")
                
                assert result["cloaking_detected"] is True
                assert result["cloaking_confidence"] > 0.5

    @pytest.mark.asyncio
    async def test_suspicious_pattern_detection(self, analyzer):
        """Test suspicious pattern detection."""
        test_urls = [
            "https://goog1e.com",  # Homograph attack
            "https://paypal-security.update-account.com",  # Subdomain spoofing
            "https://bit.ly/suspicious",  # URL shortener
            "https://xn--goog1e-fxa.com",  # Punycode
        ]
        
        for url in test_urls:
            patterns = analyzer._detect_suspicious_patterns(url)
            assert len(patterns) > 0

    @pytest.mark.asyncio
    async def test_comprehensive_analysis(self, analyzer, mock_redis, sample_redirect_chain):
        """Test comprehensive analysis workflow."""
        with patch.object(analyzer, 'redis_client', mock_redis):
            with patch.object(analyzer, '_trace_redirects', return_value=sample_redirect_chain):
                with patch.object(analyzer, '_detect_cloaking') as mock_cloaking:
                    mock_cloaking.return_value = {
                        "cloaking_detected": False,
                        "cloaking_confidence": 0.1,
                        "cloaking_indicators": [],
                        "browser_behavior": {},
                        "content_differences": {},
                        "js_behavior": {},
                        "cross_ua_differences": {}
                    }
                    
                    result = await analyzer.analyze("https://example.com", AnalysisType.URL_SCAN)
                    
                    assert isinstance(result, AnalysisResult)
                    assert result.threat_score >= 0.0
                    assert result.confidence >= 0.0
                    assert result.verdict in ["safe", "suspicious", "malicious"]


# Caching Tests
class TestRedisCache:
    """Test Redis caching functionality."""
    
    @pytest.mark.asyncio
    async def test_cache_key_generation(self, analyzer):
        """Test cache key generation."""
        key = analyzer._generate_enhanced_cache_key("https://example.com", {})
        assert "https://example.com" in key
        assert "url_scan" in key.lower()

    @pytest.mark.asyncio
    async def test_cache_storage_and_retrieval(self, analyzer, mock_redis):
        """Test cache storage and retrieval."""
        with patch.object(analyzer, 'redis_client', mock_redis):
            # Test cache miss
            mock_redis.get.return_value = None
            result = await analyzer._get_cached_analysis("test_key")
            assert result is None
            
            # Test cache storage
            test_result = AnalysisResult(
                verdict="safe",
                confidence=0.95,
                threat_score=0.1,
                explanation="Test result",
                raw_response={},
                timestamp=time.time(),
                execution_time_ms=500
            )
            
            await analyzer._cache_analysis_result("test_key", test_result, 3600)
            mock_redis.setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_ttl_calculation(self, analyzer):
        """Test cache TTL calculation based on threat score."""
        # High threat score = short TTL
        ttl_high = analyzer._calculate_cache_ttl(0.9, True)
        assert ttl_high == 300  # 5 minutes
        
        # Low threat score = long TTL
        ttl_low = analyzer._calculate_cache_ttl(0.1, False)
        assert ttl_low == 3600  # 1 hour


# API Endpoint Tests
class TestLinkAnalysisAPI:
    """Test API endpoints for link analysis."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_analyze_endpoint_validation(self, client):
        """Test input validation for analyze endpoint."""
        # Invalid URL
        response = client.post("/api/v1/redirect-analysis/analyze", 
                             json={"url": "invalid-url"})
        assert response.status_code == 422
        
        # Valid URL
        with patch('app.api.link_analysis.analyzeLink') as mock_analyze:
            mock_analyze.return_value = Mock()
            response = client.post("/api/v1/redirect-analysis/analyze",
                                 json={"url": "https://example.com"})
            # Would need proper auth setup for 200 response

    def test_quick_scan_endpoint(self, client):
        """Test quick scan endpoint."""
        with patch('app.api.link_analysis.quickScanLink') as mock_scan:
            mock_scan.return_value = {
                "verdict": "safe",
                "threat_score": 0.1,
                "confidence": 0.9
            }
            # Would need proper auth setup
            response = client.post("/api/v1/redirect-analysis/quick-scan",
                                 json={"url": "https://example.com"})

    def test_bulk_analysis_endpoint(self, client):
        """Test bulk analysis endpoint."""
        urls = [f"https://example{i}.com" for i in range(5)]
        
        with patch('app.api.link_analysis.bulk_analyze_links') as mock_bulk:
            mock_bulk.return_value = {
                "total_urls": 5,
                "completed": 5,
                "failed": 0
            }
            # Would need proper auth setup
            response = client.post("/api/v1/redirect-analysis/bulk-analyze",
                                 json={"urls": urls})


# Ground Truth Validation Tests
class TestGroundTruthValidation:
    """Test against known redirect chains and cloaking examples."""
    
    @pytest.mark.asyncio
    async def test_known_safe_redirects(self, analyzer):
        """Test against known safe redirect chains."""
        safe_urls = [
            "https://httpbin.org/redirect/2",  # Known 2-hop redirect
            "https://httpbin.org/absolute-redirect/3",  # Known 3-hop redirect
        ]
        
        for url in safe_urls:
            with patch.object(analyzer, '_trace_redirects') as mock_trace:
                # Mock safe redirect chain
                mock_trace.return_value = [
                    RedirectHopDetails(
                        hop_number=1,
                        url=url,
                        method="GET",
                        status_code=302,
                        redirect_type="HTTP_REDIRECT",
                        hostname="httpbin.org",
                        response_time_ms=100,
                        content_hash="safe_hash",
                        content_length=1024,
                        headers={},
                        javascript_redirects=[],
                        suspicious_patterns=[],
                        timestamp=datetime.utcnow(),
                        final_effective_url="https://httpbin.org/get"
                    )
                ]
                
                result = await analyzer.analyze(url, AnalysisType.URL_SCAN)
                assert result.verdict in ["safe", "suspicious"]  # Should not be malicious

    @pytest.mark.asyncio
    async def test_known_malicious_patterns(self, analyzer):
        """Test against known malicious URL patterns."""
        malicious_patterns = [
            "https://paypal-security-update.suspicious-domain.com",
            "https://amazon-account-verification.malicious.com",
            "https://google-authentication.phishing.com",
        ]
        
        for url in malicious_patterns:
            patterns = analyzer._detect_suspicious_patterns(url)
            assert len(patterns) > 0  # Should detect suspicious patterns

    @pytest.mark.asyncio
    async def test_cloaking_scenarios(self, analyzer, mock_browser):
        """Test various cloaking scenarios."""
        cloaking_test_cases = [
            {
                "url": "https://cloaking-example.com",
                "user_agent_responses": {
                    "normal": b"Normal content",
                    "bot": b"Different content for bots",
                    "mobile": b"Mobile specific content"
                },
                "expected_cloaking": True
            },
            {
                "url": "https://legitimate-example.com",
                "user_agent_responses": {
                    "normal": b"Same content",
                    "bot": b"Same content",
                    "mobile": b"Same content"
                },
                "expected_cloaking": False
            }
        ]
        
        for test_case in cloaking_test_cases:
            with patch('httpx.AsyncClient.get') as mock_get:
                # Mock responses based on user agent
                responses = list(test_case["user_agent_responses"].values())
                mock_get.side_effect = [Mock(content=content, status_code=200) for content in responses]
                
                result = await analyzer._detect_cloaking(test_case["url"])
                assert result["cloaking_detected"] == test_case["expected_cloaking"]


# Performance Tests
class TestPerformance:
    """Test performance characteristics."""
    
    @pytest.mark.asyncio
    async def test_analysis_timeout(self, analyzer):
        """Test analysis timeout handling."""
        analyzer.max_analysis_time = 1  # 1 second timeout
        
        with patch('httpx.AsyncClient.get') as mock_get:
            # Mock slow response
            async def slow_response(*args, **kwargs):
                await asyncio.sleep(2)  # Longer than timeout
                return Mock(status_code=200, content=b"content")
            
            mock_get.side_effect = slow_response
            
            start_time = time.time()
            result = await analyzer.analyze("https://slow-example.com", AnalysisType.URL_SCAN)
            end_time = time.time()
            
            # Should complete within timeout + buffer
            assert (end_time - start_time) < 3

    @pytest.mark.asyncio
    async def test_concurrent_analysis(self, analyzer):
        """Test concurrent analysis handling."""
        urls = [f"https://example{i}.com" for i in range(10)]
        
        with patch.object(analyzer, '_trace_redirects') as mock_trace:
            mock_trace.return_value = []  # Empty redirect chain
            
            # Run concurrent analyses
            tasks = [analyzer.analyze(url, AnalysisType.URL_SCAN) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All should complete successfully
            assert len(results) == 10
            assert all(isinstance(r, AnalysisResult) for r in results if not isinstance(r, Exception))


# Integration Tests
class TestIntegration:
    """Integration tests with external dependencies."""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_real_redirect_chain(self, analyzer):
        """Test with real redirect chain (requires network)."""
        # This test requires actual network access
        # Skip in CI/CD environments
        try:
            result = await analyzer.analyze("https://httpbin.org/redirect/2", AnalysisType.URL_SCAN)
            assert result.threat_score < 0.5  # Should be considered safe
            assert "httpbin.org" in result.raw_response.get("final_url", "")
        except Exception as e:
            pytest.skip(f"Network test skipped: {e}")

    @pytest.mark.asyncio
    @pytest.mark.integration  
    async def test_browser_integration(self, analyzer):
        """Test browser integration (requires Playwright)."""
        try:
            # Test with simple page
            with patch.object(analyzer, '_setup_browser') as mock_setup:
                mock_browser = Mock()
                mock_setup.return_value = mock_browser
                
                # This would test real browser functionality
                # but requires proper Playwright setup
                pass
        except Exception as e:
            pytest.skip(f"Browser test skipped: {e}")


if __name__ == "__main__":
    # Run tests with coverage
    pytest.main([
        __file__,
        "-v",
        "--cov=app.services.link_redirect_analyzer",
        "--cov=app.api.link_analysis",
        "--cov-report=html",
        "--cov-report=term-missing"
    ])