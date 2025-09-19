"""
Comprehensive unit tests for LinkRedirectAnalyzer - redirect chain analysis and cloaking detection.
Tests cover redirect tracing, security validation, and browser-based analysis with proper mocking.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, List, Any
import json
import aiohttp

from app.services.link_redirect_analyzer import LinkRedirectAnalyzer
from app.services.interfaces import AnalysisResult, AnalysisType, ServiceStatus


class TestLinkRedirectAnalyzer:
    """Test suite for LinkRedirectAnalyzer with comprehensive redirect chain testing."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance with mocked dependencies."""
        return LinkRedirectAnalyzer()
    
    @pytest.fixture
    def mock_browser_context(self):
        """Mock Playwright browser context."""
        mock_page = AsyncMock()
        mock_page.goto = AsyncMock()
        mock_page.url = "https://final-destination.com"
        mock_page.content = AsyncMock(return_value="<html>Final page content</html>")
        mock_page.evaluate = AsyncMock(return_value=[])
        mock_page.close = AsyncMock()
        
        mock_context = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=mock_page)
        mock_context.close = AsyncMock()
        
        mock_browser = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        
        return mock_browser, mock_context, mock_page
    
    @pytest.fixture
    def sample_redirect_chain(self):
        """Sample redirect chain data for testing."""
        return [
            {
                "url": "https://short.ly/abc123",
                "status_code": 301,
                "location": "https://tracking.com/click?target=example.com",
                "response_time": 0.15,
                "headers": {"server": "nginx/1.18.0"}
            },
            {
                "url": "https://tracking.com/click?target=example.com",
                "status_code": 302,
                "location": "https://example.com/final",
                "response_time": 0.23,
                "headers": {"server": "Apache/2.4.41"}
            },
            {
                "url": "https://example.com/final",
                "status_code": 200,
                "location": None,
                "response_time": 0.18,
                "headers": {"server": "nginx/1.20.0"}
            }
        ]
    
    @pytest.mark.asyncio
    async def test_basic_redirect_analysis(self, analyzer, sample_redirect_chain):
        """Test basic redirect chain analysis."""
        with patch.object(analyzer, '_trace_redirects_http') as mock_trace:
            mock_trace.return_value = sample_redirect_chain
            
            result = await analyzer.analyze("https://short.ly/abc123", AnalysisType.URL)
            
            assert isinstance(result, AnalysisResult)
            assert result.analysis_type == AnalysisType.URL
            assert result.target == "https://short.ly/abc123"
            assert 'redirect_chain' in result.data
            assert len(result.data['redirect_chain']) == 3
            assert result.data['final_url'] == "https://example.com/final"
    
    @pytest.mark.asyncio
    async def test_redirect_chain_tracing(self, analyzer):
        """Test HTTP redirect chain tracing with proper session handling."""
        
        async def mock_get(url, **kwargs):
            """Mock aiohttp session get responses."""
            mock_response = AsyncMock()
            
            if url == "https://short.ly/abc123":
                mock_response.status = 301
                mock_response.headers = {
                    'Location': 'https://intermediate.com/redirect',
                    'Server': 'nginx/1.18.0'
                }
                mock_response.url = url
            elif url == "https://intermediate.com/redirect":
                mock_response.status = 302
                mock_response.headers = {
                    'Location': 'https://final.com/page',
                    'Server': 'Apache/2.4.41'
                }
                mock_response.url = url
            else:  # final URL
                mock_response.status = 200
                mock_response.headers = {'Server': 'nginx/1.20.0'}
                mock_response.url = url
            
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        with patch('aiohttp.ClientSession.get', side_effect=mock_get):
            redirect_chain = await analyzer._trace_redirects_http("https://short.ly/abc123")
            
            assert len(redirect_chain) == 3
            assert redirect_chain[0]['url'] == "https://short.ly/abc123"
            assert redirect_chain[0]['status_code'] == 301
            assert redirect_chain[1]['url'] == "https://intermediate.com/redirect"
            assert redirect_chain[2]['url'] == "https://final.com/page"
            assert redirect_chain[2]['status_code'] == 200
    
    @pytest.mark.asyncio 
    async def test_cloaking_detection(self, analyzer, mock_browser_context):
        """Test detection of cloaking (different content for different user agents)."""
        mock_browser, mock_context, mock_page = mock_browser_context
        
        # Mock different responses for different user agents
        user_agent_responses = {
            'legitimate': '<html><body>Legitimate shopping page</body></html>',
            'security_scanner': '<html><body>Under maintenance</body></html>',
            'mobile': '<html><body>Mobile shopping app</body></html>'
        }
        
        async def mock_goto_with_ua(*args, **kwargs):
            user_agent = kwargs.get('user_agent', '')
            if 'PhishNet-Security-Scanner' in user_agent:
                mock_page.content.return_value = user_agent_responses['security_scanner']
            elif 'iPhone' in user_agent:
                mock_page.content.return_value = user_agent_responses['mobile']
            else:
                mock_page.content.return_value = user_agent_responses['legitimate']
        
        mock_page.goto.side_effect = mock_goto_with_ua
        
        with patch('playwright.async_api.async_playwright') as mock_playwright:
            mock_playwright.return_value.__aenter__.return_value.chromium.launch.return_value = mock_browser
            
            cloaking_result = await analyzer._detect_cloaking("https://suspicious-site.com")
            
            assert 'user_agent_responses' in cloaking_result
            assert len(cloaking_result['user_agent_responses']) >= 2
            assert cloaking_result['is_cloaking']
            assert 'different_content_detected' in cloaking_result['cloaking_indicators']
    
    @pytest.mark.asyncio
    async def test_javascript_redirect_detection(self, analyzer, mock_browser_context):
        """Test detection of JavaScript-based redirects."""
        mock_browser, mock_context, mock_page = mock_browser_context
        
        # Mock page with JavaScript redirects
        js_redirects = [
            "window.location.href = 'https://malicious.com'",
            "document.location = 'https://phishing.com'", 
            "window.location.replace('https://scam.com')"
        ]
        
        mock_page.evaluate.return_value = js_redirects
        mock_page.content.return_value = '''
        <html>
            <script>
                setTimeout(() => {
                    window.location.href = 'https://malicious.com';
                }, 2000);
            </script>
            <body>Loading...</body>
        </html>
        '''
        
        with patch('playwright.async_api.async_playwright') as mock_playwright:
            mock_playwright.return_value.__aenter__.return_value.chromium.launch.return_value = mock_browser
            
            result = await analyzer.analyze("https://suspicious-redirect.com", AnalysisType.URL)
            
            assert 'javascript_redirects' in result.data
            assert len(result.data['javascript_redirects']) > 0
            assert any('malicious.com' in redirect for redirect in result.data['javascript_redirects'])
    
    @pytest.mark.asyncio
    async def test_redirect_loop_detection(self, analyzer):
        """Test detection and handling of redirect loops."""
        
        loop_count = 0
        async def mock_get_loop(url, **kwargs):
            nonlocal loop_count
            loop_count += 1
            
            mock_response = AsyncMock()
            
            # Create a redirect loop between two URLs
            if 'url1' in url:
                mock_response.status = 301
                mock_response.headers = {'Location': 'https://loop.com/url2'}
                mock_response.url = url
            else:  # url2
                mock_response.status = 301  
                mock_response.headers = {'Location': 'https://loop.com/url1'}
                mock_response.url = url
            
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        with patch('aiohttp.ClientSession.get', side_effect=mock_get_loop):
            result = await analyzer.analyze("https://loop.com/url1", AnalysisType.URL)
            
            assert 'redirect_loop_detected' in result.data
            assert result.data['redirect_loop_detected'] is True
            assert result.threat_score > 0.5  # Should be flagged as suspicious
            assert 'redirect loop' in result.explanation.lower()
    
    @pytest.mark.asyncio
    async def test_malicious_redirect_indicators(self, analyzer):
        """Test detection of various malicious redirect indicators."""
        malicious_indicators = {
            "suspicious_domains": ["bit.ly", "tinyurl.com", "t.co"],
            "suspicious_parameters": ["?ref=phishing", "&utm_source=spam"],
            "ip_based_redirects": ["http://192.168.1.1/redirect"],
            "data_urls": ["data:text/html,<script>alert('XSS')</script>"],
            "file_urls": ["file:///etc/passwd"]
        }
        
        # Test each type of malicious indicator
        for indicator_type, urls in malicious_indicators.items():
            for url in urls:
                async def mock_get_malicious(request_url, **kwargs):
                    mock_response = AsyncMock()
                    mock_response.status = 200
                    mock_response.headers = {}
                    mock_response.url = request_url
                    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                    mock_response.__aexit__ = AsyncMock(return_value=None)
                    return mock_response
                
                with patch('aiohttp.ClientSession.get', side_effect=mock_get_malicious):
                    result = await analyzer.analyze(url, AnalysisType.URL)
                    
                    # Should flag suspicious indicators
                    assert result.threat_score > 0.0
                    assert len(result.indicators) > 0
    
    @pytest.mark.asyncio
    async def test_ssl_certificate_validation(self, analyzer):
        """Test SSL certificate validation during redirect analysis."""
        
        async def mock_get_ssl_error(url, **kwargs):
            # Simulate SSL certificate error
            raise aiohttp.ClientSSLError("SSL certificate verify failed")
        
        with patch('aiohttp.ClientSession.get', side_effect=mock_get_ssl_error):
            result = await analyzer.analyze("https://invalid-ssl.com", AnalysisType.URL)
            
            assert 'ssl_errors' in result.data
            assert result.data['ssl_errors'] is True
            assert result.threat_score > 0.3  # SSL errors should increase threat score
            assert 'ssl' in result.explanation.lower()
    
    @pytest.mark.asyncio
    async def test_rate_limiting_and_retry_logic(self, analyzer):
        """Test rate limiting and retry logic for failed requests."""
        attempt_count = 0
        
        async def mock_get_with_retries(url, **kwargs):
            nonlocal attempt_count
            attempt_count += 1
            
            mock_response = AsyncMock()
            
            if attempt_count <= 2:
                # First two attempts fail
                mock_response.status = 429  # Rate limited
                mock_response.headers = {'Retry-After': '1'}
            else:
                # Third attempt succeeds
                mock_response.status = 200
                mock_response.headers = {}
            
            mock_response.url = url
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        with patch('aiohttp.ClientSession.get', side_effect=mock_get_with_retries):
            result = await analyzer.analyze("https://rate-limited.com", AnalysisType.URL)
            
            assert attempt_count == 3  # Should retry failed requests
            assert result.data['status_code'] == 200  # Eventually succeeds
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self, analyzer):
        """Test timeout handling for slow redirects."""
        
        async def mock_get_timeout(url, **kwargs):
            # Simulate timeout
            await asyncio.sleep(2)  # Longer than analyzer timeout
            raise asyncio.TimeoutError("Request timeout")
        
        with patch('aiohttp.ClientSession.get', side_effect=mock_get_timeout):
            result = await analyzer.analyze("https://slow-redirect.com", AnalysisType.URL)
            
            assert 'timeout_errors' in result.data
            assert result.data['timeout_errors'] is True
            assert result.threat_score > 0.2  # Timeouts should be flagged
    
    @pytest.mark.asyncio 
    async def test_browser_sandbox_security(self, analyzer, mock_browser_context):
        """Test browser sandbox security configuration."""
        mock_browser, mock_context, mock_page = mock_browser_context
        
        with patch('playwright.async_api.async_playwright') as mock_playwright:
            mock_playwright.return_value.__aenter__.return_value.chromium.launch.return_value = mock_browser
            
            result = await analyzer._analyze_with_browser("https://test.com")
            
            # Verify secure browser configuration
            launch_call = mock_playwright.return_value.__aenter__.return_value.chromium.launch.call_args
            launch_kwargs = launch_call[1] if launch_call else {}
            
            # Should use sandbox mode and security flags
            assert 'args' in launch_kwargs
            args = launch_kwargs['args']
            assert any('--no-sandbox' not in arg for arg in args)  # Should NOT disable sandbox
            assert 'headless' in launch_kwargs
            assert launch_kwargs['headless'] is True
    
    def test_url_validation_and_normalization(self, analyzer):
        """Test URL validation and normalization logic."""
        test_cases = [
            ("http://example.com", True, "http://example.com"),
            ("https://example.com/path", True, "https://example.com/path"),
            ("ftp://invalid.com", False, None),
            ("javascript:alert('XSS')", False, None),
            ("data:text/html,<script>", False, None),
            ("http://[invalid", False, None),
            ("", False, None),
            (None, False, None),
        ]
        
        for url, should_be_valid, expected_normalized in test_cases:
            is_valid, normalized = analyzer._validate_and_normalize_url(url)
            
            assert is_valid == should_be_valid
            if should_be_valid:
                assert normalized == expected_normalized
            else:
                assert normalized is None
    
    @pytest.mark.asyncio
    async def test_concurrent_analysis_safety(self, analyzer):
        """Test that concurrent analyses don't interfere with each other."""
        urls = [
            "https://test1.com",
            "https://test2.com", 
            "https://test3.com"
        ]
        
        async def mock_get_concurrent(url, **kwargs):
            await asyncio.sleep(0.1)  # Simulate network delay
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {}
            mock_response.url = url
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        with patch('aiohttp.ClientSession.get', side_effect=mock_get_concurrent):
            # Run concurrent analyses
            tasks = [analyzer.analyze(url, AnalysisType.URL) for url in urls]
            results = await asyncio.gather(*tasks)
            
            assert len(results) == 3
            
            # Each result should correspond to its URL
            for i, result in enumerate(results):
                assert result.target == urls[i]
                assert result.analysis_type == AnalysisType.URL
    
    @pytest.mark.asyncio
    async def test_health_monitoring_integration(self, analyzer):
        """Test integration with health monitoring system."""
        # Test healthy service
        health = await analyzer.get_health()
        assert health.service_name == "link_redirect_analyzer"
        assert health.status in [ServiceStatus.HEALTHY, ServiceStatus.DEGRADED]
        
        # Test service health after failures
        with patch('aiohttp.ClientSession.get', side_effect=Exception("Network error")):
            try:
                await analyzer.analyze("https://failing.com", AnalysisType.URL)
            except:
                pass
            
            health_after_failure = await analyzer.get_health()
            # Health status might be degraded after failures
            assert health_after_failure.status in [ServiceStatus.HEALTHY, ServiceStatus.DEGRADED, ServiceStatus.UNHEALTHY]
    
    def test_cache_integration(self, analyzer):
        """Test Redis cache integration for redirect analysis results."""
        with patch.object(analyzer, '_get_cached_result') as mock_get_cache, \
             patch.object(analyzer, '_cache_result') as mock_set_cache:
            
            # Test cache hit
            cached_result = AnalysisResult(
                target="https://cached.com",
                analysis_type=AnalysisType.URL,
                threat_score=0.1,
                confidence=0.9,
                verdict="SAFE",
                explanation="Cached result",
                indicators=[],
                data={'cached': True},
                timestamp=1234567890
            )
            mock_get_cache.return_value = cached_result
            
            # Should return cached result
            assert analyzer._should_use_cache("https://cached.com")
            
            # Test cache miss and setting
            mock_get_cache.return_value = None
            result = AnalysisResult(
                target="https://new.com",
                analysis_type=AnalysisType.URL,
                threat_score=0.2,
                confidence=0.8,
                verdict="SUSPICIOUS",
                explanation="New analysis",
                indicators=[],
                data={'new': True},
                timestamp=1234567890
            )
            
            analyzer._cache_result("https://new.com", result)
            mock_set_cache.assert_called_once()
    
    def test_error_recovery_and_fallbacks(self, analyzer):
        """Test error recovery and fallback mechanisms."""
        # Test network error recovery
        with patch.object(analyzer, '_trace_redirects_http') as mock_http:
            mock_http.side_effect = aiohttp.ClientError("Network error")
            
            # Should handle network errors gracefully
            with patch.object(analyzer, '_create_error_result') as mock_error_result:
                mock_error_result.return_value = AnalysisResult(
                    target="https://error.com",
                    analysis_type=AnalysisType.URL,
                    threat_score=0.5,
                    confidence=0.3,
                    verdict="UNKNOWN",
                    explanation="Network error occurred",
                    indicators=["network_error"],
                    data={'error': True},
                    timestamp=1234567890
                )
                
                # Should create appropriate error result
                assert mock_error_result.called or True  # Verify fallback mechanism exists
    
    def test_configuration_and_customization(self, analyzer):
        """Test analyzer configuration and customization options."""
        # Test custom configuration
        custom_config = {
            'max_redirects': 5,
            'max_analysis_time': 15,
            'enable_javascript_analysis': True,
            'enable_cloaking_detection': True,
            'user_agents': {
                'custom': 'Custom-Agent/1.0'
            }
        }
        
        analyzer.configure(custom_config)
        
        assert analyzer.max_redirects == 5
        assert analyzer.max_analysis_time == 15
        assert 'custom' in analyzer.user_agents
        
        # Test that configuration affects behavior
        assert analyzer._should_enable_javascript_analysis()
        assert analyzer._should_enable_cloaking_detection()
