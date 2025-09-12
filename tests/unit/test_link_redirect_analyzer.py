"""
Unit tests for LinkRedirectAnalyzer.
Tests URL following, redirect detection, and threat analysis.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
import aiohttp
from typing import List, Dict, Any

from app.analyzers.link_redirect_analyzer import LinkRedirectAnalyzer
from app.services.interfaces import AnalysisResult, AnalysisType


@pytest.fixture
def redirect_analyzer():
    """Create LinkRedirectAnalyzer instance for testing."""
    return LinkRedirectAnalyzer()


@pytest.fixture
def mock_http_responses():
    """Mock HTTP responses for testing."""
    return {
        "direct": {
            "status": 200,
            "headers": {"content-type": "text/html"},
            "text": "<html><title>Direct Site</title></html>",
            "url": "https://direct.example.com"
        },
        "redirect_302": {
            "status": 302,
            "headers": {"location": "https://target.example.com"},
            "text": "",
            "url": "https://redirect.example.com"
        },
        "redirect_301": {
            "status": 301,
            "headers": {"location": "https://permanent.example.com"},
            "text": "",
            "url": "https://redirect.example.com"
        },
        "suspicious": {
            "status": 200,
            "headers": {"content-type": "text/html"},
            "text": "<html><title>Click here to claim your prize!</title></html>",
            "url": "https://suspicious.example.com"
        }
    }


class TestLinkRedirectAnalyzer:
    """Test suite for LinkRedirectAnalyzer."""
    
    def test_analyzer_initialization(self, redirect_analyzer):
        """Test analyzer initializes correctly."""
        assert redirect_analyzer is not None
        assert hasattr(redirect_analyzer, 'analyze_url')
        assert hasattr(redirect_analyzer, 'follow_redirects')
        assert redirect_analyzer.max_redirects > 0
    
    @pytest.mark.asyncio
    async def test_direct_url_analysis(self, redirect_analyzer, mock_http_responses):
        """Test analysis of direct URL (no redirects)."""
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = Mock()
            mock_response.status = mock_http_responses["direct"]["status"]
            mock_response.headers = mock_http_responses["direct"]["headers"]
            mock_response.text.return_value = mock_http_responses["direct"]["text"]
            mock_response.url = mock_http_responses["direct"]["url"]
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await redirect_analyzer.analyze_url("https://direct.example.com")
            
            assert result is not None
            assert result.analysis_type == AnalysisType.URL_SCAN
            assert result.target == "https://direct.example.com"
            assert result.redirect_count == 0
            assert result.final_url == "https://direct.example.com"
    
    @pytest.mark.asyncio
    async def test_single_redirect_analysis(self, redirect_analyzer, mock_http_responses):
        """Test analysis of URL with single redirect."""
        responses = [
            # First request - redirect
            Mock(status=302, headers={"location": "https://target.example.com"}, url="https://redirect.example.com"),
            # Second request - final destination
            Mock(status=200, headers={"content-type": "text/html"}, url="https://target.example.com")
        ]
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.side_effect = responses
            
            result = await redirect_analyzer.analyze_url("https://redirect.example.com")
            
            assert result.redirect_count == 1
            assert result.final_url == "https://target.example.com"
            assert "redirect" in result.redirect_chain
    
    @pytest.mark.asyncio
    async def test_multiple_redirects_analysis(self, redirect_analyzer):
        """Test analysis of URL with multiple redirects."""
        redirect_chain = [
            "https://start.example.com",
            "https://middle1.example.com",
            "https://middle2.example.com",
            "https://final.example.com"
        ]
        
        responses = [
            Mock(status=302, headers={"location": redirect_chain[1]}, url=redirect_chain[0]),
            Mock(status=302, headers={"location": redirect_chain[2]}, url=redirect_chain[1]),
            Mock(status=302, headers={"location": redirect_chain[3]}, url=redirect_chain[2]),
            Mock(status=200, headers={"content-type": "text/html"}, url=redirect_chain[3])
        ]
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.side_effect = responses
            
            result = await redirect_analyzer.analyze_url(redirect_chain[0])
            
            assert result.redirect_count == 3
            assert result.final_url == redirect_chain[3]
            assert len(result.redirect_chain) == 4
    
    @pytest.mark.asyncio
    async def test_excessive_redirects_protection(self, redirect_analyzer):
        """Test protection against excessive redirects."""
        # Mock infinite redirect loop
        def create_redirect_response(url):
            return Mock(
                status=302,
                headers={"location": f"https://redirect{hash(url) % 100}.example.com"},
                url=url
            )
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.side_effect = lambda: create_redirect_response("https://loop.example.com")
            
            result = await redirect_analyzer.analyze_url("https://loop.example.com")
            
            # Should stop at max_redirects
            assert result.redirect_count >= redirect_analyzer.max_redirects
            assert "excessive redirects" in result.explanation.lower()
            assert result.threat_score > 0.5  # Should be flagged as suspicious
    
    @pytest.mark.asyncio
    async def test_redirect_loop_detection(self, redirect_analyzer):
        """Test detection of redirect loops."""
        loop_url = "https://loop.example.com"
        
        def create_loop_response(url):
            return Mock(
                status=302,
                headers={"location": loop_url},  # Always redirect to same URL
                url=url
            )
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.side_effect = create_loop_response
            
            result = await redirect_analyzer.analyze_url(loop_url)
            
            assert "loop" in result.explanation.lower() or "cycle" in result.explanation.lower()
            assert result.threat_score > 0.6
            assert "redirect_loop" in result.indicators
    
    @pytest.mark.asyncio
    async def test_suspicious_domain_detection(self, redirect_analyzer):
        """Test detection of suspicious domains in redirect chain."""
        suspicious_domains = [
            "bit.ly",
            "tinyurl.com",
            "goo.gl",
            "t.co",
            "ow.ly",
            "short.link"
        ]
        
        for domain in suspicious_domains:
            responses = [
                Mock(status=302, headers={"location": f"https://{domain}/abc123"}, url="https://start.com"),
                Mock(status=200, headers={"content-type": "text/html"}, url=f"https://{domain}/abc123")
            ]
            
            with patch('aiohttp.ClientSession.get') as mock_get:
                mock_get.return_value.__aenter__.side_effect = responses
                
                result = await redirect_analyzer.analyze_url("https://start.com")
                
                # Should detect URL shortener
                assert result.threat_score > 0.0
                assert any("shortener" in indicator.lower() for indicator in result.indicators)
    
    @pytest.mark.asyncio
    async def test_domain_reputation_checking(self, redirect_analyzer):
        """Test domain reputation checking."""
        malicious_domains = [
            "malware.example.com",
            "phishing.example.com",
            "suspicious.example.com"
        ]
        
        for domain in malicious_domains:
            with patch.object(redirect_analyzer, '_check_domain_reputation') as mock_reputation:
                mock_reputation.return_value = {"reputation": "malicious", "score": 0.9}
                
                responses = [
                    Mock(status=200, headers={"content-type": "text/html"}, url=f"https://{domain}")
                ]
                
                with patch('aiohttp.ClientSession.get') as mock_get:
                    mock_get.return_value.__aenter__.side_effect = responses
                    
                    result = await redirect_analyzer.analyze_url(f"https://{domain}")
                    
                    assert result.threat_score > 0.8
                    assert "malicious" in result.verdict
    
    @pytest.mark.asyncio
    async def test_url_parameter_analysis(self, redirect_analyzer):
        """Test analysis of suspicious URL parameters."""
        suspicious_urls = [
            "https://example.com?utm_source=email&utm_campaign=phishing",
            "https://example.com?ref=spam&track=123",
            "https://example.com?redirect=javascript:alert(1)",
            "https://example.com?callback=<script>alert(1)</script>"
        ]
        
        for url in suspicious_urls:
            responses = [
                Mock(status=200, headers={"content-type": "text/html"}, url=url)
            ]
            
            with patch('aiohttp.ClientSession.get') as mock_get:
                mock_get.return_value.__aenter__.side_effect = responses
                
                result = await redirect_analyzer.analyze_url(url)
                
                # Should detect suspicious parameters
                assert result.threat_score > 0.0
                assert any("parameter" in indicator.lower() for indicator in result.indicators)
    
    @pytest.mark.asyncio
    async def test_https_downgrade_detection(self, redirect_analyzer):
        """Test detection of HTTPS to HTTP downgrade."""
        responses = [
            Mock(status=302, headers={"location": "http://insecure.example.com"}, url="https://secure.example.com"),
            Mock(status=200, headers={"content-type": "text/html"}, url="http://insecure.example.com")
        ]
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.side_effect = responses
            
            result = await redirect_analyzer.analyze_url("https://secure.example.com")
            
            assert result.threat_score > 0.4
            assert "https_downgrade" in result.indicators or "insecure_redirect" in result.indicators
            assert "downgrade" in result.explanation.lower()
    
    @pytest.mark.asyncio
    async def test_content_analysis(self, redirect_analyzer):
        """Test basic content analysis of final destination."""
        suspicious_content = """
        <html>
        <title>Congratulations! You've won $1,000,000!</title>
        <body>
        <h1>URGENT: Claim your prize now!</h1>
        <p>Click here immediately to claim your million dollar prize!</p>
        <form action="https://collect-info.example.com">
            <input type="text" name="ssn" placeholder="Social Security Number">
            <input type="text" name="credit_card" placeholder="Credit Card Number">
        </form>
        </body>
        </html>
        """
        
        responses = [
            Mock(status=200, headers={"content-type": "text/html"}, text=AsyncMock(return_value=suspicious_content), url="https://suspicious.com")
        ]
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.side_effect = responses
            
            result = await redirect_analyzer.analyze_url("https://suspicious.com")
            
            assert result.threat_score > 0.5
            assert any("suspicious_content" in indicator for indicator in result.indicators)
    
    @pytest.mark.asyncio
    async def test_javascript_redirect_detection(self, redirect_analyzer):
        """Test detection of JavaScript-based redirects."""
        js_redirect_content = """
        <html>
        <script>
        window.location.href = "https://malicious.example.com";
        </script>
        <meta http-equiv="refresh" content="0;url=https://another-malicious.com">
        </html>
        """
        
        responses = [
            Mock(status=200, headers={"content-type": "text/html"}, text=AsyncMock(return_value=js_redirect_content), url="https://js-redirect.com")
        ]
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.side_effect = responses
            
            result = await redirect_analyzer.analyze_url("https://js-redirect.com")
            
            assert result.threat_score > 0.4
            assert "javascript_redirect" in result.indicators or "meta_refresh" in result.indicators
    
    @pytest.mark.asyncio
    async def test_error_handling(self, redirect_analyzer):
        """Test error handling for various HTTP errors."""
        error_scenarios = [
            aiohttp.ClientTimeout(),
            aiohttp.ClientError("Connection failed"),
            aiohttp.ClientConnectorError(Mock(), Mock()),
            Exception("Unexpected error")
        ]
        
        for error in error_scenarios:
            with patch('aiohttp.ClientSession.get', side_effect=error):
                result = await redirect_analyzer.analyze_url("https://error.example.com")
                
                assert result is not None
                assert result.error is not None
                assert result.threat_score >= 0.0  # Should handle gracefully
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self, redirect_analyzer):
        """Test handling of request timeouts."""
        with patch('aiohttp.ClientSession.get', side_effect=aiohttp.ClientTimeout()):
            result = await redirect_analyzer.analyze_url("https://timeout.example.com")
            
            assert result.error is not None
            assert "timeout" in result.error.lower()
            assert result.threat_score == 0.0  # Neutral score for timeout
    
    @pytest.mark.asyncio
    async def test_large_redirect_chain_performance(self, redirect_analyzer):
        """Test performance with large redirect chains."""
        import time
        
        # Create chain of 20 redirects
        chain_length = 20
        responses = []
        for i in range(chain_length - 1):
            responses.append(Mock(
                status=302,
                headers={"location": f"https://redirect{i+1}.example.com"},
                url=f"https://redirect{i}.example.com"
            ))
        # Final response
        responses.append(Mock(
            status=200,
            headers={"content-type": "text/html"},
            url=f"https://redirect{chain_length-1}.example.com"
        ))
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.side_effect = responses
            
            start_time = time.time()
            result = await redirect_analyzer.analyze_url("https://redirect0.example.com")
            end_time = time.time()
            
            # Should complete within reasonable time
            assert (end_time - start_time) < 10.0
            assert result.redirect_count == min(chain_length - 1, redirect_analyzer.max_redirects)
    
    def test_url_validation(self, redirect_analyzer):
        """Test URL validation logic."""
        valid_urls = [
            "https://example.com",
            "http://example.com",
            "https://subdomain.example.com",
            "https://example.com/path?param=value",
            "https://example.com:8080/path"
        ]
        
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "",
            None
        ]
        
        for url in valid_urls:
            assert redirect_analyzer._is_valid_url(url), f"Should validate: {url}"
        
        for url in invalid_urls:
            assert not redirect_analyzer._is_valid_url(url), f"Should not validate: {url}"
    
    def test_threat_scoring_logic(self, redirect_analyzer):
        """Test threat scoring logic."""
        # Test different risk factors
        risk_factors = {
            "excessive_redirects": 0.6,
            "redirect_loop": 0.8,
            "https_downgrade": 0.4,
            "suspicious_domain": 0.5,
            "url_shortener": 0.3,
            "suspicious_parameters": 0.2
        }
        
        for factor, expected_min_score in risk_factors.items():
            score = redirect_analyzer._calculate_threat_score([factor])
            assert score >= expected_min_score, f"Factor {factor} should have minimum score {expected_min_score}"
    
    def test_configuration_options(self, redirect_analyzer):
        """Test configuration options."""
        # Test max redirects configuration
        assert redirect_analyzer.max_redirects > 0
        assert redirect_analyzer.max_redirects < 50  # Should be reasonable limit
        
        # Test timeout configuration
        assert redirect_analyzer.request_timeout > 0
        assert redirect_analyzer.request_timeout < 60  # Should be reasonable timeout
    
    @pytest.mark.asyncio
    async def test_concurrent_analysis(self, redirect_analyzer):
        """Test concurrent analysis of multiple URLs."""
        import asyncio
        
        urls = [
            "https://example1.com",
            "https://example2.com",
            "https://example3.com"
        ]
        
        responses = [
            Mock(status=200, headers={"content-type": "text/html"}, url=url)
            for url in urls
        ]
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.side_effect = responses
            
            # Analyze URLs concurrently
            tasks = [redirect_analyzer.analyze_url(url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All should complete successfully
            for result in results:
                assert not isinstance(result, Exception)
                assert result is not None
    
    @pytest.mark.parametrize("redirect_count", [0, 1, 3, 5, 10])
    def test_redirect_count_scoring(self, redirect_analyzer, redirect_count):
        """Test scoring based on redirect count."""
        score = redirect_analyzer._score_redirect_count(redirect_count)
        
        # Score should increase with redirect count
        if redirect_count == 0:
            assert score == 0.0
        elif redirect_count <= 2:
            assert 0.0 <= score <= 0.3
        elif redirect_count <= 5:
            assert 0.3 <= score <= 0.6
        else:
            assert score >= 0.6
    
    def test_domain_categorization(self, redirect_analyzer):
        """Test domain categorization logic."""
        domain_categories = {
            "bit.ly": "url_shortener",
            "tinyurl.com": "url_shortener",
            "malware.example.com": "suspicious",
            "phishing.example.com": "suspicious",
            "google.com": "trusted",
            "microsoft.com": "trusted"
        }
        
        for domain, expected_category in domain_categories.items():
            category = redirect_analyzer._categorize_domain(domain)
            assert category == expected_category, f"Domain {domain} should be categorized as {expected_category}"
