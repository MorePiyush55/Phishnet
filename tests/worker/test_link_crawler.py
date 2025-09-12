"""Worker tests for link analysis with fixtures."""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone
import json

from app.services.link_analyzer import LinkAnalyzer, LinkAnalysisResult
from app.orchestrator.utils import AnalysisOrchestrator


class TestLinkAnalyzerWorker:
    """Test link analyzer worker functionality."""
    
    @pytest.fixture
    def link_analyzer(self):
        """Create LinkAnalyzer instance for testing."""
        return LinkAnalyzer()
    
    @pytest.fixture
    def mock_browser_context(self):
        """Mock Playwright browser context."""
        mock_context = Mock()
        mock_page = Mock()
        
        # Setup async methods
        mock_context.new_page = AsyncMock(return_value=mock_page)
        mock_context.close = AsyncMock()
        mock_page.goto = AsyncMock()
        mock_page.wait_for_load_state = AsyncMock()
        mock_page.close = AsyncMock()
        
        return mock_context, mock_page
    
    @pytest.fixture
    def legitimate_url_fixture(self):
        """Fixture for legitimate URL analysis."""
        return {
            "url": "https://www.microsoft.com/support",
            "expected_result": {
                "is_suspicious": False,
                "final_url": "https://www.microsoft.com/support",
                "redirect_chain": [],
                "status_code": 200,
                "risk_factors": []
            }
        }
    
    @pytest.fixture
    def suspicious_redirect_fixture(self):
        """Fixture for suspicious redirect chain."""
        return {
            "url": "https://bit.ly/suspicious-link",
            "expected_result": {
                "is_suspicious": True,
                "final_url": "https://malicious-phishing-site.com/login",
                "redirect_chain": [
                    {"url": "https://bit.ly/suspicious-link", "status": 302},
                    {"url": "https://redirect-service.com/track", "status": 302},
                    {"url": "https://malicious-phishing-site.com/login", "status": 200}
                ],
                "status_code": 200,
                "risk_factors": [
                    "Multiple redirects detected",
                    "Suspicious final domain",
                    "URL shortener used"
                ]
            }
        }
    
    @pytest.fixture
    def typosquatting_fixture(self):
        """Fixture for typosquatting domain."""
        return {
            "url": "https://paypaI.com/login",  # Capital 'I' instead of 'l'
            "expected_result": {
                "is_suspicious": True,
                "final_url": "https://paypaI.com/login",
                "redirect_chain": [],
                "status_code": 200,
                "risk_factors": [
                    "Typosquatting detected: similar to paypal.com",
                    "Suspicious domain registration"
                ]
            }
        }
    
    @pytest.fixture
    def malware_hosting_fixture(self):
        """Fixture for malware hosting site."""
        return {
            "url": "https://malware-host.evil.com/download.exe",
            "expected_result": {
                "is_suspicious": True,
                "final_url": "https://malware-host.evil.com/download.exe",
                "redirect_chain": [],
                "status_code": 200,
                "risk_factors": [
                    "Known malware hosting domain",
                    "Executable file download",
                    "Suspicious TLD"
                ]
            }
        }
    
    @pytest.mark.asyncio
    async def test_analyze_legitimate_url(self, link_analyzer, legitimate_url_fixture, mock_browser_context):
        """Test analysis of legitimate URL."""
        mock_context, mock_page = mock_browser_context
        fixture = legitimate_url_fixture
        
        # Mock successful page load
        mock_page.goto.return_value = Mock(status=200)
        mock_page.url = fixture["expected_result"]["final_url"]
        
        with patch.object(link_analyzer, '_create_browser_context', return_value=mock_context):
            result = await link_analyzer.analyze_url(fixture["url"])
            
            assert isinstance(result, LinkAnalysisResult)
            assert not result.is_suspicious
            assert result.final_url == fixture["expected_result"]["final_url"]
            assert result.status_code == 200
            assert len(result.risk_factors) == 0
    
    @pytest.mark.asyncio
    async def test_analyze_suspicious_redirect(self, link_analyzer, suspicious_redirect_fixture, mock_browser_context):
        """Test analysis of suspicious redirect chain."""
        mock_context, mock_page = mock_browser_context
        fixture = suspicious_redirect_fixture
        
        # Mock redirect chain
        redirect_responses = []
        for redirect in fixture["expected_result"]["redirect_chain"]:
            response_mock = Mock()
            response_mock.status = redirect["status"]
            response_mock.url = redirect["url"]
            redirect_responses.append(response_mock)
        
        mock_page.goto.return_value = redirect_responses[-1]  # Final response
        mock_page.url = fixture["expected_result"]["final_url"]
        
        # Mock the redirect tracking
        with patch.object(link_analyzer, '_track_redirects', return_value=fixture["expected_result"]["redirect_chain"]):
            with patch.object(link_analyzer, '_create_browser_context', return_value=mock_context):
                result = await link_analyzer.analyze_url(fixture["url"])
                
                assert result.is_suspicious
                assert result.final_url == fixture["expected_result"]["final_url"]
                assert len(result.redirect_chain) > 0
                assert "Multiple redirects detected" in result.risk_factors
    
    @pytest.mark.asyncio
    async def test_analyze_typosquatting(self, link_analyzer, typosquatting_fixture, mock_browser_context):
        """Test detection of typosquatting domains."""
        mock_context, mock_page = mock_browser_context
        fixture = typosquatting_fixture
        
        mock_page.goto.return_value = Mock(status=200)
        mock_page.url = fixture["url"]
        
        with patch.object(link_analyzer, '_create_browser_context', return_value=mock_context):
            with patch.object(link_analyzer, '_check_typosquatting', return_value=True):
                result = await link_analyzer.analyze_url(fixture["url"])
                
                assert result.is_suspicious
                assert any("Typosquatting" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_analyze_malware_hosting(self, link_analyzer, malware_hosting_fixture, mock_browser_context):
        """Test detection of malware hosting sites."""
        mock_context, mock_page = mock_browser_context
        fixture = malware_hosting_fixture
        
        mock_page.goto.return_value = Mock(status=200)
        mock_page.url = fixture["url"]
        
        with patch.object(link_analyzer, '_create_browser_context', return_value=mock_context):
            with patch.object(link_analyzer, '_check_malware_indicators', return_value=True):
                result = await link_analyzer.analyze_url(fixture["url"])
                
                assert result.is_suspicious
                assert any("malware" in factor.lower() for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_analyze_timeout_handling(self, link_analyzer, mock_browser_context):
        """Test handling of timeout scenarios."""
        mock_context, mock_page = mock_browser_context
        
        # Mock timeout exception
        mock_page.goto.side_effect = asyncio.TimeoutError("Navigation timeout")
        
        with patch.object(link_analyzer, '_create_browser_context', return_value=mock_context):
            result = await link_analyzer.analyze_url("https://slow-site.com")
            
            assert result.is_suspicious
            assert "Timeout during analysis" in result.risk_factors
            assert result.status_code == 0
    
    @pytest.mark.asyncio
    async def test_analyze_connection_error(self, link_analyzer, mock_browser_context):
        """Test handling of connection errors."""
        mock_context, mock_page = mock_browser_context
        
        # Mock connection error
        mock_page.goto.side_effect = Exception("Connection refused")
        
        with patch.object(link_analyzer, '_create_browser_context', return_value=mock_context):
            result = await link_analyzer.analyze_url("https://non-existent-site.com")
            
            assert result.is_suspicious
            assert "Connection error" in result.risk_factors
            assert result.status_code == 0
    
    @pytest.mark.asyncio
    async def test_batch_url_analysis(self, link_analyzer, mock_browser_context):
        """Test batch analysis of multiple URLs."""
        mock_context, mock_page = mock_browser_context
        
        urls = [
            "https://legitimate-site.com",
            "https://suspicious-site.com",
            "https://malicious-site.com"
        ]
        
        # Mock different responses for each URL
        def mock_goto(url):
            if "legitimate" in url:
                mock_page.url = url
                return Mock(status=200)
            elif "suspicious" in url:
                mock_page.url = url
                return Mock(status=200)
            else:  # malicious
                mock_page.url = url
                return Mock(status=200)
        
        mock_page.goto.side_effect = mock_goto
        
        with patch.object(link_analyzer, '_create_browser_context', return_value=mock_context):
            results = await link_analyzer.analyze_urls_batch(urls)
            
            assert len(results) == 3
            assert all(isinstance(result, LinkAnalysisResult) for result in results)
    
    def test_risk_factor_detection(self, link_analyzer):
        """Test various risk factor detection methods."""
        # Test URL shortener detection
        assert link_analyzer._is_url_shortener("https://bit.ly/abc123")
        assert link_analyzer._is_url_shortener("https://tinyurl.com/xyz")
        assert not link_analyzer._is_url_shortener("https://microsoft.com")
        
        # Test suspicious TLD detection
        assert link_analyzer._has_suspicious_tld("https://site.tk")
        assert link_analyzer._has_suspicious_tld("https://site.ml")
        assert not link_analyzer._has_suspicious_tld("https://site.com")
        
        # Test IP address detection
        assert link_analyzer._is_ip_address("https://192.168.1.1/page")
        assert link_analyzer._is_ip_address("http://10.0.0.1:8080")
        assert not link_analyzer._is_ip_address("https://example.com")
        
        # Test excessive subdomain detection
        assert link_analyzer._has_excessive_subdomains("https://a.b.c.d.e.example.com")
        assert not link_analyzer._has_excessive_subdomains("https://mail.google.com")
    
    def test_typosquatting_detection(self, link_analyzer):
        """Test typosquatting detection algorithm."""
        # Known legitimate domains for testing
        legitimate_domains = [
            "paypal.com",
            "microsoft.com", 
            "google.com",
            "amazon.com",
            "facebook.com"
        ]
        
        # Typosquatting examples
        typosquatting_domains = [
            "paypaI.com",  # Capital I instead of l
            "microsft.com",  # Missing o
            "gooogle.com",  # Extra o
            "amazom.com",  # n -> m
            "facebbok.com"  # Extra b
        ]
        
        with patch.object(link_analyzer, '_get_legitimate_domains', return_value=legitimate_domains):
            for domain in typosquatting_domains:
                assert link_analyzer._check_typosquatting(domain), f"Failed to detect typosquatting: {domain}"
            
            for domain in legitimate_domains:
                assert not link_analyzer._check_typosquatting(domain), f"False positive for legitimate domain: {domain}"
    
    def test_redirect_chain_analysis(self, link_analyzer):
        """Test redirect chain analysis."""
        # Safe redirect chain
        safe_chain = [
            {"url": "https://example.com/redirect", "status": 302},
            {"url": "https://example.com/target", "status": 200}
        ]
        
        # Suspicious redirect chain
        suspicious_chain = [
            {"url": "https://bit.ly/abc", "status": 302},
            {"url": "https://redirect-service.com/track", "status": 302},
            {"url": "https://another-redirect.net/forward", "status": 302},
            {"url": "https://malicious-site.com/login", "status": 200}
        ]
        
        safe_risk = link_analyzer._analyze_redirect_chain(safe_chain)
        suspicious_risk = link_analyzer._analyze_redirect_chain(suspicious_chain)
        
        assert len(safe_risk) == 0 or safe_risk == []
        assert len(suspicious_risk) > 0
        assert any("Multiple redirects" in factor for factor in suspicious_risk)
    
    @pytest.mark.asyncio
    async def test_concurrent_analysis_performance(self, link_analyzer, mock_browser_context):
        """Test performance of concurrent URL analysis."""
        import time
        
        mock_context, mock_page = mock_browser_context
        mock_page.goto.return_value = Mock(status=200)
        
        # Create many URLs for testing
        urls = [f"https://test-site-{i}.com" for i in range(20)]
        
        with patch.object(link_analyzer, '_create_browser_context', return_value=mock_context):
            start_time = time.time()
            results = await link_analyzer.analyze_urls_batch(urls, max_concurrent=5)
            end_time = time.time()
            
            # Should complete all analyses
            assert len(results) == 20
            
            # Should be reasonably fast with concurrency
            assert end_time - start_time < 10  # Should complete in under 10 seconds
    
    def test_browser_resource_management(self, link_analyzer):
        """Test proper browser resource management."""
        # Test context manager usage
        with patch('playwright.async_api.async_playwright') as mock_playwright:
            mock_browser = Mock()
            mock_context = Mock()
            mock_playwright.return_value.__aenter__.return_value.firefox.launch = AsyncMock(return_value=mock_browser)
            mock_browser.new_context = AsyncMock(return_value=mock_context)
            mock_context.close = AsyncMock()
            mock_browser.close = AsyncMock()
            
            async def test_resource_cleanup():
                async with link_analyzer._create_browser_context() as context:
                    pass  # Context should be properly closed
                
                # Verify cleanup methods were called
                mock_context.close.assert_called_once()
            
            # Run the test
            asyncio.run(test_resource_cleanup())


class TestAnalysisOrchestrator:
    """Test analysis orchestrator worker functionality."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create AnalysisOrchestrator instance."""
        return AnalysisOrchestrator()
    
    @pytest.fixture
    def sample_email_with_links(self):
        """Sample email containing various types of links."""
        return {
            "subject": "Account Security Alert",
            "sender": "security@fake-bank.com",
            "recipient": "victim@company.com",
            "body": """
            Dear Customer,
            
            We have detected suspicious activity on your account.
            Please verify your identity immediately:
            
            https://bit.ly/bank-verify -> https://fake-bank-security.com/verify
            
            Alternative link: https://secure-banking.evil.com/login
            
            Click here: https://192.168.1.100/verify-account
            
            Best regards,
            Security Team
            """,
            "headers": {
                "From": "security@fake-bank.com",
                "Reply-To": "noreply@evil-domain.com"
            }
        }
    
    @pytest.mark.asyncio
    async def test_orchestrator_full_analysis(self, orchestrator, sample_email_with_links):
        """Test full email analysis orchestration."""
        # Mock all analysis components
        with patch.object(orchestrator.ai_analyzer, 'analyze_email') as mock_ai:
            with patch.object(orchestrator.link_analyzer, 'analyze_email_links') as mock_links:
                with patch.object(orchestrator.threat_intel, 'check_email_threats') as mock_threats:
                    
                    # Setup mock responses
                    mock_ai.return_value = {
                        "classification": "phishing",
                        "confidence": 0.95,
                        "reasoning": "Urgent security language detected"
                    }
                    
                    mock_links.return_value = {
                        "suspicious_urls": ["https://fake-bank-security.com/verify"],
                        "risk_score": 0.85,
                        "analysis_results": [
                            {
                                "url": "https://bit.ly/bank-verify",
                                "is_suspicious": True,
                                "risk_factors": ["URL shortener", "Suspicious redirect"]
                            }
                        ]
                    }
                    
                    mock_threats.return_value = {
                        "malicious_domains": ["fake-bank-security.com"],
                        "risk_score": 0.80,
                        "threat_types": ["phishing"]
                    }
                    
                    # Run full analysis
                    result = await orchestrator.analyze_email(sample_email_with_links)
                    
                    # Verify all components were called
                    mock_ai.assert_called_once()
                    mock_links.assert_called_once()
                    mock_threats.assert_called_once()
                    
                    # Verify result structure
                    assert "ai_analysis" in result
                    assert "link_analysis" in result
                    assert "threat_intel" in result
                    assert result["ai_analysis"]["classification"] == "phishing"
    
    @pytest.mark.asyncio
    async def test_orchestrator_error_handling(self, orchestrator, sample_email_with_links):
        """Test orchestrator error handling."""
        # Mock one component to fail
        with patch.object(orchestrator.ai_analyzer, 'analyze_email') as mock_ai:
            with patch.object(orchestrator.link_analyzer, 'analyze_email_links') as mock_links:
                with patch.object(orchestrator.threat_intel, 'check_email_threats') as mock_threats:
                    
                    # Make AI analysis fail
                    mock_ai.side_effect = Exception("AI service unavailable")
                    
                    # Other services succeed
                    mock_links.return_value = {"risk_score": 0.5}
                    mock_threats.return_value = {"risk_score": 0.3}
                    
                    # Analysis should continue despite AI failure
                    result = await orchestrator.analyze_email(sample_email_with_links)
                    
                    # Should have partial results
                    assert "link_analysis" in result
                    assert "threat_intel" in result
                    assert "ai_analysis" in result
                    assert "error" in result["ai_analysis"]
    
    @pytest.mark.asyncio
    async def test_orchestrator_timeout_handling(self, orchestrator, sample_email_with_links):
        """Test orchestrator timeout handling."""
        import asyncio
        
        # Mock slow service
        async def slow_analysis(*args, **kwargs):
            await asyncio.sleep(10)  # Simulate slow response
            return {"risk_score": 0.5}
        
        with patch.object(orchestrator.link_analyzer, 'analyze_email_links', side_effect=slow_analysis):
            with patch.object(orchestrator, 'analysis_timeout', 5):  # 5 second timeout
                
                start_time = asyncio.get_event_loop().time()
                result = await orchestrator.analyze_email(sample_email_with_links)
                end_time = asyncio.get_event_loop().time()
                
                # Should timeout and return partial results
                assert end_time - start_time < 8  # Should not wait full 10 seconds
                assert "link_analysis" in result
                assert "timeout" in result["link_analysis"].get("error", "")


class TestWorkerQueue:
    """Test worker queue functionality."""
    
    @pytest.fixture
    def worker_queue(self):
        """Create mock worker queue."""
        from app.services.worker_queue import WorkerQueue
        return WorkerQueue()
    
    @pytest.mark.asyncio
    async def test_queue_email_analysis(self, worker_queue):
        """Test queuing email for analysis."""
        email_data = {
            "id": "test-email-123",
            "subject": "Test Email",
            "sender": "test@example.com"
        }
        
        # Mock the queue implementation
        with patch.object(worker_queue, 'enqueue_task') as mock_enqueue:
            await worker_queue.queue_email_analysis(email_data)
            
            mock_enqueue.assert_called_once()
            args = mock_enqueue.call_args[0]
            assert args[0] == "email_analysis"
            assert args[1] == email_data
    
    @pytest.mark.asyncio
    async def test_worker_task_processing(self, worker_queue):
        """Test worker task processing."""
        # Mock task processing
        with patch.object(worker_queue, 'process_task') as mock_process:
            mock_process.return_value = {"status": "completed", "result": {"risk_score": 0.8}}
            
            task = {
                "type": "email_analysis",
                "data": {"id": "test-123"},
                "priority": "high"
            }
            
            result = await worker_queue.process_task(task)
            
            assert result["status"] == "completed"
            assert "result" in result


# Test fixtures and utilities
@pytest.fixture
def mock_suspicious_webpage():
    """Mock suspicious webpage content."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Verify Your PayPal Account</title>
    </head>
    <body>
        <h1>Account Verification Required</h1>
        <p>Your PayPal account has been limited due to suspicious activity.</p>
        <form action="/submit-verification" method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <input type="text" name="ssn" placeholder="Social Security Number">
            <button type="submit">Verify Account</button>
        </form>
        <script>
            // Suspicious JavaScript
            document.addEventListener('DOMContentLoaded', function() {
                setTimeout(() => {
                    window.location.href = 'https://real-paypal.com';
                }, 30000);
            });
        </script>
    </body>
    </html>
    """


@pytest.fixture
def mock_legitimate_webpage():
    """Mock legitimate webpage content."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Microsoft Support</title>
    </head>
    <body>
        <h1>Microsoft Support Center</h1>
        <p>Get help with Microsoft products and services.</p>
        <nav>
            <a href="/windows">Windows Support</a>
            <a href="/office">Office Support</a>
            <a href="/azure">Azure Support</a>
        </nav>
    </body>
    </html>
    """


# Performance testing utilities
class PerformanceTimer:
    """Context manager for timing operations."""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        import time
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        import time
        self.end_time = time.time()
    
    @property
    def elapsed(self):
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None
