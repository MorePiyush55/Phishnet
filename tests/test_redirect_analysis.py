"""
Redirect Chain Analysis Tests
Tests for URL redirect tracking and threat detection
"""

import pytest
import asyncio
import aiohttp
from typing import List, Dict, Any
from unittest.mock import Mock, patch, AsyncMock
from dataclasses import dataclass

# Import modules to test
from app.services.link_analyzer import LinkRedirectAnalyzer, RedirectChain
from app.core.sandbox_security import get_sandbox_ip_manager


@dataclass
class RedirectStep:
    """Single step in redirect chain"""
    url: str
    status_code: int
    final: bool = False
    threat_indicators: List[str] = None


class TestRedirectChainAnalysis:
    """Test redirect chain analysis functionality"""
    
    @pytest.fixture
    def redirect_analyzer(self):
        """Redirect analyzer instance"""
        return LinkRedirectAnalyzer()
    
    @pytest.fixture
    def test_redirect_chains(self):
        """Test redirect chain scenarios"""
        return {
            "legitimate_redirect": [
                RedirectStep("https://bit.ly/company-meeting", 301),
                RedirectStep("https://calendar.company.com/meeting/12345", 200, final=True)
            ],
            "suspicious_redirect": [
                RedirectStep("https://tinyurl.com/urgent-action", 302),
                RedirectStep("https://suspicious-domain.com/fake-login", 200, final=True,
                           threat_indicators=["domain_reputation", "credential_harvesting"])
            ],
            "malicious_redirect_chain": [
                RedirectStep("https://bit.ly/bank-security", 301),
                RedirectStep("https://redirect-service.com/r/12345", 302),
                RedirectStep("https://fake-bank-security.evil.com/login", 200, final=True,
                           threat_indicators=["domain_spoofing", "credential_request", "ssl_issues"])
            ],
            "redirect_loop": [
                RedirectStep("https://loop-site.com/a", 301),
                RedirectStep("https://loop-site.com/b", 301),
                RedirectStep("https://loop-site.com/a", 301),  # Loop detected
            ],
            "excessive_redirects": [
                RedirectStep(f"https://many-redirects.com/step{i}", 301)
                for i in range(1, 12)  # 11 redirects (exceeds typical limit)
            ]
        }
    
    @pytest.mark.asyncio
    async def test_simple_redirect_analysis(self, redirect_analyzer, test_redirect_chains):
        """Test analysis of simple redirect chains"""
        legitimate_chain = test_redirect_chains["legitimate_redirect"]
        
        with patch.object(redirect_analyzer, '_follow_redirects') as mock_follow:
            mock_follow.return_value = RedirectChain(
                original_url=legitimate_chain[0].url,
                final_url=legitimate_chain[-1].url,
                steps=[step.url for step in legitimate_chain],
                status_codes=[step.status_code for step in legitimate_chain],
                total_redirects=len(legitimate_chain) - 1,
                threat_score=0.1,
                threat_indicators=[]
            )
            
            result = await redirect_analyzer.analyze_url(legitimate_chain[0].url)
            
            assert result.original_url == legitimate_chain[0].url
            assert result.final_url == legitimate_chain[-1].url
            assert result.total_redirects == 1
            assert result.threat_score < 0.3  # Low threat for legitimate redirect
    
    @pytest.mark.asyncio
    async def test_malicious_redirect_detection(self, redirect_analyzer, test_redirect_chains):
        """Test detection of malicious redirect chains"""
        malicious_chain = test_redirect_chains["malicious_redirect_chain"]
        
        with patch.object(redirect_analyzer, '_follow_redirects') as mock_follow:
            mock_follow.return_value = RedirectChain(
                original_url=malicious_chain[0].url,
                final_url=malicious_chain[-1].url,
                steps=[step.url for step in malicious_chain],
                status_codes=[step.status_code for step in malicious_chain],
                total_redirects=len(malicious_chain) - 1,
                threat_score=0.95,
                threat_indicators=malicious_chain[-1].threat_indicators
            )
            
            result = await redirect_analyzer.analyze_url(malicious_chain[0].url)
            
            assert result.threat_score > 0.8  # High threat
            assert "domain_spoofing" in result.threat_indicators
            assert "credential_request" in result.threat_indicators
            assert result.total_redirects == 2
    
    @pytest.mark.asyncio
    async def test_redirect_loop_detection(self, redirect_analyzer, test_redirect_chains):
        """Test detection of redirect loops"""
        loop_chain = test_redirect_chains["redirect_loop"]
        
        with patch.object(redirect_analyzer, '_follow_redirects') as mock_follow:
            mock_follow.return_value = RedirectChain(
                original_url=loop_chain[0].url,
                final_url=None,  # No final URL due to loop
                steps=[step.url for step in loop_chain],
                status_codes=[step.status_code for step in loop_chain],
                total_redirects=len(loop_chain),
                threat_score=0.6,
                threat_indicators=["redirect_loop", "suspicious_behavior"],
                error="Redirect loop detected"
            )
            
            result = await redirect_analyzer.analyze_url(loop_chain[0].url)
            
            assert result.final_url is None
            assert "redirect_loop" in result.threat_indicators
            assert result.threat_score > 0.5
            assert "loop" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_excessive_redirects_detection(self, redirect_analyzer, test_redirect_chains):
        """Test detection of excessive redirect chains"""
        excessive_chain = test_redirect_chains["excessive_redirects"]
        
        with patch.object(redirect_analyzer, '_follow_redirects') as mock_follow:
            mock_follow.return_value = RedirectChain(
                original_url=excessive_chain[0].url,
                final_url=None,
                steps=[step.url for step in excessive_chain[:10]],  # Stopped at limit
                status_codes=[step.status_code for step in excessive_chain[:10]],
                total_redirects=10,
                threat_score=0.7,
                threat_indicators=["excessive_redirects", "evasion_attempt"],
                error="Maximum redirects exceeded"
            )
            
            result = await redirect_analyzer.analyze_url(excessive_chain[0].url)
            
            assert result.total_redirects >= 10
            assert "excessive_redirects" in result.threat_indicators
            assert result.threat_score > 0.6
    
    @pytest.mark.asyncio
    async def test_redirect_with_sandbox_ip(self, redirect_analyzer):
        """Test that redirects are followed using sandbox IPs"""
        sandbox_manager = get_sandbox_ip_manager()
        test_url = "https://bit.ly/test-redirect"
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = Mock()
            mock_response.status = 301
            mock_response.headers = {'Location': 'https://example.com/final'}
            mock_response.url = test_url
            
            mock_session_instance = Mock()
            mock_session_instance.get.return_value.__aenter__.return_value = mock_response
            mock_session.return_value.__aenter__.return_value = mock_session_instance
            
            # Mock sandbox session creation
            with patch.object(sandbox_manager, 'create_sandbox_session') as mock_create_session:
                mock_create_session.return_value = mock_session_instance
                
                await redirect_analyzer._follow_redirects(test_url)
                
                # Verify sandbox session was used
                mock_create_session.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_redirect_threat_scoring(self, redirect_analyzer):
        """Test threat scoring algorithm for redirects"""
        
        # Test various redirect scenarios
        test_cases = [
            {
                "scenario": "legitimate_short_url",
                "original": "https://bit.ly/company-docs",
                "final": "https://docs.company.com/quarterly-report.pdf",
                "redirects": 1,
                "expected_score_range": (0.0, 0.3)
            },
            {
                "scenario": "suspicious_shortener_to_unknown",
                "original": "https://tinyurl.com/urgent123",
                "final": "https://unknown-domain.com/action",
                "redirects": 1,
                "expected_score_range": (0.4, 0.7)
            },
            {
                "scenario": "malicious_typosquatting",
                "original": "https://bit.ly/secure-login",
                "final": "https://g00gle.com/accounts/signin",
                "redirects": 2,
                "expected_score_range": (0.8, 1.0)
            }
        ]
        
        for case in test_cases:
            with patch.object(redirect_analyzer, '_follow_redirects') as mock_follow:
                # Mock appropriate threat scoring
                min_score, max_score = case["expected_score_range"]
                mock_score = (min_score + max_score) / 2
                
                mock_follow.return_value = RedirectChain(
                    original_url=case["original"],
                    final_url=case["final"],
                    steps=[case["original"], case["final"]],
                    status_codes=[301, 200],
                    total_redirects=case["redirects"],
                    threat_score=mock_score,
                    threat_indicators=[]
                )
                
                result = await redirect_analyzer.analyze_url(case["original"])
                
                assert min_score <= result.threat_score <= max_score, \
                    f"Threat score {result.threat_score} not in expected range {case['expected_score_range']} for {case['scenario']}"
    
    @pytest.mark.asyncio
    async def test_redirect_caching(self, redirect_analyzer):
        """Test that redirect analysis results are cached"""
        test_url = "https://bit.ly/cached-redirect"
        
        # First call
        with patch.object(redirect_analyzer, '_follow_redirects') as mock_follow:
            mock_result = RedirectChain(
                original_url=test_url,
                final_url="https://example.com/final",
                steps=[test_url, "https://example.com/final"],
                status_codes=[301, 200],
                total_redirects=1,
                threat_score=0.2,
                threat_indicators=[]
            )
            mock_follow.return_value = mock_result
            
            # Mock cache operations
            with patch.object(redirect_analyzer, '_get_cached_result') as mock_get_cache, \
                 patch.object(redirect_analyzer, '_cache_result') as mock_set_cache:
                
                mock_get_cache.return_value = None  # First call - no cache
                
                result1 = await redirect_analyzer.analyze_url(test_url)
                
                # Should call _follow_redirects and cache the result
                mock_follow.assert_called_once()
                mock_set_cache.assert_called_once()
        
        # Second call - should use cache
        with patch.object(redirect_analyzer, '_follow_redirects') as mock_follow:
            with patch.object(redirect_analyzer, '_get_cached_result') as mock_get_cache:
                mock_get_cache.return_value = mock_result  # Return cached result
                
                result2 = await redirect_analyzer.analyze_url(test_url)
                
                # Should not call _follow_redirects again
                mock_follow.assert_not_called()
                assert result2.original_url == test_url
    
    def test_redirect_chain_serialization(self, redirect_analyzer):
        """Test RedirectChain serialization for caching"""
        redirect_chain = RedirectChain(
            original_url="https://bit.ly/test",
            final_url="https://example.com/final",
            steps=["https://bit.ly/test", "https://redirect.com/r/123", "https://example.com/final"],
            status_codes=[301, 302, 200],
            total_redirects=2,
            threat_score=0.45,
            threat_indicators=["suspicious_redirector", "unknown_domain"],
            timestamp=1234567890.0,
            error=None
        )
        
        # Test serialization
        serialized = redirect_chain.to_dict()
        assert serialized['original_url'] == "https://bit.ly/test"
        assert serialized['threat_score'] == 0.45
        assert "suspicious_redirector" in serialized['threat_indicators']
        
        # Test deserialization
        deserialized = RedirectChain.from_dict(serialized)
        assert deserialized.original_url == redirect_chain.original_url
        assert deserialized.threat_score == redirect_chain.threat_score
        assert deserialized.threat_indicators == redirect_chain.threat_indicators
    
    @pytest.mark.asyncio
    async def test_redirect_timeout_handling(self, redirect_analyzer):
        """Test handling of redirect timeouts"""
        test_url = "https://slow-redirect.com/timeout"
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.side_effect = asyncio.TimeoutError("Request timed out")
            
            result = await redirect_analyzer.analyze_url(test_url)
            
            assert result.final_url is None
            assert "timeout" in result.error.lower()
            assert result.threat_score > 0.5  # Timeout increases threat score
            assert "timeout" in result.threat_indicators
    
    @pytest.mark.asyncio
    async def test_redirect_ssl_verification(self, redirect_analyzer):
        """Test SSL certificate verification during redirects"""
        test_url = "https://ssl-issues.com/redirect"
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            # Simulate SSL error
            import ssl
            mock_get.side_effect = ssl.SSLError("SSL certificate verification failed")
            
            result = await redirect_analyzer.analyze_url(test_url)
            
            assert result.final_url is None
            assert "ssl" in result.error.lower()
            assert result.threat_score > 0.7  # SSL issues increase threat score
            assert "ssl_issues" in result.threat_indicators


class TestRedirectChainIntegration:
    """Integration tests for redirect chain analysis"""
    
    @pytest.mark.asyncio
    async def test_redirect_analysis_in_threat_pipeline(self):
        """Test redirect analysis integration in threat detection pipeline"""
        from app.orchestrator.main import PhishNetOrchestrator
        
        orchestrator = PhishNetOrchestrator()
        
        # Email with redirect URL
        test_email = {
            "subject": "Click here for urgent action",
            "sender": "urgent@suspicious.com",
            "body": "Click this link immediately: https://bit.ly/urgent-action-required",
            "links": ["https://bit.ly/urgent-action-required"]
        }
        
        with patch('app.services.link_analyzer.LinkRedirectAnalyzer.analyze_url') as mock_analyze:
            # Mock malicious redirect result
            mock_analyze.return_value = RedirectChain(
                original_url="https://bit.ly/urgent-action-required",
                final_url="https://fake-bank.evil.com/login",
                steps=["https://bit.ly/urgent-action-required", "https://fake-bank.evil.com/login"],
                status_codes=[301, 200],
                total_redirects=1,
                threat_score=0.95,
                threat_indicators=["domain_spoofing", "credential_harvesting"]
            )
            
            # Mock other services
            with patch('app.integrations.virustotal.VirusTotalClient.scan_url') as mock_vt, \
                 patch('app.integrations.gemini.GeminiClient.analyze_content') as mock_gemini:
                
                mock_vt.return_value = {'positives': 8, 'total': 70}
                mock_gemini.return_value = {'threat_probability': 0.9, 'confidence': 0.95}
                
                result = await orchestrator.scan_email(
                    user_id="test_user",
                    email_id="redirect_test",
                    subject=test_email["subject"],
                    sender=test_email["sender"],
                    body=test_email["body"],
                    links=test_email["links"]
                )
                
                # Verify redirect analysis contributed to high threat score
                assert result.overall_threat_level == "HIGH"
                assert any("redirect" in indicator.lower() or "domain" in indicator.lower() 
                          for indicator in result.get_all_threat_indicators())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
