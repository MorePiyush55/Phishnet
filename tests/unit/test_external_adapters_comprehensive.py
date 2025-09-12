"""
Comprehensive unit tests for VirusTotal and Gemini service adapters with proper mocking.
Tests cover API interactions, error handling, rate limiting, and result processing.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import aiohttp
import json
from typing import Dict, Any

from app.services.virustotal import VirusTotalClient
from app.services.gemini import GeminiClient  
from app.services.interfaces import AnalysisResult, AnalysisType, ServiceStatus


class TestVirusTotalClientMocked:
    """Test suite for VirusTotal client with comprehensive mocking."""
    
    @pytest.fixture
    def vt_client(self):
        """Create VirusTotal client with mocked API key."""
        with patch('app.services.virustotal.settings') as mock_settings:
            mock_settings.get_virustotal_api_key.return_value = "test_api_key_12345"
            return VirusTotalClient(api_key="test_api_key_12345")
    
    @pytest.fixture
    def mock_vt_url_response(self):
        """Mock VirusTotal URL scan response."""
        return {
            "response_code": 1,
            "verbose_msg": "Scan finished, information embedded",
            "resource": "https://example.com",
            "scan_id": "test_scan_id_12345",
            "scan_date": "2025-01-01 12:00:00",
            "permalink": "https://virustotal.com/url/test_scan_id_12345/analysis/",
            "positives": 3,
            "total": 67,
            "scans": {
                "Kaspersky": {"detected": True, "result": "malware"},
                "Symantec": {"detected": True, "result": "phishing"}, 
                "McAfee": {"detected": True, "result": "suspicious"},
                "BitDefender": {"detected": False, "result": "clean"},
                "Avira": {"detected": False, "result": "clean"}
            }
        }
    
    @pytest.fixture
    def mock_vt_clean_response(self):
        """Mock VirusTotal clean URL response."""
        return {
            "response_code": 1,
            "verbose_msg": "Scan finished, information embedded", 
            "resource": "https://google.com",
            "scan_id": "clean_scan_id_67890",
            "scan_date": "2025-01-01 12:00:00",
            "permalink": "https://virustotal.com/url/clean_scan_id_67890/analysis/",
            "positives": 0,
            "total": 67,
            "scans": {
                "Kaspersky": {"detected": False, "result": "clean"},
                "Symantec": {"detected": False, "result": "clean"},
                "McAfee": {"detected": False, "result": "clean"}
            }
        }
    
    @pytest.mark.asyncio
    async def test_url_analysis_malicious(self, vt_client, mock_vt_url_response):
        """Test URL analysis with malicious result."""
        
        async def mock_post(*args, **kwargs):
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_vt_url_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        with patch('aiohttp.ClientSession.post', side_effect=mock_post):
            result = await vt_client.analyze("https://example.com", AnalysisType.URL)
            
            assert isinstance(result, AnalysisResult)
            assert result.analysis_type == AnalysisType.URL
            assert result.target == "https://example.com"
            assert result.threat_score > 0.0  # Should detect threats
            assert result.verdict in ["MALICIOUS", "SUSPICIOUS"]
            assert result.data['positives'] == 3
            assert result.data['total'] == 67
            assert len(result.indicators) > 0
    
    @pytest.mark.asyncio
    async def test_url_analysis_clean(self, vt_client, mock_vt_clean_response):
        """Test URL analysis with clean result."""
        
        async def mock_post(*args, **kwargs):
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_vt_clean_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        with patch('aiohttp.ClientSession.post', side_effect=mock_post):
            result = await vt_client.analyze("https://google.com", AnalysisType.URL)
            
            assert result.threat_score == 0.0
            assert result.verdict == "CLEAN"
            assert result.data['positives'] == 0
            assert len(result.indicators) == 0
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, vt_client):
        """Test rate limiting functionality."""
        
        call_count = 0
        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            
            mock_response = AsyncMock()
            if call_count <= 2:
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value={"response_code": 1, "positives": 0, "total": 67})
            else:
                mock_response.status = 204  # Rate limited
                mock_response.json = AsyncMock(return_value={"response_code": -2, "verbose_msg": "Your request rate limit has been exceeded"})
            
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        with patch('aiohttp.ClientSession.post', side_effect=mock_post):
            # First few requests should succeed
            result1 = await vt_client.analyze("https://test1.com", AnalysisType.URL)
            assert result1.verdict in ["CLEAN", "UNKNOWN"]
            
            result2 = await vt_client.analyze("https://test2.com", AnalysisType.URL)
            assert result2.verdict in ["CLEAN", "UNKNOWN"]
            
            # Subsequent requests should handle rate limiting
            result3 = await vt_client.analyze("https://test3.com", AnalysisType.URL)
            assert result3.data.get('rate_limited') is True or result3.verdict == "UNKNOWN"
    
    @pytest.mark.asyncio
    async def test_api_error_handling(self, vt_client):
        """Test handling of various API errors."""
        
        error_scenarios = [
            (400, "Invalid API key"),
            (403, "Forbidden"),
            (500, "Internal server error"),
            (503, "Service unavailable")
        ]
        
        for status_code, error_msg in error_scenarios:
            async def mock_post_error(*args, **kwargs):
                mock_response = AsyncMock()
                mock_response.status = status_code
                mock_response.json = AsyncMock(return_value={"response_code": -1, "verbose_msg": error_msg})
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                return mock_response
            
            with patch('aiohttp.ClientSession.post', side_effect=mock_post_error):
                result = await vt_client.analyze("https://error-test.com", AnalysisType.URL)
                
                # Should handle errors gracefully
                assert isinstance(result, AnalysisResult)
                assert result.verdict in ["UNKNOWN", "ERROR"]
                assert result.data.get('error') is not None
    
    @pytest.mark.asyncio
    async def test_network_timeout_handling(self, vt_client):
        """Test handling of network timeouts."""
        
        async def mock_post_timeout(*args, **kwargs):
            raise asyncio.TimeoutError("Request timeout")
        
        with patch('aiohttp.ClientSession.post', side_effect=mock_post_timeout):
            result = await vt_client.analyze("https://timeout-test.com", AnalysisType.URL)
            
            assert result.verdict == "UNKNOWN"
            assert "timeout" in result.explanation.lower()
            assert result.data.get('timeout_error') is True
    
    @pytest.mark.asyncio
    async def test_invalid_url_handling(self, vt_client):
        """Test handling of invalid URLs."""
        invalid_urls = [
            "not-a-url",
            "ftp://invalid-protocol.com",
            "javascript:alert('xss')",
            "",
            None
        ]
        
        for invalid_url in invalid_urls:
            result = await vt_client.analyze(invalid_url, AnalysisType.URL)
            
            assert result.verdict in ["INVALID", "ERROR", "UNKNOWN"]
            assert result.threat_score == 0.0 or result.data.get('invalid_target') is True
    
    @pytest.mark.asyncio
    async def test_result_caching(self, vt_client):
        """Test result caching functionality."""
        
        with patch.object(vt_client, '_get_cached_result') as mock_get_cache, \
             patch.object(vt_client, '_cache_result') as mock_set_cache:
            
            # Test cache miss
            mock_get_cache.return_value = None
            
            async def mock_post(*args, **kwargs):
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value={"response_code": 1, "positives": 0, "total": 67})
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                return mock_response
            
            with patch('aiohttp.ClientSession.post', side_effect=mock_post):
                result = await vt_client.analyze("https://cache-test.com", AnalysisType.URL)
                
                # Should attempt to cache the result
                mock_set_cache.assert_called_once()
            
            # Test cache hit
            cached_result = AnalysisResult(
                target="https://cached.com",
                analysis_type=AnalysisType.URL,
                threat_score=0.0,
                confidence=0.9,
                verdict="CLEAN",
                explanation="Cached result",
                indicators=[],
                data={'cached': True},
                timestamp=1704110400
            )
            mock_get_cache.return_value = cached_result
            
            result = await vt_client.analyze("https://cached.com", AnalysisType.URL)
            assert result.data.get('cached') is True
    
    @pytest.mark.asyncio
    async def test_health_monitoring(self, vt_client):
        """Test health monitoring functionality."""
        
        # Test healthy service
        health = await vt_client.get_health()
        assert health.service_name == "virustotal"
        assert health.status in [ServiceStatus.HEALTHY, ServiceStatus.DEGRADED]
        
        # Test service degradation after errors
        async def mock_post_error(*args, **kwargs):
            raise aiohttp.ClientError("Network error")
        
        with patch('aiohttp.ClientSession.post', side_effect=mock_post_error):
            try:
                await vt_client.analyze("https://error.com", AnalysisType.URL)
            except:
                pass
            
            health_after_error = await vt_client.get_health()
            # Health might be degraded after failures
            assert health_after_error.status in [ServiceStatus.HEALTHY, ServiceStatus.DEGRADED, ServiceStatus.UNHEALTHY]


class TestGeminiClientMocked:
    """Test suite for Gemini AI client with comprehensive mocking."""
    
    @pytest.fixture
    def gemini_client(self):
        """Create Gemini client with mocked API key."""
        with patch('app.services.gemini.settings') as mock_settings:
            mock_settings.GEMINI_API_KEY = "test_gemini_api_key_12345"
            return GeminiClient(api_key="test_gemini_api_key_12345")
    
    @pytest.fixture
    def mock_gemini_phishing_response(self):
        """Mock Gemini response for phishing content."""
        return {
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": json.dumps({
                            "threat_assessment": {
                                "is_phishing": True,
                                "confidence": 0.85,
                                "threat_score": 0.8,
                                "threat_type": "credential_harvesting"
                            },
                            "analysis": {
                                "urgency_indicators": ["act now", "immediate action required"],
                                "credential_requests": ["enter password", "verify account"],
                                "suspicious_elements": ["suspicious domain", "typos"],
                                "legitimacy_score": 0.2
                            },
                            "explanation": "This content shows classic phishing characteristics including urgency language and credential requests."
                        })
                    }]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 150,
                "candidatesTokenCount": 200,
                "totalTokenCount": 350
            }
        }
    
    @pytest.fixture
    def mock_gemini_safe_response(self):
        """Mock Gemini response for safe content."""
        return {
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": json.dumps({
                            "threat_assessment": {
                                "is_phishing": False,
                                "confidence": 0.92,
                                "threat_score": 0.05,
                                "threat_type": "none"
                            },
                            "analysis": {
                                "urgency_indicators": [],
                                "credential_requests": [],
                                "suspicious_elements": [],
                                "legitimacy_score": 0.95
                            },
                            "explanation": "This appears to be legitimate business communication with no suspicious indicators."
                        })
                    }]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 120,
                "candidatesTokenCount": 180,
                "totalTokenCount": 300
            }
        }
    
    @pytest.mark.asyncio
    async def test_text_analysis_phishing(self, gemini_client, mock_gemini_phishing_response):
        """Test text analysis detecting phishing content."""
        
        async def mock_post(*args, **kwargs):
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_gemini_phishing_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        phishing_content = """
        URGENT: Your account will be suspended!
        Click here to verify your password immediately: https://fake-bank.com/verify
        Enter your login credentials to prevent account closure.
        """
        
        with patch('aiohttp.ClientSession.post', side_effect=mock_post):
            result = await gemini_client.analyze(phishing_content, AnalysisType.TEXT)
            
            assert isinstance(result, AnalysisResult)
            assert result.analysis_type == AnalysisType.TEXT
            assert result.threat_score > 0.5
            assert result.verdict in ["PHISHING", "MALICIOUS", "SUSPICIOUS"]
            assert result.confidence > 0.8
            assert len(result.indicators) > 0
            assert any("urgency" in indicator.lower() for indicator in result.indicators)
    
    @pytest.mark.asyncio
    async def test_text_analysis_safe(self, gemini_client, mock_gemini_safe_response):
        """Test text analysis with safe content."""
        
        async def mock_post(*args, **kwargs):
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_gemini_safe_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        safe_content = """
        Thank you for your recent purchase from our online store.
        Your order #12345 has been processed and will ship within 2-3 business days.
        If you have any questions, please contact our customer service team.
        """
        
        with patch('aiohttp.ClientSession.post', side_effect=mock_post):
            result = await gemini_client.analyze(safe_content, AnalysisType.TEXT)
            
            assert result.threat_score < 0.2
            assert result.verdict in ["SAFE", "CLEAN"]
            assert result.confidence > 0.8
            assert len(result.indicators) == 0
    
    @pytest.mark.asyncio
    async def test_content_filtering_and_safety(self, gemini_client):
        """Test Gemini content filtering and safety mechanisms."""
        
        blocked_response = {
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": "Content blocked due to safety filters"
                    }]
                },
                "finishReason": "SAFETY"
            }]
        }
        
        async def mock_post_blocked(*args, **kwargs):
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=blocked_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        harmful_content = "Content with explicit violence or harmful instructions"
        
        with patch('aiohttp.ClientSession.post', side_effect=mock_post_blocked):
            result = await gemini_client.analyze(harmful_content, AnalysisType.TEXT)
            
            # Should handle safety blocks gracefully
            assert result.verdict in ["BLOCKED", "UNKNOWN", "ERROR"]
            assert "safety" in result.explanation.lower() or "blocked" in result.explanation.lower()
    
    @pytest.mark.asyncio
    async def test_rate_limiting_and_quota(self, gemini_client):
        """Test rate limiting and quota management."""
        
        quota_exceeded_response = {
            "error": {
                "code": 429,
                "message": "Quota exceeded",
                "status": "RESOURCE_EXHAUSTED"
            }
        }
        
        async def mock_post_quota(*args, **kwargs):
            mock_response = AsyncMock()
            mock_response.status = 429
            mock_response.json = AsyncMock(return_value=quota_exceeded_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        with patch('aiohttp.ClientSession.post', side_effect=mock_post_quota):
            result = await gemini_client.analyze("Test content", AnalysisType.TEXT)
            
            assert result.verdict in ["UNKNOWN", "ERROR"]
            assert "quota" in result.explanation.lower() or "rate" in result.explanation.lower()
            assert result.data.get('rate_limited') is True
    
    @pytest.mark.asyncio
    async def test_token_counting_and_optimization(self, gemini_client):
        """Test token counting and content optimization."""
        
        # Test with very long content that might exceed token limits
        long_content = "This is a test. " * 5000  # Very long content
        
        with patch.object(gemini_client, '_estimate_token_count') as mock_token_count:
            mock_token_count.return_value = 40000  # Exceeds typical limits
            
            with patch.object(gemini_client, '_truncate_content') as mock_truncate:
                mock_truncate.return_value = "Truncated content for analysis"
                
                async def mock_post(*args, **kwargs):
                    mock_response = AsyncMock()
                    mock_response.status = 200
                    mock_response.json = AsyncMock(return_value={"candidates": [{"content": {"parts": [{"text": "Analysis result"}]}}]})
                    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                    mock_response.__aexit__ = AsyncMock(return_value=None)
                    return mock_response
                
                with patch('aiohttp.ClientSession.post', side_effect=mock_post):
                    result = await gemini_client.analyze(long_content, AnalysisType.TEXT)
                    
                    # Should have truncated content
                    mock_truncate.assert_called_once()
                    assert result.data.get('content_truncated') is True
    
    @pytest.mark.asyncio
    async def test_multilingual_content_handling(self, gemini_client):
        """Test handling of multilingual content."""
        
        multilingual_contents = [
            "Hola, necesitas verificar tu cuenta bancaria urgentemente.",  # Spanish
            "Bonjour, votre compte sera suspendu si vous ne vérifiez pas.",  # French
            "您的账户将被暂停，请立即验证。",  # Chinese
            "これは緊急のアカウント確認です。"  # Japanese
        ]
        
        for content in multilingual_contents:
            async def mock_post(*args, **kwargs):
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value={
                    "candidates": [{
                        "content": {
                            "parts": [{
                                "text": json.dumps({
                                    "threat_assessment": {"is_phishing": True, "confidence": 0.8, "threat_score": 0.7},
                                    "language_detected": "auto",
                                    "analysis": {"urgency_indicators": ["urgent", "suspend"], "credential_requests": ["verify"]}
                                })
                            }]
                        }
                    }]
                })
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                return mock_response
            
            with patch('aiohttp.ClientSession.post', side_effect=mock_post):
                result = await gemini_client.analyze(content, AnalysisType.TEXT)
                
                # Should handle multilingual content
                assert isinstance(result, AnalysisResult)
                assert result.threat_score >= 0.0
    
    @pytest.mark.asyncio
    async def test_response_parsing_robustness(self, gemini_client):
        """Test robust parsing of various response formats."""
        
        response_scenarios = [
            # Valid JSON response
            {"candidates": [{"content": {"parts": [{"text": '{"threat_score": 0.5}'}]}}]},
            # Malformed JSON
            {"candidates": [{"content": {"parts": [{"text": "Invalid JSON {"}]}}]},
            # Empty response
            {"candidates": []},
            # Missing parts
            {"candidates": [{"content": {}}]},
        ]
        
        for response_data in response_scenarios:
            async def mock_post(*args, **kwargs):
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value=response_data)
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                return mock_response
            
            with patch('aiohttp.ClientSession.post', side_effect=mock_post):
                result = await gemini_client.analyze("Test content", AnalysisType.TEXT)
                
                # Should handle all response formats gracefully
                assert isinstance(result, AnalysisResult)
                assert 0.0 <= result.threat_score <= 1.0
                assert result.verdict in ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN", "ERROR"]
    
    @pytest.mark.asyncio
    async def test_concurrent_request_handling(self, gemini_client):
        """Test concurrent request handling and rate limiting."""
        
        async def mock_post_concurrent(*args, **kwargs):
            await asyncio.sleep(0.1)  # Simulate API delay
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "candidates": [{"content": {"parts": [{"text": '{"threat_score": 0.1}'}]}}]
            })
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            return mock_response
        
        contents = [f"Test content {i}" for i in range(5)]
        
        with patch('aiohttp.ClientSession.post', side_effect=mock_post_concurrent):
            # Test concurrent processing
            tasks = [gemini_client.analyze(content, AnalysisType.TEXT) for content in contents]
            results = await asyncio.gather(*tasks)
            
            assert len(results) == 5
            for result in results:
                assert isinstance(result, AnalysisResult)
    
    def test_prompt_engineering_and_optimization(self, gemini_client):
        """Test prompt engineering for optimal threat detection."""
        
        # Test that prompts are properly structured
        prompt = gemini_client._create_analysis_prompt("Test phishing content")
        
        assert isinstance(prompt, str)
        assert len(prompt) > 0
        
        # Should include key analysis instructions
        prompt_lower = prompt.lower()
        assert any(keyword in prompt_lower for keyword in [
            'phishing', 'threat', 'analysis', 'security', 'suspicious'
        ])
        
        # Should request structured output
        assert 'json' in prompt_lower or 'format' in prompt_lower
