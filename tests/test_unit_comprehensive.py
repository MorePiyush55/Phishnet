"""
Comprehensive Unit Tests for PhishNet Core Components
Tests: adapters (mock HTTP), aggregator logic (weighting), redirect tracer, sanitizer
"""

import pytest
import asyncio
import json
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import requests_mock
import aiohttp
from urllib.parse import urlparse

# Core imports for testing
from app.core.pii_sanitizer import PIISanitizer, get_pii_sanitizer
from app.integrations.virustotal import VirusTotalClient, VirusTotalAdapter
from app.integrations.gemini import GeminiClient, GeminiAdapter  
from app.integrations.abuseipdb import AbuseIPDBClient, AbuseIPDBAdapter
from app.services.analysis.link_redirect_analyzer import LinkRedirectAnalyzer
from app.services.analysis.threat_aggregator import ThreatAggregator, ThreatResult
from app.orchestrator.main import PhishNetOrchestrator


class TestAdaptersWithMockHTTP:
    """Test all HTTP adapters with comprehensive mock scenarios"""
    
    @pytest.mark.asyncio
    async def test_virustotal_adapter_success(self):
        """Test VirusTotal adapter with successful HTTP response"""
        with requests_mock.Mocker() as m:
            # Mock successful VirusTotal response
            mock_response = {
                "data": {
                    "id": "test-scan-id",
                    "attributes": {
                        "stats": {"malicious": 5, "suspicious": 2, "clean": 63, "timeout": 0},
                        "permalink": "https://www.virustotal.com/gui/url/test-scan-id"
                    }
                }
            }
            
            m.post("https://www.virustotal.com/api/v3/urls", json=mock_response)
            m.get("https://www.virustotal.com/api/v3/analyses/test-scan-id", json=mock_response)
            
            adapter = VirusTotalAdapter(api_key="test-key")
            result = await adapter.scan_url("https://example.com")
            
            assert result is not None
            assert result.scan_id == "test-scan-id"
            assert result.positives == 5
            assert result.total == 70
            assert "virustotal.com" in result.permalink
    
    @pytest.mark.asyncio
    async def test_virustotal_adapter_rate_limit(self):
        """Test VirusTotal adapter handles rate limiting"""
        with requests_mock.Mocker() as m:
            # Mock rate limit response
            m.post("https://www.virustotal.com/api/v3/urls", 
                   status_code=429, 
                   headers={"Retry-After": "60"})
            
            adapter = VirusTotalAdapter(api_key="test-key")
            
            with pytest.raises(Exception) as exc_info:
                await adapter.scan_url("https://example.com")
            
            assert "rate limit" in str(exc_info.value).lower() or "429" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_virustotal_adapter_invalid_url(self):
        """Test VirusTotal adapter handles invalid URLs"""
        with requests_mock.Mocker() as m:
            # Mock invalid URL response
            m.post("https://www.virustotal.com/api/v3/urls", 
                   status_code=400,
                   json={"error": {"message": "Invalid URL"}})
            
            adapter = VirusTotalAdapter(api_key="test-key")
            
            with pytest.raises(Exception) as exc_info:
                await adapter.scan_url("not-a-valid-url")
            
            assert "400" in str(exc_info.value) or "invalid" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_gemini_adapter_success(self):
        """Test Gemini adapter with successful response"""
        with patch('google.generativeai.GenerativeModel') as mock_model:
            # Mock successful Gemini response
            mock_response = Mock()
            mock_response.text = json.dumps({
                "threat_probability": 0.85,
                "confidence": 0.92,
                "reasoning": "Multiple phishing indicators detected",
                "risk_factors": ["urgent_language", "credential_request", "suspicious_domain"]
            })
            
            mock_model.return_value.generate_content.return_value = mock_response
            
            adapter = GeminiAdapter(api_key="test-key")
            result = await adapter.analyze_content("URGENT: Click here to verify your account")
            
            assert result is not None
            assert result['threat_probability'] == 0.85
            assert result['confidence'] == 0.92
            assert len(result['risk_factors']) == 3
    
    @pytest.mark.asyncio
    async def test_gemini_adapter_quota_exceeded(self):
        """Test Gemini adapter handles quota exceeded"""
        with patch('google.generativeai.GenerativeModel') as mock_model:
            # Mock quota exceeded error
            mock_model.return_value.generate_content.side_effect = Exception("Quota exceeded")
            
            adapter = GeminiAdapter(api_key="test-key")
            
            with pytest.raises(Exception) as exc_info:
                await adapter.analyze_content("Test content")
            
            assert "quota" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_abuseipdb_adapter_success(self):
        """Test AbuseIPDB adapter with successful response"""
        with requests_mock.Mocker() as m:
            # Mock successful AbuseIPDB response
            mock_response = {
                "data": {
                    "ipAddress": "192.168.1.1",
                    "abuseConfidenceScore": 75,
                    "countryCode": "US",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Test ISP",
                    "totalReports": 15,
                    "lastReportedAt": "2025-09-11T10:00:00+00:00"
                }
            }
            
            m.get("https://api.abuseipdb.com/api/v2/check", json=mock_response)
            
            adapter = AbuseIPDBAdapter(api_key="test-key")
            result = await adapter.check_ip("192.168.1.1")
            
            assert result is not None
            assert result.ip_address == "192.168.1.1"
            assert result.abuse_confidence == 75
            assert result.total_reports == 15
    
    @pytest.mark.asyncio
    async def test_abuseipdb_adapter_clean_ip(self):
        """Test AbuseIPDB adapter with clean IP"""
        with requests_mock.Mocker() as m:
            # Mock clean IP response
            mock_response = {
                "data": {
                    "ipAddress": "8.8.8.8",
                    "abuseConfidenceScore": 0,
                    "countryCode": "US",
                    "usageType": "Search Engine Spider",
                    "isp": "Google LLC",
                    "totalReports": 0,
                    "lastReportedAt": None
                }
            }
            
            m.get("https://api.abuseipdb.com/api/v2/check", json=mock_response)
            
            adapter = AbuseIPDBAdapter(api_key="test-key")
            result = await adapter.check_ip("8.8.8.8")
            
            assert result is not None
            assert result.ip_address == "8.8.8.8"
            assert result.abuse_confidence == 0
            assert result.total_reports == 0


class TestAggregatorLogic:
    """Test threat aggregator weighting logic"""
    
    def setup_method(self):
        """Set up test aggregator"""
        self.aggregator = ThreatAggregator()
    
    def test_virustotal_weighting(self):
        """Test VirusTotal result weighting"""
        # High threat scenario
        vt_result = Mock()
        vt_result.positives = 25
        vt_result.total = 70
        vt_result.permalink = "https://virustotal.com/test"
        
        weight = self.aggregator._calculate_virustotal_weight(vt_result)
        
        # Should be high weight for 25/70 positive detections (35.7%)
        assert weight > 0.8
        assert weight <= 1.0
    
    def test_virustotal_weighting_clean(self):
        """Test VirusTotal weighting for clean URLs"""
        # Clean URL scenario
        vt_result = Mock()
        vt_result.positives = 0
        vt_result.total = 70
        vt_result.permalink = "https://virustotal.com/test"
        
        weight = self.aggregator._calculate_virustotal_weight(vt_result)
        
        # Should be very low weight for clean URLs
        assert weight < 0.1
    
    def test_gemini_weighting(self):
        """Test Gemini AI analysis weighting"""
        # High threat AI analysis
        gemini_result = {
            'threat_probability': 0.95,
            'confidence': 0.88,
            'reasoning': 'Multiple phishing indicators',
            'risk_factors': ['urgent_language', 'credential_request', 'domain_spoofing']
        }
        
        weight = self.aggregator._calculate_gemini_weight(gemini_result)
        
        # Should be high weight for high probability + confidence
        assert weight > 0.9
        assert weight <= 1.0
    
    def test_gemini_weighting_low_confidence(self):
        """Test Gemini weighting with low confidence"""
        # Low confidence scenario
        gemini_result = {
            'threat_probability': 0.60,
            'confidence': 0.40,
            'reasoning': 'Uncertain analysis',
            'risk_factors': ['mild_urgency']
        }
        
        weight = self.aggregator._calculate_gemini_weight(gemini_result)
        
        # Should reduce weight due to low confidence
        assert weight < 0.6
    
    def test_abuseipdb_weighting(self):
        """Test AbuseIPDB result weighting"""
        # High abuse score
        abuse_result = Mock()
        abuse_result.abuse_confidence = 85
        abuse_result.total_reports = 50
        
        weight = self.aggregator._calculate_abuseipdb_weight(abuse_result)
        
        # Should be high weight for high abuse confidence
        assert weight > 0.8
        assert weight <= 1.0
    
    def test_abuseipdb_weighting_clean(self):
        """Test AbuseIPDB weighting for clean IPs"""
        # Clean IP
        abuse_result = Mock()
        abuse_result.abuse_confidence = 0
        abuse_result.total_reports = 0
        
        weight = self.aggregator._calculate_abuseipdb_weight(abuse_result)
        
        # Should be very low weight for clean IPs
        assert weight < 0.1
    
    def test_aggregate_threat_score_high(self):
        """Test aggregation of high threat indicators"""
        # High threat from all sources
        vt_result = Mock()
        vt_result.positives = 30
        vt_result.total = 70
        vt_result.permalink = "https://virustotal.com/test"
        
        gemini_result = {
            'threat_probability': 0.92,
            'confidence': 0.95,
            'reasoning': 'Clear phishing attempt',
            'risk_factors': ['urgent_language', 'credential_request', 'domain_spoofing', 'typosquatting']
        }
        
        abuse_result = Mock()
        abuse_result.abuse_confidence = 90
        abuse_result.total_reports = 75
        
        threat_result = self.aggregator.aggregate_results(
            virustotal_result=vt_result,
            gemini_result=gemini_result,
            abuseipdb_result=abuse_result
        )
        
        assert threat_result.overall_threat_level == "HIGH"
        assert threat_result.confidence_score > 0.9
        assert threat_result.threat_score > 0.85
    
    def test_aggregate_threat_score_low(self):
        """Test aggregation of low threat indicators"""
        # Low threat from all sources
        vt_result = Mock()
        vt_result.positives = 0
        vt_result.total = 70
        vt_result.permalink = "https://virustotal.com/test"
        
        gemini_result = {
            'threat_probability': 0.15,
            'confidence': 0.85,
            'reasoning': 'Appears legitimate',
            'risk_factors': []
        }
        
        abuse_result = Mock()
        abuse_result.abuse_confidence = 5
        abuse_result.total_reports = 1
        
        threat_result = self.aggregator.aggregate_results(
            virustotal_result=vt_result,
            gemini_result=gemini_result,
            abuseipdb_result=abuse_result
        )
        
        assert threat_result.overall_threat_level == "LOW"
        assert threat_result.confidence_score > 0.7
        assert threat_result.threat_score < 0.3
    
    def test_aggregate_threat_score_mixed(self):
        """Test aggregation with mixed threat indicators"""
        # Mixed signals - high VT, low AI, medium abuse
        vt_result = Mock()
        vt_result.positives = 15
        vt_result.total = 70
        vt_result.permalink = "https://virustotal.com/test"
        
        gemini_result = {
            'threat_probability': 0.25,
            'confidence': 0.70,
            'reasoning': 'Some suspicious elements',
            'risk_factors': ['mild_urgency']
        }
        
        abuse_result = Mock()
        abuse_result.abuse_confidence = 45
        abuse_result.total_reports = 10
        
        threat_result = self.aggregator.aggregate_results(
            virustotal_result=vt_result,
            gemini_result=gemini_result,
            abuseipdb_result=abuse_result
        )
        
        assert threat_result.overall_threat_level in ["MEDIUM", "HIGH"]
        assert 0.4 < threat_result.threat_score < 0.8


class TestRedirectTracer:
    """Test redirect tracer with simulated redirects"""
    
    def setup_method(self):
        """Set up test redirect analyzer"""
        self.analyzer = LinkRedirectAnalyzer()
    
    @pytest.mark.asyncio
    async def test_simple_redirect_chain(self):
        """Test following a simple redirect chain"""
        with patch('aiohttp.ClientSession.head') as mock_head:
            # Simulate redirect chain: short URL -> landing page -> final destination
            mock_responses = [
                # First request - redirect to intermediate
                Mock(status=302, headers={'Location': 'https://intermediate.com/page'}),
                # Second request - redirect to final
                Mock(status=302, headers={'Location': 'https://final-destination.com/page'}),
                # Third request - final destination
                Mock(status=200, headers={})
            ]
            
            mock_head.side_effect = mock_responses
            
            result = await self.analyzer.trace_redirects("https://short.ly/abc123")
            
            assert result is not None
            assert len(result.redirect_chain) == 3
            assert result.redirect_chain[0] == "https://short.ly/abc123"
            assert result.redirect_chain[1] == "https://intermediate.com/page"
            assert result.redirect_chain[2] == "https://final-destination.com/page"
            assert result.final_url == "https://final-destination.com/page"
            assert result.redirect_count == 2
    
    @pytest.mark.asyncio
    async def test_redirect_loop_detection(self):
        """Test detection of redirect loops"""
        with patch('aiohttp.ClientSession.head') as mock_head:
            # Simulate redirect loop
            mock_responses = [
                Mock(status=302, headers={'Location': 'https://site-b.com'}),
                Mock(status=302, headers={'Location': 'https://site-c.com'}),
                Mock(status=302, headers={'Location': 'https://site-a.com'}),  # Back to start
            ]
            
            mock_head.side_effect = mock_responses
            
            result = await self.analyzer.trace_redirects("https://site-a.com")
            
            assert result is not None
            assert result.has_loop
            assert result.threat_indicators['redirect_loop']
    
    @pytest.mark.asyncio
    async def test_excessive_redirects(self):
        """Test detection of excessive redirects"""
        with patch('aiohttp.ClientSession.head') as mock_head:
            # Simulate excessive redirects (> 10)
            mock_responses = []
            for i in range(15):
                mock_responses.append(
                    Mock(status=302, headers={'Location': f'https://site{i}.com'})
                )
            
            mock_head.side_effect = mock_responses
            
            result = await self.analyzer.trace_redirects("https://start.com")
            
            assert result is not None
            assert result.redirect_count > 10
            assert result.threat_indicators['excessive_redirects']
    
    @pytest.mark.asyncio
    async def test_domain_cloaking_detection(self):
        """Test detection of domain cloaking"""
        with patch('aiohttp.ClientSession.head') as mock_head:
            # Simulate cloaking: legitimate-looking domain -> malicious domain
            mock_responses = [
                Mock(status=302, headers={'Location': 'https://google-security-check.evil.com/verify'}),
                Mock(status=200, headers={})
            ]
            
            mock_head.side_effect = mock_responses
            
            result = await self.analyzer.trace_redirects("https://google-security.com/verify")
            
            assert result is not None
            assert result.threat_indicators['domain_cloaking']
            assert result.cloaking_domains is not None
            assert len(result.cloaking_domains) > 0
    
    @pytest.mark.asyncio
    async def test_suspicious_tld_detection(self):
        """Test detection of suspicious TLDs"""
        with patch('aiohttp.ClientSession.head') as mock_head:
            # Simulate redirect to suspicious TLD
            mock_responses = [
                Mock(status=302, headers={'Location': 'https://legitimate-bank.tk/login'}),
                Mock(status=200, headers={})
            ]
            
            mock_head.side_effect = mock_responses
            
            result = await self.analyzer.trace_redirects("https://bank-security.com")
            
            assert result is not None
            assert result.threat_indicators['suspicious_tld']
    
    @pytest.mark.asyncio
    async def test_http_to_https_downgrade(self):
        """Test detection of HTTPS to HTTP downgrades"""
        with patch('aiohttp.ClientSession.head') as mock_head:
            # Simulate HTTPS -> HTTP downgrade
            mock_responses = [
                Mock(status=302, headers={'Location': 'http://insecure-site.com/login'}),
                Mock(status=200, headers={})
            ]
            
            mock_head.side_effect = mock_responses
            
            result = await self.analyzer.trace_redirects("https://secure-start.com")
            
            assert result is not None
            assert result.threat_indicators['https_downgrade']
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Test handling of request timeouts"""
        with patch('aiohttp.ClientSession.head') as mock_head:
            # Simulate timeout
            mock_head.side_effect = asyncio.TimeoutError("Request timeout")
            
            result = await self.analyzer.trace_redirects("https://slow-site.com")
            
            assert result is not None
            assert result.error is not None
            assert "timeout" in result.error.lower()


class TestSanitizer:
    """Test PII sanitizer functionality"""
    
    def setup_method(self):
        """Set up test sanitizer"""
        self.sanitizer = get_pii_sanitizer()
    
    def test_email_sanitization(self):
        """Test email address sanitization"""
        test_content = "Contact support at john.doe@company.com for assistance"
        
        result = self.sanitizer.sanitize_for_third_party(test_content, "virustotal")
        sanitized = result['sanitized_content']
        
        assert "john.doe@company.com" not in sanitized
        assert "[EMAIL_ADDRESS]" in sanitized or "***" in sanitized
        assert "company.com" in sanitized  # Domain should be preserved for threat analysis
    
    def test_phone_sanitization(self):
        """Test phone number sanitization"""
        test_content = "Call us at +1 (555) 123-4567 or 555.123.4567"
        
        result = self.sanitizer.sanitize_for_third_party(test_content, "gemini")
        sanitized = result['sanitized_content']
        
        assert "555-123-4567" not in sanitized
        assert "555.123.4567" not in sanitized
        assert "[PHONE_NUMBER]" in sanitized or "***" in sanitized
    
    def test_ssn_sanitization(self):
        """Test SSN sanitization"""
        test_content = "SSN: 123-45-6789 for verification"
        
        result = self.sanitizer.sanitize_for_third_party(test_content, "openai")
        sanitized = result['sanitized_content']
        
        assert "123-45-6789" not in sanitized
        assert "[SSN]" in sanitized or "***" in sanitized
    
    def test_credit_card_sanitization(self):
        """Test credit card number sanitization"""
        test_content = "Card number: 4532-1234-5678-9012 expires 12/25"
        
        result = self.sanitizer.sanitize_for_third_party(test_content, "anthropic")
        sanitized = result['sanitized_content']
        
        assert "4532-1234-5678-9012" not in sanitized
        assert "[CREDIT_CARD]" in sanitized or "***" in sanitized
    
    def test_url_token_sanitization(self):
        """Test URL token/parameter sanitization"""
        test_content = "Reset password: https://site.com/reset?token=abc123secret&user=john.doe@site.com"
        
        result = self.sanitizer.sanitize_for_third_party(test_content, "virustotal")
        sanitized = result['sanitized_content']
        
        assert "abc123secret" not in sanitized
        assert "john.doe@site.com" not in sanitized
        assert "site.com" in sanitized  # Domain should be preserved
    
    def test_mixed_pii_sanitization(self):
        """Test sanitization of mixed PII types"""
        test_content = """
        Dear John Doe,
        
        Your account john.doe@company.com has been compromised.
        Please call us at (555) 123-4567 immediately.
        
        For verification, we'll need:
        - SSN: 123-45-6789
        - Credit Card: 4532-1234-5678-9012
        - Account: https://bank.com/login?user=john.doe@company.com&token=secret123
        
        Thank you,
        Security Team
        """
        
        result = self.sanitizer.sanitize_for_third_party(test_content, "gemini")
        sanitized = result['sanitized_content']
        
        # Verify all PII types are redacted
        assert "john.doe@company.com" not in sanitized
        assert "555-123-4567" not in sanitized
        assert "123-45-6789" not in sanitized
        assert "4532-1234-5678-9012" not in sanitized
        assert "secret123" not in sanitized
        
        # Verify structure and domains are preserved
        assert "company.com" in sanitized
        assert "bank.com" in sanitized
        assert "Dear" in sanitized
        assert "Security Team" in sanitized
    
    def test_service_specific_sanitization(self):
        """Test service-specific sanitization rules"""
        test_content = "Contact: john.doe@company.com, Phone: 555-123-4567"
        
        # Test different services have appropriate sanitization
        services = ["virustotal", "gemini", "openai", "anthropic"]
        
        for service in services:
            result = self.sanitizer.sanitize_for_third_party(test_content, service)
            sanitized = result['sanitized_content']
            
            # All services should redact PII
            assert "john.doe@company.com" not in sanitized
            assert "555-123-4567" not in sanitized
            
            # But preserve structure for analysis
            assert "company.com" in sanitized or "[EMAIL_DOMAIN]" in sanitized
    
    def test_sanitization_preserves_threats(self):
        """Test that sanitization preserves threat indicators"""
        test_content = """
        URGENT: Your account john.doe@company.com will be suspended!
        
        Click here immediately: https://fake-bank.evil.com/verify?user=john.doe@company.com&urgent=true
        
        Enter your:
        - Password
        - SSN: 123-45-6789
        - Credit Card: 4532-1234-5678-9012
        """
        
        result = self.sanitizer.sanitize_for_third_party(test_content, "gemini")
        sanitized = result['sanitized_content']
        
        # PII should be redacted
        assert "john.doe@company.com" not in sanitized
        assert "123-45-6789" not in sanitized
        assert "4532-1234-5678-9012" not in sanitized
        
        # Threat indicators should be preserved
        assert "URGENT" in sanitized
        assert "suspended" in sanitized
        assert "fake-bank.evil.com" in sanitized
        assert "Password" in sanitized
        assert "Credit Card" in sanitized


class TestIntegrationMockScenarios:
    """Test integration scenarios with comprehensive mocking"""
    
    @pytest.mark.asyncio
    async def test_full_scan_pipeline_mock(self):
        """Test complete scan pipeline with all mocked services"""
        with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
             patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse, \
             patch('app.services.analysis.link_redirect_analyzer.LinkRedirectAnalyzer.trace_redirects') as mock_redirect:
            
            # Mock service responses
            mock_vt.return_value = Mock(
                scan_id="test-scan-123",
                positives=8,
                total=70,
                permalink="https://virustotal.com/test"
            )
            
            mock_gemini.return_value = {
                'threat_probability': 0.75,
                'confidence': 0.88,
                'reasoning': 'Suspicious phishing indicators detected',
                'risk_factors': ['urgent_language', 'credential_request']
            }
            
            mock_abuse.return_value = Mock(
                ip_address="203.0.113.50",
                abuse_confidence=65,
                total_reports=25
            )
            
            mock_redirect.return_value = Mock(
                final_url="https://suspicious-site.com/login",
                redirect_chain=["https://bit.ly/abc", "https://suspicious-site.com/login"],
                redirect_count=1,
                has_loop=False,
                threat_indicators={'domain_cloaking': True, 'suspicious_tld': False},
                cloaking_domains=["suspicious-site.com"]
            )
            
            # Test orchestrator integration
            orchestrator = PhishNetOrchestrator()
            
            result = await orchestrator.scan_email(
                user_id="test_user",
                email_id="test_email_123",
                subject="URGENT: Verify your account immediately",
                sender="security@fake-bank.com",
                body="Click here to verify: https://bit.ly/abc",
                links=["https://bit.ly/abc"]
            )
            
            # Verify complete pipeline execution
            assert result is not None
            assert result.overall_threat_level in ["MEDIUM", "HIGH"]
            assert result.confidence_score > 0.7
            assert len(result.evidence_links) > 0
            
            # Verify all services were called
            mock_vt.assert_called_once()
            mock_gemini.assert_called_once()
            mock_abuse.assert_called_once()
            mock_redirect.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
