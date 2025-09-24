"""
Integration tests for the unified threat intelligence service.

Tests cache behavior, fallback scenarios, API integrations, and privacy protection.
"""

import asyncio
import os
import sys
import pytest
import pytest_asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, AsyncMock
from typing import Dict, Any

# Add backend to Python path
backend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.integrations.unified_service import (
    UnifiedThreatIntelligenceService, 
    ThreatIntelligenceConfig
)
from app.integrations.threat_intel.base import ThreatLevel, ResourceType, APIStatus
from app.integrations.caching import ThreatIntelligenceCache


@pytest.fixture
def test_config():
    """Test configuration with mock API keys."""
    return ThreatIntelligenceConfig(
        virustotal_api_key="test_vt_key",
        abuseipdb_api_key="test_abuse_key", 
        gemini_api_key="test_gemini_key",
        redis_url="redis://localhost:6379",
        cache_enabled=True,
        pii_sanitization_enabled=True,
        audit_logging_enabled=True
    )


@pytest_asyncio.fixture
async def unified_service(test_config):
    """Create and initialize unified service for testing."""
    service = UnifiedThreatIntelligenceService(test_config)
    
    # Mock external API clients to avoid real API calls
    with patch('app.integrations.threat_intel.virustotal.VirusTotalClient') as mock_vt, \
         patch('app.integrations.threat_intel.abuseipdb.AbuseIPDBClient') as mock_abuse, \
         patch('app.integrations.threat_intel.gemini.GeminiClient') as mock_gemini:
        
        await service.initialize()
        yield service
        await service.close()


@pytest_asyncio.fixture
async def redis_cache():
    """Create Redis cache for testing."""
    cache = ThreatIntelligenceCache("redis://localhost:6379")
    yield cache
    await cache.close()


class TestCacheBehavior:
    """Test caching functionality and behavior."""
    
    @pytest.mark.asyncio
    async def test_cache_miss_then_hit(self, unified_service):
        """Test that first query hits API, subsequent queries hit cache."""
        url = "https://test-suspicious.com"
        
        # Mock VirusTotal response
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.data = MagicMock()
        mock_response.data.threat_level = ThreatLevel.HIGH
        mock_response.data.confidence = 0.85
        mock_response.data.details = {"scan_result": "malicious"}
        
        with patch.object(unified_service.resilient_clients["virustotal"], 'resilient_call', 
                         return_value=mock_response) as mock_call:
            
            # First analysis - should hit API
            result1 = await unified_service.analyze_url(url)
            assert not result1.cache_hit
            assert mock_call.call_count == 1
            
            # Second analysis - should hit cache
            result2 = await unified_service.analyze_url(url)
            assert result2.cache_hit
            assert mock_call.call_count == 1  # No additional API calls
            
            # Verify results are consistent
            assert result1.aggregated_score == result2.aggregated_score
            assert result1.primary_result.threat_level == result2.primary_result.threat_level
    
    @pytest.mark.asyncio
    async def test_cache_ttl_expiration(self, unified_service):
        """Test that cache entries expire after TTL."""
        url = "https://test-ttl.com"
        
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.data = MagicMock()
        mock_response.data.threat_level = ThreatLevel.LOW
        mock_response.data.confidence = 0.5
        
        with patch.object(unified_service.resilient_clients["virustotal"], 'resilient_call',
                         return_value=mock_response) as mock_call:
            
            # Set very short TTL for testing
            original_calculate_ttl = unified_service.cache._calculate_ttl
            unified_service.cache._calculate_ttl = lambda threat_level: 1  # 1 second TTL
            
            try:
                # First call
                result1 = await unified_service.analyze_url(url)
                assert not result1.cache_hit
                
                # Immediate second call - should hit cache
                result2 = await unified_service.analyze_url(url)
                assert result2.cache_hit
                
                # Wait for TTL expiration
                await asyncio.sleep(2)
                
                # Third call - should hit API again
                result3 = await unified_service.analyze_url(url)
                assert not result3.cache_hit
                assert mock_call.call_count == 2
                
            finally:
                unified_service.cache._calculate_ttl = original_calculate_ttl
    
    @pytest.mark.asyncio
    async def test_cache_different_resources(self, unified_service):
        """Test that different resources have separate cache entries."""
        url1 = "https://site1.com"
        url2 = "https://site2.com"
        
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.data = MagicMock()
        mock_response.data.threat_level = ThreatLevel.SAFE
        mock_response.data.confidence = 0.9
        
        with patch.object(unified_service.resilient_clients["virustotal"], 'resilient_call',
                         return_value=mock_response) as mock_call:
            
            # Analyze different URLs
            result1 = await unified_service.analyze_url(url1)
            result2 = await unified_service.analyze_url(url2)
            
            # Both should be cache misses
            assert not result1.cache_hit
            assert not result2.cache_hit
            assert mock_call.call_count == 2
            
            # Re-analyze same URLs - should hit cache
            result3 = await unified_service.analyze_url(url1)
            result4 = await unified_service.analyze_url(url2)
            
            assert result3.cache_hit
            assert result4.cache_hit
            assert mock_call.call_count == 2  # No additional calls


class TestFallbackScenarios:
    """Test fallback behavior during service outages."""
    
    @pytest.mark.asyncio
    async def test_single_service_failure(self, unified_service):
        """Test behavior when one service fails but others succeed."""
        url = "https://test-fallback.com"
        
        # Mock VirusTotal failure
        vt_failure = Exception("VirusTotal API unavailable")
        
        # Mock Gemini success
        gemini_success = MagicMock()
        gemini_success.success = True
        gemini_success.data = MagicMock()
        gemini_success.data.threat_level = ThreatLevel.MEDIUM
        gemini_success.data.confidence = 0.7
        
        with patch.object(unified_service.resilient_clients["virustotal"], 'resilient_call',
                         side_effect=vt_failure), \
             patch.object(unified_service.resilient_clients["gemini"], 'resilient_call',
                         return_value=gemini_success):
            
            result = await unified_service.analyze_url(url)
            
            # Should have error for VirusTotal but still get Gemini result
            assert len(result.errors) > 0
            assert any("virustotal" in error.lower() for error in result.errors)
            
            # Should still have analysis result from Gemini
            assert result.primary_result is not None
            assert result.aggregated_score > 0
            assert "gemini" in result.sources_used
            assert "virustotal" not in result.sources_used
    
    @pytest.mark.asyncio
    async def test_all_services_failure(self, unified_service):
        """Test behavior when all services fail."""
        url = "https://test-all-fail.com"
        
        failure = Exception("All services unavailable")
        
        with patch.object(unified_service.resilient_clients["virustotal"], 'resilient_call',
                         side_effect=failure), \
             patch.object(unified_service.resilient_clients["gemini"], 'resilient_call',
                         side_effect=failure):
            
            result = await unified_service.analyze_url(url)
            
            # Should have errors for all services
            assert len(result.errors) >= 2
            
            # Should have no successful results
            assert result.primary_result is None
            assert result.aggregated_score == 0.0
            assert len(result.sources_used) == 0
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_behavior(self, unified_service):
        """Test circuit breaker opens after consecutive failures."""
        url = "https://test-circuit-breaker.com"
        
        # Mock consecutive failures to trip circuit breaker
        failure = Exception("Service consistently failing")
        
        with patch.object(unified_service.resilient_clients["virustotal"], 'resilient_call',
                         side_effect=failure):
            
            # Make multiple failing requests
            for i in range(5):
                result = await unified_service.analyze_url(f"{url}?attempt={i}")
                assert len(result.errors) > 0
            
            # Check circuit breaker state
            health = await unified_service.get_service_health()
            vt_health = health["virustotal"]
            
            # Circuit breaker should be open or half-open after failures
            assert vt_health.circuit_breaker_state in ["open", "half_open"]
            assert not vt_health.is_healthy


class TestQuotaTracking:
    """Test API quota tracking functionality."""
    
    @pytest.mark.asyncio
    async def test_quota_decrements(self, unified_service):
        """Test that quota tracking decrements correctly."""
        url = "https://test-quota.com"
        
        # Mock response with quota info
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.data = MagicMock()
        mock_response.data.threat_level = ThreatLevel.SAFE
        mock_response.data.confidence = 0.8
        
        # Mock quota tracking
        initial_quota = 1000
        with patch.object(unified_service.services["virustotal"], 'get_quota_status',
                         return_value={"requests_remaining": initial_quota}):
            
            with patch.object(unified_service.resilient_clients["virustotal"], 'resilient_call',
                             return_value=mock_response):
                
                # Make analysis request
                result = await unified_service.analyze_url(url)
                assert result.aggregated_score > 0
                
                # Check health includes quota info
                health = await unified_service.get_service_health()
                vt_health = health["virustotal"]
                
                # Should have quota information
                assert vt_health.quota_remaining is not None
    
    @pytest.mark.asyncio
    async def test_quota_exhaustion_handling(self, unified_service):
        """Test behavior when API quota is exhausted."""
        url = "https://test-quota-exhausted.com"
        
        # Mock quota exhausted response
        quota_error = Exception("API quota exceeded")
        
        with patch.object(unified_service.resilient_clients["virustotal"], 'resilient_call',
                         side_effect=quota_error):
            
            result = await unified_service.analyze_url(url)
            
            # Should handle quota exhaustion gracefully
            assert len(result.errors) > 0
            assert any("quota" in error.lower() or "exceeded" in error.lower() 
                      for error in result.errors)


class TestPrivacyProtection:
    """Test privacy protection and PII sanitization."""
    
    @pytest.mark.asyncio
    async def test_pii_sanitization(self, unified_service):
        """Test that PII is sanitized before API calls."""
        # Content with PII
        pii_content = """
        Dear john.doe@example.com,
        Your account has been suspended.
        Please call us at (555) 123-4567 or visit https://malicious-site.com
        Reference ID: SSN 123-45-6789
        """
        
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.data = MagicMock()
        mock_response.data.threat_level = ThreatLevel.HIGH
        mock_response.data.confidence = 0.9
        
        with patch.object(unified_service.privacy_wrappers["gemini"], 'safe_analyze_content',
                         return_value=(mock_response, {"pii_detected": True, "fields_sanitized": ["email", "phone", "ssn"]})) as mock_safe_call:
            
            result = await unified_service.analyze_content(pii_content)
            
            # Should indicate privacy protection was used
            assert result.privacy_protected
            assert len(result.audit_logs) > 0
            
            # Verify safe_analyze_content was called
            mock_safe_call.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_audit_logging(self, unified_service):
        """Test that privacy-related actions are logged."""
        url = "https://test-audit.com"
        
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.data = MagicMock()
        mock_response.data.threat_level = ThreatLevel.LOW
        mock_response.data.confidence = 0.6
        
        audit_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "service": "virustotal",
            "action": "analyze_url",
            "pii_detected": False,
            "data_sent": "sanitized_url"
        }
        
        with patch.object(unified_service.privacy_wrappers["virustotal"], 'safe_analyze_url',
                         return_value=(mock_response, audit_log)):
            
            result = await unified_service.analyze_url(url)
            
            # Should have audit log
            assert len(result.audit_logs) > 0
            audit_entry = result.audit_logs[0]
            assert "service" in audit_entry
            assert "timestamp" in audit_entry
            assert "action" in audit_entry


class TestServiceHealth:
    """Test service health monitoring."""
    
    @pytest.mark.asyncio
    async def test_health_status_healthy(self, unified_service):
        """Test health status when all services are healthy."""
        # Mock healthy responses
        for service_name in unified_service.resilient_clients:
            mock_health = {
                "circuit_breaker": {
                    "state": "closed",
                    "last_success": datetime.utcnow().isoformat(),
                    "failure_count": 0
                },
                "quota": {"requests_remaining": 1000}
            }
            
            with patch.object(unified_service.resilient_clients[service_name], 'get_health_status',
                             return_value=mock_health):
                pass
        
        health = await unified_service.get_service_health()
        
        # All services should be healthy
        for service_name, service_health in health.items():
            assert service_health.is_healthy
            assert service_health.circuit_breaker_state == "closed"
    
    @pytest.mark.asyncio
    async def test_health_status_degraded(self, unified_service):
        """Test health status when some services are degraded."""
        # Mock mixed health states
        health_states = {
            "virustotal": {
                "circuit_breaker": {"state": "closed", "last_success": datetime.utcnow().isoformat()},
                "quota": {"requests_remaining": 1000}
            },
            "abuseipdb": {
                "circuit_breaker": {"state": "half_open", "last_failure": datetime.utcnow().isoformat()},
                "quota": {"requests_remaining": 100}
            },
            "gemini": {
                "circuit_breaker": {"state": "open", "last_failure": datetime.utcnow().isoformat()},
                "quota": {"requests_remaining": 0}
            }
        }
        
        for service_name, mock_health in health_states.items():
            if service_name in unified_service.resilient_clients:
                with patch.object(unified_service.resilient_clients[service_name], 'get_health_status',
                                 return_value=mock_health):
                    pass
        
        health = await unified_service.get_service_health()
        
        # Should reflect mixed health states
        assert any(not h.is_healthy for h in health.values())
        assert any(h.is_healthy for h in health.values())


class TestPerformanceMetrics:
    """Test performance monitoring and metrics."""
    
    @pytest.mark.asyncio
    async def test_processing_time_tracking(self, unified_service):
        """Test that processing times are tracked correctly."""
        url = "https://test-performance.com"
        
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.data = MagicMock()
        mock_response.data.threat_level = ThreatLevel.SAFE
        mock_response.data.confidence = 0.8
        
        # Add artificial delay
        async def delayed_call(*args, **kwargs):
            await asyncio.sleep(0.1)  # 100ms delay
            return mock_response
        
        with patch.object(unified_service.resilient_clients["virustotal"], 'resilient_call',
                         side_effect=delayed_call):
            
            result = await unified_service.analyze_url(url)
            
            # Should track processing time
            assert result.processing_time > 0.1  # At least 100ms
            assert result.processing_time < 1.0   # But reasonable
    
    @pytest.mark.asyncio
    async def test_cache_performance_metrics(self, unified_service):
        """Test cache performance metrics."""
        url = "https://test-cache-metrics.com"
        
        mock_response = MagicMock()
        mock_response.success = True
        mock_response.data = MagicMock()
        mock_response.data.threat_level = ThreatLevel.MEDIUM
        mock_response.data.confidence = 0.75
        
        with patch.object(unified_service.resilient_clients["virustotal"], 'resilient_call',
                         return_value=mock_response):
            
            # First call - cache miss
            result1 = await unified_service.analyze_url(url)
            
            # Second call - cache hit
            result2 = await unified_service.analyze_url(url)
            
            # Get cache stats
            cache_stats = await unified_service.get_cache_stats()
            
            # Should show cache activity
            assert cache_stats.get("hits", 0) > 0
            assert cache_stats.get("total_keys", 0) > 0
            
            # Cache hit should be faster
            assert result2.processing_time < result1.processing_time


if __name__ == "__main__":
    pytest.main([__file__, "-v"])