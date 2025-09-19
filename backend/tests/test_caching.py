"""
Caching System Tests
Tests for Redis caching, VirusTotal cache utilization, and cache performance
"""

import pytest
import asyncio
import json
import time
from typing import Dict, Any, Optional
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta

# Import modules to test
from app.core.cache_manager import CacheManager, CacheKey
from app.integrations.virustotal import VirusTotalClient
from app.services.threat_analyzer import ThreatAnalysisResult


class TestCacheManager:
    """Test core caching functionality"""
    
    @pytest.fixture
    def cache_manager(self, mock_redis):
        """Cache manager with mocked Redis"""
        with patch('app.core.cache_manager.get_redis_client') as mock_get_redis:
            mock_get_redis.return_value = mock_redis
            return CacheManager()
    
    @pytest.fixture
    def sample_cache_data(self):
        """Sample data for caching tests"""
        return {
            "url_scan_result": {
                "url": "https://example.com",
                "scan_id": "vt_scan_12345",
                "positives": 0,
                "total": 70,
                "scan_date": "2024-01-01T12:00:00Z",
                "permalink": "https://virustotal.com/url/12345"
            },
            "threat_analysis": {
                "scan_id": "threat_analysis_67890",
                "overall_threat_level": "LOW",
                "confidence_score": 0.95,
                "subject_analysis": {"threat_score": 0.1},
                "body_analysis": {"threat_score": 0.05},
                "link_analysis": [{"threat_score": 0.02}],
                "timestamp": time.time()
            },
            "redirect_chain": {
                "original_url": "https://bit.ly/test123",
                "final_url": "https://legitimate-site.com/page",
                "total_redirects": 1,
                "threat_score": 0.15,
                "cached_at": time.time()
            }
        }
    
    @pytest.mark.asyncio
    async def test_basic_cache_operations(self, cache_manager, sample_cache_data, mock_redis):
        """Test basic cache set/get operations"""
        test_key = "test:cache:key"
        test_data = sample_cache_data["url_scan_result"]
        
        # Configure mock
        mock_redis.get.return_value = None
        mock_redis.set.return_value = True
        
        # Test cache miss
        result = await cache_manager.get(test_key)
        assert result is None
        mock_redis.get.assert_called_with(test_key)
        
        # Test cache set
        await cache_manager.set(test_key, test_data, ttl=3600)
        mock_redis.set.assert_called_with(
            test_key, 
            json.dumps(test_data, default=str), 
            ex=3600
        )
        
        # Test cache hit
        mock_redis.get.return_value = json.dumps(test_data, default=str)
        result = await cache_manager.get(test_key)
        
        assert result == test_data
    
    @pytest.mark.asyncio
    async def test_cache_key_generation(self, cache_manager):
        """Test cache key generation for different data types"""
        
        # URL scan key
        url_key = cache_manager.generate_key(CacheKey.URL_SCAN, "https://example.com")
        assert url_key == "phishnet:url_scan:https://example.com"
        
        # Threat analysis key
        threat_key = cache_manager.generate_key(CacheKey.THREAT_ANALYSIS, "email_123")
        assert threat_key == "phishnet:threat_analysis:email_123"
        
        # Redirect analysis key
        redirect_key = cache_manager.generate_key(CacheKey.REDIRECT_ANALYSIS, "https://bit.ly/test")
        assert redirect_key == "phishnet:redirect_analysis:https://bit.ly/test"
        
        # User consent key
        consent_key = cache_manager.generate_key(CacheKey.USER_CONSENT, "user_456")
        assert consent_key == "phishnet:user_consent:user_456"
    
    @pytest.mark.asyncio
    async def test_cache_expiration(self, cache_manager, mock_redis):
        """Test cache expiration and TTL handling"""
        test_key = "test:expiration"
        test_data = {"test": "data"}
        
        # Test different TTL values
        ttl_configs = [
            (3600, "1 hour TTL"),
            (86400, "24 hour TTL"),
            (None, "No expiration")
        ]
        
        for ttl, description in ttl_configs:
            await cache_manager.set(test_key, test_data, ttl=ttl)
            
            if ttl:
                mock_redis.set.assert_called_with(
                    test_key,
                    json.dumps(test_data, default=str),
                    ex=ttl
                )
            else:
                mock_redis.set.assert_called_with(
                    test_key,
                    json.dumps(test_data, default=str)
                )
    
    @pytest.mark.asyncio
    async def test_cache_deletion(self, cache_manager, mock_redis):
        """Test cache deletion operations"""
        test_key = "test:deletion"
        
        mock_redis.delete.return_value = 1
        
        result = await cache_manager.delete(test_key)
        assert result is True
        mock_redis.delete.assert_called_with(test_key)
        
        # Test deletion of non-existent key
        mock_redis.delete.return_value = 0
        result = await cache_manager.delete("non_existent_key")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_cache_pattern_deletion(self, cache_manager, mock_redis):
        """Test deletion of keys by pattern"""
        pattern = "phishnet:user_123:*"
        
        # Mock keys matching pattern
        mock_redis.keys.return_value = [
            "phishnet:user_123:scan_1",
            "phishnet:user_123:scan_2",
            "phishnet:user_123:consent"
        ]
        mock_redis.delete.return_value = 3
        
        result = await cache_manager.delete_pattern(pattern)
        assert result == 3
        mock_redis.keys.assert_called_with(pattern)
        mock_redis.delete.assert_called_once()


class TestVirusTotalCaching:
    """Test VirusTotal result caching and utilization"""
    
    @pytest.fixture
    def vt_client(self, mock_redis):
        """VirusTotal client with mocked cache"""
        with patch('app.core.cache_manager.get_redis_client') as mock_get_redis:
            mock_get_redis.return_value = mock_redis
            return VirusTotalClient(api_key="test_api_key")
    
    @pytest.fixture
    def sample_vt_responses(self):
        """Sample VirusTotal API responses"""
        return {
            "clean_url": {
                "scan_id": "clean_scan_123",
                "positives": 0,
                "total": 70,
                "scan_date": "2024-01-01 12:00:00",
                "permalink": "https://virustotal.com/url/clean_scan_123",
                "url": "https://legitimate-site.com"
            },
            "malicious_url": {
                "scan_id": "malicious_scan_456",
                "positives": 15,
                "total": 70,
                "scan_date": "2024-01-01 12:00:00",
                "permalink": "https://virustotal.com/url/malicious_scan_456",
                "url": "https://malicious-site.evil"
            }
        }
    
    @pytest.mark.asyncio
    async def test_vt_cache_miss_and_store(self, vt_client, sample_vt_responses, mock_redis):
        """Test VirusTotal cache miss, API call, and result storage"""
        test_url = "https://new-site.com"
        vt_response = sample_vt_responses["clean_url"].copy()
        vt_response["url"] = test_url
        
        # Configure cache miss
        mock_redis.get.return_value = None
        mock_redis.set.return_value = True
        
        # Mock VirusTotal API response
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = Mock()
            mock_response.status = 200
            mock_response.json.return_value = asyncio.coroutine(lambda: vt_response)()
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await vt_client.scan_url(test_url)
            
            # Verify API was called
            mock_get.assert_called_once()
            
            # Verify result was cached
            cache_key = f"phishnet:url_scan:{test_url}"
            mock_redis.set.assert_called_once()
            
            # Verify correct result
            assert result["positives"] == 0
            assert result["url"] == test_url
    
    @pytest.mark.asyncio
    async def test_vt_cache_hit(self, vt_client, sample_vt_responses, mock_redis):
        """Test VirusTotal cache hit - no API call"""
        test_url = "https://cached-site.com"
        cached_response = sample_vt_responses["clean_url"].copy()
        cached_response["url"] = test_url
        
        # Configure cache hit
        mock_redis.get.return_value = json.dumps(cached_response, default=str)
        
        # Mock VirusTotal API (should not be called)
        with patch('aiohttp.ClientSession.get') as mock_get:
            result = await vt_client.scan_url(test_url)
            
            # Verify API was NOT called
            mock_get.assert_not_called()
            
            # Verify cached result was returned
            assert result["positives"] == 0
            assert result["url"] == test_url
    
    @pytest.mark.asyncio
    async def test_vt_cache_expiration_and_refresh(self, vt_client, sample_vt_responses, mock_redis):
        """Test VirusTotal cache expiration and refresh"""
        test_url = "https://expired-cache.com"
        old_response = sample_vt_responses["clean_url"].copy()
        new_response = sample_vt_responses["malicious_url"].copy()
        new_response["url"] = test_url
        
        # First call - cache miss
        mock_redis.get.return_value = None
        mock_redis.set.return_value = True
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = Mock()
            mock_response.status = 200
            mock_response.json.return_value = asyncio.coroutine(lambda: old_response)()
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result1 = await vt_client.scan_url(test_url)
            assert result1["positives"] == 0
            
            # Second call - cache expired, new scan shows malicious
            mock_redis.get.return_value = None  # Simulate expiration
            mock_response.json.return_value = asyncio.coroutine(lambda: new_response)()
            
            result2 = await vt_client.scan_url(test_url)
            assert result2["positives"] == 15  # Now shows as malicious
    
    @pytest.mark.asyncio
    async def test_vt_quota_protection_with_cache(self, vt_client, mock_redis):
        """Test that caching protects VirusTotal API quota"""
        test_urls = [
            "https://site1.com",
            "https://site2.com", 
            "https://site1.com",  # Repeat - should use cache
            "https://site3.com",
            "https://site2.com"   # Repeat - should use cache
        ]
        
        api_call_count = 0
        
        def mock_api_call(*args, **kwargs):
            nonlocal api_call_count
            api_call_count += 1
            return {
                "scan_id": f"scan_{api_call_count}",
                "positives": 0,
                "total": 70
            }
        
        # Configure cache behavior
        cache_data = {}
        
        def mock_get(key):
            return cache_data.get(key)
        
        def mock_set(key, value, ex=None):
            cache_data[key] = value
            return True
        
        mock_redis.get.side_effect = mock_get
        mock_redis.set.side_effect = mock_set
        
        with patch('aiohttp.ClientSession.get') as mock_get_api:
            mock_response = Mock()
            mock_response.status = 200
            mock_response.json.side_effect = [
                asyncio.coroutine(lambda: mock_api_call())() for _ in range(10)
            ]
            mock_get_api.return_value.__aenter__.return_value = mock_response
            
            # Scan all URLs
            for url in test_urls:
                await vt_client.scan_url(url)
            
            # Should only make 3 API calls (site1, site2, site3)
            # Repeated URLs should use cache
            assert api_call_count == 3
            assert mock_get_api.call_count == 3


class TestThreatAnalysisCaching:
    """Test threat analysis result caching"""
    
    @pytest.fixture
    def threat_analyzer(self, mock_redis):
        """Threat analyzer with mocked cache"""
        with patch('app.core.cache_manager.get_redis_client') as mock_get_redis:
            mock_get_redis.return_value = mock_redis
            from app.services.threat_analyzer import ThreatAnalyzer
            return ThreatAnalyzer()
    
    @pytest.mark.asyncio
    async def test_threat_analysis_caching(self, threat_analyzer, mock_redis):
        """Test caching of complete threat analysis results"""
        email_id = "test_email_123"
        email_data = {
            "subject": "Test email subject",
            "body": "Test email body content",
            "links": ["https://example.com"],
            "sender": "test@example.com"
        }
        
        # Mock cache miss initially
        mock_redis.get.return_value = None
        mock_redis.set.return_value = True
        
        # Mock analysis result
        with patch.object(threat_analyzer, '_perform_analysis') as mock_analyze:
            mock_result = ThreatAnalysisResult(
                scan_id=email_id,
                overall_threat_level="LOW",
                confidence_score=0.95,
                subject_analysis={"threat_score": 0.1},
                body_analysis={"threat_score": 0.05},
                link_analysis=[{"threat_score": 0.02}],
                timestamp=time.time()
            )
            mock_analyze.return_value = mock_result
            
            # First analysis - should perform full analysis
            result1 = await threat_analyzer.analyze_email(email_id, email_data)
            
            # Verify analysis was performed
            mock_analyze.assert_called_once()
            
            # Verify result was cached
            cache_key = f"phishnet:threat_analysis:{email_id}"
            mock_redis.set.assert_called_once()
            
            # Second analysis - should use cache
            mock_redis.get.return_value = json.dumps(mock_result.to_dict(), default=str)
            
            result2 = await threat_analyzer.analyze_email(email_id, email_data)
            
            # Should not perform analysis again
            assert mock_analyze.call_count == 1
            
            # Results should be identical
            assert result1.overall_threat_level == result2.overall_threat_level
            assert result1.confidence_score == result2.confidence_score
    
    @pytest.mark.asyncio
    async def test_partial_cache_utilization(self, threat_analyzer, mock_redis):
        """Test utilizing cached components in threat analysis"""
        email_id = "partial_cache_test"
        email_data = {
            "subject": "Test subject",
            "body": "Test body with link https://cached-site.com",
            "links": ["https://cached-site.com", "https://new-site.com"],
            "sender": "test@example.com"
        }
        
        # Mock cached URL scan for one URL
        cached_url_result = {
            "scan_id": "cached_scan",
            "positives": 0,
            "total": 70,
            "url": "https://cached-site.com"
        }
        
        def mock_cache_get(key):
            if "https://cached-site.com" in key:
                return json.dumps(cached_url_result, default=str)
            return None
        
        mock_redis.get.side_effect = mock_cache_get
        mock_redis.set.return_value = True
        
        with patch('app.integrations.virustotal.VirusTotalClient.scan_url') as mock_vt:
            # Should only be called for non-cached URL
            mock_vt.return_value = {
                "scan_id": "new_scan",
                "positives": 2,
                "total": 70,
                "url": "https://new-site.com"
            }
            
            await threat_analyzer.analyze_email(email_id, email_data)
            
            # Should only scan the non-cached URL
            mock_vt.assert_called_once_with("https://new-site.com")


class TestCachePerformance:
    """Test cache performance and optimization"""
    
    @pytest.mark.asyncio
    async def test_concurrent_cache_access(self, mock_redis):
        """Test concurrent cache access performance"""
        cache_manager = CacheManager()
        
        with patch('app.core.cache_manager.get_redis_client') as mock_get_redis:
            mock_get_redis.return_value = mock_redis
            
            # Configure mock for concurrent access
            mock_redis.get.return_value = json.dumps({"test": "data"}, default=str)
            mock_redis.set.return_value = True
            
            # Simulate concurrent cache operations
            async def cache_operation(key_suffix: int):
                key = f"concurrent_test_{key_suffix}"
                await cache_manager.set(key, {"data": key_suffix})
                result = await cache_manager.get(key)
                return result
            
            # Run 50 concurrent operations
            tasks = [cache_operation(i) for i in range(50)]
            start_time = time.time()
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            end_time = time.time()
            
            # All operations should succeed
            assert all(not isinstance(r, Exception) for r in results)
            
            # Should complete quickly (under 2 seconds)
            assert end_time - start_time < 2.0
    
    @pytest.mark.asyncio
    async def test_cache_memory_efficiency(self, mock_redis):
        """Test cache memory usage with large datasets"""
        cache_manager = CacheManager()
        
        with patch('app.core.cache_manager.get_redis_client') as mock_get_redis:
            mock_get_redis.return_value = mock_redis
            mock_redis.set.return_value = True
            
            # Test with large data objects
            large_data = {
                "email_content": "x" * 10000,  # 10KB email content
                "analysis_results": ["result"] * 1000,  # Large analysis results
                "metadata": {"key": "value"} * 100
            }
            
            start_time = time.time()
            
            # Cache 100 large objects
            for i in range(100):
                key = f"large_object_{i}"
                await cache_manager.set(key, large_data, ttl=3600)
            
            end_time = time.time()
            
            # Should handle large objects efficiently
            assert end_time - start_time < 5.0
            assert mock_redis.set.call_count == 100
    
    def test_cache_key_collision_prevention(self):
        """Test that cache keys are unique and collision-free"""
        cache_manager = CacheManager()
        
        # Test various key generation scenarios
        test_cases = [
            (CacheKey.URL_SCAN, "https://example.com"),
            (CacheKey.URL_SCAN, "https://example.com/path"),
            (CacheKey.THREAT_ANALYSIS, "email_123"),
            (CacheKey.THREAT_ANALYSIS, "email_123_v2"),
            (CacheKey.USER_CONSENT, "user_456"),
            (CacheKey.REDIRECT_ANALYSIS, "https://bit.ly/test"),
        ]
        
        generated_keys = set()
        
        for cache_type, identifier in test_cases:
            key = cache_manager.generate_key(cache_type, identifier)
            
            # Ensure no collisions
            assert key not in generated_keys, f"Key collision detected: {key}"
            generated_keys.add(key)
            
            # Ensure keys are properly formatted
            assert key.startswith("phishnet:")
            assert cache_type.value in key
            assert identifier in key or identifier.replace("/", "_") in key


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
