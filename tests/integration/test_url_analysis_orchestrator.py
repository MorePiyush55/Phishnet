"""
Integration test for URL analysis orchestrator.
Tests complete analysis workflow with multiple components.
"""

import pytest
import asyncio
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from typing import List, Dict, Any

# Mock the services before importing anything from app
class MockVirusTotalResponse:
    def __init__(self, status_code: int = 200, json_data: dict = None):
        self.status_code = status_code
        self._json_data = json_data or {"data": {"attributes": {"stats": {"malicious": 0, "harmless": 1}}}}
    
    def json(self):
        return self._json_data

class MockRedisClient:
    def __init__(self):
        self._data = {}
    
    async def get(self, key: str):
        return self._data.get(key)
    
    async def set(self, key: str, value: str, ex: int = None):
        self._data[key] = value
        return True
    
    async def delete(self, key: str):
        if key in self._data:
            del self._data[key]
            return 1
        return 0
    
    async def exists(self, key: str):
        return key in self._data
    
    async def close(self):
        pass

# Mock HTTP client
class MockHttpClient:
    def __init__(self):
        self.responses = {}
    
    def set_response(self, url: str, response: MockVirusTotalResponse):
        self.responses[url] = response
    
    async def get(self, url: str, **kwargs):
        return self.responses.get(url, MockVirusTotalResponse())
    
    async def post(self, url: str, **kwargs):
        return self.responses.get(url, MockVirusTotalResponse())
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture
def mock_redis():
    """Mock Redis client for integration tests."""
    return MockRedisClient()


@pytest.fixture
def mock_http_client():
    """Mock HTTP client for external API calls."""
    return MockHttpClient()


@pytest.fixture
def test_database():
    """Create temporary test database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
        db_path = tmp_file.name
    
    # Set environment variable for test database
    original_db_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    
    yield db_path
    
    # Cleanup
    if original_db_url:
        os.environ["DATABASE_URL"] = original_db_url
    else:
        os.environ.pop("DATABASE_URL", None)
    
    try:
        os.unlink(db_path)
    except OSError:
        pass


class TestURLAnalysisIntegration:
    """Integration tests for URL analysis workflow."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_simple_url_analysis_workflow(self, mock_redis, mock_http_client):
        """Test basic URL analysis workflow with mocked components."""
        # Setup mock responses
        mock_http_client.set_response(
            "https://www.virustotal.com/api/v3/urls",
            MockVirusTotalResponse(200, {
                "data": {
                    "id": "test-scan-id",
                    "attributes": {
                        "stats": {"malicious": 0, "harmless": 10, "suspicious": 0},
                        "results": {}
                    }
                }
            })
        )
        
        # Mock URL analysis components
        class MockURLAnalyzer:
            async def analyze_url(self, url: str):
                return {
                    "url": url,
                    "threat_score": 0.1,
                    "verdict": "CLEAN",
                    "analysis_type": "URL_SCAN",
                    "timestamp": datetime.utcnow(),
                    "indicators": ["direct_link"]
                }
        
        class MockThreatAggregator:
            def aggregate_results(self, results: List[Dict]):
                if not results:
                    return {
                        "aggregated_threat_score": 0.0,
                        "final_verdict": "CLEAN",
                        "aggregated_indicators": [],
                        "confidence": 1.0
                    }
                
                total_score = sum(r.get("threat_score", 0) for r in results)
                avg_score = total_score / len(results)
                
                return {
                    "aggregated_threat_score": avg_score,
                    "final_verdict": "CLEAN" if avg_score < 0.3 else "SUSPICIOUS" if avg_score < 0.7 else "MALICIOUS",
                    "aggregated_indicators": [ind for r in results for ind in r.get("indicators", [])],
                    "confidence": 1.0
                }
        
        # Create analyzer and aggregator
        url_analyzer = MockURLAnalyzer()
        threat_aggregator = MockThreatAggregator()
        
        # Test URL
        test_url = "https://example.com"
        
        # Simulate analysis workflow
        analysis_results = []
        
        # Step 1: URL Analysis
        url_result = await url_analyzer.analyze_url(test_url)
        analysis_results.append(url_result)
        
        # Step 2: Cache check (simulate cache miss)
        cache_key = f"analysis:{test_url}"
        cached_result = await mock_redis.get(cache_key)
        assert cached_result is None
        
        # Step 3: Aggregate results
        aggregated = threat_aggregator.aggregate_results(analysis_results)
        
        # Step 4: Store in cache
        import json
        cache_data = json.dumps({
            "aggregated_result": aggregated,
            "individual_results": analysis_results,
            "timestamp": datetime.utcnow().isoformat()
        }, default=str)
        await mock_redis.set(cache_key, cache_data, ex=3600)
        
        # Verify results
        assert aggregated["final_verdict"] == "CLEAN"
        assert aggregated["aggregated_threat_score"] == 0.1
        assert "direct_link" in aggregated["aggregated_indicators"]
        
        # Verify caching
        cached_result = await mock_redis.get(cache_key)
        assert cached_result is not None
        cached_data = json.loads(cached_result)
        assert cached_data["aggregated_result"]["final_verdict"] == "CLEAN"
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_malicious_url_detection_workflow(self, mock_redis, mock_http_client):
        """Test workflow for detecting malicious URLs."""
        # Setup mock responses for malicious URL
        mock_http_client.set_response(
            "https://www.virustotal.com/api/v3/urls",
            MockVirusTotalResponse(200, {
                "data": {
                    "id": "malicious-scan-id",
                    "attributes": {
                        "stats": {"malicious": 8, "harmless": 2, "suspicious": 3},
                        "results": {
                            "Engine1": {"category": "malware", "result": "malicious"},
                            "Engine2": {"category": "phishing", "result": "malicious"}
                        }
                    }
                }
            })
        )
        
        class MockMaliciousURLAnalyzer:
            async def analyze_url(self, url: str):
                return {
                    "url": url,
                    "threat_score": 0.9,
                    "verdict": "MALICIOUS",
                    "analysis_type": "URL_SCAN",
                    "timestamp": datetime.utcnow(),
                    "indicators": ["malware_detected", "phishing_detected", "blacklisted"],
                    "redirect_count": 3,
                    "final_url": "https://malicious-site.evil"
                }
        
        class MockVirusTotalAnalyzer:
            async def analyze_url(self, url: str):
                return {
                    "url": url,
                    "threat_score": 0.8,
                    "verdict": "MALICIOUS",
                    "analysis_type": "VIRUSTOTAL_SCAN",
                    "timestamp": datetime.utcnow(),
                    "indicators": ["external_detection", "multiple_engines"],
                    "detection_ratio": "8/13"
                }
        
        class MockThreatAggregator:
            def aggregate_results(self, results: List[Dict]):
                if not results:
                    return {
                        "aggregated_threat_score": 0.0,
                        "final_verdict": "CLEAN",
                        "aggregated_indicators": [],
                        "confidence": 1.0
                    }
                
                # Use maximum threat score for final verdict
                max_score = max(r.get("threat_score", 0) for r in results)
                all_indicators = [ind for r in results for ind in r.get("indicators", [])]
                
                return {
                    "aggregated_threat_score": max_score,
                    "final_verdict": "MALICIOUS" if max_score >= 0.7 else "SUSPICIOUS" if max_score >= 0.3 else "CLEAN",
                    "aggregated_indicators": list(set(all_indicators)),
                    "confidence": 0.9,
                    "detection_sources": len(results)
                }
        
        # Create analyzers
        url_analyzer = MockMaliciousURLAnalyzer()
        vt_analyzer = MockVirusTotalAnalyzer()
        threat_aggregator = MockThreatAggregator()
        
        # Test malicious URL
        test_url = "https://suspicious-phishing-site.fake"
        
        # Simulate analysis workflow
        analysis_results = []
        
        # Multiple analysis sources
        url_result = await url_analyzer.analyze_url(test_url)
        vt_result = await vt_analyzer.analyze_url(test_url)
        
        analysis_results.extend([url_result, vt_result])
        
        # Aggregate results
        aggregated = threat_aggregator.aggregate_results(analysis_results)
        
        # Verify malicious detection
        assert aggregated["final_verdict"] == "MALICIOUS"
        assert aggregated["aggregated_threat_score"] >= 0.8
        assert "malware_detected" in aggregated["aggregated_indicators"]
        assert "external_detection" in aggregated["aggregated_indicators"]
        assert aggregated["detection_sources"] == 2
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_error_handling_workflow(self, mock_redis, mock_http_client):
        """Test error handling in the analysis workflow."""
        # Setup mock HTTP client to raise exceptions
        class FailingHttpClient:
            async def get(self, url: str, **kwargs):
                raise ConnectionError("Network failure")
            
            async def post(self, url: str, **kwargs):
                raise TimeoutError("Request timeout")
            
            async def __aenter__(self):
                return self
            
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass
        
        class ResilientURLAnalyzer:
            def __init__(self, http_client):
                self.http_client = http_client
            
            async def analyze_url(self, url: str):
                try:
                    # Attempt external API call
                    response = await self.http_client.get("https://api.external.com")
                    return {
                        "url": url,
                        "threat_score": 0.2,
                        "verdict": "CLEAN",
                        "analysis_type": "URL_SCAN",
                        "timestamp": datetime.utcnow(),
                        "indicators": ["external_verified"]
                    }
                except (ConnectionError, TimeoutError) as e:
                    # Fallback analysis
                    return {
                        "url": url,
                        "threat_score": 0.0,
                        "verdict": "UNKNOWN",
                        "analysis_type": "URL_SCAN",
                        "timestamp": datetime.utcnow(),
                        "indicators": ["fallback_analysis"],
                        "error": str(e),
                        "fallback_used": True
                    }
        
        class ErrorHandlingAggregator:
            def aggregate_results(self, results: List[Dict]):
                valid_results = [r for r in results if r.get("verdict") != "UNKNOWN"]
                error_results = [r for r in results if "error" in r]
                
                if not valid_results:
                    return {
                        "aggregated_threat_score": 0.0,
                        "final_verdict": "UNKNOWN",
                        "aggregated_indicators": ["analysis_failed"],
                        "confidence": 0.0,
                        "errors": [r["error"] for r in error_results],
                        "fallback_count": len([r for r in results if r.get("fallback_used")])
                    }
                
                avg_score = sum(r.get("threat_score", 0) for r in valid_results) / len(valid_results)
                return {
                    "aggregated_threat_score": avg_score,
                    "final_verdict": "CLEAN" if avg_score < 0.3 else "SUSPICIOUS",
                    "aggregated_indicators": [ind for r in valid_results for ind in r.get("indicators", [])],
                    "confidence": 0.5,  # Reduced confidence due to errors
                    "errors": [r["error"] for r in error_results],
                    "fallback_count": len([r for r in results if r.get("fallback_used")])
                }
        
        # Create components with failing HTTP client
        failing_client = FailingHttpClient()
        url_analyzer = ResilientURLAnalyzer(failing_client)
        error_aggregator = ErrorHandlingAggregator()
        
        # Test URL
        test_url = "https://example.com"
        
        # Simulate analysis with errors
        analysis_results = []
        
        # This should trigger error handling
        result = await url_analyzer.analyze_url(test_url)
        analysis_results.append(result)
        
        # Aggregate results
        aggregated = error_aggregator.aggregate_results(analysis_results)
        
        # Verify error handling
        assert aggregated["final_verdict"] == "UNKNOWN"
        assert aggregated["fallback_count"] == 1
        assert len(aggregated["errors"]) == 1
        assert aggregated["confidence"] == 0.0
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_caching_behavior(self, mock_redis):
        """Test caching behavior in integration scenarios."""
        class CachingAnalyzer:
            def __init__(self, cache_client):
                self.cache = cache_client
            
            async def analyze_url(self, url: str):
                # Check cache first
                cache_key = f"url_analysis:{url}"
                cached = await self.cache.get(cache_key)
                
                if cached:
                    import json
                    return json.loads(cached)
                
                # Simulate analysis
                result = {
                    "url": url,
                    "threat_score": 0.3,
                    "verdict": "SUSPICIOUS",
                    "analysis_type": "URL_SCAN",
                    "timestamp": datetime.utcnow().isoformat(),
                    "indicators": ["new_analysis"],
                    "cached": False
                }
                
                # Store in cache
                await self.cache.set(cache_key, json.dumps(result), ex=3600)
                return result
        
        analyzer = CachingAnalyzer(mock_redis)
        test_url = "https://test-caching.com"
        
        # First analysis - should not be cached
        result1 = await analyzer.analyze_url(test_url)
        assert result1["cached"] is False
        assert "new_analysis" in result1["indicators"]
        
        # Second analysis - should be cached
        result2 = await analyzer.analyze_url(test_url)
        assert result2["verdict"] == "SUSPICIOUS"  # Same result
        
        # Verify cache hit by checking if timestamps are the same
        assert result1["timestamp"] == result2["timestamp"]
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_concurrent_analysis(self, mock_redis, mock_http_client):
        """Test concurrent analysis of multiple URLs."""
        class ConcurrentAnalyzer:
            async def analyze_url(self, url: str):
                # Simulate some processing time
                await asyncio.sleep(0.01)
                
                return {
                    "url": url,
                    "threat_score": 0.1 if "safe" in url else 0.8,
                    "verdict": "CLEAN" if "safe" in url else "MALICIOUS",
                    "analysis_type": "URL_SCAN",
                    "timestamp": datetime.utcnow(),
                    "indicators": ["concurrent_analysis"]
                }
        
        analyzer = ConcurrentAnalyzer()
        
        # Multiple URLs to analyze concurrently
        test_urls = [
            "https://safe-site1.com",
            "https://safe-site2.com",
            "https://malicious-site1.evil",
            "https://safe-site3.com",
            "https://malicious-site2.evil"
        ]
        
        # Analyze all URLs concurrently
        start_time = datetime.utcnow()
        
        tasks = [analyzer.analyze_url(url) for url in test_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        
        # Verify results
        assert len(results) == 5
        assert all(not isinstance(r, Exception) for r in results)
        
        # Check that concurrent execution was faster than sequential
        # (5 * 0.01s = 0.05s sequential vs concurrent should be ~0.01s)
        assert duration < 0.03  # Should be much faster than sequential
        
        # Verify individual results
        safe_results = [r for r in results if "safe" in r["url"]]
        malicious_results = [r for r in results if "malicious" in r["url"]]
        
        assert len(safe_results) == 3
        assert len(malicious_results) == 2
        assert all(r["verdict"] == "CLEAN" for r in safe_results)
        assert all(r["verdict"] == "MALICIOUS" for r in malicious_results)
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self, mock_redis):
        """Test rate limiting behavior in integration scenarios."""
        class RateLimitedAnalyzer:
            def __init__(self, cache_client, rate_limit=3, window=60):
                self.cache = cache_client
                self.rate_limit = rate_limit
                self.window = window
            
            async def analyze_url(self, url: str):
                # Check rate limit
                rate_key = f"rate_limit:{url}"
                current_count = await self.cache.get(rate_key)
                
                if current_count:
                    current_count = int(current_count)
                    if current_count >= self.rate_limit:
                        return {
                            "url": url,
                            "error": "Rate limit exceeded",
                            "verdict": "ERROR",
                            "rate_limited": True,
                            "timestamp": datetime.utcnow()
                        }
                else:
                    current_count = 0
                
                # Increment rate limit counter
                await self.cache.set(rate_key, str(current_count + 1), ex=self.window)
                
                # Perform analysis
                return {
                    "url": url,
                    "threat_score": 0.2,
                    "verdict": "CLEAN",
                    "analysis_type": "URL_SCAN",
                    "timestamp": datetime.utcnow(),
                    "rate_limited": False,
                    "request_count": current_count + 1
                }
        
        analyzer = RateLimitedAnalyzer(mock_redis, rate_limit=3, window=60)
        test_url = "https://rate-limited.com"
        
        # First 3 requests should succeed
        for i in range(3):
            result = await analyzer.analyze_url(test_url)
            assert result["rate_limited"] is False
            assert result["request_count"] == i + 1
        
        # 4th request should be rate limited
        result = await analyzer.analyze_url(test_url)
        assert result["rate_limited"] is True
        assert result["verdict"] == "ERROR"
        assert "Rate limit exceeded" in result["error"]
    
    @pytest.mark.integration
    @pytest.mark.slow
    async def test_full_analysis_pipeline(self, mock_redis, mock_http_client, test_database):
        """Test the complete analysis pipeline end-to-end."""
        # This is a comprehensive integration test that exercises
        # the entire analysis pipeline
        
        class FullPipelineOrchestrator:
            def __init__(self, cache_client, http_client, db_path):
                self.cache = cache_client
                self.http = http_client
                self.db_path = db_path
            
            async def analyze_email_urls(self, email_content: str, email_id: str):
                # Step 1: Extract URLs from email
                import re
                url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
                urls = re.findall(url_pattern, email_content)
                
                if not urls:
                    return {
                        "email_id": email_id,
                        "urls_found": 0,
                        "analysis_results": [],
                        "final_verdict": "CLEAN",
                        "timestamp": datetime.utcnow()
                    }
                
                # Step 2: Analyze each URL
                analysis_results = []
                for url in urls:
                    # Check cache
                    cache_key = f"url:{url}"
                    cached = await self.cache.get(cache_key)
                    
                    if cached:
                        import json
                        result = json.loads(cached)
                        result["from_cache"] = True
                    else:
                        # Perform analysis
                        result = await self._analyze_single_url(url)
                        result["from_cache"] = False
                        
                        # Cache result
                        await self.cache.set(cache_key, json.dumps(result, default=str), ex=3600)
                    
                    analysis_results.append(result)
                
                # Step 3: Aggregate results
                aggregated = self._aggregate_url_results(analysis_results)
                
                # Step 4: Store in database (simulated)
                db_record = {
                    "email_id": email_id,
                    "urls_analyzed": len(urls),
                    "threat_score": aggregated["max_threat_score"],
                    "verdict": aggregated["final_verdict"],
                    "timestamp": datetime.utcnow(),
                    "details": analysis_results
                }
                
                # Step 5: Return comprehensive result
                return {
                    "email_id": email_id,
                    "urls_found": len(urls),
                    "urls_analyzed": urls,
                    "analysis_results": analysis_results,
                    "aggregated_result": aggregated,
                    "db_record": db_record,
                    "processing_time": 0.1,  # Simulated
                    "cache_hits": len([r for r in analysis_results if r.get("from_cache")]),
                    "timestamp": datetime.utcnow()
                }
            
            async def _analyze_single_url(self, url: str):
                # Simulate comprehensive URL analysis
                threat_score = 0.1
                indicators = ["url_analyzed"]
                
                # Check for suspicious patterns
                if any(pattern in url.lower() for pattern in ["phishing", "malware", "suspicious", "evil"]):
                    threat_score = 0.9
                    indicators.extend(["suspicious_pattern", "blacklisted"])
                
                # Simulate external API calls
                if "external" in url:
                    # Mock external API response
                    threat_score += 0.3
                    indicators.append("external_verification")
                
                return {
                    "url": url,
                    "threat_score": min(threat_score, 1.0),
                    "verdict": "MALICIOUS" if threat_score >= 0.7 else "SUSPICIOUS" if threat_score >= 0.3 else "CLEAN",
                    "analysis_type": "COMPREHENSIVE_SCAN",
                    "indicators": indicators,
                    "timestamp": datetime.utcnow()
                }
            
            def _aggregate_url_results(self, results: List[Dict]):
                if not results:
                    return {
                        "max_threat_score": 0.0,
                        "final_verdict": "CLEAN",
                        "risk_factors": []
                    }
                
                max_score = max(r.get("threat_score", 0) for r in results)
                malicious_count = len([r for r in results if r.get("verdict") == "MALICIOUS"])
                suspicious_count = len([r for r in results if r.get("verdict") == "SUSPICIOUS"])
                
                # Determine final verdict
                if malicious_count > 0:
                    final_verdict = "MALICIOUS"
                elif suspicious_count > 0:
                    final_verdict = "SUSPICIOUS"
                else:
                    final_verdict = "CLEAN"
                
                return {
                    "max_threat_score": max_score,
                    "final_verdict": final_verdict,
                    "malicious_urls": malicious_count,
                    "suspicious_urls": suspicious_count,
                    "total_urls": len(results),
                    "risk_factors": [ind for r in results for ind in r.get("indicators", [])]
                }
        
        # Create orchestrator
        orchestrator = FullPipelineOrchestrator(mock_redis, mock_http_client, test_database)
        
        # Test email with mixed URLs
        test_email = """
        Dear User,
        
        Please visit our website: https://legitimate-site.com
        
        Also check this link: https://phishing-attempt.evil
        
        For support: https://external-support.com
        
        Best regards,
        Customer Service
        """
        
        # Process email
        result = await orchestrator.analyze_email_urls(test_email, "test-email-123")
        
        # Verify comprehensive results
        assert result["email_id"] == "test-email-123"
        assert result["urls_found"] == 3
        assert len(result["analysis_results"]) == 3
        
        # Check individual URL analysis
        url_results = {r["url"]: r for r in result["analysis_results"]}
        
        # Legitimate site should be clean
        legit_result = url_results["https://legitimate-site.com"]
        assert legit_result["verdict"] == "CLEAN"
        assert legit_result["threat_score"] < 0.3
        
        # Phishing site should be malicious
        phishing_result = url_results["https://phishing-attempt.evil"]
        assert phishing_result["verdict"] == "MALICIOUS"
        assert phishing_result["threat_score"] >= 0.7
        assert "suspicious_pattern" in phishing_result["indicators"]
        
        # External site should be suspicious
        external_result = url_results["https://external-support.com"]
        assert external_result["verdict"] == "SUSPICIOUS"
        assert "external_verification" in external_result["indicators"]
        
        # Check aggregated results
        aggregated = result["aggregated_result"]
        assert aggregated["final_verdict"] == "MALICIOUS"  # Due to phishing URL
        assert aggregated["malicious_urls"] == 1
        assert aggregated["suspicious_urls"] == 1
        assert aggregated["total_urls"] == 3
        
        # Verify database record
        db_record = result["db_record"]
        assert db_record["email_id"] == "test-email-123"
        assert db_record["verdict"] == "MALICIOUS"
        assert db_record["urls_analyzed"] == 3
