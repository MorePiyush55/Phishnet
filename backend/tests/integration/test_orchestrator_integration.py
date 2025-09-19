"""
Integration Tests for Orchestrator with Test DB & Redis

Tests the orchestrator with real component interactions using test database,
test Redis instance, and realistic data flows. Focus on integration between
components rather than external API calls.
"""

import pytest
import asyncio
import uuid
import json
import tempfile
import os
import hashlib
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any, List
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import redis

# Mock external APIs but keep internal components real
@pytest.fixture(scope="session")
def test_database():
    """Create test database for integration tests."""
    # Use a temporary SQLite database for testing
    db_file = tempfile.mktemp(suffix='.db')
    engine = create_engine(f'sqlite:///{db_file}', echo=False)
    
    # Import models and create tables
    try:
        from app.core.database import Base
        Base.metadata.create_all(engine)
        
        # Create session factory
        TestSessionLocal = sessionmaker(bind=engine)
        
        yield {
            'engine': engine,
            'session_factory': TestSessionLocal,
            'url': f'sqlite:///{db_file}'
        }
    finally:
        # Cleanup with proper handling
        try:
            engine.dispose()  # Close all connections first
            if os.path.exists(db_file):
                # Retry deletion with delay for Windows file locking
                import time
                for _ in range(3):
                    try:
                        os.unlink(db_file)
                        break
                    except PermissionError:
                        time.sleep(0.1)
        except Exception:
            pass  # Ignore cleanup errors


@pytest.fixture(scope="session")
def test_redis():
    """Create test Redis client for integration tests."""
    # Use test Redis database (db=1)
    redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
    
    try:
        # Test connection
        redis_client.ping()
        
        # Clear test database
        redis_client.flushdb()
        
        yield redis_client
    except redis.ConnectionError:
        # If Redis is not available, use mock
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_redis.get.return_value = None
        mock_redis.set.return_value = True
        mock_redis.delete.return_value = 1
        mock_redis.exists.return_value = False
        mock_redis.flushdb.return_value = True
        mock_redis.keys.return_value = []
        yield mock_redis
    finally:
        try:
            redis_client.flushdb()  # Clean up after tests
        except:
            pass


@pytest.fixture
def mock_external_apis():
    """Mock external API calls while keeping internal logic real."""
    with patch('app.services.virustotal.VirusTotalClient.analyze_url') as mock_vt, \
         patch('app.services.gemini.GeminiAnalyzer.analyze_content') as mock_gemini, \
         patch('app.services.abuseipdb.AbuseIPDBClient.check_ip') as mock_abuse:
        
        # Configure realistic mock responses
        mock_vt.return_value = {
            'analysis_type': 'virustotal_scan',
            'verdict': 'safe',
            'confidence': 0.8,
            'threat_level': 'low',
            'details': {
                'stats': {'malicious': 0, 'suspicious': 0, 'harmless': 1},
                'reputation': 'good',
                'scan_date': datetime.now().isoformat()
            }
        }
        
        mock_gemini.return_value = {
            'analysis_type': 'ai_content_analysis',
            'verdict': 'safe',
            'confidence': 0.7,
            'threat_level': 'low',
            'details': {
                'phishing_indicators': [],
                'sentiment': 'neutral',
                'confidence_score': 0.7
            }
        }
        
        mock_abuse.return_value = {
            'analysis_type': 'ip_reputation',
            'verdict': 'safe',
            'confidence': 0.9,
            'threat_level': 'low',
            'details': {
                'abuse_confidence': 0,
                'country_code': 'US',
                'usage_type': 'datacenter'
            }
        }
        
        yield {
            'virustotal': mock_vt,
            'gemini': mock_gemini,
            'abuseipdb': mock_abuse
        }


@pytest.fixture
async def orchestrator_with_test_env(test_database, test_redis, mock_external_apis):
    """Create orchestrator with test database and Redis."""
    # Set up test environment variables
    test_env = {
        'DATABASE_URL': test_database['url'],
        'REDIS_URL': f'redis://localhost:6379/1',
        'TESTING': 'true',
        'ENVIRONMENT': 'development',
        'SECRET_KEY': 'test-secret-key-with-32-plus-characters-for-testing',
        'ENABLE_EXTERNAL_APIS': 'true',  # Enable for integration testing
        'VIRUSTOTAL_API_KEY': 'test_key',
        'GEMINI_API_KEY': 'test_key',
        'ABUSEIPDB_API_KEY': 'test_key'
    }
    
    with patch.dict(os.environ, test_env):
        # Import after environment is set
        from app.orchestrator.real_threat_orchestrator import RealThreatOrchestrator
        
        orchestrator = RealThreatOrchestrator()
        await orchestrator.initialize()
        
        yield orchestrator


@pytest.mark.asyncio
class TestOrchestratorIntegration:
    """Integration tests for the orchestrator with real components."""
    
    async def test_email_analysis_workflow(self, orchestrator_with_test_env, test_redis):
        """Test complete email analysis workflow with component integration."""
        orchestrator = orchestrator_with_test_env
        
        # Prepare realistic email data
        email_data = {
            'sender': 'test@example.com',
            'subject': 'Test Email Subject',
            'content': 'This is test email content with a link: https://example.com',
            'html_content': '<p>This is <a href="https://example.com">test content</a></p>',
            'links': ['https://example.com', 'https://suspicious.test.com'],
            'attachments': [],
            'headers': {
                'Message-ID': '<test@example.com>',
                'Received': 'from example.com'
            },
            'received_at': datetime.now().isoformat()
        }
        
        user_id = 1
        request_id = str(uuid.uuid4())
        
        # Execute analysis
        result = await orchestrator.analyze_email_comprehensive(
            email_data=email_data,
            user_id=user_id,
            request_id=request_id
        )
        
        # Verify result structure
        assert result is not None
        assert 'threat_level' in result
        assert 'verdict' in result
        assert 'confidence' in result
        assert 'analysis_details' in result
        assert 'sanitized_content' in result
        
        # Verify sanitization occurred
        assert 'sanitized_content' in result
        sanitized = result['sanitized_content']
        assert 'safe_content' in sanitized
        assert 'links_analyzed' in sanitized
        
        # Verify threat aggregation
        assert result['threat_level'] in ['low', 'medium', 'high', 'critical']
        assert 0.0 <= result['confidence'] <= 1.0
        
        # Verify analysis details contain component results
        details = result['analysis_details']
        assert 'link_analysis' in details
        assert 'content_analysis' in details
        
        print(f"✅ Email analysis workflow completed successfully")
        print(f"   Threat Level: {result['threat_level']}")
        print(f"   Confidence: {result['confidence']:.2f}")
        print(f"   Links Analyzed: {len(sanitized.get('links_analyzed', []))}")
    
    async def test_url_analysis_with_caching(self, orchestrator_with_test_env, test_redis):
        """Test URL analysis with Redis caching integration."""
        orchestrator = orchestrator_with_test_env
        
        test_url = 'https://example.com/test-page'
        
        # First analysis - should cache result
        result1 = await orchestrator._analyze_single_url_comprehensive(test_url)
        
        # Verify result structure
        assert result1 is not None
        assert 'verdict' in result1
        assert 'confidence' in result1
        assert 'threat_level' in result1
        
        # Second analysis - should use cache
        result2 = await orchestrator._analyze_single_url_comprehensive(test_url)
        
        # Results should be identical (from cache)
        assert result1['verdict'] == result2['verdict']
        assert result1['confidence'] == result2['confidence']
        
        # Check that cache key exists in Redis
        cache_key = f"url_analysis:{hashlib.sha256(test_url.encode()).hexdigest()}"
        cached_value = test_redis.get(cache_key)
        assert cached_value is not None
        
        print(f"✅ URL analysis caching working correctly")
        print(f"   Cache Key: {cache_key}")
        print(f"   Cached Result Available: {cached_value is not None}")
    
    async def test_bulk_url_analysis_concurrency(self, orchestrator_with_test_env):
        """Test concurrent analysis of multiple URLs."""
        orchestrator = orchestrator_with_test_env
        
        test_urls = [
            'https://example.com',
            'https://google.com',
            'https://github.com',
            'https://stackoverflow.com',
            'https://test.com'
        ]
        
        # Measure analysis time
        start_time = datetime.now()
        
        # Analyze URLs concurrently
        results = await orchestrator._analyze_urls_batch(test_urls)
        
        end_time = datetime.now()
        analysis_duration = (end_time - start_time).total_seconds()
        
        # Verify all URLs were analyzed
        assert len(results) == len(test_urls)
        
        # Verify result structure for each URL
        for url, result in results.items():
            assert url in test_urls
            assert 'verdict' in result
            assert 'confidence' in result
            assert 'threat_level' in result
            assert 'analysis_details' in result
        
        # Verify reasonable performance (should be faster than sequential)
        # With 5 URLs, concurrent analysis should complete within reasonable time
        assert analysis_duration < 30.0  # Reasonable upper bound
        
        print(f"✅ Bulk URL analysis completed successfully")
        print(f"   URLs Analyzed: {len(results)}")
        print(f"   Analysis Duration: {analysis_duration:.2f} seconds")
        print(f"   Average per URL: {analysis_duration / len(test_urls):.2f} seconds")
    
    async def test_threat_aggregation_integration(self, orchestrator_with_test_env):
        """Test threat aggregation across multiple analysis components."""
        orchestrator = orchestrator_with_test_env
        
        # Test data with mixed threat levels
        email_data = {
            'sender': 'suspicious@phishing-domain.com',
            'subject': 'URGENT: Verify your account NOW!',
            'content': 'Click here immediately: https://evil-site.com/steal-credentials',
            'html_content': '<p>Click <a href="https://evil-site.com">here</a> urgently!</p>',
            'links': ['https://evil-site.com/steal-credentials'],
            'attachments': [{'name': 'malware.exe', 'size': 1024}],
            'headers': {'Message-ID': '<suspicious@phishing.com>'},
            'received_at': datetime.now().isoformat()
        }
        
        # Mock external APIs to return suspicious/malicious results
        with patch('app.services.virustotal.VirusTotalClient.analyze_url') as mock_vt:
            mock_vt.return_value = {
                'analysis_type': 'virustotal_scan',
                'verdict': 'malicious',
                'confidence': 0.9,
                'threat_level': 'high',
                'details': {
                    'stats': {'malicious': 5, 'suspicious': 2, 'harmless': 0},
                    'reputation': 'bad'
                }
            }
            
            result = await orchestrator.analyze_email_comprehensive(
                email_data=email_data,
                user_id=1,
                request_id=str(uuid.uuid4())
            )
        
        # Verify threat aggregation elevated the threat level
        assert result['threat_level'] in ['high', 'critical']
        assert result['confidence'] >= 0.7  # High confidence in threat detection
        assert result['verdict'] in ['suspicious', 'malicious']
        
        # Verify aggregation details
        details = result['analysis_details']
        assert 'threat_scores' in details
        assert 'contributing_factors' in details
        
        print(f"✅ Threat aggregation working correctly")
        print(f"   Final Threat Level: {result['threat_level']}")
        print(f"   Aggregated Confidence: {result['confidence']:.2f}")
        print(f"   Verdict: {result['verdict']}")
    
    async def test_security_sanitization_integration(self, orchestrator_with_test_env):
        """Test security sanitization integration in analysis workflow."""
        orchestrator = orchestrator_with_test_env
        
        # Email with XSS and other security issues
        email_data = {
            'sender': 'test@example.com',
            'subject': 'Test Email',
            'content': 'Normal content',
            'html_content': '''
                <script>alert('XSS');</script>
                <p>Click <a href="javascript:malicious()">here</a></p>
                <img src="x" onerror="alert('XSS')">
                <iframe src="https://evil.com"></iframe>
            ''',
            'links': [
                'javascript:alert("XSS")',
                'https://example.com',
                'data:text/html,<script>alert("XSS")</script>'
            ],
            'attachments': [],
            'headers': {'Message-ID': '<test@example.com>'},
            'received_at': datetime.now().isoformat()
        }
        
        result = await orchestrator.analyze_email_comprehensive(
            email_data=email_data,
            user_id=1,
            request_id=str(uuid.uuid4())
        )
        
        # Verify sanitization occurred
        sanitized = result['sanitized_content']
        
        # XSS should be removed
        assert '<script>' not in sanitized['safe_content']
        assert 'javascript:' not in sanitized['safe_content']
        assert 'onerror=' not in sanitized['safe_content']
        
        # Dangerous links should be filtered
        safe_links = sanitized.get('links_analyzed', [])
        for link_info in safe_links:
            url = link_info.get('url', '')
            assert not url.startswith('javascript:')
            assert not url.startswith('data:')
        
        # Verify security report
        assert 'security_issues_found' in sanitized
        security_issues = sanitized['security_issues_found']
        assert len(security_issues) > 0  # Should detect XSS attempts
        
        print(f"✅ Security sanitization working correctly")
        print(f"   Security Issues Found: {len(security_issues)}")
        print(f"   Content Sanitized: {len(sanitized['safe_content'])} chars")
    
    async def test_worker_mode_simulation(self, orchestrator_with_test_env, test_redis):
        """Test orchestrator in worker mode with job queue simulation."""
        orchestrator = orchestrator_with_test_env
        
        # Simulate job queue entry
        job_id = str(uuid.uuid4())
        job_data = {
            'id': job_id,
            'type': 'email_analysis',
            'data': {
                'sender': 'test@example.com',
                'subject': 'Worker Test Email',
                'content': 'Test content for worker processing',
                'links': ['https://example.com'],
                'received_at': datetime.now().isoformat()
            },
            'user_id': 1,
            'priority': 'normal',
            'created_at': datetime.now().isoformat()
        }
        
        # Store job in Redis (simulating queue)
        job_key = f"job:{job_id}"
        test_redis.set(job_key, json.dumps(job_data))
        
        # Process job (simulating worker)
        job_json = test_redis.get(job_key)
        assert job_json is not None
        
        job = json.loads(job_json)
        email_data = job['data']
        
        # Process the job
        result = await orchestrator.analyze_email_comprehensive(
            email_data=email_data,
            user_id=job['user_id'],
            request_id=job['id']
        )
        
        # Store result (simulating worker completion)
        result_key = f"result:{job_id}"
        test_redis.set(result_key, json.dumps(result))
        
        # Verify job completion
        stored_result = test_redis.get(result_key)
        assert stored_result is not None
        
        parsed_result = json.loads(stored_result)
        assert parsed_result['threat_level'] is not None
        assert parsed_result['verdict'] is not None
        
        # Cleanup
        test_redis.delete(job_key)
        test_redis.delete(result_key)
        
        print(f"✅ Worker mode simulation successful")
        print(f"   Job ID: {job_id}")
        print(f"   Processing Result: {parsed_result['verdict']}")
    
    async def test_error_handling_and_resilience(self, orchestrator_with_test_env):
        """Test error handling and system resilience."""
        orchestrator = orchestrator_with_test_env
        
        # Test with invalid email data
        invalid_email_data = {
            'sender': None,  # Invalid
            'subject': '',
            'content': None,  # Invalid
            'links': ['not-a-url'],  # Invalid URL
            'received_at': 'invalid-date'  # Invalid date
        }
        
        # Should handle gracefully without crashing
        result = await orchestrator.analyze_email_comprehensive(
            email_data=invalid_email_data,
            user_id=1,
            request_id=str(uuid.uuid4())
        )
        
        # Should return a result even with invalid data
        assert result is not None
        assert 'threat_level' in result
        assert 'error_details' in result or 'analysis_details' in result
        
        # Test with network simulation failure
        with patch('app.services.virustotal.VirusTotalClient.analyze_url') as mock_vt:
            mock_vt.side_effect = Exception("Network error")
            
            valid_email = {
                'sender': 'test@example.com',
                'subject': 'Test',
                'content': 'Test content',
                'links': ['https://example.com'],
                'received_at': datetime.now().isoformat()
            }
            
            result = await orchestrator.analyze_email_comprehensive(
                email_data=valid_email,
                user_id=1,
                request_id=str(uuid.uuid4())
            )
            
            # Should still return a result using fallback mechanisms
            assert result is not None
            assert 'threat_level' in result
        
        print(f"✅ Error handling and resilience verified")
        print(f"   Invalid data handling: OK")
        print(f"   Network failure handling: OK")


if __name__ == "__main__":
    # Run integration tests independently
    pytest.main([__file__, "-v", "--tb=short"])
