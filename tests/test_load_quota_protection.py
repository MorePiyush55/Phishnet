"""
Comprehensive Load Tests for PhishNet
Ensure queuing + caching protects external quotas
Simulate X emails/minute and observe system stays under API caps
Test system performance under high load scenarios
"""

import pytest
import asyncio
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, List, Any, Optional
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta
import json

# Core imports
from app.orchestrator.main import PhishNetOrchestrator
from app.core.cache_manager import get_cache_manager
from app.core.rate_limiter import get_rate_limiter
from app.core.queue_manager import get_queue_manager
from app.integrations.virustotal import VirusTotalAdapter
from app.integrations.gemini import GeminiAdapter
from app.integrations.abuseipdb import AbuseIPDBAdapter


@dataclass
class LoadTestMetrics:
    """Metrics for load testing"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    api_calls_made: int = 0
    average_response_time: float = 0.0
    peak_response_time: float = 0.0
    requests_per_second: float = 0.0
    quota_violations: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    
    def duration(self) -> float:
        return self.end_time - self.start_time
    
    def cache_hit_rate(self) -> float:
        total_cacheable = self.cache_hits + self.cache_misses
        return (self.cache_hits / total_cacheable) if total_cacheable > 0 else 0.0
    
    def success_rate(self) -> float:
        return (self.successful_requests / self.total_requests) if self.total_requests > 0 else 0.0
    
    def api_efficiency(self) -> float:
        """How many requests served per API call"""
        return (self.total_requests / self.api_calls_made) if self.api_calls_made > 0 else 0.0


class APIQuotaMonitor:
    """Monitor API quota usage during load tests"""
    
    def __init__(self):
        self.service_calls = {
            'virustotal': {'count': 0, 'limit': 500, 'window': 'daily'},
            'gemini': {'count': 0, 'limit': 1000, 'window': 'daily'},
            'abuseipdb': {'count': 0, 'limit': 1000, 'window': 'daily'},
            'openai': {'count': 0, 'limit': 3000, 'window': 'daily'}
        }
        self.violations = []
        self.start_time = time.time()
    
    def record_api_call(self, service: str):
        """Record an API call"""
        if service in self.service_calls:
            self.service_calls[service]['count'] += 1
            
            # Check for quota violation
            if self.service_calls[service]['count'] > self.service_calls[service]['limit']:
                violation = {
                    'service': service,
                    'timestamp': time.time(),
                    'calls_made': self.service_calls[service]['count'],
                    'limit': self.service_calls[service]['limit']
                }
                self.violations.append(violation)
    
    def get_quota_usage(self) -> Dict[str, float]:
        """Get quota usage percentage for each service"""
        usage = {}
        for service, data in self.service_calls.items():
            usage[service] = (data['count'] / data['limit']) * 100
        return usage
    
    def has_violations(self) -> bool:
        """Check if any quota violations occurred"""
        return len(self.violations) > 0
    
    def reset(self):
        """Reset quota monitoring"""
        for service in self.service_calls:
            self.service_calls[service]['count'] = 0
        self.violations.clear()
        self.start_time = time.time()


class LoadTestRunner:
    """Run load tests with various scenarios"""
    
    def __init__(self):
        self.orchestrator = PhishNetOrchestrator()
        self.cache_manager = get_cache_manager()
        self.rate_limiter = get_rate_limiter()
        self.queue_manager = get_queue_manager()
        self.quota_monitor = APIQuotaMonitor()
        self.metrics = LoadTestMetrics()
    
    async def simulate_email_load(self, emails_per_minute: int, duration_minutes: int) -> LoadTestMetrics:
        """Simulate sustained email load"""
        
        # Reset metrics
        self.metrics = LoadTestMetrics()
        self.quota_monitor.reset()
        self.metrics.start_time = time.time()
        
        # Generate test emails
        test_emails = self._generate_test_emails(emails_per_minute * duration_minutes)
        
        # Calculate intervals
        total_emails = len(test_emails)
        interval = (duration_minutes * 60) / total_emails
        
        print(f"Starting load test: {emails_per_minute} emails/min for {duration_minutes} minutes")
        print(f"Total emails: {total_emails}, Interval: {interval:.2f}s")
        
        # Process emails with timing
        response_times = []
        
        for i, email_data in enumerate(test_emails):
            start_request = time.time()
            
            try:
                # Process email
                result = await self._process_email_with_monitoring(email_data)
                
                if result:
                    self.metrics.successful_requests += 1
                else:
                    self.metrics.failed_requests += 1
                
                # Record timing
                response_time = time.time() - start_request
                response_times.append(response_time)
                
                # Update metrics
                self.metrics.total_requests += 1
                
                # Wait for next interval
                if i < total_emails - 1:  # Don't wait after last email
                    await asyncio.sleep(interval)
                
            except Exception as e:
                self.metrics.failed_requests += 1
                print(f"Error processing email {i}: {e}")
        
        # Finalize metrics
        self.metrics.end_time = time.time()
        
        if response_times:
            self.metrics.average_response_time = statistics.mean(response_times)
            self.metrics.peak_response_time = max(response_times)
        
        self.metrics.requests_per_second = self.metrics.total_requests / self.metrics.duration()
        self.metrics.quota_violations = len(self.quota_monitor.violations)
        
        # Get cache metrics
        cache_stats = self.cache_manager.get_stats()
        self.metrics.cache_hits = cache_stats.get('hits', 0)
        self.metrics.cache_misses = cache_stats.get('misses', 0)
        
        # Get API call count
        self.metrics.api_calls_made = sum(
            data['count'] for data in self.quota_monitor.service_calls.values()
        )
        
        return self.metrics
    
    async def _process_email_with_monitoring(self, email_data: Dict[str, Any]) -> bool:
        """Process email with quota monitoring"""
        
        # Mock API calls with quota tracking
        with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
             patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
            
            # Setup mocks to track calls
            def track_vt_call(*args, **kwargs):
                self.quota_monitor.record_api_call('virustotal')
                return Mock(scan_id="load-test", positives=0, total=50, permalink="https://vt.com/test")
            
            def track_gemini_call(*args, **kwargs):
                self.quota_monitor.record_api_call('gemini')
                return {'threat_probability': 0.1, 'confidence': 0.7, 'reasoning': 'Legitimate email'}
            
            def track_abuse_call(*args, **kwargs):
                self.quota_monitor.record_api_call('abuseipdb')
                return Mock(ip_address="1.2.3.4", abuse_confidence=0, total_reports=0)
            
            mock_vt.side_effect = track_vt_call
            mock_gemini.side_effect = track_gemini_call
            mock_abuse.side_effect = track_abuse_call
            
            try:
                # Process email through orchestrator
                result = await self.orchestrator.scan_email(
                    user_id=email_data['user_id'],
                    email_id=email_data['email_id'],
                    subject=email_data['subject'],
                    sender=email_data['sender'],
                    body=email_data['body'],
                    links=email_data.get('links', [])
                )
                
                return result is not None
                
            except Exception as e:
                print(f"Error in orchestrator: {e}")
                return False
    
    def _generate_test_emails(self, count: int) -> List[Dict[str, Any]]:
        """Generate test emails for load testing"""
        
        # Email templates for variety
        templates = [
            {
                'subject': 'Weekly Newsletter #{i}',
                'sender': 'newsletter@company.com',
                'body': 'This is our weekly newsletter with updates and news.',
                'links': ['https://company.com/newsletter/{i}']
            },
            {
                'subject': 'Meeting Reminder #{i}',
                'sender': 'calendar@office.com',
                'body': 'Reminder about your upcoming meeting tomorrow.',
                'links': ['https://office.com/calendar/meeting/{i}']
            },
            {
                'subject': 'System Notification #{i}',
                'sender': 'noreply@system.com',
                'body': 'System maintenance is scheduled for this weekend.',
                'links': []
            },
            {
                'subject': 'Account Update #{i}',
                'sender': 'support@service.com',
                'body': 'Your account settings have been updated successfully.',
                'links': ['https://service.com/account/settings/{i}']
            },
            {
                'subject': 'Suspicious: Urgent Action Required #{i}',
                'sender': 'security@fake-bank.com',
                'body': 'Your account has been compromised. Click here immediately.',
                'links': ['https://fake-bank.com/urgent/{i}']
            }
        ]
        
        emails = []
        for i in range(count):
            template = templates[i % len(templates)]
            
            email = {
                'user_id': f'load_test_user_{i % 10}',  # Simulate 10 users
                'email_id': f'load_test_email_{i}',
                'subject': template['subject'].format(i=i),
                'sender': template['sender'],
                'body': template['body'],
                'links': [link.format(i=i) for link in template['links']]
            }
            
            emails.append(email)
        
        return emails


class TestLoadAndQuotaProtection:
    """Test load handling and quota protection"""
    
    def setup_method(self):
        """Set up load testing environment"""
        self.load_runner = LoadTestRunner()
    
    @pytest.mark.asyncio
    async def test_low_load_10_emails_per_minute(self):
        """Test system under low load - 10 emails/minute"""
        
        metrics = await self.load_runner.simulate_email_load(
            emails_per_minute=10,
            duration_minutes=2
        )
        
        # Assertions for low load
        assert metrics.success_rate() >= 0.95, f"Success rate too low: {metrics.success_rate()}"
        assert metrics.average_response_time <= 5.0, f"Response time too high: {metrics.average_response_time}s"
        assert not self.load_runner.quota_monitor.has_violations(), "Quota violations at low load"
        
        print(f"Low Load Results:")
        print(f"  Success Rate: {metrics.success_rate():.2%}")
        print(f"  Avg Response Time: {metrics.average_response_time:.2f}s")
        print(f"  Cache Hit Rate: {metrics.cache_hit_rate():.2%}")
        print(f"  API Efficiency: {metrics.api_efficiency():.1f} requests/API call")
    
    @pytest.mark.asyncio
    async def test_medium_load_50_emails_per_minute(self):
        """Test system under medium load - 50 emails/minute"""
        
        metrics = await self.load_runner.simulate_email_load(
            emails_per_minute=50,
            duration_minutes=3
        )
        
        # Assertions for medium load
        assert metrics.success_rate() >= 0.90, f"Success rate too low: {metrics.success_rate()}"
        assert metrics.average_response_time <= 10.0, f"Response time too high: {metrics.average_response_time}s"
        assert not self.load_runner.quota_monitor.has_violations(), "Quota violations at medium load"
        assert metrics.cache_hit_rate() >= 0.30, f"Cache hit rate too low: {metrics.cache_hit_rate()}"
        
        print(f"Medium Load Results:")
        print(f"  Success Rate: {metrics.success_rate():.2%}")
        print(f"  Avg Response Time: {metrics.average_response_time:.2f}s")
        print(f"  Cache Hit Rate: {metrics.cache_hit_rate():.2%}")
        print(f"  API Efficiency: {metrics.api_efficiency():.1f} requests/API call")
    
    @pytest.mark.asyncio
    async def test_high_load_100_emails_per_minute(self):
        """Test system under high load - 100 emails/minute"""
        
        metrics = await self.load_runner.simulate_email_load(
            emails_per_minute=100,
            duration_minutes=2
        )
        
        # Assertions for high load
        assert metrics.success_rate() >= 0.85, f"Success rate too low: {metrics.success_rate()}"
        assert metrics.average_response_time <= 15.0, f"Response time too high: {metrics.average_response_time}s"
        assert not self.load_runner.quota_monitor.has_violations(), "Quota violations at high load"
        assert metrics.cache_hit_rate() >= 0.50, f"Cache hit rate too low: {metrics.cache_hit_rate()}"
        
        print(f"High Load Results:")
        print(f"  Success Rate: {metrics.success_rate():.2%}")
        print(f"  Avg Response Time: {metrics.average_response_time:.2f}s")
        print(f"  Cache Hit Rate: {metrics.cache_hit_rate():.2%}")
        print(f"  API Efficiency: {metrics.api_efficiency():.1f} requests/API call")
    
    @pytest.mark.asyncio
    async def test_extreme_load_200_emails_per_minute(self):
        """Test system under extreme load - 200 emails/minute"""
        
        metrics = await self.load_runner.simulate_email_load(
            emails_per_minute=200,
            duration_minutes=1
        )
        
        # Assertions for extreme load (more lenient)
        assert metrics.success_rate() >= 0.75, f"Success rate too low: {metrics.success_rate()}"
        assert metrics.average_response_time <= 30.0, f"Response time too high: {metrics.average_response_time}s"
        assert not self.load_runner.quota_monitor.has_violations(), "Quota violations at extreme load"
        assert metrics.cache_hit_rate() >= 0.70, f"Cache hit rate too low: {metrics.cache_hit_rate()}"
        
        print(f"Extreme Load Results:")
        print(f"  Success Rate: {metrics.success_rate():.2%}")
        print(f"  Avg Response Time: {metrics.average_response_time:.2f}s")
        print(f"  Cache Hit Rate: {metrics.cache_hit_rate():.2%}")
        print(f"  API Efficiency: {metrics.api_efficiency():.1f} requests/API call")
    
    @pytest.mark.asyncio
    async def test_quota_protection_effectiveness(self):
        """Test that caching and queueing protect API quotas"""
        
        # Run sustained high load
        metrics = await self.load_runner.simulate_email_load(
            emails_per_minute=150,
            duration_minutes=3
        )
        
        # Check quota usage
        quota_usage = self.load_runner.quota_monitor.get_quota_usage()
        
        print(f"Quota Usage After High Load:")
        for service, usage in quota_usage.items():
            print(f"  {service}: {usage:.1f}%")
        
        # Assertions for quota protection
        assert all(usage < 80.0 for usage in quota_usage.values()), "API quota usage too high"
        assert metrics.api_efficiency() >= 3.0, f"API efficiency too low: {metrics.api_efficiency()}"
        assert metrics.cache_hit_rate() >= 0.60, f"Cache not protecting APIs: {metrics.cache_hit_rate()}"
        
        # Verify no quota violations
        assert not self.load_runner.quota_monitor.has_violations(), "Quota violations detected!"
    
    @pytest.mark.asyncio
    async def test_cache_warming_and_efficiency(self):
        """Test cache warming improves efficiency"""
        
        # First run - cold cache
        print("Running with cold cache...")
        cold_metrics = await self.load_runner.simulate_email_load(
            emails_per_minute=50,
            duration_minutes=2
        )
        
        # Reset only metrics, keep cache warm
        self.load_runner.quota_monitor.reset()
        
        # Second run - warm cache
        print("Running with warm cache...")
        warm_metrics = await self.load_runner.simulate_email_load(
            emails_per_minute=50,
            duration_minutes=2
        )
        
        print(f"Cache Warming Results:")
        print(f"  Cold Cache Hit Rate: {cold_metrics.cache_hit_rate():.2%}")
        print(f"  Warm Cache Hit Rate: {warm_metrics.cache_hit_rate():.2%}")
        print(f"  Cold API Efficiency: {cold_metrics.api_efficiency():.1f}")
        print(f"  Warm API Efficiency: {warm_metrics.api_efficiency():.1f}")
        
        # Assertions for cache warming
        assert warm_metrics.cache_hit_rate() > cold_metrics.cache_hit_rate(), "Cache warming ineffective"
        assert warm_metrics.api_efficiency() > cold_metrics.api_efficiency(), "API efficiency not improved"
        assert warm_metrics.average_response_time <= cold_metrics.average_response_time, "Response time not improved"


class TestConcurrentLoad:
    """Test concurrent processing capabilities"""
    
    def setup_method(self):
        """Set up concurrent testing"""
        self.orchestrator = PhishNetOrchestrator()
        self.quota_monitor = APIQuotaMonitor()
    
    @pytest.mark.asyncio
    async def test_concurrent_email_processing(self):
        """Test concurrent email processing"""
        
        # Generate emails for concurrent processing
        test_emails = [
            {
                'user_id': f'concurrent_user_{i}',
                'email_id': f'concurrent_email_{i}',
                'subject': f'Concurrent Test Email {i}',
                'sender': f'sender{i}@test.com',
                'body': f'This is concurrent test email number {i}',
                'links': [f'https://test{i}.com']
            }
            for i in range(20)
        ]
        
        # Mock API responses
        with patch('app.integrations.virustotal.VirusTotalAdapter.scan_url') as mock_vt, \
             patch('app.integrations.gemini.GeminiAdapter.analyze_content') as mock_gemini, \
             patch('app.integrations.abuseipdb.AbuseIPDBAdapter.check_ip') as mock_abuse:
            
            # Track concurrent calls
            call_times = []
            
            def track_call_time(*args, **kwargs):
                call_times.append(time.time())
                return Mock(scan_id="concurrent", positives=0, total=50)
            
            mock_vt.side_effect = track_call_time
            mock_gemini.return_value = {'threat_probability': 0.1, 'confidence': 0.7}
            mock_abuse.return_value = Mock(abuse_confidence=0)
            
            # Process emails concurrently
            start_time = time.time()
            
            tasks = []
            for email_data in test_emails:
                task = self.orchestrator.scan_email(
                    user_id=email_data['user_id'],
                    email_id=email_data['email_id'],
                    subject=email_data['subject'],
                    sender=email_data['sender'],
                    body=email_data['body'],
                    links=email_data['links']
                )
                tasks.append(task)
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Analyze results
            successful = sum(1 for r in results if r is not None and not isinstance(r, Exception))
            failed = len(results) - successful
            
            print(f"Concurrent Processing Results:")
            print(f"  Total Emails: {len(test_emails)}")
            print(f"  Successful: {successful}")
            print(f"  Failed: {failed}")
            print(f"  Duration: {duration:.2f}s")
            print(f"  Throughput: {len(test_emails)/duration:.1f} emails/second")
            
            # Assertions
            assert successful >= 18, f"Too many failures: {failed}"
            assert duration <= 30, f"Processing took too long: {duration}s"
    
    @pytest.mark.asyncio
    async def test_queue_backpressure_handling(self):
        """Test queue handles backpressure correctly"""
        
        queue_manager = get_queue_manager()
        
        # Simulate queue filling up
        for i in range(100):
            email_task = {
                'user_id': f'queue_user_{i}',
                'email_id': f'queue_email_{i}',
                'priority': 'normal',
                'created_at': time.time()
            }
            
            try:
                await queue_manager.enqueue_email_scan(email_task)
            except Exception as e:
                print(f"Queue backpressure at {i} items: {e}")
                break
        
        # Check queue health
        queue_stats = queue_manager.get_queue_stats()
        
        print(f"Queue Backpressure Test:")
        print(f"  Queue Size: {queue_stats.get('size', 0)}")
        print(f"  Max Size: {queue_stats.get('max_size', 'unlimited')}")
        print(f"  Pending: {queue_stats.get('pending', 0)}")
        print(f"  Processing: {queue_stats.get('processing', 0)}")
        
        # Assertions
        assert queue_stats.get('size', 0) <= queue_stats.get('max_size', 1000), "Queue size exceeded maximum"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
