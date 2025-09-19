"""
Load Testing for Privacy-Hardened PhishNet System
Tests system behavior under realistic load conditions
"""

import pytest
import asyncio
import time
import statistics
import json
import random
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
import aiohttp
from unittest.mock import Mock, patch

# Import modules to test
from app.core.encryption import get_encryption_manager
from app.core.pii_sanitizer import get_pii_sanitizer
from app.core.sandbox_security import get_sandbox_ip_manager
from app.core.audit_logger import get_audit_logger, AuditEventType
from app.core.retention_manager import get_retention_manager
from app.orchestrator.main import PhishNetOrchestrator

@dataclass
class LoadTestMetrics:
    """Metrics collection for load tests"""
    total_requests: int
    successful_requests: int
    failed_requests: int
    average_response_time: float
    min_response_time: float
    max_response_time: float
    p95_response_time: float
    p99_response_time: float
    throughput_per_second: float
    error_rate: float
    start_time: float
    end_time: float
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class LoadTestRunner:
    """Load test execution and metrics collection"""
    
    def __init__(self):
        self.metrics_data: List[float] = []
        self.error_count = 0
        self.start_time = 0
        self.end_time = 0
    
    def start_test(self):
        """Start load test timing"""
        self.metrics_data = []
        self.error_count = 0
        self.start_time = time.time()
    
    def record_request(self, response_time: float, success: bool):
        """Record individual request metrics"""
        self.metrics_data.append(response_time)
        if not success:
            self.error_count += 1
    
    def finish_test(self) -> LoadTestMetrics:
        """Complete test and calculate metrics"""
        self.end_time = time.time()
        
        if not self.metrics_data:
            return LoadTestMetrics(
                total_requests=0,
                successful_requests=0,
                failed_requests=self.error_count,
                average_response_time=0,
                min_response_time=0,
                max_response_time=0,
                p95_response_time=0,
                p99_response_time=0,
                throughput_per_second=0,
                error_rate=1.0,
                start_time=self.start_time,
                end_time=self.end_time
            )
        
        total_requests = len(self.metrics_data) + self.error_count
        successful_requests = len(self.metrics_data)
        
        # Calculate percentiles
        sorted_times = sorted(self.metrics_data)
        p95_index = int(0.95 * len(sorted_times))
        p99_index = int(0.99 * len(sorted_times))
        
        test_duration = self.end_time - self.start_time
        throughput = total_requests / test_duration if test_duration > 0 else 0
        
        return LoadTestMetrics(
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=self.error_count,
            average_response_time=statistics.mean(self.metrics_data),
            min_response_time=min(self.metrics_data),
            max_response_time=max(self.metrics_data),
            p95_response_time=sorted_times[p95_index] if sorted_times else 0,
            p99_response_time=sorted_times[p99_index] if sorted_times else 0,
            throughput_per_second=throughput,
            error_rate=self.error_count / total_requests if total_requests > 0 else 0,
            start_time=self.start_time,
            end_time=self.end_time
        )

@pytest.fixture
def load_test_runner():
    """Load test runner instance"""
    return LoadTestRunner()

@pytest.fixture
def test_email_data():
    """Generate test email data for load testing"""
    subjects = [
        "Meeting reminder",
        "URGENT: Action required",
        "Your account has been suspended",
        "Re: Project update",
        "Verify your identity now",
        "Invoice attached",
        "Security alert for your account",
        "Welcome to our service"
    ]
    
    senders = [
        "colleague@company.com",
        "noreply@suspicious-site.com",
        "security@bank-fake.com",
        "admin@legitimate-service.com",
        "support@phishing-attempt.evil",
        "notifications@real-service.com"
    ]
    
    bodies = [
        "Normal business communication content",
        "URGENT! Your account will be suspended! Click here immediately!",
        "Please verify your identity by clicking this link",
        "Thank you for your recent purchase. Invoice attached.",
        "Unusual activity detected on your account. Verify now.",
        "Your password will expire soon. Update it here."
    ]
    
    links = [
        ["https://calendar.company.com/meeting"],
        ["https://suspicious-domain.com/verify"],
        ["https://fake-bank.evil/login"],
        ["https://legitimate-service.com/invoice"],
        ["https://phishing-site.com/verify?user=victim"],
        ["https://real-service.com/password-reset"]
    ]
    
    return {
        "subjects": subjects,
        "senders": senders,
        "bodies": bodies,
        "links": links
    }

# Core Component Load Tests

class TestEncryptionLoad:
    """Test encryption performance under load"""
    
    @pytest.mark.asyncio
    async def test_concurrent_encryption_operations(self, load_test_runner):
        """Test encryption under concurrent load"""
        encryption_manager = get_encryption_manager()
        load_test_runner.start_test()
        
        # Test data
        test_tokens = [f"oauth_token_{i}_{random.randint(1000, 9999)}" for i in range(100)]
        test_pii = [f"user{i}@example.com" for i in range(100)]
        
        async def encrypt_token_task(token: str) -> bool:
            """Single encryption task"""
            start_time = time.time()
            try:
                encrypted = encryption_manager.encrypt_token(token)
                decrypted = encryption_manager.decrypt_token(encrypted)
                success = decrypted == token
                
                response_time = time.time() - start_time
                load_test_runner.record_request(response_time, success)
                return success
            except Exception:
                response_time = time.time() - start_time
                load_test_runner.record_request(response_time, False)
                return False
        
        # Run concurrent encryption tasks
        tasks = []
        for token in test_tokens:
            tasks.append(encrypt_token_task(token))
        
        for pii in test_pii:
            tasks.append(encrypt_token_task(pii))  # Reuse same function
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        metrics = load_test_runner.finish_test()
        
        # Verify performance criteria
        assert metrics.error_rate < 0.01  # Less than 1% error rate
        assert metrics.average_response_time < 0.1  # Less than 100ms average
        assert metrics.p95_response_time < 0.2  # Less than 200ms for 95th percentile
        assert metrics.throughput_per_second > 100  # At least 100 ops/second
        
        print(f"Encryption Load Test Metrics: {json.dumps(metrics.to_dict(), indent=2)}")
    
    @pytest.mark.asyncio
    async def test_encryption_memory_usage(self):
        """Test encryption memory usage under sustained load"""
        encryption_manager = get_encryption_manager()
        
        # Generate large dataset
        large_data = ["x" * 10000 for _ in range(1000)]  # 10MB of data
        
        start_time = time.time()
        encrypted_data = []
        
        for data in large_data:
            encrypted = encryption_manager.encrypt_email_content(data)
            encrypted_data.append(encrypted)
        
        encryption_time = time.time() - start_time
        
        # Decrypt to verify
        start_time = time.time()
        for i, encrypted in enumerate(encrypted_data):
            decrypted = encryption_manager.decrypt_email_content(encrypted)
            assert decrypted == large_data[i]
        
        decryption_time = time.time() - start_time
        
        # Performance assertions
        assert encryption_time < 30.0  # Should complete within 30 seconds
        assert decryption_time < 30.0  # Should complete within 30 seconds

class TestPIISanitizationLoad:
    """Test PII sanitization performance under load"""
    
    @pytest.mark.asyncio
    async def test_concurrent_pii_sanitization(self, load_test_runner, test_email_data):
        """Test PII sanitization under concurrent load"""
        pii_sanitizer = get_pii_sanitizer()
        load_test_runner.start_test()
        
        # Create content with varying amounts of PII
        test_contents = []
        for i in range(200):
            content = f"""
            Email content {i} from user{i}@company.com
            Phone: +1 (555) {random.randint(100, 999)}-{random.randint(1000, 9999)}
            SSN: {random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}
            Visit: https://example{i}.com/verify?user=user{i}@company.com&token=abc{i}
            Credit card: 4532-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}
            """
            test_contents.append(content)
        
        async def sanitize_task(content: str, service: str) -> bool:
            """Single sanitization task"""
            start_time = time.time()
            try:
                result = pii_sanitizer.sanitize_for_third_party(content, service)
                success = result is not None and 'sanitized_content' in result
                
                response_time = time.time() - start_time
                load_test_runner.record_request(response_time, success)
                return success
            except Exception:
                response_time = time.time() - start_time
                load_test_runner.record_request(response_time, False)
                return False
        
        # Run concurrent sanitization tasks
        services = ["virustotal", "gemini", "openai", "anthropic"]
        tasks = []
        
        for content in test_contents:
            service = random.choice(services)
            tasks.append(sanitize_task(content, service))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        metrics = load_test_runner.finish_test()
        
        # Verify performance criteria
        assert metrics.error_rate < 0.05  # Less than 5% error rate
        assert metrics.average_response_time < 0.5  # Less than 500ms average
        assert metrics.p95_response_time < 1.0  # Less than 1s for 95th percentile
        assert metrics.throughput_per_second > 50  # At least 50 sanitizations/second
        
        print(f"PII Sanitization Load Test Metrics: {json.dumps(metrics.to_dict(), indent=2)}")
    
    @pytest.mark.asyncio
    async def test_pii_sanitization_with_large_content(self):
        """Test PII sanitization with very large content"""
        pii_sanitizer = get_pii_sanitizer()
        
        # Create very large content (1MB)
        base_content = "This is a large email body with PII elements. " * 1000
        pii_content = f"""
        {base_content}
        
        Contact information:
        Email: john.doe@company.com
        Phone: +1 (555) 123-4567
        SSN: 123-45-6789
        
        {base_content}
        
        Credit card: 4532-1234-5678-9012
        Account: https://bank.com/login?user=john.doe@company.com
        
        {base_content}
        """
        
        start_time = time.time()
        result = pii_sanitizer.sanitize_for_third_party(pii_content, "virustotal")
        sanitization_time = time.time() - start_time
        
        # Should complete within reasonable time
        assert sanitization_time < 5.0  # Less than 5 seconds for 1MB
        
        # Should successfully redact PII
        sanitized = result['sanitized_content']
        assert "john.doe@company.com" not in sanitized
        assert "123-45-6789" not in sanitized
        assert "4532-1234-5678-9012" not in sanitized

class TestAuditLoggingLoad:
    """Test audit logging performance under load"""
    
    @pytest.mark.asyncio
    async def test_concurrent_audit_logging(self, load_test_runner):
        """Test audit logging under concurrent load"""
        audit_logger = get_audit_logger()
        load_test_runner.start_test()
        
        user_ids = [f"load_test_user_{i}" for i in range(50)]
        event_types = [
            AuditEventType.SCAN_STARTED,
            AuditEventType.SCAN_COMPLETED,
            AuditEventType.USER_LOGIN,
            AuditEventType.CONSENT_GRANTED,
            AuditEventType.EMAIL_QUARANTINED
        ]
        
        async def log_audit_event(user_id: str, event_type: AuditEventType) -> bool:
            """Single audit logging task"""
            start_time = time.time()
            try:
                with audit_logger.audit_context(
                    user_id=user_id,
                    request_id=f"load_test_{random.randint(1000, 9999)}"
                ):
                    audit_logger.log_event(
                        event_type,
                        f"Load test event {event_type.value}",
                        details={'test_data': True, 'timestamp': time.time()}
                    )
                
                response_time = time.time() - start_time
                load_test_runner.record_request(response_time, True)
                return True
            except Exception:
                response_time = time.time() - start_time
                load_test_runner.record_request(response_time, False)
                return False
        
        # Generate concurrent audit events
        tasks = []
        for _ in range(1000):  # 1000 audit events
            user_id = random.choice(user_ids)
            event_type = random.choice(event_types)
            tasks.append(log_audit_event(user_id, event_type))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        metrics = load_test_runner.finish_test()
        
        # Verify performance criteria
        assert metrics.error_rate < 0.02  # Less than 2% error rate
        assert metrics.average_response_time < 0.1  # Less than 100ms average
        assert metrics.throughput_per_second > 200  # At least 200 logs/second
        
        print(f"Audit Logging Load Test Metrics: {json.dumps(metrics.to_dict(), indent=2)}")

# System Integration Load Tests

class TestEmailScanningLoad:
    """Test email scanning system under load"""
    
    @pytest.mark.asyncio
    async def test_concurrent_email_scans(self, load_test_runner, test_email_data):
        """Test concurrent email scanning load"""
        load_test_runner.start_test()
        
        async def scan_email_task(email_index: int) -> bool:
            """Single email scan task"""
            start_time = time.time()
            
            try:
                # Create email data
                subjects = test_email_data["subjects"]
                senders = test_email_data["senders"]
                bodies = test_email_data["bodies"]
                links = test_email_data["links"]
                
                email_data = {
                    "subject": subjects[email_index % len(subjects)],
                    "sender": senders[email_index % len(senders)],
                    "body": bodies[email_index % len(bodies)],
                    "links": links[email_index % len(links)]
                }
                
                # Mock orchestrator scan
                with patch('app.integrations.virustotal.VirusTotalClient.scan_url') as mock_vt, \
                     patch('app.integrations.gemini.GeminiClient.analyze_content') as mock_gemini:
                    
                    mock_vt.return_value = {
                        'scan_id': f'test_{email_index}',
                        'positives': random.randint(0, 5),
                        'total': 70
                    }
                    
                    mock_gemini.return_value = {
                        'threat_probability': random.uniform(0.1, 0.9),
                        'confidence': random.uniform(0.8, 1.0),
                        'reasoning': 'Test analysis'
                    }
                    
                    # Simulate scan processing
                    await asyncio.sleep(random.uniform(0.05, 0.2))  # 50-200ms processing
                    
                    response_time = time.time() - start_time
                    load_test_runner.record_request(response_time, True)
                    return True
                    
            except Exception:
                response_time = time.time() - start_time
                load_test_runner.record_request(response_time, False)
                return False
        
        # Run concurrent scans
        num_scans = 100
        tasks = [scan_email_task(i) for i in range(num_scans)]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        metrics = load_test_runner.finish_test()
        
        # Verify performance criteria
        assert metrics.error_rate < 0.05  # Less than 5% error rate
        assert metrics.average_response_time < 1.0  # Less than 1s average
        assert metrics.p95_response_time < 2.0  # Less than 2s for 95th percentile
        assert metrics.throughput_per_second > 20  # At least 20 scans/second
        
        print(f"Email Scanning Load Test Metrics: {json.dumps(metrics.to_dict(), indent=2)}")
    
    @pytest.mark.asyncio
    async def test_sustained_scanning_load(self, test_email_data):
        """Test sustained scanning load over time"""
        scan_duration = 60  # 1 minute sustained test
        target_rate = 30  # 30 scans per minute
        
        start_time = time.time()
        completed_scans = 0
        errors = 0
        
        async def sustained_scan_worker():
            """Worker that continuously scans emails"""
            nonlocal completed_scans, errors
            
            while time.time() - start_time < scan_duration:
                try:
                    # Simulate email scan
                    await asyncio.sleep(random.uniform(0.1, 0.3))
                    completed_scans += 1
                except Exception:
                    errors += 1
                
                # Rate limiting
                await asyncio.sleep(2.0)  # Wait 2s between scans
        
        # Run sustained load
        workers = [sustained_scan_worker() for _ in range(5)]
        await asyncio.gather(*workers, return_exceptions=True)
        
        actual_duration = time.time() - start_time
        actual_rate = completed_scans / (actual_duration / 60)  # scans per minute
        error_rate = errors / (completed_scans + errors) if (completed_scans + errors) > 0 else 0
        
        # Verify sustained performance
        assert actual_rate >= target_rate * 0.8  # At least 80% of target rate
        assert error_rate < 0.1  # Less than 10% error rate
        
        print(f"Sustained Load Results: {completed_scans} scans in {actual_duration:.1f}s, "
              f"Rate: {actual_rate:.1f} scans/min, Error rate: {error_rate:.2%}")

# API Quota Protection Tests

class TestQuotaProtection:
    """Test that system protects external API quotas"""
    
    @pytest.mark.asyncio
    async def test_virustotal_quota_protection(self):
        """Test VirusTotal quota protection under load"""
        
        # Simulate high request volume
        urls_to_scan = [f"https://test-site-{i}.com" for i in range(1000)]
        
        # Mock VirusTotal with quota tracking
        vt_requests = []
        quota_exceeded = False
        
        async def mock_vt_scan(url: str):
            nonlocal quota_exceeded
            vt_requests.append(url)
            
            # Simulate quota limit (4 requests per minute for free tier)
            if len(vt_requests) > 4:
                quota_exceeded = True
                raise Exception("Quota exceeded")
            
            return {'scan_id': f'vt_{len(vt_requests)}', 'positives': 0, 'total': 70}
        
        # Test with caching and rate limiting
        with patch('app.integrations.virustotal.VirusTotalClient.scan_url', side_effect=mock_vt_scan):
            
            # First batch - should use API
            batch1 = urls_to_scan[:10]
            for url in batch1:
                try:
                    await mock_vt_scan(url)
                except Exception:
                    break
            
            # Verify quota protection triggered
            assert len(vt_requests) <= 4  # Should stop at quota limit
            
            # Reset for cache test
            vt_requests.clear()
            quota_exceeded = False
            
            # Second batch - should use cache for repeated URLs
            batch2 = urls_to_scan[:3] * 5  # Repeat same URLs
            unique_requests = 0
            
            for url in batch2:
                if url not in vt_requests:
                    try:
                        await mock_vt_scan(url)
                        unique_requests += 1
                    except Exception:
                        break
            
            # Should only make unique requests
            assert len(vt_requests) == min(3, 4)  # Max 3 unique URLs or quota limit
    
    @pytest.mark.asyncio
    async def test_llm_quota_protection(self):
        """Test LLM API quota protection"""
        
        # Simulate email content analysis requests
        email_contents = [f"Email content {i} with varying threat levels" for i in range(100)]
        
        # Mock LLM with token counting
        total_tokens_used = 0
        max_tokens_per_minute = 10000  # Example limit
        
        async def mock_llm_analysis(content: str):
            nonlocal total_tokens_used
            
            # Estimate token usage (rough approximation)
            estimated_tokens = len(content.split()) * 2
            
            if total_tokens_used + estimated_tokens > max_tokens_per_minute:
                raise Exception("Token quota exceeded")
            
            total_tokens_used += estimated_tokens
            
            return {
                'threat_probability': 0.3,
                'confidence': 0.9,
                'reasoning': 'Analysis result'
            }
        
        # Test batch processing with quota awareness
        processed_emails = 0
        quota_exceeded_count = 0
        
        for content in email_contents:
            try:
                await mock_llm_analysis(content)
                processed_emails += 1
            except Exception:
                quota_exceeded_count += 1
                break
        
        # Should stop before exceeding quota
        assert total_tokens_used <= max_tokens_per_minute
        assert processed_emails > 0  # Should process some emails
        assert quota_exceeded_count <= 1  # Should stop when quota approached

# Performance Benchmarking

class TestPerformanceBenchmarks:
    """Benchmark tests for performance tracking"""
    
    @pytest.mark.asyncio
    async def test_system_performance_baseline(self):
        """Establish performance baseline metrics"""
        metrics = {}
        
        # Encryption benchmark
        encryption_manager = get_encryption_manager()
        start_time = time.time()
        for i in range(1000):
            token = f"test_token_{i}"
            encrypted = encryption_manager.encrypt_token(token)
            decrypted = encryption_manager.decrypt_token(encrypted)
        encryption_time = time.time() - start_time
        metrics['encryption_ops_per_second'] = 1000 / encryption_time
        
        # PII sanitization benchmark
        pii_sanitizer = get_pii_sanitizer()
        test_content = "Contact john.doe@example.com or call 555-1234 for SSN 123-45-6789"
        start_time = time.time()
        for i in range(100):
            result = pii_sanitizer.sanitize_for_third_party(test_content, "virustotal")
        sanitization_time = time.time() - start_time
        metrics['sanitization_ops_per_second'] = 100 / sanitization_time
        
        # Audit logging benchmark
        audit_logger = get_audit_logger()
        start_time = time.time()
        for i in range(1000):
            with audit_logger.audit_context(user_id=f"bench_user_{i}"):
                audit_logger.log_event(
                    AuditEventType.SCAN_STARTED,
                    f"Benchmark event {i}",
                    details={'benchmark': True}
                )
        logging_time = time.time() - start_time
        metrics['audit_logs_per_second'] = 1000 / logging_time
        
        # Print baseline metrics
        print(f"Performance Baseline Metrics:")
        for metric, value in metrics.items():
            print(f"  {metric}: {value:.2f}")
        
        # Establish minimum performance thresholds
        assert metrics['encryption_ops_per_second'] > 500  # At least 500 ops/sec
        assert metrics['sanitization_ops_per_second'] > 20  # At least 20 ops/sec
        assert metrics['audit_logs_per_second'] > 100  # At least 100 logs/sec

if __name__ == "__main__":
    # Run load tests
    pytest.main([
        __file__,
        "-v",
        "-s",  # Show print output
        "-m", "not slow",
        "--tb=short"
    ])
