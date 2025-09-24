"""
Performance and Load Testing Suite

Comprehensive performance testing for the PhishNet application:
- API endpoint performance testing
- Database query performance testing  
- Email processing throughput testing
- Concurrent user load testing
- Memory usage monitoring
- Response time benchmarking
- Scalability testing
- Resource utilization testing
"""

import pytest
import asyncio
import time
import psutil
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from unittest.mock import AsyncMock, MagicMock
from concurrent.futures import ThreadPoolExecutor, as_completed
import aiohttp
import json
import resource

from backend.app.main import app
from backend.app.services import EmailService, ThreatAnalysisService
from backend.app.ml import ThreatClassifier
from backend.app.db import DatabaseManager
from backend.app.observability import get_logger

logger = get_logger(__name__)

class PerformanceMonitor:
    """Monitor system performance during tests."""
    
    def __init__(self):
        self.start_time = None
        self.start_memory = None
        self.start_cpu = None
        self.metrics = []
    
    def start_monitoring(self):
        """Start performance monitoring."""
        self.start_time = time.time()
        self.start_memory = psutil.virtual_memory().used
        self.start_cpu = psutil.cpu_percent(interval=None)
        process = psutil.Process()
        self.start_process_memory = process.memory_info().rss
    
    def record_metric(self, operation: str, duration: float, custom_metrics: Dict = None):
        """Record a performance metric."""
        metric = {
            "operation": operation,
            "duration": duration,
            "timestamp": time.time(),
            "memory_used": psutil.virtual_memory().used - self.start_memory,
            "cpu_percent": psutil.cpu_percent(interval=None)
        }
        if custom_metrics:
            metric.update(custom_metrics)
        self.metrics.append(metric)
    
    def get_summary(self) -> Dict:
        """Get performance summary."""
        if not self.metrics:
            return {}
        
        durations = [m["duration"] for m in self.metrics]
        memory_usage = [m["memory_used"] for m in self.metrics]
        
        return {
            "total_operations": len(self.metrics),
            "total_duration": time.time() - self.start_time,
            "avg_duration": statistics.mean(durations),
            "min_duration": min(durations),
            "max_duration": max(durations),
            "p95_duration": statistics.quantiles(durations, n=20)[18] if len(durations) > 20 else max(durations),
            "p99_duration": statistics.quantiles(durations, n=100)[98] if len(durations) > 100 else max(durations),
            "max_memory_used": max(memory_usage) if memory_usage else 0,
            "avg_cpu_percent": statistics.mean([m["cpu_percent"] for m in self.metrics])
        }

@pytest.fixture
def performance_monitor():
    """Create performance monitor."""
    return PerformanceMonitor()

@pytest.fixture
async def email_service():
    """Create email service for testing."""
    return EmailService(
        db_manager=AsyncMock(),
        threat_analyzer=AsyncMock()
    )

@pytest.fixture
async def threat_service():
    """Create threat analysis service for testing."""
    return ThreatAnalysisService(
        ml_model=AsyncMock(),
        db_manager=AsyncMock()
    )

class TestAPIPerformance:
    """Test API endpoint performance."""
    
    @pytest.mark.asyncio
    async def test_health_endpoint_performance(self, performance_monitor):
        """Test health endpoint response time."""
        performance_monitor.start_monitoring()
        
        # Test multiple health checks
        response_times = []
        
        async with aiohttp.ClientSession() as session:
            for _ in range(100):
                start_time = time.time()
                async with session.get("http://localhost:8000/health") as response:
                    await response.text()
                end_time = time.time()
                response_times.append(end_time - start_time)
        
        # Record metrics
        for rt in response_times:
            performance_monitor.record_metric("health_check", rt)
        
        # Verify performance requirements
        avg_response_time = statistics.mean(response_times)
        p95_response_time = statistics.quantiles(response_times, n=20)[18]
        
        assert avg_response_time < 0.05, f"Average health check too slow: {avg_response_time:.3f}s"
        assert p95_response_time < 0.1, f"P95 health check too slow: {p95_response_time:.3f}s"
        assert max(response_times) < 0.2, f"Max health check too slow: {max(response_times):.3f}s"
    
    @pytest.mark.asyncio
    async def test_auth_endpoint_performance(self, performance_monitor):
        """Test authentication endpoint performance."""
        performance_monitor.start_monitoring()
        
        # Test authentication requests
        auth_times = []
        
        auth_data = {
            "username": "test_user",
            "password": "test_password"
        }
        
        async with aiohttp.ClientSession() as session:
            for _ in range(50):
                start_time = time.time()
                async with session.post(
                    "http://localhost:8000/auth/login",
                    json=auth_data
                ) as response:
                    await response.text()
                end_time = time.time()
                auth_times.append(end_time - start_time)
        
        # Record metrics
        for at in auth_times:
            performance_monitor.record_metric("authentication", at)
        
        # Verify performance requirements
        avg_auth_time = statistics.mean(auth_times)
        p95_auth_time = statistics.quantiles(auth_times, n=20)[18]
        
        assert avg_auth_time < 0.5, f"Average auth too slow: {avg_auth_time:.3f}s"
        assert p95_auth_time < 1.0, f"P95 auth too slow: {p95_auth_time:.3f}s"
    
    @pytest.mark.asyncio
    async def test_scan_endpoint_performance(self, performance_monitor):
        """Test email scan endpoint performance."""
        performance_monitor.start_monitoring()
        
        # Test scan requests
        scan_times = []
        
        scan_data = {
            "email_content": "Test email content for performance testing",
            "sender": "test@example.com",
            "subject": "Performance test email"
        }
        
        async with aiohttp.ClientSession() as session:
            # Add auth header (mock token)
            headers = {"Authorization": "Bearer test_token"}
            
            for _ in range(25):  # Smaller batch for compute-intensive operation
                start_time = time.time()
                async with session.post(
                    "http://localhost:8000/api/scan",
                    json=scan_data,
                    headers=headers
                ) as response:
                    await response.text()
                end_time = time.time()
                scan_times.append(end_time - start_time)
        
        # Record metrics
        for st in scan_times:
            performance_monitor.record_metric("email_scan", st)
        
        # Verify performance requirements
        avg_scan_time = statistics.mean(scan_times)
        p95_scan_time = statistics.quantiles(scan_times, n=20)[18] if len(scan_times) > 20 else max(scan_times)
        
        assert avg_scan_time < 2.0, f"Average scan too slow: {avg_scan_time:.3f}s"
        assert p95_scan_time < 5.0, f"P95 scan too slow: {p95_scan_time:.3f}s"

class TestDatabasePerformance:
    """Test database query performance."""
    
    @pytest.mark.asyncio
    async def test_user_lookup_performance(self, performance_monitor):
        """Test user lookup query performance."""
        db_manager = DatabaseManager()
        performance_monitor.start_monitoring()
        
        # Test user lookups
        lookup_times = []
        
        for i in range(100):
            user_id = f"test_user_{i % 10}"  # Reuse some users
            
            start_time = time.time()
            user = await db_manager.get_user(user_id)
            end_time = time.time()
            
            lookup_times.append(end_time - start_time)
        
        # Record metrics
        for lt in lookup_times:
            performance_monitor.record_metric("user_lookup", lt)
        
        # Verify performance requirements
        avg_lookup_time = statistics.mean(lookup_times)
        p95_lookup_time = statistics.quantiles(lookup_times, n=20)[18]
        
        assert avg_lookup_time < 0.01, f"Average user lookup too slow: {avg_lookup_time:.4f}s"
        assert p95_lookup_time < 0.05, f"P95 user lookup too slow: {p95_lookup_time:.4f}s"
    
    @pytest.mark.asyncio
    async def test_email_query_performance(self, performance_monitor):
        """Test email query performance."""
        db_manager = DatabaseManager()
        performance_monitor.start_monitoring()
        
        # Test email queries
        query_times = []
        
        for i in range(50):
            user_id = f"test_user_{i % 5}"
            
            start_time = time.time()
            emails = await db_manager.get_user_emails(user_id, limit=100)
            end_time = time.time()
            
            query_times.append(end_time - start_time)
        
        # Record metrics
        for qt in query_times:
            performance_monitor.record_metric("email_query", qt)
        
        # Verify performance requirements
        avg_query_time = statistics.mean(query_times)
        p95_query_time = statistics.quantiles(query_times, n=20)[18] if len(query_times) > 20 else max(query_times)
        
        assert avg_query_time < 0.1, f"Average email query too slow: {avg_query_time:.3f}s"
        assert p95_query_time < 0.5, f"P95 email query too slow: {p95_query_time:.3f}s"
    
    @pytest.mark.asyncio
    async def test_bulk_insert_performance(self, performance_monitor):
        """Test bulk database insert performance."""
        db_manager = DatabaseManager()
        performance_monitor.start_monitoring()
        
        # Test bulk inserts
        batch_sizes = [10, 50, 100, 500]
        
        for batch_size in batch_sizes:
            # Prepare test data
            test_emails = []
            for i in range(batch_size):
                test_emails.append({
                    "user_id": "test_user_bulk",
                    "subject": f"Test email {i}",
                    "body": f"Test email body {i}",
                    "sender": f"sender_{i}@example.com",
                    "received_at": datetime.utcnow()
                })
            
            start_time = time.time()
            await db_manager.bulk_insert_emails(test_emails)
            end_time = time.time()
            
            duration = end_time - start_time
            throughput = batch_size / duration
            
            performance_monitor.record_metric(
                f"bulk_insert_{batch_size}", 
                duration,
                {"throughput": throughput, "batch_size": batch_size}
            )
            
            # Verify performance requirements
            assert throughput > 50, f"Bulk insert throughput too low: {throughput:.1f} emails/sec"

class TestEmailProcessingPerformance:
    """Test email processing performance."""
    
    @pytest.mark.asyncio
    async def test_email_parsing_performance(self, email_service, performance_monitor):
        """Test email parsing performance."""
        performance_monitor.start_monitoring()
        
        # Test email parsing
        parsing_times = []
        
        # Sample email content of various sizes
        email_sizes = [1024, 10240, 51200, 102400]  # 1KB, 10KB, 50KB, 100KB
        
        for size in email_sizes:
            email_content = f"""
Subject: Performance test email
From: sender@example.com
To: recipient@example.com
Content-Type: text/plain

{'A' * size}
"""
            
            for _ in range(10):  # Test each size 10 times
                start_time = time.time()
                parsed_email = await email_service.parse_email(email_content)
                end_time = time.time()
                
                parsing_times.append(end_time - start_time)
                
                performance_monitor.record_metric(
                    f"email_parsing_{size}B", 
                    end_time - start_time,
                    {"email_size": size}
                )
        
        # Verify performance requirements
        avg_parsing_time = statistics.mean(parsing_times)
        assert avg_parsing_time < 0.1, f"Average email parsing too slow: {avg_parsing_time:.3f}s"
    
    @pytest.mark.asyncio
    async def test_threat_analysis_performance(self, threat_service, performance_monitor):
        """Test threat analysis performance."""
        performance_monitor.start_monitoring()
        
        # Test threat analysis
        analysis_times = []
        
        test_emails = [
            {
                "subject": "Urgent: Verify your account",
                "body": "Click here to verify your account: http://phishing-site.com",
                "sender": "noreply@bank-fake.com"
            },
            {
                "subject": "Team meeting reminder",
                "body": "Don't forget our team meeting tomorrow at 2 PM",
                "sender": "manager@company.com"
            },
            {
                "subject": "Invoice #12345",
                "body": "Please find attached the invoice for your recent purchase",
                "sender": "billing@legitimate-store.com"
            }
        ]
        
        for email in test_emails:
            for _ in range(20):  # Analyze each email 20 times
                start_time = time.time()
                analysis_result = await threat_service.analyze_email(email)
                end_time = time.time()
                
                analysis_times.append(end_time - start_time)
                
                performance_monitor.record_metric("threat_analysis", end_time - start_time)
        
        # Verify performance requirements
        avg_analysis_time = statistics.mean(analysis_times)
        p95_analysis_time = statistics.quantiles(analysis_times, n=20)[18]
        
        assert avg_analysis_time < 1.0, f"Average threat analysis too slow: {avg_analysis_time:.3f}s"
        assert p95_analysis_time < 2.0, f"P95 threat analysis too slow: {p95_analysis_time:.3f}s"
    
    @pytest.mark.asyncio
    async def test_batch_processing_performance(self, email_service, performance_monitor):
        """Test batch email processing performance."""
        performance_monitor.start_monitoring()
        
        # Test batch processing
        batch_sizes = [10, 50, 100]
        
        for batch_size in batch_sizes:
            # Prepare email batch
            email_batch = []
            for i in range(batch_size):
                email_batch.append({
                    "id": f"email_{i}",
                    "subject": f"Test email {i}",
                    "body": f"Test email body content {i}",
                    "sender": f"sender_{i}@example.com"
                })
            
            start_time = time.time()
            results = await email_service.process_email_batch(email_batch)
            end_time = time.time()
            
            duration = end_time - start_time
            throughput = batch_size / duration
            
            performance_monitor.record_metric(
                f"batch_processing_{batch_size}",
                duration,
                {"throughput": throughput, "batch_size": batch_size}
            )
            
            # Verify performance requirements
            assert throughput > 10, f"Batch processing throughput too low: {throughput:.1f} emails/sec"
            assert len(results) == batch_size, "Should process all emails in batch"

class TestConcurrentLoadPerformance:
    """Test concurrent load performance."""
    
    @pytest.mark.asyncio
    async def test_concurrent_user_load(self, performance_monitor):
        """Test concurrent user load handling."""
        performance_monitor.start_monitoring()
        
        concurrent_users = [10, 25, 50, 100]
        
        for user_count in concurrent_users:
            # Test concurrent requests
            async def simulate_user_session():
                """Simulate a user session."""
                session_start = time.time()
                
                async with aiohttp.ClientSession() as session:
                    # Login
                    auth_data = {"username": f"user_{time.time()}", "password": "password"}
                    async with session.post("http://localhost:8000/auth/login", json=auth_data) as response:
                        auth_result = await response.text()
                    
                    # Perform email scan
                    scan_data = {
                        "email_content": "Test email for concurrent load testing",
                        "sender": "test@example.com",
                        "subject": "Load test email"
                    }
                    headers = {"Authorization": "Bearer test_token"}
                    async with session.post("http://localhost:8000/api/scan", json=scan_data, headers=headers) as response:
                        scan_result = await response.text()
                
                session_end = time.time()
                return session_end - session_start
            
            # Run concurrent user sessions
            start_time = time.time()
            
            tasks = [simulate_user_session() for _ in range(user_count)]
            session_durations = await asyncio.gather(*tasks)
            
            end_time = time.time()
            total_duration = end_time - start_time
            
            # Record metrics
            avg_session_duration = statistics.mean(session_durations)
            max_session_duration = max(session_durations)
            
            performance_monitor.record_metric(
                f"concurrent_load_{user_count}",
                total_duration,
                {
                    "user_count": user_count,
                    "avg_session_duration": avg_session_duration,
                    "max_session_duration": max_session_duration,
                    "requests_per_second": (user_count * 2) / total_duration  # 2 requests per user
                }
            )
            
            # Verify performance requirements
            assert avg_session_duration < 5.0, f"Average session too slow under load: {avg_session_duration:.3f}s"
            assert max_session_duration < 10.0, f"Max session too slow under load: {max_session_duration:.3f}s"
    
    @pytest.mark.asyncio
    async def test_concurrent_threat_analysis(self, threat_service, performance_monitor):
        """Test concurrent threat analysis performance."""
        performance_monitor.start_monitoring()
        
        # Test concurrent threat analysis
        async def analyze_email_concurrently(email_data):
            """Analyze email concurrently."""
            start_time = time.time()
            result = await threat_service.analyze_email(email_data)
            end_time = time.time()
            return end_time - start_time
        
        # Prepare test emails
        test_emails = []
        for i in range(50):
            test_emails.append({
                "subject": f"Test email {i}",
                "body": f"Test email body content {i}",
                "sender": f"sender_{i}@example.com"
            })
        
        # Run concurrent analysis
        start_time = time.time()
        
        tasks = [analyze_email_concurrently(email) for email in test_emails]
        analysis_durations = await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        # Record metrics
        avg_analysis_duration = statistics.mean(analysis_durations)
        throughput = len(test_emails) / total_duration
        
        performance_monitor.record_metric(
            "concurrent_threat_analysis",
            total_duration,
            {
                "email_count": len(test_emails),
                "avg_analysis_duration": avg_analysis_duration,
                "throughput": throughput
            }
        )
        
        # Verify performance requirements
        assert throughput > 10, f"Concurrent analysis throughput too low: {throughput:.1f} emails/sec"
        assert avg_analysis_duration < 2.0, f"Average concurrent analysis too slow: {avg_analysis_duration:.3f}s"

class TestMemoryPerformance:
    """Test memory usage performance."""
    
    @pytest.mark.asyncio
    async def test_memory_usage_under_load(self, email_service, performance_monitor):
        """Test memory usage under load."""
        performance_monitor.start_monitoring()
        
        # Monitor memory usage during intensive operations
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        memory_samples = []
        
        # Process large number of emails
        for batch in range(10):
            # Create email batch
            email_batch = []
            for i in range(100):
                email_batch.append({
                    "id": f"memory_test_{batch}_{i}",
                    "subject": f"Memory test email {i}" * 10,  # Longer subject
                    "body": f"Memory test email body content {i}" * 100,  # Longer body
                    "sender": f"sender_{i}@example.com"
                })
            
            # Process batch
            await email_service.process_email_batch(email_batch)
            
            # Sample memory usage
            current_memory = process.memory_info().rss
            memory_usage_mb = (current_memory - initial_memory) / 1024 / 1024
            memory_samples.append(memory_usage_mb)
            
            performance_monitor.record_metric(
                f"memory_usage_batch_{batch}",
                0,  # Duration not relevant for memory test
                {"memory_usage_mb": memory_usage_mb}
            )
            
            # Force garbage collection
            import gc
            gc.collect()
        
        # Verify memory usage requirements
        max_memory_usage = max(memory_samples)
        avg_memory_usage = statistics.mean(memory_samples)
        
        assert max_memory_usage < 500, f"Memory usage too high: {max_memory_usage:.1f}MB"
        assert avg_memory_usage < 200, f"Average memory usage too high: {avg_memory_usage:.1f}MB"
    
    @pytest.mark.asyncio
    async def test_memory_leak_detection(self, threat_service, performance_monitor):
        """Test for memory leaks."""
        performance_monitor.start_monitoring()
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Perform many operations to detect memory leaks
        test_email = {
            "subject": "Memory leak test",
            "body": "Test email for memory leak detection",
            "sender": "test@example.com"
        }
        
        memory_measurements = []
        
        for i in range(100):
            # Perform threat analysis
            await threat_service.analyze_email(test_email)
            
            # Measure memory every 10 iterations
            if i % 10 == 0:
                current_memory = process.memory_info().rss
                memory_usage = (current_memory - initial_memory) / 1024 / 1024
                memory_measurements.append(memory_usage)
            
            # Force garbage collection periodically
            if i % 50 == 0:
                import gc
                gc.collect()
        
        # Check for memory leak (memory should not increase significantly)
        if len(memory_measurements) > 5:
            early_avg = statistics.mean(memory_measurements[:3])
            late_avg = statistics.mean(memory_measurements[-3:])
            memory_increase = late_avg - early_avg
            
            performance_monitor.record_metric(
                "memory_leak_test",
                0,
                {
                    "early_avg_mb": early_avg,
                    "late_avg_mb": late_avg,
                    "memory_increase_mb": memory_increase
                }
            )
            
            # Memory increase should be minimal (< 10MB for 100 operations)
            assert memory_increase < 10, f"Potential memory leak detected: {memory_increase:.1f}MB increase"

class TestScalabilityPerformance:
    """Test scalability performance."""
    
    @pytest.mark.asyncio
    async def test_database_connection_scaling(self, performance_monitor):
        """Test database connection pool scaling."""
        performance_monitor.start_monitoring()
        
        # Test with increasing connection loads
        connection_counts = [5, 10, 20, 50]
        
        for conn_count in connection_counts:
            db_manager = DatabaseManager(max_connections=conn_count)
            
            # Perform concurrent database operations
            async def db_operation():
                start_time = time.time()
                async with db_manager.get_connection() as conn:
                    # Simulate database work
                    await asyncio.sleep(0.01)
                end_time = time.time()
                return end_time - start_time
            
            start_time = time.time()
            
            # Run concurrent operations (more than connection pool size)
            tasks = [db_operation() for _ in range(conn_count * 2)]
            operation_durations = await asyncio.gather(*tasks)
            
            end_time = time.time()
            total_duration = end_time - start_time
            
            avg_operation_time = statistics.mean(operation_durations)
            
            performance_monitor.record_metric(
                f"db_scaling_{conn_count}",
                total_duration,
                {
                    "connection_count": conn_count,
                    "operations": len(tasks),
                    "avg_operation_time": avg_operation_time
                }
            )
            
            # Verify scaling performance
            assert avg_operation_time < 1.0, f"DB operations too slow with {conn_count} connections: {avg_operation_time:.3f}s"
    
    @pytest.mark.asyncio
    async def test_api_throughput_scaling(self, performance_monitor):
        """Test API throughput scaling."""
        performance_monitor.start_monitoring()
        
        # Test API throughput with increasing request rates
        request_rates = [10, 25, 50, 100]  # Requests per second
        
        for rate in request_rates:
            requests_sent = 0
            successful_requests = 0
            failed_requests = 0
            response_times = []
            
            start_time = time.time()
            test_duration = 10  # 10 seconds
            
            async def send_request():
                nonlocal requests_sent, successful_requests, failed_requests
                
                async with aiohttp.ClientSession() as session:
                    request_start = time.time()
                    try:
                        async with session.get("http://localhost:8000/health") as response:
                            await response.text()
                            successful_requests += 1
                            request_end = time.time()
                            response_times.append(request_end - request_start)
                    except Exception:
                        failed_requests += 1
                    requests_sent += 1
            
            # Send requests at specified rate
            while time.time() - start_time < test_duration:
                batch_start = time.time()
                
                # Send batch of requests
                batch_size = min(rate, 10)  # Limit batch size
                tasks = [send_request() for _ in range(batch_size)]
                await asyncio.gather(*tasks, return_exceptions=True)
                
                # Wait to maintain rate
                batch_duration = time.time() - batch_start
                sleep_time = (batch_size / rate) - batch_duration
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
            
            # Calculate metrics
            actual_rate = successful_requests / test_duration
            error_rate = failed_requests / requests_sent if requests_sent > 0 else 0
            avg_response_time = statistics.mean(response_times) if response_times else 0
            
            performance_monitor.record_metric(
                f"api_throughput_{rate}",
                test_duration,
                {
                    "target_rate": rate,
                    "actual_rate": actual_rate,
                    "error_rate": error_rate,
                    "avg_response_time": avg_response_time,
                    "successful_requests": successful_requests,
                    "failed_requests": failed_requests
                }
            )
            
            # Verify throughput requirements
            assert actual_rate >= rate * 0.8, f"Throughput too low: {actual_rate:.1f} < {rate * 0.8:.1f} req/sec"
            assert error_rate < 0.05, f"Error rate too high: {error_rate:.3f}"
            assert avg_response_time < 1.0, f"Response time too high at {rate} req/sec: {avg_response_time:.3f}s"

class TestResourceUtilization:
    """Test resource utilization efficiency."""
    
    @pytest.mark.asyncio
    async def test_cpu_utilization(self, performance_monitor):
        """Test CPU utilization efficiency."""
        performance_monitor.start_monitoring()
        
        # Monitor CPU usage during intensive operations
        cpu_samples = []
        
        async def cpu_intensive_task():
            """Simulate CPU-intensive threat analysis."""
            # Simulate ML model computation
            for _ in range(10000):
                hash_value = hashlib.sha256(f"test_{time.time()}".encode()).hexdigest()
            await asyncio.sleep(0.001)  # Yield control
        
        start_time = time.time()
        
        # Run CPU-intensive tasks
        tasks = [cpu_intensive_task() for _ in range(20)]
        
        # Monitor CPU usage while tasks run
        monitor_task = asyncio.create_task(self._monitor_cpu_usage(cpu_samples, duration=5))
        
        await asyncio.gather(*tasks)
        monitor_task.cancel()
        
        end_time = time.time()
        
        # Calculate CPU metrics
        avg_cpu = statistics.mean(cpu_samples) if cpu_samples else 0
        max_cpu = max(cpu_samples) if cpu_samples else 0
        
        performance_monitor.record_metric(
            "cpu_utilization_test",
            end_time - start_time,
            {
                "avg_cpu_percent": avg_cpu,
                "max_cpu_percent": max_cpu,
                "cpu_samples": len(cpu_samples)
            }
        )
        
        # Verify CPU utilization
        assert avg_cpu < 80, f"Average CPU utilization too high: {avg_cpu:.1f}%"
        assert max_cpu < 95, f"Max CPU utilization too high: {max_cpu:.1f}%"
    
    async def _monitor_cpu_usage(self, cpu_samples: List[float], duration: int):
        """Monitor CPU usage for specified duration."""
        end_time = time.time() + duration
        
        while time.time() < end_time:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_samples.append(cpu_percent)
    
    @pytest.mark.asyncio
    async def test_disk_io_performance(self, performance_monitor):
        """Test disk I/O performance."""
        performance_monitor.start_monitoring()
        
        # Test file I/O operations
        test_data = "Test data for disk I/O performance testing" * 1000
        file_sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
        
        for size in file_sizes:
            # Prepare test data
            data = test_data[:size]
            
            # Write performance test
            start_time = time.time()
            
            for i in range(10):
                with open(f"test_file_{size}_{i}.tmp", "w") as f:
                    f.write(data)
            
            write_time = time.time() - start_time
            
            # Read performance test
            start_time = time.time()
            
            for i in range(10):
                with open(f"test_file_{size}_{i}.tmp", "r") as f:
                    f.read()
            
            read_time = time.time() - start_time
            
            # Clean up
            for i in range(10):
                try:
                    import os
                    os.remove(f"test_file_{size}_{i}.tmp")
                except:
                    pass
            
            # Calculate throughput
            write_throughput = (size * 10) / write_time / 1024  # KB/s
            read_throughput = (size * 10) / read_time / 1024   # KB/s
            
            performance_monitor.record_metric(
                f"disk_io_{size}B",
                write_time + read_time,
                {
                    "write_throughput_kbs": write_throughput,
                    "read_throughput_kbs": read_throughput,
                    "file_size": size
                }
            )
            
            # Verify I/O performance
            assert write_throughput > 100, f"Write throughput too low: {write_throughput:.1f} KB/s"
            assert read_throughput > 500, f"Read throughput too low: {read_throughput:.1f} KB/s"

# Performance test summary and reporting
class TestPerformanceSummary:
    """Generate performance test summary."""
    
    @pytest.mark.asyncio
    async def test_generate_performance_report(self, performance_monitor):
        """Generate comprehensive performance report."""
        # This test would run after all other performance tests
        # to generate a summary report
        
        summary = performance_monitor.get_summary()
        
        performance_report = {
            "test_timestamp": datetime.utcnow().isoformat(),
            "system_info": {
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total / 1024 / 1024 / 1024,  # GB
                "python_version": pytest.__version__
            },
            "performance_summary": summary,
            "recommendations": []
        }
        
        # Add recommendations based on results
        if summary.get("avg_duration", 0) > 1.0:
            performance_report["recommendations"].append("Consider optimizing slow operations")
        
        if summary.get("max_memory_used", 0) > 500 * 1024 * 1024:  # 500MB
            performance_report["recommendations"].append("Memory usage is high, consider optimization")
        
        if summary.get("avg_cpu_percent", 0) > 70:
            performance_report["recommendations"].append("CPU utilization is high during tests")
        
        # Save report
        with open("performance_test_report.json", "w") as f:
            json.dump(performance_report, f, indent=2)
        
        logger.info("Performance test report generated", extra={"report": performance_report})
        
        # Verify minimum performance standards met
        assert summary.get("total_operations", 0) > 0, "No performance operations recorded"

if __name__ == "__main__":
    # Run performance tests
    pytest.main([__file__, "-v", "--tb=short", "-x"])  # Stop on first failure for performance tests