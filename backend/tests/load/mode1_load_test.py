"""
Load Testing Script for Mode 1 Pipeline
========================================
Simulates realistic email processing load for Mode 1.
"""

from locust import HttpUser, task, between, events
import random
import json
from datetime import datetime


class Mode1LoadTest(HttpUser):
    """Simulates Mode 1 email processing load."""
    
    wait_time = between(1, 5)  # Wait 1-5 seconds between tasks
    
    def on_start(self):
        """Initialize test user."""
        self.tenant_id = f"tenant-{random.randint(1, 10)}"
    
    @task(10)
    def check_status(self):
        """Check Mode 1 status (frequent operation)."""
        self.client.get("/api/v1/mode1/status")
    
    @task(5)
    def get_pipeline_stats(self):
        """Get pipeline statistics."""
        self.client.get("/api/v1/mode1/pipeline/stats")
    
    @task(3)
    def get_bottlenecks(self):
        """Check for bottlenecks."""
        self.client.get("/api/v1/mode1/pipeline/bottlenecks")
    
    @task(2)
    def get_tenant_metrics(self):
        """Get tenant-specific metrics."""
        self.client.get(f"/api/v1/mode1/pipeline/tenants/{self.tenant_id}")
    
    @task(1)
    def get_dedup_stats(self):
        """Get deduplication statistics."""
        self.client.get("/api/v1/mode1/dedup/stats")


class CircuitBreakerStressTest(HttpUser):
    """Stress test circuit breakers."""
    
    wait_time = between(0.1, 0.5)  # Aggressive load
    
    @task
    def rapid_requests(self):
        """Make rapid requests to trigger circuit breakers."""
        self.client.get("/api/v1/mode1/status")


# Event handlers for metrics
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when test starts."""
    print("Starting Mode 1 load test...")
    print(f"Target: {environment.host}")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when test stops."""
    print("\nLoad test complete!")
    print(f"Total requests: {environment.stats.total.num_requests}")
    print(f"Total failures: {environment.stats.total.num_failures}")
    print(f"Average response time: {environment.stats.total.avg_response_time:.2f}ms")
    print(f"p95 response time: {environment.stats.total.get_response_time_percentile(0.95):.2f}ms")
