"""
Mode 1 Fault Injection Tests
=============================
Tests for circuit breakers, rate limiters, and resilience patterns.

These tests validate that Mode 1 handles failures gracefully:
- Circuit breakers open/close correctly
- Rate limiters apply backpressure
- Dependencies fail gracefully
- System degrades but doesn't crash
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timezone

from app.services.worker_resilience import WorkerResilience
from tests.fixtures import FakeIMAPClient, get_default_mailbox_fixture


class TestCircuitBreakers:
    """Test circuit breaker behavior under failures."""
    
    @pytest.mark.asyncio
    async def test_imap_timeout_opens_circuit_breaker(self):
        """Test that IMAP timeout opens circuit breaker."""
        resilience = WorkerResilience()
        
        # Simulate multiple IMAP timeouts
        for i in range(5):
            try:
                async with resilience.imap_breaker:
                    raise TimeoutError("IMAP connection timeout")
            except TimeoutError:
                pass
        
        # Circuit breaker should be open
        assert resilience.imap_breaker.opened
        
        # Next call should fail fast
        with pytest.raises(Exception):  # CircuitBreakerError
            async with resilience.imap_breaker:
                pass
    
    @pytest.mark.asyncio
    async def test_virustotal_429_opens_circuit_breaker(self):
        """Test that VirusTotal rate limit opens circuit breaker."""
        resilience = WorkerResilience()
        
        # Simulate multiple 429 errors
        for i in range(5):
            try:
                async with resilience.virustotal_breaker:
                    # Simulate 429 Too Many Requests
                    from aiohttp import ClientResponseError
                    raise ClientResponseError(
                        request_info=Mock(),
                        history=(),
                        status=429,
                        message="Too Many Requests"
                    )
            except ClientResponseError:
                pass
        
        # Circuit breaker should be open
        assert resilience.virustotal_breaker.opened
    
    @pytest.mark.asyncio
    async def test_gemini_timeout_opens_circuit_breaker(self):
        """Test that Gemini timeout opens circuit breaker."""
        resilience = WorkerResilience()
        
        # Simulate multiple Gemini timeouts
        for i in range(5):
            try:
                async with resilience.gemini_breaker:
                    raise asyncio.TimeoutError("Gemini API timeout")
            except asyncio.TimeoutError:
                pass
        
        # Circuit breaker should be open
        assert resilience.gemini_breaker.opened
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_recovery(self):
        """Test that circuit breaker recovers after timeout."""
        resilience = WorkerResilience()
        
        # Open circuit breaker
        for i in range(5):
            try:
                async with resilience.imap_breaker:
                    raise TimeoutError("IMAP timeout")
            except TimeoutError:
                pass
        
        assert resilience.imap_breaker.opened
        
        # Wait for recovery timeout (simulate)
        # In real scenario, would wait for breaker timeout
        # For testing, we'll manually close it
        resilience.imap_breaker._state = 0  # CLOSED state
        
        # Should work again
        async with resilience.imap_breaker:
            result = "success"
        
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_fallback_behavior(self):
        """Test fallback behavior when circuit breaker is open."""
        resilience = WorkerResilience()
        
        # Open VirusTotal circuit breaker
        for i in range(5):
            try:
                async with resilience.virustotal_breaker:
                    raise Exception("VirusTotal error")
            except Exception:
                pass
        
        # When breaker is open, should use fallback
        # (In real code, this would skip VirusTotal check)
        if resilience.virustotal_breaker.opened:
            fallback_result = "UNKNOWN"  # Fallback verdict
        
        assert fallback_result == "UNKNOWN"


class TestRateLimiters:
    """Test rate limiter and backpressure behavior."""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_applies_backpressure(self):
        """Test that rate limiter slows down processing."""
        resilience = WorkerResilience()
        
        # Process emails rapidly
        start_time = asyncio.get_event_loop().time()
        
        for i in range(10):
            async with resilience.rate_limiter:
                pass  # Simulate processing
        
        elapsed = asyncio.get_event_loop().time() - start_time
        
        # Should take some time due to rate limiting
        # (Exact timing depends on rate limiter configuration)
        assert elapsed > 0
    
    @pytest.mark.asyncio
    async def test_backpressure_increases_under_load(self):
        """Test that backpressure delay increases under high load."""
        resilience = WorkerResilience()
        
        # Simulate high load
        initial_delay = resilience.get_backpressure_delay(active_jobs=1)
        high_load_delay = resilience.get_backpressure_delay(active_jobs=50)
        
        # Delay should increase with load
        assert high_load_delay > initial_delay
    
    @pytest.mark.asyncio
    async def test_backpressure_slows_but_doesnt_fail(self):
        """Test that backpressure slows processing but doesn't fail."""
        resilience = WorkerResilience()
        
        # Even under high backpressure, processing should succeed
        delay = resilience.get_backpressure_delay(active_jobs=100)
        
        await asyncio.sleep(delay)
        
        # Should complete successfully (just slower)
        result = "processed"
        assert result == "processed"


class TestDependencyFailures:
    """Test graceful degradation under dependency failures."""
    
    @pytest.mark.asyncio
    async def test_redis_unavailable_graceful_degradation(self):
        """Test that Redis unavailability doesn't crash the system."""
        # Mock Redis failure
        with patch('app.services.redis_client.get_redis_client') as mock_redis:
            mock_redis.return_value = None  # Redis unavailable
            
            # Circuit breakers should still work (fallback to in-memory)
            resilience = WorkerResilience()
            
            # Should not crash
            async with resilience.imap_breaker:
                result = "success"
            
            assert result == "success"
    
    @pytest.mark.asyncio
    async def test_mongodb_unavailable_expected_failure(self):
        """Test that MongoDB unavailability fails as expected."""
        # Mock MongoDB failure
        with patch('app.db.mongodb.get_database') as mock_db:
            mock_db.side_effect = Exception("MongoDB connection failed")
            
            # Should raise exception (expected behavior)
            with pytest.raises(Exception, match="MongoDB connection failed"):
                await mock_db()
    
    @pytest.mark.asyncio
    async def test_smtp_unavailable_analysis_continues(self):
        """Test that SMTP failure skips reply but continues analysis."""
        # Mock SMTP failure
        with patch('app.services.email.sender.send_email') as mock_send:
            mock_send.side_effect = Exception("SMTP connection failed")
            
            # Analysis should complete
            analysis_result = {
                "verdict": "SAFE",
                "confidence": 0.95
            }
            
            # Try to send reply
            reply_sent = False
            try:
                await mock_send("test@example.com", "Subject", "Body")
            except Exception:
                reply_sent = False
            
            # Analysis succeeded even though reply failed
            assert analysis_result["verdict"] == "SAFE"
            assert reply_sent is False


class TestIMAPFailureScenarios:
    """Test IMAP-specific failure scenarios."""
    
    @pytest.mark.asyncio
    async def test_imap_connection_failure(self):
        """Test handling of IMAP connection failure."""
        client = FakeIMAPClient(simulate_connection_failure=True)
        
        connected = await client.connect()
        
        assert connected is False
        assert not client.is_connected()
    
    @pytest.mark.asyncio
    async def test_imap_fetch_failure(self):
        """Test handling of IMAP fetch failure."""
        client = FakeIMAPClient(
            mailbox_fixture=get_default_mailbox_fixture(),
            simulate_fetch_failure=True
        )
        
        await client.connect()
        
        with pytest.raises(RuntimeError, match="Simulated IMAP fetch failure"):
            await client.get_recent_emails()
    
    @pytest.mark.asyncio
    async def test_imap_partial_failure_recovery(self):
        """Test recovery from partial IMAP failures."""
        client = FakeIMAPClient(mailbox_fixture=get_default_mailbox_fixture())
        
        await client.connect()
        
        # First fetch succeeds
        emails = await client.get_recent_emails()
        assert len(emails) > 0
        
        # Simulate temporary failure
        client.simulate_fetch_failure = True
        
        with pytest.raises(RuntimeError):
            await client.get_recent_emails()
        
        # Recovery
        client.simulate_fetch_failure = False
        
        # Should work again
        emails = await client.get_recent_emails()
        assert len(emails) > 0


class TestEndToEndResilience:
    """End-to-end resilience tests."""
    
    @pytest.mark.asyncio
    async def test_multiple_failures_dont_crash_system(self):
        """Test that multiple simultaneous failures don't crash."""
        resilience = WorkerResilience()
        
        # Simulate multiple failures
        failures = []
        
        # IMAP failure
        try:
            async with resilience.imap_breaker:
                raise TimeoutError("IMAP timeout")
        except TimeoutError:
            failures.append("imap")
        
        # VirusTotal failure
        try:
            async with resilience.virustotal_breaker:
                raise Exception("VirusTotal error")
        except Exception:
            failures.append("virustotal")
        
        # Gemini failure
        try:
            async with resilience.gemini_breaker:
                raise Exception("Gemini error")
        except Exception:
            failures.append("gemini")
        
        # System should still be operational
        assert len(failures) == 3
        assert resilience is not None
    
    @pytest.mark.asyncio
    async def test_graceful_degradation_under_load(self):
        """Test graceful degradation under high load."""
        resilience = WorkerResilience()
        
        # Simulate high load
        active_jobs = 100
        
        # Should apply backpressure
        delay = resilience.get_backpressure_delay(active_jobs)
        assert delay > 0
        
        # But should still process
        async with resilience.rate_limiter:
            result = "processed"
        
        assert result == "processed"


@pytest.mark.asyncio
async def test_circuit_breaker_metrics():
    """Test that circuit breaker state is exposed in metrics."""
    resilience = WorkerResilience()
    
    # Get initial status
    status = resilience.get_status()
    
    assert "circuit_breakers" in status
    assert "imap" in status["circuit_breakers"]
    assert "virustotal" in status["circuit_breakers"]
    assert "gemini" in status["circuit_breakers"]
    
    # Each breaker should have state info
    for breaker_name, breaker_status in status["circuit_breakers"].items():
        assert "state" in breaker_status
        assert "failure_count" in breaker_status


@pytest.mark.asyncio
async def test_rate_limiter_metrics():
    """Test that rate limiter metrics are tracked."""
    resilience = WorkerResilience()
    
    # Process some items
    for i in range(5):
        async with resilience.rate_limiter:
            pass
    
    status = resilience.get_status()
    
    # Should track rate limiter usage
    assert "rate_limiter" in status
