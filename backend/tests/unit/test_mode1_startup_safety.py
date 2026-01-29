"""
Test Mode 1 Startup Safety
===========================
Tests for singleton orchestrator lock and fail-fast behavior.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

from app.services.mode1_lock import Mode1Lock, get_mode1_lock


class TestMode1Lock:
    """Test suite for Mode 1 orchestrator singleton lock."""
    
    @pytest.mark.asyncio
    async def test_acquire_lock_success(self):
        """Test successful lock acquisition."""
        lock = Mode1Lock()
        
        acquired = await lock.acquire_lock("test-orchestrator-1")
        
        assert acquired is True
        assert await lock.is_locked() is True
        assert await lock.get_lock_owner() == "test-orchestrator-1"
        
        # Cleanup
        await lock.release_lock("test-orchestrator-1")
    
    @pytest.mark.asyncio
    async def test_acquire_lock_already_locked(self):
        """Test lock acquisition when already locked."""
        lock = Mode1Lock()
        
        # First orchestrator acquires lock
        await lock.acquire_lock("test-orchestrator-1")
        
        # Second orchestrator tries to acquire
        acquired = await lock.acquire_lock("test-orchestrator-2")
        
        assert acquired is False
        assert await lock.get_lock_owner() == "test-orchestrator-1"
        
        # Cleanup
        await lock.release_lock("test-orchestrator-1")
    
    @pytest.mark.asyncio
    async def test_release_lock_success(self):
        """Test successful lock release."""
        lock = Mode1Lock()
        
        await lock.acquire_lock("test-orchestrator-1")
        released = await lock.release_lock("test-orchestrator-1")
        
        assert released is True
        assert await lock.is_locked() is False
    
    @pytest.mark.asyncio
    async def test_release_lock_not_owner(self):
        """Test lock release by non-owner."""
        lock = Mode1Lock()
        
        await lock.acquire_lock("test-orchestrator-1")
        released = await lock.release_lock("test-orchestrator-2")
        
        assert released is False
        assert await lock.is_locked() is True
        
        # Cleanup
        await lock.release_lock("test-orchestrator-1")
    
    @pytest.mark.asyncio
    async def test_stale_lock_recovery(self):
        """Test recovery from stale lock (dead process)."""
        lock = Mode1Lock()
        
        # Simulate stale lock by writing PID file with non-existent PID
        if lock.pid_file.exists():
            lock.pid_file.unlink()
        
        lock.pid_file.write_text("99999\nstale-orchestrator\n2026-01-01T00:00:00Z")
        
        # New orchestrator should be able to acquire lock
        acquired = await lock.acquire_lock("test-orchestrator-new")
        
        assert acquired is True
        assert await lock.get_lock_owner() == "test-orchestrator-new"
        
        # Cleanup
        await lock.release_lock("test-orchestrator-new")
    
    @pytest.mark.asyncio
    async def test_singleton_instance(self):
        """Test get_mode1_lock returns singleton."""
        lock1 = get_mode1_lock()
        lock2 = get_mode1_lock()
        
        assert lock1 is lock2


class TestMode1StartupSafety:
    """Test suite for Mode 1 startup safety."""
    
    @pytest.mark.asyncio
    async def test_fail_fast_in_development(self):
        """Test that startup fails fast in development when lock is held."""
        with patch('app.config.settings.settings') as mock_settings:
            mock_settings.MODE1_ENABLED = True
            mock_settings.MODE1_AUTO_START = True
            mock_settings.MODE1_FAIL_FAST = True
            mock_settings.is_development.return_value = True
            
            # Acquire lock with first orchestrator
            lock = get_mode1_lock()
            await lock.acquire_lock("first-orchestrator")
            
            # Second orchestrator should raise RuntimeError
            with pytest.raises(RuntimeError, match="Another Mode 1 orchestrator is already running"):
                # Simulate startup logic
                lock_acquired = await lock.acquire_lock("second-orchestrator")
                if not lock_acquired and mock_settings.is_development() and mock_settings.MODE1_FAIL_FAST:
                    raise RuntimeError("Another Mode 1 orchestrator is already running")
            
            # Cleanup
            await lock.release_lock("first-orchestrator")
    
    @pytest.mark.asyncio
    async def test_degrade_gracefully_in_production(self):
        """Test that startup degrades gracefully in production when lock is held."""
        with patch('app.config.settings.settings') as mock_settings:
            mock_settings.MODE1_ENABLED = True
            mock_settings.MODE1_AUTO_START = True
            mock_settings.MODE1_FAIL_FAST = False
            mock_settings.is_development.return_value = False
            
            # Acquire lock with first orchestrator
            lock = get_mode1_lock()
            await lock.acquire_lock("first-orchestrator")
            
            # Second orchestrator should NOT raise, just log warning
            lock_acquired = await lock.acquire_lock("second-orchestrator")
            
            assert lock_acquired is False
            # In production, this would just log a warning and continue
            
            # Cleanup
            await lock.release_lock("first-orchestrator")


@pytest.mark.asyncio
async def test_multiple_reload_simulation():
    """
    Simulate multiple uvicorn reloads to ensure no duplicate orchestrators.
    
    This test simulates the scenario where uvicorn --reload triggers
    multiple application startups.
    """
    lock = get_mode1_lock()
    
    # First startup
    acquired1 = await lock.acquire_lock("reload-1")
    assert acquired1 is True
    
    # Second startup (reload triggered)
    acquired2 = await lock.acquire_lock("reload-2")
    assert acquired2 is False  # Should fail because lock is held
    
    # First instance shuts down
    await lock.release_lock("reload-1")
    
    # Third startup (after first shutdown)
    acquired3 = await lock.acquire_lock("reload-3")
    assert acquired3 is True  # Should succeed now
    
    # Cleanup
    await lock.release_lock("reload-3")
