"""
Test IMAP Coordination Lock
============================
Tests for IMAP ownership coordination between Mode 1 and on-demand workers.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch

from app.services.imap_coordination import IMAPCoordinationLock, IMAPLockContext
from app.services.tenant_mailbox import IMAPOwnership, MailboxConfig


class TestIMAPCoordinationLock:
    """Test IMAP coordination lock enforcement."""
    
    @pytest.mark.asyncio
    async def test_mode1_ownership_grants_mode1_access(self):
        """Test that MODE1 ownership grants access to Mode 1."""
        lock_manager = IMAPCoordinationLock(redis_client=None)
        
        mailbox = Mock(spec=MailboxConfig)
        mailbox.ownership = IMAPOwnership.MODE1
        mailbox.tenant_id = "test-tenant"
        
        # Mode 1 should get access
        granted = await lock_manager.acquire_lock(mailbox, "mode1")
        assert granted is True
    
    @pytest.mark.asyncio
    async def test_mode1_ownership_denies_ondemand_access(self):
        """Test that MODE1 ownership denies access to on-demand."""
        lock_manager = IMAPCoordinationLock(redis_client=None)
        
        mailbox = Mock(spec=MailboxConfig)
        mailbox.ownership = IMAPOwnership.MODE1
        mailbox.tenant_id = "test-tenant"
        
        # On-demand should be denied
        granted = await lock_manager.acquire_lock(mailbox, "ondemand")
        assert granted is False
    
    @pytest.mark.asyncio
    async def test_ondemand_ownership_grants_ondemand_access(self):
        """Test that ONDEMAND ownership grants access to on-demand."""
        lock_manager = IMAPCoordinationLock(redis_client=None)
        
        mailbox = Mock(spec=MailboxConfig)
        mailbox.ownership = IMAPOwnership.ONDEMAND
        mailbox.tenant_id = "test-tenant"
        
        # On-demand should get access
        granted = await lock_manager.acquire_lock(mailbox, "ondemand")
        assert granted is True
    
    @pytest.mark.asyncio
    async def test_ondemand_ownership_denies_mode1_access(self):
        """Test that ONDEMAND ownership denies access to Mode 1."""
        lock_manager = IMAPCoordinationLock(redis_client=None)
        
        mailbox = Mock(spec=MailboxConfig)
        mailbox.ownership = IMAPOwnership.ONDEMAND
        mailbox.tenant_id = "test-tenant"
        
        # Mode 1 should be denied
        granted = await lock_manager.acquire_lock(mailbox, "mode1")
        assert granted is False
    
    @pytest.mark.asyncio
    async def test_shared_ownership_requires_redis_lock(self):
        """Test that SHARED ownership requires Redis lock."""
        # Mock Redis client
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=True)
        
        lock_manager = IMAPCoordinationLock(redis_client=mock_redis)
        
        mailbox = Mock(spec=MailboxConfig)
        mailbox.ownership = IMAPOwnership.SHARED
        mailbox.tenant_id = "test-tenant"
        mailbox.coordination_lock_key = None
        
        # First requester should get lock
        granted = await lock_manager.acquire_lock(mailbox, "mode1")
        assert granted is True
        
        # Verify Redis was called
        mock_redis.set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_shared_ownership_denies_second_requester(self):
        """Test that SHARED ownership denies second requester."""
        # Mock Redis client - lock already held
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=False)  # Lock exists
        mock_redis.get = AsyncMock(return_value="mode1")
        
        lock_manager = IMAPCoordinationLock(redis_client=mock_redis)
        
        mailbox = Mock(spec=MailboxConfig)
        mailbox.ownership = IMAPOwnership.SHARED
        mailbox.tenant_id = "test-tenant"
        mailbox.coordination_lock_key = None
        
        # Second requester should be denied
        granted = await lock_manager.acquire_lock(mailbox, "ondemand")
        assert granted is False
    
    @pytest.mark.asyncio
    async def test_release_lock_for_shared_ownership(self):
        """Test releasing lock for SHARED ownership."""
        # Mock Redis client
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value="mode1")
        mock_redis.delete = AsyncMock()
        
        lock_manager = IMAPCoordinationLock(redis_client=mock_redis)
        
        mailbox = Mock(spec=MailboxConfig)
        mailbox.ownership = IMAPOwnership.SHARED
        mailbox.tenant_id = "test-tenant"
        mailbox.coordination_lock_key = None
        
        # Release lock
        await lock_manager.release_lock(mailbox, "mode1")
        
        # Verify Redis delete was called
        mock_redis.delete.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cannot_release_lock_held_by_another(self):
        """Test that you can't release a lock held by someone else."""
        # Mock Redis client
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value="mode1")
        mock_redis.delete = AsyncMock()
        
        lock_manager = IMAPCoordinationLock(redis_client=mock_redis)
        
        mailbox = Mock(spec=MailboxConfig)
        mailbox.ownership = IMAPOwnership.SHARED
        mailbox.tenant_id = "test-tenant"
        mailbox.coordination_lock_key = None
        
        # Try to release lock held by mode1
        await lock_manager.release_lock(mailbox, "ondemand")
        
        # Delete should NOT be called
        mock_redis.delete.assert_not_called()


class TestIMAPLockContext:
    """Test IMAP lock context manager."""
    
    @pytest.mark.asyncio
    async def test_context_manager_acquires_and_releases_lock(self):
        """Test that context manager acquires and releases lock."""
        mailbox = Mock(spec=MailboxConfig)
        mailbox.ownership = IMAPOwnership.MODE1
        mailbox.tenant_id = "test-tenant"
        
        async with IMAPLockContext(mailbox, "mode1") as ctx:
            assert ctx.acquired is True
        
        # Lock should be released after context exit
    
    @pytest.mark.asyncio
    async def test_context_manager_raises_on_lock_failure(self):
        """Test that context manager raises exception if lock fails."""
        mailbox = Mock(spec=MailboxConfig)
        mailbox.ownership = IMAPOwnership.MODE1
        mailbox.tenant_id = "test-tenant"
        
        # Try to acquire with wrong requester
        with pytest.raises(RuntimeError, match="Failed to acquire IMAP lock"):
            async with IMAPLockContext(mailbox, "ondemand"):
                pass


@pytest.mark.asyncio
async def test_ownership_coordination_prevents_conflicts():
    """
    End-to-end test: Ownership coordination prevents conflicts.
    
    Simulates Mode 1 and on-demand worker trying to access same mailbox.
    """
    lock_manager = IMAPCoordinationLock(redis_client=None)
    
    # MODE1 ownership mailbox
    mailbox = Mock(spec=MailboxConfig)
    mailbox.ownership = IMAPOwnership.MODE1
    mailbox.tenant_id = "acme-corp"
    
    # Mode 1 gets access
    mode1_access = await lock_manager.acquire_lock(mailbox, "mode1")
    assert mode1_access is True
    
    # On-demand is denied
    ondemand_access = await lock_manager.acquire_lock(mailbox, "ondemand")
    assert ondemand_access is False
    
    # No conflict!
