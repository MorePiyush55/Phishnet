"""
IMAP Coordination Lock Enforcement
===================================
Enforces IMAP ownership rules to prevent conflicts between Mode 1 and on-demand workers.

Rules:
- MODE1: Only Mode 1 orchestrator can access
- ONDEMAND: Only on-demand worker can access
- SHARED: Both can access (requires Redis lock)
"""

import asyncio
from typing import Optional
from datetime import datetime, timezone, timedelta

from app.config.logging import get_logger
from app.services.tenant_mailbox import IMAPOwnership, MailboxConfig
from app.services.redis_client import get_redis_client

logger = get_logger(__name__)


class IMAPCoordinationLock:
    """Manages IMAP access coordination between Mode 1 and on-demand workers."""
    
    def __init__(self, redis_client=None):
        """
        Initialize coordination lock manager.
        
        Args:
            redis_client: Redis client for distributed locking
        """
        self.redis = redis_client or get_redis_client()
        self.lock_ttl = 300  # 5 minutes
    
    async def acquire_lock(
        self,
        mailbox_config: MailboxConfig,
        requester: str  # "mode1" or "ondemand"
    ) -> bool:
        """
        Attempt to acquire IMAP access lock.
        
        Args:
            mailbox_config: Mailbox configuration
            requester: Who is requesting access ("mode1" or "ondemand")
            
        Returns:
            True if lock acquired, False otherwise
        """
        ownership = mailbox_config.ownership
        
        # MODE1 ownership - only Mode 1 can access
        if ownership == IMAPOwnership.MODE1:
            if requester == "mode1":
                logger.debug(f"MODE1 ownership: Granted access to Mode 1 for {mailbox_config.tenant_id}")
                return True
            else:
                logger.warning(f"MODE1 ownership: Denied access to {requester} for {mailbox_config.tenant_id}")
                return False
        
        # ONDEMAND ownership - only on-demand worker can access
        elif ownership == IMAPOwnership.ONDEMAND:
            if requester == "ondemand":
                logger.debug(f"ONDEMAND ownership: Granted access to on-demand for {mailbox_config.tenant_id}")
                return True
            else:
                logger.warning(f"ONDEMAND ownership: Denied access to {requester} for {mailbox_config.tenant_id}")
                return False
        
        # SHARED ownership - requires Redis lock
        elif ownership == IMAPOwnership.SHARED:
            return await self._acquire_shared_lock(mailbox_config, requester)
        
        else:
            logger.error(f"Unknown ownership type: {ownership}")
            return False
    
    async def _acquire_shared_lock(
        self,
        mailbox_config: MailboxConfig,
        requester: str
    ) -> bool:
        """
        Acquire Redis lock for shared mailbox.
        
        Args:
            mailbox_config: Mailbox configuration
            requester: Who is requesting access
            
        Returns:
            True if lock acquired, False otherwise
        """
        if not self.redis:
            logger.error("Redis not available for SHARED ownership coordination")
            return False
        
        lock_key = mailbox_config.coordination_lock_key or f"imap:lock:{mailbox_config.tenant_id}"
        
        try:
            # Try to acquire lock with TTL
            acquired = await self.redis.set(
                lock_key,
                requester,
                ex=self.lock_ttl,
                nx=True  # Only set if not exists
            )
            
            if acquired:
                logger.info(f"SHARED ownership: {requester} acquired lock for {mailbox_config.tenant_id}")
                return True
            else:
                # Check who holds the lock
                current_holder = await self.redis.get(lock_key)
                logger.debug(f"SHARED ownership: Lock held by {current_holder} for {mailbox_config.tenant_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to acquire shared lock: {e}")
            return False
    
    async def release_lock(
        self,
        mailbox_config: MailboxConfig,
        requester: str
    ) -> None:
        """
        Release IMAP access lock.
        
        Args:
            mailbox_config: Mailbox configuration
            requester: Who is releasing the lock
        """
        ownership = mailbox_config.ownership
        
        # Only SHARED ownership requires explicit release
        if ownership == IMAPOwnership.SHARED:
            await self._release_shared_lock(mailbox_config, requester)
    
    async def _release_shared_lock(
        self,
        mailbox_config: MailboxConfig,
        requester: str
    ) -> None:
        """Release Redis lock for shared mailbox."""
        if not self.redis:
            return
        
        lock_key = mailbox_config.coordination_lock_key or f"imap:lock:{mailbox_config.tenant_id}"
        
        try:
            # Only release if we hold the lock
            current_holder = await self.redis.get(lock_key)
            
            if current_holder == requester:
                await self.redis.delete(lock_key)
                logger.info(f"SHARED ownership: {requester} released lock for {mailbox_config.tenant_id}")
            else:
                logger.warning(f"SHARED ownership: {requester} tried to release lock held by {current_holder}")
                
        except Exception as e:
            logger.error(f"Failed to release shared lock: {e}")
    
    async def extend_lock(
        self,
        mailbox_config: MailboxConfig,
        requester: str
    ) -> bool:
        """
        Extend lock TTL for long-running operations.
        
        Args:
            mailbox_config: Mailbox configuration
            requester: Who is extending the lock
            
        Returns:
            True if lock extended, False otherwise
        """
        if mailbox_config.ownership != IMAPOwnership.SHARED:
            return True  # No lock to extend
        
        if not self.redis:
            return False
        
        lock_key = mailbox_config.coordination_lock_key or f"imap:lock:{mailbox_config.tenant_id}"
        
        try:
            # Only extend if we hold the lock
            current_holder = await self.redis.get(lock_key)
            
            if current_holder == requester:
                await self.redis.expire(lock_key, self.lock_ttl)
                logger.debug(f"Extended lock for {mailbox_config.tenant_id}")
                return True
            else:
                logger.warning(f"Cannot extend lock held by {current_holder}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to extend lock: {e}")
            return False


# Context manager for automatic lock acquisition/release
class IMAPLockContext:
    """Context manager for IMAP coordination lock."""
    
    def __init__(
        self,
        mailbox_config: MailboxConfig,
        requester: str,
        lock_manager: Optional[IMAPCoordinationLock] = None
    ):
        """
        Initialize lock context.
        
        Args:
            mailbox_config: Mailbox configuration
            requester: Who is requesting access
            lock_manager: Lock manager (creates new if None)
        """
        self.mailbox_config = mailbox_config
        self.requester = requester
        self.lock_manager = lock_manager or IMAPCoordinationLock()
        self.acquired = False
    
    async def __aenter__(self):
        """Acquire lock on enter."""
        self.acquired = await self.lock_manager.acquire_lock(
            self.mailbox_config,
            self.requester
        )
        
        if not self.acquired:
            raise RuntimeError(
                f"Failed to acquire IMAP lock for {self.mailbox_config.tenant_id}. "
                f"Ownership: {self.mailbox_config.ownership}, Requester: {self.requester}"
            )
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Release lock on exit."""
        if self.acquired:
            await self.lock_manager.release_lock(
                self.mailbox_config,
                self.requester
            )
        
        return False  # Don't suppress exceptions
