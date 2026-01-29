"""
Mode 1 Orchestrator Singleton Lock
===================================
Prevents multiple orchestrator instances from running simultaneously.

Uses:
- PID-based lock for development (simple, no dependencies)
- Redis-based lock for production (distributed, multi-instance safe)
"""

import os
import asyncio
from typing import Optional
from datetime import datetime, timezone
from pathlib import Path

from app.config.logging import get_logger
from app.config.settings import get_settings

logger = get_logger(__name__)
settings = get_settings()


class Mode1Lock:
    """Singleton lock for Mode 1 orchestrator."""
    
    def __init__(self):
        self.lock_key = "mode1:orchestrator:lock"
        self.lock_owner: Optional[str] = None
        self.pid_file = Path("/tmp/mode1_orchestrator.pid")
        
    async def acquire_lock(self, orchestrator_id: str) -> bool:
        """
        Acquire orchestrator lock.
        
        Args:
            orchestrator_id: Unique identifier for this orchestrator instance
            
        Returns:
            True if lock acquired, False if already locked
        """
        if settings.is_development():
            return await self._acquire_pid_lock(orchestrator_id)
        else:
            return await self._acquire_redis_lock(orchestrator_id)
    
    async def release_lock(self, orchestrator_id: str) -> bool:
        """
        Release orchestrator lock.
        
        Args:
            orchestrator_id: Unique identifier for this orchestrator instance
            
        Returns:
            True if lock released, False if not owned
        """
        if settings.is_development():
            return await self._release_pid_lock(orchestrator_id)
        else:
            return await self._release_redis_lock(orchestrator_id)
    
    async def is_locked(self) -> bool:
        """Check if orchestrator is currently locked."""
        if settings.is_development():
            return self.pid_file.exists()
        else:
            return await self._is_redis_locked()
    
    async def get_lock_owner(self) -> Optional[str]:
        """Get current lock owner identifier."""
        if settings.is_development():
            return await self._get_pid_lock_owner()
        else:
            return await self._get_redis_lock_owner()
    
    # ========================================================================
    # PID-based lock (Development)
    # ========================================================================
    
    async def _acquire_pid_lock(self, orchestrator_id: str) -> bool:
        """Acquire PID-based lock for development."""
        try:
            # Check if lock file exists
            if self.pid_file.exists():
                # Read existing PID
                existing_pid = int(self.pid_file.read_text().strip())
                
                # Check if process is still running
                if self._is_process_running(existing_pid):
                    logger.warning(
                        f"Mode 1 orchestrator already running (PID: {existing_pid})"
                    )
                    return False
                else:
                    logger.info(
                        f"Stale lock file found (PID: {existing_pid}), removing"
                    )
                    self.pid_file.unlink()
            
            # Create lock file with current PID
            current_pid = os.getpid()
            self.pid_file.write_text(f"{current_pid}\n{orchestrator_id}\n{datetime.now(timezone.utc).isoformat()}")
            self.lock_owner = orchestrator_id
            
            logger.info(f"Acquired Mode 1 orchestrator lock (PID: {current_pid})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to acquire PID lock: {e}")
            return False
    
    async def _release_pid_lock(self, orchestrator_id: str) -> bool:
        """Release PID-based lock."""
        try:
            if not self.pid_file.exists():
                logger.warning("No lock file to release")
                return False
            
            # Verify ownership
            content = self.pid_file.read_text().strip().split('\n')
            if len(content) >= 2 and content[1] == orchestrator_id:
                self.pid_file.unlink()
                self.lock_owner = None
                logger.info(f"Released Mode 1 orchestrator lock")
                return True
            else:
                logger.warning(f"Lock not owned by {orchestrator_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to release PID lock: {e}")
            return False
    
    async def _get_pid_lock_owner(self) -> Optional[str]:
        """Get PID lock owner."""
        try:
            if not self.pid_file.exists():
                return None
            
            content = self.pid_file.read_text().strip().split('\n')
            return content[1] if len(content) >= 2 else None
            
        except Exception as e:
            logger.error(f"Failed to get PID lock owner: {e}")
            return None
    
    def _is_process_running(self, pid: int) -> bool:
        """Check if process with given PID is running."""
        try:
            # Send signal 0 to check if process exists
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    
    # ========================================================================
    # Redis-based lock (Production)
    # ========================================================================
    
    async def _acquire_redis_lock(self, orchestrator_id: str) -> bool:
        """Acquire Redis-based lock for production."""
        try:
            from app.services.redis_client import get_redis_client
            redis = await get_redis_client()
            
            if not redis:
                logger.warning("Redis not available, falling back to PID lock")
                return await self._acquire_pid_lock(orchestrator_id)
            
            # Try to acquire lock with TTL (auto-expire after 5 minutes)
            lock_data = {
                "orchestrator_id": orchestrator_id,
                "pid": os.getpid(),
                "acquired_at": datetime.now(timezone.utc).isoformat()
            }
            
            # SET NX (only if not exists) with EX (expiry)
            acquired = await redis.set(
                self.lock_key,
                str(lock_data),
                nx=True,  # Only set if not exists
                ex=300    # Expire after 5 minutes
            )
            
            if acquired:
                self.lock_owner = orchestrator_id
                logger.info(f"Acquired Mode 1 orchestrator lock (Redis)")
                
                # Start heartbeat to keep lock alive
                asyncio.create_task(self._redis_lock_heartbeat(orchestrator_id))
                return True
            else:
                existing_owner = await self._get_redis_lock_owner()
                logger.warning(
                    f"Mode 1 orchestrator already running (owner: {existing_owner})"
                )
                return False
                
        except Exception as e:
            logger.error(f"Failed to acquire Redis lock: {e}")
            # Fallback to PID lock
            return await self._acquire_pid_lock(orchestrator_id)
    
    async def _release_redis_lock(self, orchestrator_id: str) -> bool:
        """Release Redis-based lock."""
        try:
            from app.services.redis_client import get_redis_client
            redis = await get_redis_client()
            
            if not redis:
                return await self._release_pid_lock(orchestrator_id)
            
            # Only delete if we own the lock
            current_owner = await self._get_redis_lock_owner()
            if current_owner == orchestrator_id:
                await redis.delete(self.lock_key)
                self.lock_owner = None
                logger.info(f"Released Mode 1 orchestrator lock (Redis)")
                return True
            else:
                logger.warning(f"Lock not owned by {orchestrator_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to release Redis lock: {e}")
            return False
    
    async def _is_redis_locked(self) -> bool:
        """Check if Redis lock exists."""
        try:
            from app.services.redis_client import get_redis_client
            redis = await get_redis_client()
            
            if not redis:
                return self.pid_file.exists()
            
            return await redis.exists(self.lock_key)
            
        except Exception as e:
            logger.error(f"Failed to check Redis lock: {e}")
            return False
    
    async def _get_redis_lock_owner(self) -> Optional[str]:
        """Get Redis lock owner."""
        try:
            from app.services.redis_client import get_redis_client
            redis = await get_redis_client()
            
            if not redis:
                return await self._get_pid_lock_owner()
            
            lock_data = await redis.get(self.lock_key)
            if lock_data:
                # Parse lock data (simple string format)
                import ast
                data = ast.literal_eval(lock_data)
                return data.get("orchestrator_id")
            return None
            
        except Exception as e:
            logger.error(f"Failed to get Redis lock owner: {e}")
            return None
    
    async def _redis_lock_heartbeat(self, orchestrator_id: str):
        """Keep Redis lock alive with periodic heartbeat."""
        try:
            from app.services.redis_client import get_redis_client
            
            while self.lock_owner == orchestrator_id:
                await asyncio.sleep(60)  # Heartbeat every minute
                
                redis = await get_redis_client()
                if redis:
                    # Extend TTL
                    await redis.expire(self.lock_key, 300)
                    logger.debug("Mode 1 orchestrator lock heartbeat")
                    
        except asyncio.CancelledError:
            logger.debug("Lock heartbeat cancelled")
        except Exception as e:
            logger.error(f"Lock heartbeat failed: {e}")


# Singleton instance
_mode1_lock: Optional[Mode1Lock] = None


def get_mode1_lock() -> Mode1Lock:
    """Get singleton Mode1Lock instance."""
    global _mode1_lock
    if _mode1_lock is None:
        _mode1_lock = Mode1Lock()
    return _mode1_lock
