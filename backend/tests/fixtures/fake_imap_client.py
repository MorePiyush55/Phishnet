"""
Fake IMAP Client
================
In-memory IMAP client for deterministic testing.
No network calls, controllable failures, pre-loaded fixtures.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import copy

from app.services.imap.imap_client_interface import IMAPClientInterface
from app.config.logging import get_logger

logger = get_logger(__name__)


class FakeIMAPClient(IMAPClientInterface):
    """In-memory IMAP client for testing."""
    
    def __init__(
        self,
        mailbox_fixture: Optional[List[Dict[str, Any]]] = None,
        simulate_connection_failure: bool = False,
        simulate_fetch_failure: bool = False
    ):
        """
        Initialize fake IMAP client.
        
        Args:
            mailbox_fixture: Pre-loaded email fixtures
            simulate_connection_failure: Simulate connection failures
            simulate_fetch_failure: Simulate fetch failures
        """
        self.emails = copy.deepcopy(mailbox_fixture or [])
        self.read_uids = set()
        self.deleted_uids = set()
        self.moved_emails = {}  # uid -> folder
        self._connected = False
        
        # Failure simulation
        self.simulate_connection_failure = simulate_connection_failure
        self.simulate_fetch_failure = simulate_fetch_failure
        
        # Metrics
        self.connect_count = 0
        self.fetch_count = 0
        self.mark_read_count = 0
    
    async def connect(self) -> bool:
        """Connect to fake IMAP server."""
        self.connect_count += 1
        
        if self.simulate_connection_failure:
            logger.debug("Simulating IMAP connection failure")
            self._connected = False
            return False
        
        self._connected = True
        logger.debug("Fake IMAP connected")
        return True
    
    async def disconnect(self) -> None:
        """Disconnect from fake IMAP server."""
        self._connected = False
        logger.debug("Fake IMAP disconnected")
    
    async def get_recent_emails(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recent unread emails from fixture."""
        if not self._connected:
            raise RuntimeError("IMAP client not connected")
        
        self.fetch_count += 1
        
        if self.simulate_fetch_failure:
            logger.debug("Simulating IMAP fetch failure")
            raise RuntimeError("Simulated IMAP fetch failure")
        
        # Return unread, non-deleted emails
        unread = [
            email for email in self.emails
            if email['uid'] not in self.read_uids
            and email['uid'] not in self.deleted_uids
        ]
        
        result = unread[:limit]
        logger.debug(f"Fake IMAP fetched {len(result)} emails")
        return result
    
    async def mark_as_read(self, uid: str) -> bool:
        """Mark email as read."""
        if not self._connected:
            raise RuntimeError("IMAP client not connected")
        
        self.mark_read_count += 1
        self.read_uids.add(uid)
        logger.debug(f"Fake IMAP marked {uid} as read")
        return True
    
    async def delete_email(self, uid: str) -> bool:
        """Delete email."""
        if not self._connected:
            raise RuntimeError("IMAP client not connected")
        
        self.deleted_uids.add(uid)
        logger.debug(f"Fake IMAP deleted {uid}")
        return True
    
    async def move_to_folder(self, uid: str, folder: str) -> bool:
        """Move email to folder."""
        if not self._connected:
            raise RuntimeError("IMAP client not connected")
        
        self.moved_emails[uid] = folder
        logger.debug(f"Fake IMAP moved {uid} to {folder}")
        return True
    
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected
    
    # Test helper methods
    
    def add_email(self, email: Dict[str, Any]) -> None:
        """Add email to mailbox (test helper)."""
        self.emails.append(email)
    
    def reset(self) -> None:
        """Reset client state (test helper)."""
        self.read_uids.clear()
        self.deleted_uids.clear()
        self.moved_emails.clear()
        self.connect_count = 0
        self.fetch_count = 0
        self.mark_read_count = 0
    
    def get_unread_count(self) -> int:
        """Get count of unread emails (test helper)."""
        return len([
            e for e in self.emails
            if e['uid'] not in self.read_uids
            and e['uid'] not in self.deleted_uids
        ])
