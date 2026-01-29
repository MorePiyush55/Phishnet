"""
Real IMAP Client
================
Production IMAP client wrapping QuickIMAPService.
"""

from typing import List, Dict, Any, Optional
import asyncio

from app.services.imap.imap_client_interface import IMAPClientInterface
from app.services.quick_imap import QuickIMAPService
from app.config.logging import get_logger

logger = get_logger(__name__)


class RealIMAPClient(IMAPClientInterface):
    """Production IMAP client using QuickIMAPService."""
    
    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        port: int = 993,
        folder: str = "INBOX"
    ):
        """
        Initialize real IMAP client.
        
        Args:
            host: IMAP server hostname
            user: IMAP username
            password: IMAP password
            port: IMAP port (default: 993)
            folder: IMAP folder to monitor (default: INBOX)
        """
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.folder = folder
        
        self._imap_service: Optional[QuickIMAPService] = None
        self._connected = False
    
    async def connect(self) -> bool:
        """Connect to IMAP server."""
        try:
            # Run synchronous IMAP connection in thread pool
            self._imap_service = await asyncio.to_thread(
                QuickIMAPService,
                self.host,
                self.user,
                self.password,
                self.port,
                self.folder
            )
            
            self._connected = True
            logger.info(f"Connected to IMAP server: {self.host}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to IMAP server: {e}")
            self._connected = False
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from IMAP server."""
        try:
            if self._imap_service:
                await asyncio.to_thread(self._imap_service.disconnect)
                self._connected = False
                logger.info("Disconnected from IMAP server")
        except Exception as e:
            logger.error(f"Error disconnecting from IMAP: {e}")
    
    async def get_recent_emails(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recent unread emails."""
        if not self._imap_service:
            raise RuntimeError("IMAP client not connected")
        
        try:
            # Run synchronous IMAP fetch in thread pool
            emails = await asyncio.to_thread(
                self._imap_service.get_recent_emails,
                limit
            )
            
            logger.debug(f"Fetched {len(emails)} emails from IMAP")
            return emails
            
        except Exception as e:
            logger.error(f"Failed to fetch emails: {e}")
            return []
    
    async def mark_as_read(self, uid: str) -> bool:
        """Mark email as read."""
        if not self._imap_service:
            raise RuntimeError("IMAP client not connected")
        
        try:
            await asyncio.to_thread(
                self._imap_service.mark_as_read,
                uid
            )
            return True
        except Exception as e:
            logger.error(f"Failed to mark email as read: {e}")
            return False
    
    async def delete_email(self, uid: str) -> bool:
        """Delete email."""
        if not self._imap_service:
            raise RuntimeError("IMAP client not connected")
        
        try:
            await asyncio.to_thread(
                self._imap_service.delete_email,
                uid
            )
            return True
        except Exception as e:
            logger.error(f"Failed to delete email: {e}")
            return False
    
    async def move_to_folder(self, uid: str, folder: str) -> bool:
        """Move email to folder."""
        if not self._imap_service:
            raise RuntimeError("IMAP client not connected")
        
        try:
            await asyncio.to_thread(
                self._imap_service.move_to_folder,
                uid,
                folder
            )
            return True
        except Exception as e:
            logger.error(f"Failed to move email: {e}")
            return False
    
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected
