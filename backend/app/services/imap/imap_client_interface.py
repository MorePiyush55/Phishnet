"""
IMAP Client Interface
=====================
Abstract interface for IMAP operations to enable testing with fake clients.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from datetime import datetime


class IMAPClientInterface(ABC):
    """Abstract interface for IMAP client operations."""
    
    @abstractmethod
    async def connect(self) -> bool:
        """
        Connect to IMAP server.
        
        Returns:
            True if connection successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from IMAP server."""
        pass
    
    @abstractmethod
    async def get_recent_emails(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Fetch recent unread emails.
        
        Args:
            limit: Maximum number of emails to fetch
            
        Returns:
            List of email metadata dictionaries with keys:
            - uid: Email UID
            - message_id: Message-ID header
            - subject: Email subject
            - from: Sender address
            - date: Email date
            - raw: Raw email content (bytes)
        """
        pass
    
    @abstractmethod
    async def mark_as_read(self, uid: str) -> bool:
        """
        Mark email as read.
        
        Args:
            uid: Email UID
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def delete_email(self, uid: str) -> bool:
        """
        Delete email.
        
        Args:
            uid: Email UID
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def move_to_folder(self, uid: str, folder: str) -> bool:
        """
        Move email to folder.
        
        Args:
            uid: Email UID
            folder: Destination folder name
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def is_connected(self) -> bool:
        """
        Check if client is connected.
        
        Returns:
            True if connected, False otherwise
        """
        pass
