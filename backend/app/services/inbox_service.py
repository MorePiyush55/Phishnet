"""Business logic services for inbox operations."""

from datetime import datetime, timezone
from typing import Optional, List, Tuple
import hashlib
import re

from app.models.inbox_models import (
    InboxEmail,
    EmailThread,
    EmailParticipant,
    FolderType,
    InboxStats,
    FolderCount,
)
from app.repositories.inbox_repository import InboxRepository, LabelRepository


class InboxService:
    """
    Business logic for inbox operations.
    
    Handles email listing, actions, and organization with proper
    validation and business rules.
    """
    
    def __init__(self, repository: InboxRepository):
        """Initialize service with repository."""
        self.repo = repository
    
    async def list_emails(
        self,
        user_id: str,
        folder: Optional[str] = None,
        labels: Optional[List[str]] = None,
        is_read: Optional[bool] = None,
        is_starred: Optional[bool] = None,
        has_attachment: Optional[bool] = None,
        limit: int = 50,
        cursor: Optional[str] = None
    ) -> Tuple[List[InboxEmail], Optional[str], bool]:
        """
        List emails with pagination and filters.
        
        Args:
            user_id: User identifier
            folder: Folder filter
            labels: Label filters
            is_read: Read status filter
            is_starred: Starred status filter
            has_attachment: Attachment filter
            limit: Page size
            cursor: Pagination cursor
        
        Returns:
            Tuple of (emails, next_cursor, has_more)
        """
        return await self.repo.get_emails_paginated(
            user_id=user_id,
            folder=folder,
            labels=labels,
            is_read=is_read,
            is_starred=is_starred,
            has_attachment=has_attachment,
            limit=limit,
            cursor=cursor
        )
    
    async def get_email_details(
        self,
        message_id: str,
        user_id: str
    ) -> Optional[InboxEmail]:
        """Get full email details."""
        return await self.repo.get_email_by_id(message_id, user_id)
    
    async def mark_as_read(
        self,
        message_ids: List[str],
        user_id: str
    ) -> int:
        """Mark emails as read."""
        return await self.repo.update_read_status(message_ids, user_id, True)
    
    async def mark_as_unread(
        self,
        message_ids: List[str],
        user_id: str
    ) -> int:
        """Mark emails as unread."""
        return await self.repo.update_read_status(message_ids, user_id, False)
    
    async def toggle_star(
        self,
        message_ids: List[str],
        user_id: str,
        is_starred: bool
    ) -> int:
        """Toggle starred status."""
        return await self.repo.update_star_status(message_ids, user_id, is_starred)
    
    async def archive_emails(
        self,
        message_ids: List[str],
        user_id: str
    ) -> int:
        """
        Archive emails (remove from inbox, keep in all mail).
        
        In Gmail-style inbox, archiving removes the inbox label
        but keeps the email accessible in "All Mail".
        """
        # Remove from inbox folder
        return await self.repo.move_to_folder(
            message_ids,
            user_id,
            FolderType.ALL_MAIL.value
        )
    
    async def delete_emails(
        self,
        message_ids: List[str],
        user_id: str
    ) -> int:
        """Move emails to trash."""
        return await self.repo.delete_emails(message_ids, user_id, permanent=False)
    
    async def restore_emails(
        self,
        message_ids: List[str],
        user_id: str,
        target_folder: str = FolderType.INBOX.value
    ) -> int:
        """Restore emails from trash."""
        return await self.repo.move_to_folder(message_ids, user_id, target_folder)
    
    async def permanent_delete(
        self,
        message_ids: List[str],
        user_id: str
    ) -> int:
        """Permanently delete emails (cannot be recovered)."""
        return await self.repo.delete_emails(message_ids, user_id, permanent=True)
    
    async def move_to_spam(
        self,
        message_ids: List[str],
        user_id: str
    ) -> int:
        """Mark emails as spam and move to spam folder."""
        return await self.repo.move_to_folder(
            message_ids,
            user_id,
            FolderType.SPAM.value
        )
    
    async def mark_not_spam(
        self,
        message_ids: List[str],
        user_id: str
    ) -> int:
        """Mark emails as not spam and restore to inbox."""
        return await self.repo.move_to_folder(
            message_ids,
            user_id,
            FolderType.INBOX.value
        )
    
    async def apply_labels(
        self,
        message_ids: List[str],
        user_id: str,
        label_ids: List[str]
    ) -> int:
        """Apply labels to emails."""
        return await self.repo.apply_labels(message_ids, user_id, label_ids)
    
    async def remove_labels(
        self,
        message_ids: List[str],
        user_id: str,
        label_ids: List[str]
    ) -> int:
        """Remove labels from emails."""
        return await self.repo.remove_labels(message_ids, user_id, label_ids)
    
    async def get_inbox_stats(self, user_id: str) -> InboxStats:
        """Get inbox statistics for dashboard."""
        return await self.repo.get_inbox_stats(user_id)
    
    async def get_folder_counts(self, user_id: str) -> List[FolderCount]:
        """Get email counts for all folders."""
        return await self.repo.get_folder_counts(user_id)


class ThreadingService:
    """
    Service for email threading and conversation grouping.
    
    Implements Gmail-style threading based on subject and participants.
    """
    
    @staticmethod
    def normalize_subject(subject: str) -> str:
        """
        Normalize email subject for threading.
        
        Removes Re:, Fwd:, Fw:, etc. prefixes and extra whitespace.
        
        Args:
            subject: Original subject
        
        Returns:
            Normalized subject
        """
        # Remove common prefixes (case-insensitive)
        prefixes = [
            r"^re:\s*",
            r"^fwd:\s*",
            r"^fw:\s*",
            r"^forward:\s*",
            r"^\[.*?\]\s*",  # Remove [tags]
        ]
        
        normalized = subject.lower().strip()
        
        for prefix in prefixes:
            normalized = re.sub(prefix, "", normalized, flags=re.IGNORECASE)
        
        # Remove extra whitespace
        normalized = " ".join(normalized.split())
        
        return normalized
    
    @staticmethod
    def generate_thread_id(
        subject: str,
        participants: List[EmailParticipant]
    ) -> str:
        """
        Generate thread ID based on subject and participants.
        
        Args:
            subject: Email subject
            participants: List of all participants (sender + recipients)
        
        Returns:
            Thread ID (16-character hash)
        """
        # Normalize subject
        normalized_subject = ThreadingService.normalize_subject(subject)
        
        # Extract and sort participant emails
        participant_emails = sorted([p.email.lower() for p in participants])
        
        # Create thread key
        thread_key = f"{normalized_subject}:{','.join(participant_emails)}"
        
        # Generate hash
        thread_hash = hashlib.sha256(thread_key.encode()).hexdigest()
        
        # Return first 16 characters
        return thread_hash[:16]
    
    @staticmethod
    async def group_emails_by_thread(
        emails: List[InboxEmail]
    ) -> dict[str, List[InboxEmail]]:
        """
        Group emails by thread ID.
        
        Args:
            emails: List of emails to group
        
        Returns:
            Dictionary mapping thread_id to list of emails
        """
        threads: dict[str, List[InboxEmail]] = {}
        
        for email in emails:
            thread_id = email.thread_id
            if thread_id not in threads:
                threads[thread_id] = []
            threads[thread_id].append(email)
        
        return threads
    
    @staticmethod
    async def get_thread_participants(
        emails: List[InboxEmail]
    ) -> List[EmailParticipant]:
        """
        Get all unique participants in a thread.
        
        Args:
            emails: List of emails in thread
        
        Returns:
            List of unique participants
        """
        participants_map: dict[str, EmailParticipant] = {}
        
        for email in emails:
            # Add sender
            if email.sender.email not in participants_map:
                participants_map[email.sender.email] = email.sender
            
            # Add recipients
            for recipient in email.recipients.to:
                if recipient.email not in participants_map:
                    participants_map[recipient.email] = recipient
            
            for recipient in email.recipients.cc:
                if recipient.email not in participants_map:
                    participants_map[recipient.email] = recipient
        
        return list(participants_map.values())
    
    @staticmethod
    async def get_thread_count(thread_id: str, user_id: str) -> int:
        """Get number of emails in a thread."""
        return await InboxEmail.find(
            {"thread_id": thread_id, "user_id": user_id}
        ).count()


class SearchService:
    """
    Service for email search with advanced filters.
    
    Supports Gmail-style search syntax: from:, to:, subject:, has:, before:, after:
    """
    
    def __init__(self, repository: InboxRepository):
        """Initialize service with repository."""
        self.repo = repository
    
    @staticmethod
    def parse_search_query(query: str) -> dict:
        """
        Parse advanced search query.
        
        Supports syntax like:
        - from:john@example.com
        - to:jane@example.com
        - subject:meeting
        - has:attachment
        - before:2024-01-01
        - after:2024-01-01
        - is:read / is:unread
        - is:starred
        
        Args:
            query: Search query string
        
        Returns:
            Dictionary of parsed filters
        """
        filters = {
            "query": "",
            "from_email": None,
            "to_email": None,
            "subject": None,
            "has_attachment": None,
            "before_date": None,
            "after_date": None,
            "is_read": None,
            "is_starred": None,
        }
        
        # Extract filters
        patterns = {
            "from_email": r"from:(\S+)",
            "to_email": r"to:(\S+)",
            "subject": r"subject:(\S+)",
        }
        
        remaining_query = query
        
        for key, pattern in patterns.items():
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                filters[key] = match.group(1)
                remaining_query = remaining_query.replace(match.group(0), "")
        
        # Handle has: filter
        if re.search(r"has:attachment", query, re.IGNORECASE):
            filters["has_attachment"] = True
            remaining_query = re.sub(r"has:attachment", "", remaining_query, flags=re.IGNORECASE)
        
        # Handle is: filters
        if re.search(r"is:read", query, re.IGNORECASE):
            filters["is_read"] = True
            remaining_query = re.sub(r"is:read", "", remaining_query, flags=re.IGNORECASE)
        
        if re.search(r"is:unread", query, re.IGNORECASE):
            filters["is_read"] = False
            remaining_query = re.sub(r"is:unread", "", remaining_query, flags=re.IGNORECASE)
        
        if re.search(r"is:starred", query, re.IGNORECASE):
            filters["is_starred"] = True
            remaining_query = re.sub(r"is:starred", "", remaining_query, flags=re.IGNORECASE)
        
        # Handle date filters
        before_match = re.search(r"before:(\d{4}-\d{2}-\d{2})", query, re.IGNORECASE)
        if before_match:
            try:
                filters["before_date"] = datetime.fromisoformat(before_match.group(1))
                remaining_query = remaining_query.replace(before_match.group(0), "")
            except ValueError:
                pass
        
        after_match = re.search(r"after:(\d{4}-\d{2}-\d{2})", query, re.IGNORECASE)
        if after_match:
            try:
                filters["after_date"] = datetime.fromisoformat(after_match.group(1))
                remaining_query = remaining_query.replace(after_match.group(0), "")
            except ValueError:
                pass
        
        # Remaining text is the free-text query
        filters["query"] = remaining_query.strip()
        
        return filters
    
    async def search_emails(
        self,
        user_id: str,
        query: str,
        folder: Optional[str] = None,
        limit: int = 50
    ) -> List[InboxEmail]:
        """
        Search emails with advanced filters.
        
        Args:
            user_id: User identifier
            query: Search query (supports advanced syntax)
            folder: Limit search to specific folder
            limit: Maximum results
        
        Returns:
            List of matching emails
        """
        # Parse query
        filters = self.parse_search_query(query)
        
        # Execute search
        return await self.repo.search_emails(
            user_id=user_id,
            query=filters["query"],
            from_email=filters["from_email"],
            to_email=filters["to_email"],
            subject=filters["subject"],
            has_attachment=filters["has_attachment"],
            before_date=filters["before_date"],
            after_date=filters["after_date"],
            folder=folder,
            limit=limit
        )


class LabelService:
    """Service for email label management."""
    
    def __init__(self, repository: LabelRepository):
        """Initialize service with repository."""
        self.repo = repository
    
    async def create_label(
        self,
        user_id: str,
        name: str,
        color: str = "#808080",
        parent_label_id: Optional[str] = None
    ) -> EmailLabel:
        """
        Create a new label.
        
        Args:
            user_id: User identifier
            name: Label name (1-50 characters)
            color: Label color (hex code)
            parent_label_id: Parent label for nesting (max 2 levels)
        
        Returns:
            Created label
        
        Raises:
            ValueError: If validation fails
        """
        # Validate name
        if not name or len(name) > 50:
            raise ValueError("Label name must be 1-50 characters")
        
        # Validate color (hex code)
        if not re.match(r"^#[0-9A-Fa-f]{6}$", color):
            raise ValueError("Invalid color format (use #RRGGBB)")
        
        # Check nesting level (max 2 levels)
        if parent_label_id:
            parent = await self.repo.get_label_by_id(parent_label_id, user_id)
            if not parent:
                raise ValueError("Parent label not found")
            
            if parent.parent_label_id:
                raise ValueError("Maximum nesting level (2) exceeded")
        
        # Generate label ID
        label_id = f"label_{user_id}_{hashlib.md5(name.encode()).hexdigest()[:8]}"
        
        # Create label
        return await self.repo.create_label(
            user_id=user_id,
            label_id=label_id,
            name=name,
            color=color,
            parent_label_id=parent_label_id
        )
    
    async def get_user_labels(self, user_id: str) -> List[EmailLabel]:
        """Get all labels for a user."""
        return await self.repo.get_user_labels(user_id)
    
    async def update_label(
        self,
        label_id: str,
        user_id: str,
        name: Optional[str] = None,
        color: Optional[str] = None
    ) -> Optional[EmailLabel]:
        """Update label properties."""
        # Validate inputs
        if name and (not name or len(name) > 50):
            raise ValueError("Label name must be 1-50 characters")
        
        if color and not re.match(r"^#[0-9A-Fa-f]{6}$", color):
            raise ValueError("Invalid color format (use #RRGGBB)")
        
        return await self.repo.update_label(label_id, user_id, name, color)
    
    async def delete_label(
        self,
        label_id: str,
        user_id: str
    ) -> bool:
        """Delete a label (emails are not deleted)."""
        return await self.repo.delete_label(label_id, user_id)
