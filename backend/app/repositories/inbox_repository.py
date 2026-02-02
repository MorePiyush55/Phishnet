"""Repository layer for inbox operations with caching support."""

from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
import hashlib
import json

from beanie import PydanticObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING
import redis.asyncio as redis

from app.models.inbox_models import (
    InboxEmail,
    EmailLabel,
    EmailThread,
    EmailDraft,
    EmailFolder,
    FolderCount,
    InboxStats,
    FolderType,
    EmailParticipant,
)


class InboxRepository:
    """
    Data access layer for inbox operations.
    
    Implements cursor-based pagination, caching, and bulk operations
    for efficient inbox management.
    """
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        """Initialize repository with optional Redis cache."""
        self.redis = redis_client
        self.cache_ttl = {
            "folder_counts": 300,  # 5 minutes
            "recent_searches": 600,  # 10 minutes
            "email_snippets": 1800,  # 30 minutes
        }
    
    # ==================== Email Listing & Retrieval ====================
    
    async def get_emails_paginated(
        self,
        user_id: str,
        folder: Optional[str] = None,
        labels: Optional[List[str]] = None,
        is_read: Optional[bool] = None,
        is_starred: Optional[bool] = None,
        has_attachment: Optional[bool] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
        sort_by: str = "received_at",
        sort_order: int = DESCENDING,
    ) -> Tuple[List[InboxEmail], Optional[str], bool]:
        """
        Get paginated list of emails with filters.
        
        Args:
            user_id: User identifier
            folder: Folder to filter by (inbox, sent, etc.)
            labels: List of label IDs to filter by
            is_read: Filter by read status
            is_starred: Filter by starred status
            has_attachment: Filter by attachment presence
            limit: Number of emails per page (max 100)
            cursor: Pagination cursor (received_at timestamp)
            sort_by: Field to sort by
            sort_order: Sort order (ASCENDING or DESCENDING)
        
        Returns:
            Tuple of (emails, next_cursor, has_more)
        """
        # Build query
        query: Dict[str, Any] = {"user_id": user_id}
        
        if folder:
            query["folder"] = folder
        
        if labels:
            query["labels"] = {"$in": labels}
        
        if is_read is not None:
            query["is_read"] = is_read
        
        if is_starred is not None:
            query["is_starred"] = is_starred
        
        if has_attachment is not None:
            query["has_attachment"] = has_attachment
        
        # Handle cursor-based pagination
        if cursor:
            try:
                cursor_time = datetime.fromisoformat(cursor)
                if sort_order == DESCENDING:
                    query[sort_by] = {"$lt": cursor_time}
                else:
                    query[sort_by] = {"$gt": cursor_time}
            except (ValueError, TypeError):
                pass  # Invalid cursor, ignore
        
        # Limit to max 100 per page
        limit = min(limit, 100)
        
        # Fetch emails
        emails = await InboxEmail.find(query).sort(
            [(sort_by, sort_order)]
        ).limit(limit + 1).to_list()
        
        # Check if there are more results
        has_more = len(emails) > limit
        if has_more:
            emails = emails[:limit]
        
        # Generate next cursor
        next_cursor = None
        if has_more and emails:
            last_email = emails[-1]
            next_cursor = getattr(last_email, sort_by).isoformat()
        
        return emails, next_cursor, has_more
    
    async def get_email_by_id(
        self,
        message_id: str,
        user_id: str
    ) -> Optional[InboxEmail]:
        """
        Get single email by message ID.
        
        Args:
            message_id: Unique message identifier
            user_id: User identifier (for authorization)
        
        Returns:
            Email document or None if not found
        """
        return await InboxEmail.find_one(
            {"message_id": message_id, "user_id": user_id}
        )
    
    async def get_thread_emails(
        self,
        thread_id: str,
        user_id: str
    ) -> List[InboxEmail]:
        """
        Get all emails in a conversation thread.
        
        Args:
            thread_id: Thread identifier
            user_id: User identifier
        
        Returns:
            List of emails in thread, sorted by received_at
        """
        return await InboxEmail.find(
            {"thread_id": thread_id, "user_id": user_id}
        ).sort([("received_at", ASCENDING)]).to_list()
    
    # ==================== Email Actions ====================
    
    async def update_read_status(
        self,
        message_ids: List[str],
        user_id: str,
        is_read: bool
    ) -> int:
        """
        Update read status for emails.
        
        Args:
            message_ids: List of message IDs to update
            user_id: User identifier
            is_read: New read status
        
        Returns:
            Number of emails updated
        """
        result = await InboxEmail.find(
            {"message_id": {"$in": message_ids}, "user_id": user_id}
        ).update_many(
            {"$set": {"is_read": is_read, "updated_at": datetime.now(timezone.utc)}}
        )
        
        # Invalidate folder counts cache
        await self._invalidate_folder_counts_cache(user_id)
        
        return result.modified_count
    
    async def update_star_status(
        self,
        message_ids: List[str],
        user_id: str,
        is_starred: bool
    ) -> int:
        """Update starred status for emails."""
        result = await InboxEmail.find(
            {"message_id": {"$in": message_ids}, "user_id": user_id}
        ).update_many(
            {"$set": {"is_starred": is_starred, "updated_at": datetime.now(timezone.utc)}}
        )
        
        return result.modified_count
    
    async def move_to_folder(
        self,
        message_ids: List[str],
        user_id: str,
        target_folder: str
    ) -> int:
        """
        Move emails to a different folder.
        
        Args:
            message_ids: List of message IDs to move
            user_id: User identifier
            target_folder: Target folder name
        
        Returns:
            Number of emails moved
        """
        result = await InboxEmail.find(
            {"message_id": {"$in": message_ids}, "user_id": user_id}
        ).update_many(
            {"$set": {"folder": target_folder, "updated_at": datetime.now(timezone.utc)}}
        )
        
        # Invalidate folder counts cache
        await self._invalidate_folder_counts_cache(user_id)
        
        return result.modified_count
    
    async def apply_labels(
        self,
        message_ids: List[str],
        user_id: str,
        label_ids: List[str]
    ) -> int:
        """
        Apply labels to emails.
        
        Args:
            message_ids: List of message IDs
            user_id: User identifier
            label_ids: List of label IDs to apply
        
        Returns:
            Number of emails updated
        """
        result = await InboxEmail.find(
            {"message_id": {"$in": message_ids}, "user_id": user_id}
        ).update_many(
            {
                "$addToSet": {"labels": {"$each": label_ids}},
                "$set": {"updated_at": datetime.now(timezone.utc)}
            }
        )
        
        return result.modified_count
    
    async def remove_labels(
        self,
        message_ids: List[str],
        user_id: str,
        label_ids: List[str]
    ) -> int:
        """Remove labels from emails."""
        result = await InboxEmail.find(
            {"message_id": {"$in": message_ids}, "user_id": user_id}
        ).update_many(
            {
                "$pull": {"labels": {"$in": label_ids}},
                "$set": {"updated_at": datetime.now(timezone.utc)}
            }
        )
        
        return result.modified_count
    
    async def delete_emails(
        self,
        message_ids: List[str],
        user_id: str,
        permanent: bool = False
    ) -> int:
        """
        Delete emails (move to trash or permanent delete).
        
        Args:
            message_ids: List of message IDs to delete
            user_id: User identifier
            permanent: If True, permanently delete. Otherwise move to trash.
        
        Returns:
            Number of emails deleted
        """
        if permanent:
            # Permanent deletion
            result = await InboxEmail.find(
                {"message_id": {"$in": message_ids}, "user_id": user_id}
            ).delete()
            count = result.deleted_count
        else:
            # Move to trash
            count = await self.move_to_folder(message_ids, user_id, FolderType.TRASH.value)
        
        # Invalidate folder counts cache
        await self._invalidate_folder_counts_cache(user_id)
        
        return count
    
    # ==================== Search ====================
    
    async def search_emails(
        self,
        user_id: str,
        query: str,
        from_email: Optional[str] = None,
        to_email: Optional[str] = None,
        subject: Optional[str] = None,
        has_attachment: Optional[bool] = None,
        before_date: Optional[datetime] = None,
        after_date: Optional[datetime] = None,
        folder: Optional[str] = None,
        limit: int = 50
    ) -> List[InboxEmail]:
        """
        Search emails with advanced filters.
        
        Args:
            user_id: User identifier
            query: Free text search query
            from_email: Filter by sender email
            to_email: Filter by recipient email
            subject: Filter by subject
            has_attachment: Filter by attachment presence
            before_date: Filter by date before
            after_date: Filter by date after
            folder: Filter by folder
            limit: Maximum results
        
        Returns:
            List of matching emails
        """
        # Check cache first
        cache_key = self._generate_search_cache_key(
            user_id, query, from_email, to_email, subject,
            has_attachment, before_date, after_date, folder
        )
        
        if self.redis:
            cached = await self.redis.get(cache_key)
            if cached:
                # Return cached results (would need to deserialize)
                pass
        
        # Build search query
        search_query: Dict[str, Any] = {"user_id": user_id}
        
        # Text search
        if query:
            search_query["$text"] = {"$search": query}
        
        # Advanced filters
        if from_email:
            search_query["sender.email"] = {"$regex": from_email, "$options": "i"}
        
        if to_email:
            search_query["recipients.to.email"] = {"$regex": to_email, "$options": "i"}
        
        if subject:
            search_query["subject"] = {"$regex": subject, "$options": "i"}
        
        if has_attachment is not None:
            search_query["has_attachment"] = has_attachment
        
        if before_date:
            search_query.setdefault("received_at", {})["$lt"] = before_date
        
        if after_date:
            search_query.setdefault("received_at", {})["$gt"] = after_date
        
        if folder:
            search_query["folder"] = folder
        
        # Execute search
        results = await InboxEmail.find(search_query).limit(limit).to_list()
        
        # Cache results
        if self.redis:
            # Would cache serialized results here
            pass
        
        return results
    
    # ==================== Folder & Label Management ====================
    
    async def get_folder_counts(self, user_id: str) -> List[FolderCount]:
        """
        Get email counts for all folders.
        
        Args:
            user_id: User identifier
        
        Returns:
            List of folder counts
        """
        # Check cache first
        cache_key = f"folder_counts:{user_id}"
        
        if self.redis:
            cached = await self.redis.get(cache_key)
            if cached:
                try:
                    data = json.loads(cached)
                    return [FolderCount(**item) for item in data]
                except (json.JSONDecodeError, TypeError):
                    pass
        
        # Aggregate counts by folder
        pipeline = [
            {"$match": {"user_id": user_id}},
            {
                "$group": {
                    "_id": "$folder",
                    "total": {"$sum": 1},
                    "unread": {
                        "$sum": {"$cond": [{"$eq": ["$is_read", False]}, 1, 0]}
                    }
                }
            }
        ]
        
        results = await InboxEmail.aggregate(pipeline).to_list()
        
        folder_counts = [
            FolderCount(folder=item["_id"], total=item["total"], unread=item["unread"])
            for item in results
        ]
        
        # Cache results
        if self.redis:
            cache_data = [fc.dict() for fc in folder_counts]
            await self.redis.setex(
                cache_key,
                self.cache_ttl["folder_counts"],
                json.dumps(cache_data)
            )
        
        return folder_counts
    
    async def get_inbox_stats(self, user_id: str) -> InboxStats:
        """Get comprehensive inbox statistics."""
        folder_counts = await self.get_folder_counts(user_id)
        
        # Calculate totals
        total_emails = sum(fc.total for fc in folder_counts)
        unread_emails = sum(fc.unread for fc in folder_counts)
        
        # Get starred count
        starred_count = await InboxEmail.find(
            {"user_id": user_id, "is_starred": True}
        ).count()
        
        # Get spam count
        spam_count = next(
            (fc.total for fc in folder_counts if fc.folder == FolderType.SPAM.value),
            0
        )
        
        # Get high-risk email count
        threat_count = await InboxEmail.find(
            {"user_id": user_id, "risk_level": {"$in": ["HIGH", "CRITICAL"]}}
        ).count()
        
        return InboxStats(
            total_emails=total_emails,
            unread_emails=unread_emails,
            starred_emails=starred_count,
            spam_emails=spam_count,
            threat_emails=threat_count,
            folder_counts=folder_counts
        )
    
    # ==================== Bulk Operations ====================
    
    async def bulk_update_read_status(
        self,
        user_id: str,
        folder: Optional[str] = None,
        is_read: bool = True
    ) -> int:
        """Bulk update read status for all emails in a folder."""
        query: Dict[str, Any] = {"user_id": user_id}
        if folder:
            query["folder"] = folder
        
        result = await InboxEmail.find(query).update_many(
            {"$set": {"is_read": is_read, "updated_at": datetime.now(timezone.utc)}}
        )
        
        await self._invalidate_folder_counts_cache(user_id)
        
        return result.modified_count
    
    # ==================== Helper Methods ====================
    
    async def _invalidate_folder_counts_cache(self, user_id: str):
        """Invalidate folder counts cache for a user."""
        if self.redis:
            cache_key = f"folder_counts:{user_id}"
            await self.redis.delete(cache_key)
    
    def _generate_search_cache_key(
        self,
        user_id: str,
        query: str,
        from_email: Optional[str],
        to_email: Optional[str],
        subject: Optional[str],
        has_attachment: Optional[bool],
        before_date: Optional[datetime],
        after_date: Optional[datetime],
        folder: Optional[str]
    ) -> str:
        """Generate cache key for search query."""
        params = {
            "user_id": user_id,
            "query": query,
            "from": from_email,
            "to": to_email,
            "subject": subject,
            "has_attachment": has_attachment,
            "before": before_date.isoformat() if before_date else None,
            "after": after_date.isoformat() if after_date else None,
            "folder": folder
        }
        
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        
        # Generate hash
        params_str = json.dumps(params, sort_keys=True)
        hash_key = hashlib.md5(params_str.encode()).hexdigest()
        
        return f"search:{user_id}:{hash_key}"


class LabelRepository:
    """Repository for email label operations."""
    
    async def create_label(
        self,
        user_id: str,
        label_id: str,
        name: str,
        color: str = "#808080",
        parent_label_id: Optional[str] = None
    ) -> EmailLabel:
        """Create a new email label."""
        label = EmailLabel(
            label_id=label_id,
            user_id=user_id,
            name=name,
            color=color,
            parent_label_id=parent_label_id
        )
        
        await label.insert()
        return label
    
    async def get_user_labels(self, user_id: str) -> List[EmailLabel]:
        """Get all labels for a user."""
        return await EmailLabel.find(
            {"user_id": user_id}
        ).sort([("name", ASCENDING)]).to_list()
    
    async def get_label_by_id(
        self,
        label_id: str,
        user_id: str
    ) -> Optional[EmailLabel]:
        """Get label by ID."""
        return await EmailLabel.find_one(
            {"label_id": label_id, "user_id": user_id}
        )
    
    async def update_label(
        self,
        label_id: str,
        user_id: str,
        name: Optional[str] = None,
        color: Optional[str] = None
    ) -> Optional[EmailLabel]:
        """Update label properties."""
        label = await self.get_label_by_id(label_id, user_id)
        if not label:
            return None
        
        if name:
            label.name = name
        if color:
            label.color = color
        
        label.updated_at = datetime.now(timezone.utc)
        await label.save()
        
        return label
    
    async def delete_label(
        self,
        label_id: str,
        user_id: str
    ) -> bool:
        """
        Delete a label (does not delete emails).
        
        Returns:
            True if deleted, False if not found
        """
        label = await self.get_label_by_id(label_id, user_id)
        if not label:
            return False
        
        # Remove label from all emails
        await InboxEmail.find(
            {"user_id": user_id, "labels": label_id}
        ).update_many(
            {"$pull": {"labels": label_id}}
        )
        
        # Delete label
        await label.delete()
        
        return True
