"""MongoDB document models for inbox functionality using Beanie ODM."""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum

from beanie import Document, Indexed
from pydantic import Field, EmailStr, BaseModel
from pymongo import IndexModel, ASCENDING, DESCENDING


class FolderType(str, Enum):
    """System folder types."""
    INBOX = "inbox"
    SENT = "sent"
    DRAFTS = "drafts"
    SPAM = "spam"
    TRASH = "trash"
    ALL_MAIL = "all_mail"
    ARCHIVE = "archive"


class EmailParticipant(BaseModel):
    """Email participant (sender or recipient)."""
    name: Optional[str] = None
    email: EmailStr
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "John Doe",
                "email": "john@example.com"
            }
        }


class EmailRecipients(BaseModel):
    """Email recipients (To, CC, BCC)."""
    to: List[EmailParticipant] = Field(default_factory=list)
    cc: List[EmailParticipant] = Field(default_factory=list)
    bcc: List[EmailParticipant] = Field(default_factory=list)  # Only visible to sender
    
    class Config:
        json_schema_extra = {
            "example": {
                "to": [{"name": "Jane Doe", "email": "jane@example.com"}],
                "cc": [{"name": "Bob Smith", "email": "bob@example.com"}],
                "bcc": []
            }
        }


class EmailAttachment(BaseModel):
    """Email attachment metadata."""
    attachment_id: str = Field(description="Unique attachment identifier")
    filename: str
    size_bytes: int
    mime_type: str
    download_url: Optional[str] = None
    gridfs_id: Optional[str] = None  # GridFS file ID if stored in MongoDB
    
    class Config:
        json_schema_extra = {
            "example": {
                "attachment_id": "att_123",
                "filename": "document.pdf",
                "size_bytes": 1024000,
                "mime_type": "application/pdf",
                "download_url": "/api/v1/inbox/attachments/att_123"
            }
        }


class InboxEmail(Document):
    """
    Email document model for inbox functionality.
    
    This model extends the basic email analysis with inbox-specific features
    like labels, folders, threading, and read/unread status.
    """
    
    # Unique identifiers
    message_id: Indexed(str, unique=True) = Field(description="Unique message identifier")
    thread_id: str = Field(description="Thread identifier for conversation grouping")
    user_id: str = Field(description="User who owns this email")
    
    # Participants
    sender: EmailParticipant
    recipients: EmailRecipients
    
    # Content
    subject: str
    snippet: str = Field(description="First 200 characters for preview", max_length=200)
    body_text: Optional[str] = None  # Plain text version
    body_html: Optional[str] = None  # HTML version (sanitized)
    
    # Status flags
    is_read: bool = False
    is_starred: bool = False
    is_draft: bool = False
    is_sent: bool = False
    
    # Organization
    labels: List[str] = Field(default_factory=list, description="Applied label IDs")
    folder: str = Field(default=FolderType.INBOX.value, description="Current folder")
    
    # Attachments
    has_attachment: bool = False
    attachments: List[EmailAttachment] = Field(default_factory=list)
    
    # Timestamps
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sent_at: Optional[datetime] = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # PhishNet-specific threat analysis
    threat_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_level: str = Field(default="SAFE")  # SAFE, SUSPICIOUS, PHISHING
    threat_indicators: List[str] = Field(default_factory=list)
    analysis_completed: bool = False
    
    # Metadata
    size_bytes: Optional[int] = None
    headers: Dict[str, Any] = Field(default_factory=dict)
    
    class Settings:
        name = "inbox_emails"
        indexes = [
            # Primary queries
            IndexModel(
                [("user_id", ASCENDING), ("folder", ASCENDING), ("received_at", DESCENDING)],
                name="user_folder_received"
            ),
            IndexModel(
                [("user_id", ASCENDING), ("is_read", ASCENDING)],
                name="user_read_status"
            ),
            IndexModel(
                [("thread_id", ASCENDING), ("received_at", DESCENDING)],
                name="thread_emails"
            ),
            
            # Secondary queries
            IndexModel([("labels", ASCENDING)], name="labels_index"),
            IndexModel([("sender.email", ASCENDING)], name="sender_index"),
            IndexModel([("has_attachment", ASCENDING)], name="attachment_index"),
            IndexModel([("is_starred", ASCENDING)], name="starred_index"),
            IndexModel([("risk_level", ASCENDING)], name="risk_level_index"),
            
            # Search index (text search on subject and body)
            IndexModel(
                [("subject", "text"), ("body_text", "text")],
                name="email_text_search"
            ),
            
            # Unique constraint
            IndexModel([("message_id", ASCENDING)], unique=True, name="unique_message_id"),
        ]


class EmailLabel(Document):
    """
    Custom user-defined label for email organization.
    
    Supports Gmail-style multi-label system with optional nesting (2 levels max).
    """
    
    label_id: Indexed(str, unique=True) = Field(description="Unique label identifier")
    user_id: str = Field(description="User who owns this label")
    name: str = Field(description="Label name", min_length=1, max_length=50)
    color: str = Field(default="#808080", description="Label color (hex code)")
    
    # Nesting support (2 levels max)
    parent_label_id: Optional[str] = None
    
    # Metadata
    email_count: int = Field(default=0, description="Number of emails with this label")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Settings:
        name = "email_labels"
        indexes = [
            IndexModel(
                [("user_id", ASCENDING), ("name", ASCENDING)],
                unique=True,
                name="user_label_name_unique"
            ),
            IndexModel([("label_id", ASCENDING)], unique=True, name="unique_label_id"),
            IndexModel([("parent_label_id", ASCENDING)], name="parent_label_index"),
        ]


class EmailThread(Document):
    """
    Email thread/conversation metadata.
    
    Groups related emails together based on subject and participants.
    """
    
    thread_id: Indexed(str, unique=True) = Field(description="Unique thread identifier")
    user_id: str = Field(description="User who owns this thread")
    
    # Thread metadata
    subject: str = Field(description="Normalized subject (without Re:, Fwd:)")
    participants: List[EmailParticipant] = Field(description="All participants in thread")
    
    # Statistics
    message_count: int = Field(default=1, description="Number of messages in thread")
    unread_count: int = Field(default=0, description="Number of unread messages")
    
    # Timestamps
    first_message_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_message_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Status
    has_starred: bool = False
    has_attachment: bool = False
    
    class Settings:
        name = "email_threads"
        indexes = [
            IndexModel([("thread_id", ASCENDING)], unique=True, name="unique_thread_id"),
            IndexModel(
                [("user_id", ASCENDING), ("last_message_at", DESCENDING)],
                name="user_threads"
            ),
        ]


class EmailDraft(Document):
    """
    Draft email storage with auto-save support.
    
    Drafts are automatically saved every 30 seconds while composing.
    """
    
    draft_id: Indexed(str, unique=True) = Field(description="Unique draft identifier")
    user_id: str = Field(description="User who owns this draft")
    
    # Email content
    recipients: EmailRecipients
    subject: str = ""
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    
    # Attachments
    attachments: List[EmailAttachment] = Field(default_factory=list)
    
    # Draft metadata
    is_reply: bool = False
    is_reply_all: bool = False
    is_forward: bool = False
    original_message_id: Optional[str] = None  # If reply/forward
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_auto_save: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Settings:
        name = "email_drafts"
        indexes = [
            IndexModel([("draft_id", ASCENDING)], unique=True, name="unique_draft_id"),
            IndexModel(
                [("user_id", ASCENDING), ("updated_at", DESCENDING)],
                name="user_drafts"
            ),
        ]


class EmailFolder(Document):
    """
    Email folder definition (system and custom).
    
    System folders: Inbox, Sent, Drafts, Spam, Trash, All Mail
    Custom folders: User-defined folders for organization
    """
    
    folder_id: Indexed(str, unique=True) = Field(description="Unique folder identifier")
    user_id: str = Field(description="User who owns this folder")
    name: str = Field(description="Folder name")
    folder_type: str = Field(description="System or custom folder type")
    
    # Folder metadata
    is_system: bool = Field(default=False, description="System folder (cannot be deleted)")
    email_count: int = Field(default=0, description="Total emails in folder")
    unread_count: int = Field(default=0, description="Unread emails in folder")
    
    # Display settings
    color: Optional[str] = None
    icon: Optional[str] = None
    sort_order: int = Field(default=0, description="Display order in sidebar")
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Settings:
        name = "email_folders"
        indexes = [
            IndexModel([("folder_id", ASCENDING)], unique=True, name="unique_folder_id"),
            IndexModel(
                [("user_id", ASCENDING), ("sort_order", ASCENDING)],
                name="user_folders_sorted"
            ),
            IndexModel(
                [("user_id", ASCENDING), ("name", ASCENDING)],
                name="user_folder_name"
            ),
        ]


class FolderCount(BaseModel):
    """Folder count summary for sidebar display."""
    folder: str
    total: int = 0
    unread: int = 0


class InboxStats(BaseModel):
    """Inbox statistics for dashboard."""
    total_emails: int = 0
    unread_emails: int = 0
    starred_emails: int = 0
    spam_emails: int = 0
    threat_emails: int = 0  # High-risk emails
    folder_counts: List[FolderCount] = Field(default_factory=list)
