"""API router for inbox operations."""

from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field

from app.models.inbox_models import (
    InboxEmail,
    EmailLabel,
    FolderType,
    InboxStats,
    FolderCount,
)
from app.services.inbox_service import (
    InboxService,
    SearchService,
    LabelService,
    ThreadingService,
)
from app.repositories.inbox_repository import InboxRepository, LabelRepository
from app.auth.dependencies import get_current_user  # Assuming auth dependency exists


# ==================== Request/Response Models ====================

class EmailListResponse(BaseModel):
    """Response model for email list."""
    emails: List[InboxEmail]
    next_cursor: Optional[str] = None
    has_more: bool = False
    total_count: Optional[int] = None


class UpdateReadStatusRequest(BaseModel):
    """Request to update read status."""
    is_read: bool


class UpdateStarStatusRequest(BaseModel):
    """Request to update star status."""
    is_starred: bool


class MoveToFolderRequest(BaseModel):
    """Request to move emails to folder."""
    folder: str = Field(..., description="Target folder name")


class ApplyLabelsRequest(BaseModel):
    """Request to apply labels."""
    label_ids: List[str] = Field(..., description="List of label IDs to apply")


class RemoveLabelsRequest(BaseModel):
    """Request to remove labels."""
    label_ids: List[str] = Field(..., description="List of label IDs to remove")


class BulkEmailActionRequest(BaseModel):
    """Request for bulk email actions."""
    message_ids: List[str] = Field(..., description="List of message IDs", max_items=100)


class CreateLabelRequest(BaseModel):
    """Request to create a new label."""
    name: str = Field(..., min_length=1, max_length=50)
    color: str = Field(default="#808080", pattern=r"^#[0-9A-Fa-f]{6}$")
    parent_label_id: Optional[str] = None


class UpdateLabelRequest(BaseModel):
    """Request to update a label."""
    name: Optional[str] = Field(None, min_length=1, max_length=50)
    color: Optional[str] = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")


# ==================== Router Setup ====================

router = APIRouter(
    prefix="/api/v1/inbox",
    tags=["inbox"],
    responses={404: {"description": "Not found"}},
)


# ==================== Dependencies ====================

async def get_inbox_service() -> InboxService:
    """Get inbox service instance."""
    repo = InboxRepository()
    return InboxService(repo)


async def get_search_service() -> SearchService:
    """Get search service instance."""
    repo = InboxRepository()
    return SearchService(repo)


async def get_label_service() -> LabelService:
    """Get label service instance."""
    repo = LabelRepository()
    return LabelService(repo)


# ==================== Email Listing & Retrieval Endpoints ====================

@router.get("/emails", response_model=EmailListResponse)
async def list_emails(
    folder: Optional[str] = Query(None, description="Filter by folder"),
    labels: Optional[List[str]] = Query(None, description="Filter by labels"),
    is_read: Optional[bool] = Query(None, description="Filter by read status"),
    is_starred: Optional[bool] = Query(None, description="Filter by starred status"),
    has_attachment: Optional[bool] = Query(None, description="Filter by attachment presence"),
    limit: int = Query(50, ge=1, le=100, description="Number of emails per page"),
    cursor: Optional[str] = Query(None, description="Pagination cursor"),
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """
    List emails with pagination and filters.
    
    Supports cursor-based pagination for efficient scrolling through large inboxes.
    """
    user_id = current_user["user_id"]
    
    emails, next_cursor, has_more = await service.list_emails(
        user_id=user_id,
        folder=folder,
        labels=labels,
        is_read=is_read,
        is_starred=is_starred,
        has_attachment=has_attachment,
        limit=limit,
        cursor=cursor,
    )
    
    return EmailListResponse(
        emails=emails,
        next_cursor=next_cursor,
        has_more=has_more,
    )


@router.get("/emails/{message_id}", response_model=InboxEmail)
async def get_email(
    message_id: str,
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """
    Get single email by message ID.
    
    Returns full email details including body, headers, and attachments.
    """
    user_id = current_user["user_id"]
    
    email = await service.get_email_details(message_id, user_id)
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with message_id '{message_id}' not found"
        )
    
    return email


@router.get("/threads/{thread_id}", response_model=List[InboxEmail])
async def get_thread(
    thread_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Get all emails in a conversation thread.
    
    Returns emails sorted by received_at in ascending order.
    """
    user_id = current_user["user_id"]
    
    repo = InboxRepository()
    emails = await repo.get_thread_emails(thread_id, user_id)
    
    if not emails:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Thread with thread_id '{thread_id}' not found"
        )
    
    return emails


# ==================== Email Action Endpoints ====================

@router.patch("/emails/{message_id}/read", status_code=status.HTTP_200_OK)
async def update_read_status(
    message_id: str,
    request: UpdateReadStatusRequest,
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Mark email as read or unread."""
    user_id = current_user["user_id"]
    
    if request.is_read:
        count = await service.mark_as_read([message_id], user_id)
    else:
        count = await service.mark_as_unread([message_id], user_id)
    
    if count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with message_id '{message_id}' not found"
        )
    
    return {"message": "Read status updated successfully", "updated_count": count}


@router.patch("/emails/{message_id}/star", status_code=status.HTTP_200_OK)
async def update_star_status(
    message_id: str,
    request: UpdateStarStatusRequest,
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Star or unstar email."""
    user_id = current_user["user_id"]
    
    count = await service.toggle_star([message_id], user_id, request.is_starred)
    
    if count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with message_id '{message_id}' not found"
        )
    
    return {"message": "Star status updated successfully", "updated_count": count}


@router.post("/emails/{message_id}/move", status_code=status.HTTP_200_OK)
async def move_email(
    message_id: str,
    request: MoveToFolderRequest,
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Move email to a different folder."""
    user_id = current_user["user_id"]
    
    # Validate folder
    valid_folders = [f.value for f in FolderType]
    if request.folder not in valid_folders:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid folder. Must be one of: {valid_folders}"
        )
    
    repo = InboxRepository()
    count = await repo.move_to_folder([message_id], user_id, request.folder)
    
    if count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with message_id '{message_id}' not found"
        )
    
    return {"message": f"Email moved to {request.folder}", "updated_count": count}


@router.post("/emails/{message_id}/labels", status_code=status.HTTP_200_OK)
async def apply_labels(
    message_id: str,
    request: ApplyLabelsRequest,
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Apply labels to email."""
    user_id = current_user["user_id"]
    
    count = await service.apply_labels([message_id], user_id, request.label_ids)
    
    if count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with message_id '{message_id}' not found"
        )
    
    return {"message": "Labels applied successfully", "updated_count": count}


@router.delete("/emails/{message_id}/labels", status_code=status.HTTP_200_OK)
async def remove_labels(
    message_id: str,
    request: RemoveLabelsRequest,
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Remove labels from email."""
    user_id = current_user["user_id"]
    
    count = await service.remove_labels([message_id], user_id, request.label_ids)
    
    if count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with message_id '{message_id}' not found"
        )
    
    return {"message": "Labels removed successfully", "updated_count": count}


@router.delete("/emails/{message_id}", status_code=status.HTTP_200_OK)
async def delete_email(
    message_id: str,
    permanent: bool = Query(False, description="Permanently delete (cannot be recovered)"),
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Delete email (move to trash or permanent delete)."""
    user_id = current_user["user_id"]
    
    if permanent:
        count = await service.permanent_delete([message_id], user_id)
        message = "Email permanently deleted"
    else:
        count = await service.delete_emails([message_id], user_id)
        message = "Email moved to trash"
    
    if count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with message_id '{message_id}' not found"
        )
    
    return {"message": message, "deleted_count": count}


@router.post("/emails/{message_id}/restore", status_code=status.HTTP_200_OK)
async def restore_email(
    message_id: str,
    target_folder: str = Query(FolderType.INBOX.value, description="Target folder for restoration"),
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Restore email from trash."""
    user_id = current_user["user_id"]
    
    count = await service.restore_emails([message_id], user_id, target_folder)
    
    if count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email with message_id '{message_id}' not found"
        )
    
    return {"message": f"Email restored to {target_folder}", "restored_count": count}


# ==================== Bulk Operation Endpoints ====================

@router.post("/emails/bulk/read", status_code=status.HTTP_200_OK)
async def bulk_mark_read(
    request: BulkEmailActionRequest,
    is_read: bool = Query(True, description="Mark as read (true) or unread (false)"),
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Bulk mark emails as read or unread."""
    user_id = current_user["user_id"]
    
    if is_read:
        count = await service.mark_as_read(request.message_ids, user_id)
    else:
        count = await service.mark_as_unread(request.message_ids, user_id)
    
    return {"message": "Bulk read status updated", "updated_count": count}


@router.post("/emails/bulk/star", status_code=status.HTTP_200_OK)
async def bulk_star(
    request: BulkEmailActionRequest,
    is_starred: bool = Query(True, description="Star (true) or unstar (false)"),
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Bulk star or unstar emails."""
    user_id = current_user["user_id"]
    
    count = await service.toggle_star(request.message_ids, user_id, is_starred)
    
    return {"message": "Bulk star status updated", "updated_count": count}


@router.post("/emails/bulk/move", status_code=status.HTTP_200_OK)
async def bulk_move(
    request: BulkEmailActionRequest,
    folder: str = Query(..., description="Target folder"),
    current_user: dict = Depends(get_current_user),
):
    """Bulk move emails to folder."""
    user_id = current_user["user_id"]
    
    # Validate folder
    valid_folders = [f.value for f in FolderType]
    if folder not in valid_folders:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid folder. Must be one of: {valid_folders}"
        )
    
    repo = InboxRepository()
    count = await repo.move_to_folder(request.message_ids, user_id, folder)
    
    return {"message": f"Emails moved to {folder}", "updated_count": count}


@router.post("/emails/bulk/labels", status_code=status.HTTP_200_OK)
async def bulk_apply_labels(
    request: BulkEmailActionRequest,
    label_ids: List[str] = Query(..., description="Label IDs to apply"),
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Bulk apply labels to emails."""
    user_id = current_user["user_id"]
    
    count = await service.apply_labels(request.message_ids, user_id, label_ids)
    
    return {"message": "Labels applied to emails", "updated_count": count}


@router.post("/emails/bulk/delete", status_code=status.HTTP_200_OK)
async def bulk_delete(
    request: BulkEmailActionRequest,
    permanent: bool = Query(False, description="Permanently delete"),
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Bulk delete emails."""
    user_id = current_user["user_id"]
    
    if permanent:
        count = await service.permanent_delete(request.message_ids, user_id)
        message = "Emails permanently deleted"
    else:
        count = await service.delete_emails(request.message_ids, user_id)
        message = "Emails moved to trash"
    
    return {"message": message, "deleted_count": count}


# ==================== Search Endpoints ====================

@router.get("/search", response_model=EmailListResponse)
async def search_emails(
    q: str = Query(..., description="Search query (supports advanced syntax)"),
    folder: Optional[str] = Query(None, description="Limit search to folder"),
    limit: int = Query(50, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    service: SearchService = Depends(get_search_service),
):
    """
    Search emails with advanced filters.
    
    Supports Gmail-style search syntax:
    - from:john@example.com
    - to:jane@example.com
    - subject:meeting
    - has:attachment
    - before:2024-01-01
    - after:2024-01-01
    - is:read / is:unread
    - is:starred
    """
    user_id = current_user["user_id"]
    
    results = await service.search_emails(user_id, q, folder, limit)
    
    return EmailListResponse(
        emails=results,
        next_cursor=None,  # Search doesn't support pagination yet
        has_more=False,
    )


# ==================== Folder & Label Endpoints ====================

@router.get("/folders", response_model=List[FolderCount])
async def get_folders(
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Get all folders with email counts."""
    user_id = current_user["user_id"]
    
    return await service.get_folder_counts(user_id)


@router.get("/stats", response_model=InboxStats)
async def get_inbox_stats(
    current_user: dict = Depends(get_current_user),
    service: InboxService = Depends(get_inbox_service),
):
    """Get comprehensive inbox statistics."""
    user_id = current_user["user_id"]
    
    return await service.get_inbox_stats(user_id)


@router.get("/labels", response_model=List[EmailLabel])
async def get_labels(
    current_user: dict = Depends(get_current_user),
    service: LabelService = Depends(get_label_service),
):
    """Get all user labels."""
    user_id = current_user["user_id"]
    
    return await service.get_user_labels(user_id)


@router.post("/labels", response_model=EmailLabel, status_code=status.HTTP_201_CREATED)
async def create_label(
    request: CreateLabelRequest,
    current_user: dict = Depends(get_current_user),
    service: LabelService = Depends(get_label_service),
):
    """Create a new label."""
    user_id = current_user["user_id"]
    
    try:
        label = await service.create_label(
            user_id=user_id,
            name=request.name,
            color=request.color,
            parent_label_id=request.parent_label_id,
        )
        return label
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.patch("/labels/{label_id}", response_model=EmailLabel)
async def update_label(
    label_id: str,
    request: UpdateLabelRequest,
    current_user: dict = Depends(get_current_user),
    service: LabelService = Depends(get_label_service),
):
    """Update label properties."""
    user_id = current_user["user_id"]
    
    try:
        label = await service.update_label(
            label_id=label_id,
            user_id=user_id,
            name=request.name,
            color=request.color,
        )
        
        if not label:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Label with label_id '{label_id}' not found"
            )
        
        return label
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.delete("/labels/{label_id}", status_code=status.HTTP_200_OK)
async def delete_label(
    label_id: str,
    current_user: dict = Depends(get_current_user),
    service: LabelService = Depends(get_label_service),
):
    """Delete a label (emails are not deleted)."""
    user_id = current_user["user_id"]
    
    deleted = await service.delete_label(label_id, user_id)
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Label with label_id '{label_id}' not found"
        )
    
    return {"message": "Label deleted successfully"}
