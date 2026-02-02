"""
API Integration Tests for Inbox System

Tests all inbox API endpoints including:
- Email listing and retrieval
- Email actions (read, star, move)
- Bulk operations
- Search functionality
- Label management
"""

import pytest
from httpx import AsyncClient


# ==================== Email Listing & Retrieval Tests ====================

@pytest.mark.asyncio
async def test_list_emails_default(client: AsyncClient, auth_headers, sample_emails):
    """Test listing emails with default parameters."""
    response = await client.get(
        "/api/v1/inbox/emails",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert "emails" in data
    assert "next_cursor" in data
    assert "has_more" in data
    assert isinstance(data["emails"], list)
    assert len(data["emails"]) <= 50  # Default limit


@pytest.mark.asyncio
async def test_list_emails_with_folder_filter(client: AsyncClient, auth_headers, sample_emails):
    """Test listing emails filtered by folder."""
    response = await client.get(
        "/api/v1/inbox/emails",
        params={"folder": "inbox"},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # All emails should be from inbox folder
    for email in data["emails"]:
        assert email["folder"] == "inbox"


@pytest.mark.asyncio
async def test_list_emails_pagination(client: AsyncClient, auth_headers, sample_emails):
    """Test cursor-based pagination."""
    # First page
    response1 = await client.get(
        "/api/v1/inbox/emails",
        params={"limit": 5},
        headers=auth_headers
    )
    
    assert response1.status_code == 200
    data1 = response1.json()
    
    assert len(data1["emails"]) == 5
    assert data1["has_more"] is True
    assert data1["next_cursor"] is not None
    
    # Second page
    response2 = await client.get(
        "/api/v1/inbox/emails",
        params={"limit": 5, "cursor": data1["next_cursor"]},
        headers=auth_headers
    )
    
    assert response2.status_code == 200
    data2 = response2.json()
    
    assert len(data2["emails"]) == 5
    
    # Emails should be different
    email_ids_1 = {e["message_id"] for e in data1["emails"]}
    email_ids_2 = {e["message_id"] for e in data2["emails"]}
    assert email_ids_1.isdisjoint(email_ids_2)


@pytest.mark.asyncio
async def test_list_emails_with_filters(client: AsyncClient, auth_headers, sample_emails):
    """Test listing emails with multiple filters."""
    response = await client.get(
        "/api/v1/inbox/emails",
        params={
            "folder": "inbox",
            "is_read": False,
            "is_starred": False,
            "limit": 10
        },
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Verify filters applied
    for email in data["emails"]:
        assert email["folder"] == "inbox"
        assert email["is_read"] is False
        assert email["is_starred"] is False


@pytest.mark.asyncio
async def test_get_email_by_id(client: AsyncClient, auth_headers, sample_emails):
    """Test retrieving single email by message ID."""
    test_email = sample_emails[0]
    
    response = await client.get(
        f"/api/v1/inbox/emails/{test_email.message_id}",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["message_id"] == test_email.message_id
    assert data["subject"] == test_email.subject
    assert "body_text" in data
    assert "body_html" in data


@pytest.mark.asyncio
async def test_get_email_not_found(client: AsyncClient, auth_headers):
    """Test retrieving non-existent email returns 404."""
    response = await client.get(
        "/api/v1/inbox/emails/nonexistent_id",
        headers=auth_headers
    )
    
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_thread(client: AsyncClient, auth_headers, sample_emails):
    """Test retrieving all emails in a thread."""
    # Get thread_id from first email
    thread_id = sample_emails[0].thread_id
    
    response = await client.get(
        f"/api/v1/inbox/threads/{thread_id}",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert isinstance(data, list)
    assert len(data) > 0
    
    # All emails should have same thread_id
    for email in data:
        assert email["thread_id"] == thread_id


# ==================== Email Action Tests ====================

@pytest.mark.asyncio
async def test_mark_email_as_read(client: AsyncClient, auth_headers, sample_emails):
    """Test marking email as read."""
    test_email = sample_emails[1]  # Unread email
    assert test_email.is_read is False
    
    response = await client.patch(
        f"/api/v1/inbox/emails/{test_email.message_id}/read",
        json={"is_read": True},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify email is now read
    verify_response = await client.get(
        f"/api/v1/inbox/emails/{test_email.message_id}",
        headers=auth_headers
    )
    assert verify_response.json()["is_read"] is True


@pytest.mark.asyncio
async def test_mark_email_as_unread(client: AsyncClient, auth_headers, sample_emails):
    """Test marking email as unread."""
    test_email = sample_emails[0]  # Read email
    assert test_email.is_read is True
    
    response = await client.patch(
        f"/api/v1/inbox/emails/{test_email.message_id}/read",
        json={"is_read": False},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify email is now unread
    verify_response = await client.get(
        f"/api/v1/inbox/emails/{test_email.message_id}",
        headers=auth_headers
    )
    assert verify_response.json()["is_read"] is False


@pytest.mark.asyncio
async def test_toggle_star(client: AsyncClient, auth_headers, sample_emails):
    """Test starring and unstarring email."""
    test_email = sample_emails[1]  # Unstarred email
    
    # Star email
    response = await client.patch(
        f"/api/v1/inbox/emails/{test_email.message_id}/star",
        json={"is_starred": True},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify starred
    verify_response = await client.get(
        f"/api/v1/inbox/emails/{test_email.message_id}",
        headers=auth_headers
    )
    assert verify_response.json()["is_starred"] is True
    
    # Unstar email
    response = await client.patch(
        f"/api/v1/inbox/emails/{test_email.message_id}/star",
        json={"is_starred": False},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify unstarred
    verify_response = await client.get(
        f"/api/v1/inbox/emails/{test_email.message_id}",
        headers=auth_headers
    )
    assert verify_response.json()["is_starred"] is False


@pytest.mark.asyncio
async def test_move_email_to_folder(client: AsyncClient, auth_headers, sample_emails):
    """Test moving email to different folder."""
    test_email = sample_emails[0]
    
    response = await client.post(
        f"/api/v1/inbox/emails/{test_email.message_id}/move",
        json={"folder": "archive"},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify email moved
    verify_response = await client.get(
        f"/api/v1/inbox/emails/{test_email.message_id}",
        headers=auth_headers
    )
    assert verify_response.json()["folder"] == "archive"


@pytest.mark.asyncio
async def test_delete_email(client: AsyncClient, auth_headers, sample_emails):
    """Test deleting email (move to trash)."""
    test_email = sample_emails[0]
    
    response = await client.delete(
        f"/api/v1/inbox/emails/{test_email.message_id}",
        params={"permanent": False},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify email moved to trash
    verify_response = await client.get(
        f"/api/v1/inbox/emails/{test_email.message_id}",
        headers=auth_headers
    )
    assert verify_response.json()["folder"] == "trash"


@pytest.mark.asyncio
async def test_restore_email(client: AsyncClient, auth_headers, sample_emails, test_db):
    """Test restoring email from trash."""
    test_email = sample_emails[0]
    
    # First move to trash
    test_email.folder = "trash"
    await test_email.save()
    
    # Restore
    response = await client.post(
        f"/api/v1/inbox/emails/{test_email.message_id}/restore",
        params={"target_folder": "inbox"},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify email restored
    verify_response = await client.get(
        f"/api/v1/inbox/emails/{test_email.message_id}",
        headers=auth_headers
    )
    assert verify_response.json()["folder"] == "inbox"


# ==================== Bulk Operation Tests ====================

@pytest.mark.asyncio
async def test_bulk_mark_read(client: AsyncClient, auth_headers, sample_emails):
    """Test bulk marking emails as read."""
    # Select first 5 unread emails
    message_ids = [e.message_id for e in sample_emails[1:6:2]]  # Odd indices = unread
    
    response = await client.post(
        "/api/v1/inbox/emails/bulk/read",
        json={"message_ids": message_ids},
        params={"is_read": True},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify all emails are marked as read
    for message_id in message_ids:
        verify_response = await client.get(
            f"/api/v1/inbox/emails/{message_id}",
            headers=auth_headers
        )
        assert verify_response.json()["is_read"] is True


@pytest.mark.asyncio
async def test_bulk_star(client: AsyncClient, auth_headers, sample_emails):
    """Test bulk starring emails."""
    message_ids = [e.message_id for e in sample_emails[:3]]
    
    response = await client.post(
        "/api/v1/inbox/emails/bulk/star",
        json={"message_ids": message_ids},
        params={"is_starred": True},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify all emails are starred
    for message_id in message_ids:
        verify_response = await client.get(
            f"/api/v1/inbox/emails/{message_id}",
            headers=auth_headers
        )
        assert verify_response.json()["is_starred"] is True


@pytest.mark.asyncio
async def test_bulk_move(client: AsyncClient, auth_headers, sample_emails):
    """Test bulk moving emails to folder."""
    message_ids = [e.message_id for e in sample_emails[:3]]
    
    response = await client.post(
        "/api/v1/inbox/emails/bulk/move",
        json={"message_ids": message_ids},
        params={"folder": "archive"},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify all emails moved
    for message_id in message_ids:
        verify_response = await client.get(
            f"/api/v1/inbox/emails/{message_id}",
            headers=auth_headers
        )
        assert verify_response.json()["folder"] == "archive"


@pytest.mark.asyncio
async def test_bulk_delete(client: AsyncClient, auth_headers, sample_emails):
    """Test bulk deleting emails."""
    message_ids = [e.message_id for e in sample_emails[:3]]
    
    response = await client.post(
        "/api/v1/inbox/emails/bulk/delete",
        json={"message_ids": message_ids},
        params={"permanent": False},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify all emails moved to trash
    for message_id in message_ids:
        verify_response = await client.get(
            f"/api/v1/inbox/emails/{message_id}",
            headers=auth_headers
        )
        assert verify_response.json()["folder"] == "trash"


@pytest.mark.asyncio
async def test_bulk_operation_limit(client: AsyncClient, auth_headers, sample_emails):
    """Test bulk operation respects 100 email limit."""
    # Try to process 101 emails
    message_ids = [f"msg_{i}" for i in range(101)]
    
    response = await client.post(
        "/api/v1/inbox/emails/bulk/read",
        json={"message_ids": message_ids},
        params={"is_read": True},
        headers=auth_headers
    )
    
    # Should return 400 Bad Request
    assert response.status_code == 400


# ==================== Search Tests ====================

@pytest.mark.asyncio
async def test_search_emails_basic(client: AsyncClient, auth_headers, sample_emails):
    """Test basic email search."""
    response = await client.get(
        "/api/v1/inbox/search",
        params={"q": "Test Email 5"},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert "emails" in data
    assert len(data["emails"]) > 0


@pytest.mark.asyncio
async def test_search_with_from_filter(client: AsyncClient, auth_headers, sample_emails):
    """Test search with from: filter."""
    response = await client.get(
        "/api/v1/inbox/search",
        params={"q": "from:sender0@example.com"},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # All results should be from specified sender
    for email in data["emails"]:
        assert email["sender"]["email"] == "sender0@example.com"


@pytest.mark.asyncio
async def test_search_with_subject_filter(client: AsyncClient, auth_headers, sample_emails):
    """Test search with subject: filter."""
    response = await client.get(
        "/api/v1/inbox/search",
        params={"q": "subject:Email 10"},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert len(data["emails"]) > 0
    for email in data["emails"]:
        assert "Email 10" in email["subject"]


@pytest.mark.asyncio
async def test_search_with_is_read_filter(client: AsyncClient, auth_headers, sample_emails):
    """Test search with is:read filter."""
    response = await client.get(
        "/api/v1/inbox/search",
        params={"q": "is:read"},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # All results should be read
    for email in data["emails"]:
        assert email["is_read"] is True


@pytest.mark.asyncio
async def test_search_with_has_attachment_filter(client: AsyncClient, auth_headers, sample_emails):
    """Test search with has:attachment filter."""
    response = await client.get(
        "/api/v1/inbox/search",
        params={"q": "has:attachment"},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # All results should have attachments
    for email in data["emails"]:
        assert email["has_attachment"] is True


# ==================== Folder & Stats Tests ====================

@pytest.mark.asyncio
async def test_get_folders(client: AsyncClient, auth_headers, sample_emails):
    """Test getting folder counts."""
    response = await client.get(
        "/api/v1/inbox/folders",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert isinstance(data, list)
    
    # Should have inbox folder
    inbox_folder = next((f for f in data if f["folder"] == "inbox"), None)
    assert inbox_folder is not None
    assert "total" in inbox_folder
    assert "unread" in inbox_folder


@pytest.mark.asyncio
async def test_get_stats(client: AsyncClient, auth_headers, sample_emails):
    """Test getting inbox statistics."""
    response = await client.get(
        "/api/v1/inbox/stats",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert "total_emails" in data
    assert "unread_count" in data
    assert "starred_count" in data


# ==================== Label Tests ====================

@pytest.mark.asyncio
async def test_get_labels(client: AsyncClient, auth_headers, sample_labels):
    """Test getting user labels."""
    response = await client.get(
        "/api/v1/inbox/labels",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert isinstance(data, list)
    assert len(data) == 3  # We created 3 labels in fixture


@pytest.mark.asyncio
async def test_create_label(client: AsyncClient, auth_headers):
    """Test creating new label."""
    response = await client.post(
        "/api/v1/inbox/labels",
        json={
            "name": "Important",
            "color": "#FF9800"
        },
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["name"] == "Important"
    assert data["color"] == "#FF9800"
    assert "label_id" in data


@pytest.mark.asyncio
async def test_create_nested_label(client: AsyncClient, auth_headers, sample_labels):
    """Test creating nested label."""
    parent_label = sample_labels[0]
    
    response = await client.post(
        "/api/v1/inbox/labels",
        json={
            "name": "Meetings",
            "color": "#9C27B0",
            "parent_label_id": parent_label.label_id
        },
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["name"] == "Meetings"
    assert data["parent_label_id"] == parent_label.label_id


@pytest.mark.asyncio
async def test_update_label(client: AsyncClient, auth_headers, sample_labels):
    """Test updating label."""
    label = sample_labels[0]
    
    response = await client.patch(
        f"/api/v1/inbox/labels/{label.label_id}",
        json={"name": "Work Updated", "color": "#00FF00"},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["name"] == "Work Updated"
    assert data["color"] == "#00FF00"


@pytest.mark.asyncio
async def test_delete_label(client: AsyncClient, auth_headers, sample_labels):
    """Test deleting label."""
    label = sample_labels[1]
    
    response = await client.delete(
        f"/api/v1/inbox/labels/{label.label_id}",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    
    # Verify label deleted
    verify_response = await client.get(
        "/api/v1/inbox/labels",
        headers=auth_headers
    )
    labels = verify_response.json()
    assert not any(l["label_id"] == label.label_id for l in labels)


# ==================== Error Handling Tests ====================

@pytest.mark.asyncio
async def test_unauthorized_request(client: AsyncClient):
    """Test request without authentication returns 401."""
    response = await client.get("/api/v1/inbox/emails")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_invalid_folder_parameter(client: AsyncClient, auth_headers):
    """Test invalid folder parameter returns 400."""
    response = await client.get(
        "/api/v1/inbox/emails",
        params={"folder": "invalid_folder"},
        headers=auth_headers
    )
    
    # Should either return 400 or empty list
    assert response.status_code in [200, 400]


@pytest.mark.asyncio
async def test_invalid_cursor(client: AsyncClient, auth_headers):
    """Test invalid cursor parameter returns 400."""
    response = await client.get(
        "/api/v1/inbox/emails",
        params={"cursor": "invalid_cursor_format"},
        headers=auth_headers
    )
    
    assert response.status_code == 400
