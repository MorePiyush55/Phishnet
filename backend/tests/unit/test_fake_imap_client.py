"""
Test Fake IMAP Client
======================
Tests for FakeIMAPClient to ensure it behaves correctly.
"""

import pytest
from tests.fixtures import (
    FakeIMAPClient,
    get_default_mailbox_fixture,
    SAFE_EMAIL_FIXTURE,
    PHISHING_EMAIL_FIXTURE
)


class TestFakeIMAPClient:
    """Test suite for FakeIMAPClient."""
    
    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful connection."""
        client = FakeIMAPClient()
        
        connected = await client.connect()
        
        assert connected is True
        assert client.is_connected() is True
        assert client.connect_count == 1
    
    @pytest.mark.asyncio
    async def test_connect_failure(self):
        """Test connection failure simulation."""
        client = FakeIMAPClient(simulate_connection_failure=True)
        
        connected = await client.connect()
        
        assert connected is False
        assert client.is_connected() is False
    
    @pytest.mark.asyncio
    async def test_get_recent_emails(self):
        """Test fetching recent emails."""
        fixture = get_default_mailbox_fixture()
        client = FakeIMAPClient(mailbox_fixture=fixture)
        
        await client.connect()
        emails = await client.get_recent_emails(limit=10)
        
        assert len(emails) == 3  # Default fixture has 3 emails
        assert client.fetch_count == 1
    
    @pytest.mark.asyncio
    async def test_get_recent_emails_with_limit(self):
        """Test fetching with limit."""
        fixture = get_default_mailbox_fixture()
        client = FakeIMAPClient(mailbox_fixture=fixture)
        
        await client.connect()
        emails = await client.get_recent_emails(limit=2)
        
        assert len(emails) == 2
    
    @pytest.mark.asyncio
    async def test_mark_as_read(self):
        """Test marking email as read."""
        fixture = [SAFE_EMAIL_FIXTURE]
        client = FakeIMAPClient(mailbox_fixture=fixture)
        
        await client.connect()
        
        # Initially 1 unread
        assert client.get_unread_count() == 1
        
        # Mark as read
        success = await client.mark_as_read('1001')
        
        assert success is True
        assert client.get_unread_count() == 0
        assert client.mark_read_count == 1
    
    @pytest.mark.asyncio
    async def test_get_recent_excludes_read_emails(self):
        """Test that get_recent_emails excludes read emails."""
        fixture = get_default_mailbox_fixture()
        client = FakeIMAPClient(mailbox_fixture=fixture)
        
        await client.connect()
        
        # Fetch all emails
        emails = await client.get_recent_emails()
        assert len(emails) == 3
        
        # Mark one as read
        await client.mark_as_read('1001')
        
        # Fetch again - should exclude read email
        emails = await client.get_recent_emails()
        assert len(emails) == 2
        assert all(e['uid'] != '1001' for e in emails)
    
    @pytest.mark.asyncio
    async def test_delete_email(self):
        """Test deleting email."""
        fixture = [SAFE_EMAIL_FIXTURE]
        client = FakeIMAPClient(mailbox_fixture=fixture)
        
        await client.connect()
        
        # Delete email
        success = await client.delete_email('1001')
        
        assert success is True
        assert '1001' in client.deleted_uids
        
        # Deleted email should not appear in recent
        emails = await client.get_recent_emails()
        assert len(emails) == 0
    
    @pytest.mark.asyncio
    async def test_move_to_folder(self):
        """Test moving email to folder."""
        fixture = [SAFE_EMAIL_FIXTURE]
        client = FakeIMAPClient(mailbox_fixture=fixture)
        
        await client.connect()
        
        # Move email
        success = await client.move_to_folder('1001', 'Archive')
        
        assert success is True
        assert client.moved_emails['1001'] == 'Archive'
    
    @pytest.mark.asyncio
    async def test_fetch_failure_simulation(self):
        """Test fetch failure simulation."""
        client = FakeIMAPClient(simulate_fetch_failure=True)
        
        await client.connect()
        
        with pytest.raises(RuntimeError, match="Simulated IMAP fetch failure"):
            await client.get_recent_emails()
    
    @pytest.mark.asyncio
    async def test_not_connected_error(self):
        """Test operations without connection raise error."""
        client = FakeIMAPClient()
        
        with pytest.raises(RuntimeError, match="IMAP client not connected"):
            await client.get_recent_emails()
    
    @pytest.mark.asyncio
    async def test_reset(self):
        """Test reset helper method."""
        fixture = get_default_mailbox_fixture()
        client = FakeIMAPClient(mailbox_fixture=fixture)
        
        await client.connect()
        await client.mark_as_read('1001')
        await client.delete_email('1002')
        
        # Reset
        client.reset()
        
        assert len(client.read_uids) == 0
        assert len(client.deleted_uids) == 0
        assert client.connect_count == 0
        assert client.fetch_count == 0
    
    @pytest.mark.asyncio
    async def test_add_email_helper(self):
        """Test add_email helper method."""
        client = FakeIMAPClient(mailbox_fixture=[])
        
        await client.connect()
        
        # Initially empty
        emails = await client.get_recent_emails()
        assert len(emails) == 0
        
        # Add email
        client.add_email(SAFE_EMAIL_FIXTURE)
        
        # Now has 1 email
        emails = await client.get_recent_emails()
        assert len(emails) == 1


@pytest.mark.asyncio
async def test_deterministic_behavior():
    """
    Test that FakeIMAPClient provides deterministic behavior.
    
    This is critical for reliable testing - same fixture should
    always produce same results.
    """
    fixture = get_default_mailbox_fixture()
    
    # Create two clients with same fixture
    client1 = FakeIMAPClient(mailbox_fixture=fixture)
    client2 = FakeIMAPClient(mailbox_fixture=fixture)
    
    await client1.connect()
    await client2.connect()
    
    # Both should return same emails
    emails1 = await client1.get_recent_emails()
    emails2 = await client2.get_recent_emails()
    
    assert len(emails1) == len(emails2)
    assert [e['uid'] for e in emails1] == [e['uid'] for e in emails2]


@pytest.mark.asyncio
async def test_no_network_calls():
    """
    Test that FakeIMAPClient makes no network calls.
    
    This test should complete instantly (< 100ms) proving
    no network I/O is happening.
    """
    import time
    
    fixture = get_default_mailbox_fixture()
    client = FakeIMAPClient(mailbox_fixture=fixture)
    
    start = time.time()
    
    await client.connect()
    emails = await client.get_recent_emails()
    await client.mark_as_read(emails[0]['uid'])
    await client.disconnect()
    
    elapsed = time.time() - start
    
    # Should complete in under 100ms (no network calls)
    assert elapsed < 0.1, f"Took {elapsed}s - likely making network calls!"
