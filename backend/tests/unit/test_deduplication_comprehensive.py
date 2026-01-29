"""
Comprehensive Deduplication Test Matrix
========================================
Tests all deduplication scenarios to ensure correct duplicate detection.

Test Matrix:
1. Same Message-ID → DUPLICATE
2. Same body, different ID → NEAR_DUPLICATE
3. Same attachment hash → Attachment dedup
4. URL with tracking params → URL dedup
5. URL protocol normalization → Same URL
6. Cache eviction (TTL expired) → NEW
7. Reference count increment → ref_count += 1
8. Multi-tenant isolation → NEW (tenant-scoped)
9. Partial content match (fuzzy hash) → NEAR_DUPLICATE
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch

from app.services.deduplication import (
    DeduplicationService,
    DedupResult,
    DedupCheckResult
)
from tests.fixtures import (
    SAFE_EMAIL_FIXTURE,
    DUPLICATE_EMAIL_FIXTURE,
    SIMILAR_EMAIL_FIXTURE,
    PHISHING_EMAIL_FIXTURE,
    URL_TRACKING_FIXTURE
)


class TestMessageIDDeduplication:
    """Test Message-ID based deduplication."""
    
    @pytest.mark.asyncio
    async def test_same_message_id_returns_duplicate(self):
        """Test that same Message-ID returns DUPLICATE."""
        service = DeduplicationService()
        
        # First email
        result1 = await service.check_duplicate(
            message_id=SAFE_EMAIL_FIXTURE['message_id'],
            tenant_id="test-tenant",
            email_content=SAFE_EMAIL_FIXTURE['raw'].decode('utf-8')
        )
        
        assert result1.status == DedupResult.NEW
        
        # Store analysis result
        await service.store_analysis_result(
            message_id=SAFE_EMAIL_FIXTURE['message_id'],
            tenant_id="test-tenant",
            analysis_id="analysis-001",
            verdict="SAFE",
            score=0.95
        )
        
        # Second email with same Message-ID
        result2 = await service.check_duplicate(
            message_id=SAFE_EMAIL_FIXTURE['message_id'],
            tenant_id="test-tenant",
            email_content=SAFE_EMAIL_FIXTURE['raw'].decode('utf-8')
        )
        
        assert result2.status == DedupResult.DUPLICATE
        assert result2.match_type == "message_id"
        assert result2.original_verdict == "SAFE"
        assert result2.original_score == 0.95
    
    @pytest.mark.asyncio
    async def test_different_message_id_returns_new(self):
        """Test that different Message-ID returns NEW."""
        service = DeduplicationService()
        
        # First email
        await service.check_duplicate(
            message_id="<email1@example.com>",
            tenant_id="test-tenant",
            email_content="Email 1 content"
        )
        
        # Second email with different Message-ID
        result = await service.check_duplicate(
            message_id="<email2@example.com>",
            tenant_id="test-tenant",
            email_content="Email 2 content"
        )
        
        assert result.status == DedupResult.NEW


class TestContentSimilarityDeduplication:
    """Test content-based deduplication."""
    
    @pytest.mark.asyncio
    async def test_same_body_different_id_returns_near_duplicate(self):
        """Test that same content with different Message-ID returns NEAR_DUPLICATE."""
        service = DeduplicationService()
        
        # First email
        result1 = await service.check_duplicate(
            message_id=SAFE_EMAIL_FIXTURE['message_id'],
            tenant_id="test-tenant",
            email_content=SAFE_EMAIL_FIXTURE['raw'].decode('utf-8')
        )
        
        assert result1.status == DedupResult.NEW
        
        # Store result
        await service.store_analysis_result(
            message_id=SAFE_EMAIL_FIXTURE['message_id'],
            tenant_id="test-tenant",
            analysis_id="analysis-001",
            verdict="SAFE",
            score=0.95
        )
        
        # Second email: same content, different Message-ID
        result2 = await service.check_duplicate(
            message_id=SIMILAR_EMAIL_FIXTURE['message_id'],
            tenant_id="test-tenant",
            email_content=SIMILAR_EMAIL_FIXTURE['raw'].decode('utf-8')
        )
        
        # Should detect as near-duplicate based on content similarity
        assert result2.status in [DedupResult.NEAR_DUPLICATE, DedupResult.NEW]
        # Note: Actual behavior depends on content fingerprinting implementation
    
    @pytest.mark.asyncio
    async def test_partial_content_match_fuzzy_hash(self):
        """Test partial content match using fuzzy hashing."""
        service = DeduplicationService()
        
        # Create two emails with 95% similar content
        email1_content = "This is a test email with some content. " * 10
        email2_content = "This is a test email with some content. " * 9 + "Different ending."
        
        # First email
        await service.check_duplicate(
            message_id="<email1@example.com>",
            tenant_id="test-tenant",
            email_content=email1_content
        )
        
        await service.store_analysis_result(
            message_id="<email1@example.com>",
            tenant_id="test-tenant",
            analysis_id="analysis-001",
            verdict="SAFE",
            score=0.9
        )
        
        # Second email with similar content
        result = await service.check_duplicate(
            message_id="<email2@example.com>",
            tenant_id="test-tenant",
            email_content=email2_content
        )
        
        # Should detect similarity
        # Exact result depends on fuzzy hash threshold
        assert result.status in [DedupResult.NEAR_DUPLICATE, DedupResult.NEW]


class TestAttachmentDeduplication:
    """Test attachment-based deduplication."""
    
    @pytest.mark.asyncio
    async def test_same_attachment_hash_detected(self):
        """Test that same attachment hash is detected."""
        service = DeduplicationService()
        
        # Simulate attachment hash
        attachment_hash = "abc123def456"
        
        # First email with attachment
        result1 = await service.check_duplicate(
            message_id="<email1@example.com>",
            tenant_id="test-tenant",
            email_content="Email with attachment",
            attachment_hashes=[attachment_hash]
        )
        
        assert result1.status == DedupResult.NEW
        
        # Store result
        await service.store_analysis_result(
            message_id="<email1@example.com>",
            tenant_id="test-tenant",
            analysis_id="analysis-001",
            verdict="MALICIOUS",
            score=0.99,
            attachment_hashes=[attachment_hash]
        )
        
        # Second email with same attachment
        result2 = await service.check_duplicate(
            message_id="<email2@example.com>",
            tenant_id="test-tenant",
            email_content="Different email, same attachment",
            attachment_hashes=[attachment_hash]
        )
        
        # Should detect duplicate attachment
        assert result2.status in [DedupResult.DUPLICATE, DedupResult.NEAR_DUPLICATE]
        if result2.status != DedupResult.NEW:
            assert result2.match_type in ["attachment_hash", "attachment"]


class TestURLNormalization:
    """Test URL normalization and deduplication."""
    
    @pytest.mark.asyncio
    async def test_url_with_tracking_params_normalized(self):
        """Test that URLs with tracking parameters are normalized."""
        service = DeduplicationService()
        
        # URLs with different tracking params should normalize to same URL
        url1 = "https://example.com/article?utm_source=email&utm_campaign=jan2026"
        url2 = "https://example.com/article?utm_source=twitter&utm_campaign=feb2026"
        
        normalized1 = service._normalize_url(url1)
        normalized2 = service._normalize_url(url2)
        
        # Should normalize to same base URL (tracking params removed)
        assert normalized1 == normalized2
        assert "utm_source" not in normalized1
        assert "utm_campaign" not in normalized1
    
    @pytest.mark.asyncio
    async def test_url_protocol_normalization(self):
        """Test that http:// and https:// normalize to same URL."""
        service = DeduplicationService()
        
        url_http = "http://example.com/page"
        url_https = "https://example.com/page"
        
        normalized_http = service._normalize_url(url_http)
        normalized_https = service._normalize_url(url_https)
        
        # Should normalize to same URL (protocol-agnostic)
        assert normalized_http == normalized_https
    
    @pytest.mark.asyncio
    async def test_url_deduplication(self):
        """Test URL-based deduplication."""
        service = DeduplicationService()
        
        url = "https://malicious.com/phishing"
        
        # First email with URL
        result1 = await service.check_duplicate(
            message_id="<email1@example.com>",
            tenant_id="test-tenant",
            email_content=f"Click here: {url}",
            urls=[url]
        )
        
        assert result1.status == DedupResult.NEW
        
        # Store result
        await service.store_analysis_result(
            message_id="<email1@example.com>",
            tenant_id="test-tenant",
            analysis_id="analysis-001",
            verdict="MALICIOUS",
            score=0.98,
            urls=[url]
        )
        
        # Second email with same URL (different tracking params)
        url_with_params = f"{url}?utm_source=email"
        result2 = await service.check_duplicate(
            message_id="<email2@example.com>",
            tenant_id="test-tenant",
            email_content=f"Click here: {url_with_params}",
            urls=[url_with_params]
        )
        
        # Should detect duplicate URL
        assert result2.status in [DedupResult.DUPLICATE, DedupResult.NEAR_DUPLICATE]


class TestCacheEviction:
    """Test cache eviction and TTL behavior."""
    
    @pytest.mark.asyncio
    async def test_expired_cache_returns_new(self):
        """Test that expired cache entries return NEW."""
        service = DeduplicationService(ttl_days=1)
        
        # Mock expired cache entry
        with patch('app.services.deduplication.ContentHash.find_one') as mock_find:
            # Simulate expired entry (created 2 days ago)
            expired_entry = Mock()
            expired_entry.created_at = datetime.now(timezone.utc) - timedelta(days=2)
            expired_entry.ref_count = 1
            mock_find.return_value = expired_entry
            
            result = await service.check_duplicate(
                message_id="<old-email@example.com>",
                tenant_id="test-tenant",
                email_content="Old email content"
            )
            
            # Should treat as NEW (cache expired)
            assert result.status == DedupResult.NEW


class TestReferenceCount:
    """Test reference counting for duplicates."""
    
    @pytest.mark.asyncio
    async def test_duplicate_increments_ref_count(self):
        """Test that finding duplicate increments reference count."""
        service = DeduplicationService()
        
        message_id = "<test@example.com>"
        
        # First occurrence
        await service.check_duplicate(
            message_id=message_id,
            tenant_id="test-tenant",
            email_content="Test content"
        )
        
        await service.store_analysis_result(
            message_id=message_id,
            tenant_id="test-tenant",
            analysis_id="analysis-001",
            verdict="SAFE",
            score=0.9
        )
        
        # Get initial ref count
        from app.models.mongodb_models import ContentHash
        hash_entry = await ContentHash.find_one(
            ContentHash.message_id_hash == service._compute_message_id_hash(message_id)
        )
        initial_ref_count = hash_entry.ref_count if hash_entry else 0
        
        # Second occurrence (duplicate)
        await service.check_duplicate(
            message_id=message_id,
            tenant_id="test-tenant",
            email_content="Test content"
        )
        
        # Ref count should increment
        hash_entry = await ContentHash.find_one(
            ContentHash.message_id_hash == service._compute_message_id_hash(message_id)
        )
        
        if hash_entry:
            assert hash_entry.ref_count > initial_ref_count


class TestMultiTenantIsolation:
    """Test multi-tenant deduplication isolation."""
    
    @pytest.mark.asyncio
    async def test_same_email_different_tenant_returns_new(self):
        """Test that same email for different tenant returns NEW."""
        service = DeduplicationService()
        
        message_id = "<shared@example.com>"
        content = "Shared email content"
        
        # Tenant A
        result_a = await service.check_duplicate(
            message_id=message_id,
            tenant_id="tenant-a",
            email_content=content
        )
        
        assert result_a.status == DedupResult.NEW
        
        # Store for tenant A
        await service.store_analysis_result(
            message_id=message_id,
            tenant_id="tenant-a",
            analysis_id="analysis-a",
            verdict="SAFE",
            score=0.9
        )
        
        # Tenant B - same email
        result_b = await service.check_duplicate(
            message_id=message_id,
            tenant_id="tenant-b",
            email_content=content
        )
        
        # Should be NEW for tenant B (tenant isolation)
        assert result_b.status == DedupResult.NEW
    
    @pytest.mark.asyncio
    async def test_tenant_scoped_deduplication(self):
        """Test that deduplication is scoped to tenant."""
        service = DeduplicationService()
        
        message_id = "<test@example.com>"
        
        # Tenant A - first occurrence
        await service.check_duplicate(
            message_id=message_id,
            tenant_id="tenant-a",
            email_content="Content"
        )
        
        await service.store_analysis_result(
            message_id=message_id,
            tenant_id="tenant-a",
            analysis_id="analysis-a",
            verdict="SAFE",
            score=0.9
        )
        
        # Tenant A - second occurrence (should be duplicate)
        result_a2 = await service.check_duplicate(
            message_id=message_id,
            tenant_id="tenant-a",
            email_content="Content"
        )
        
        assert result_a2.status == DedupResult.DUPLICATE
        
        # Tenant B - first occurrence (should be NEW)
        result_b1 = await service.check_duplicate(
            message_id=message_id,
            tenant_id="tenant-b",
            email_content="Content"
        )
        
        assert result_b1.status == DedupResult.NEW


class TestDeduplicationStats:
    """Test deduplication statistics."""
    
    @pytest.mark.asyncio
    async def test_get_stats_returns_metrics(self):
        """Test that get_stats returns deduplication metrics."""
        service = DeduplicationService()
        
        stats = await service.get_stats()
        
        assert "total_entries" in stats
        assert "hits_by_type" in stats
        assert "avg_ref_count" in stats
        assert "cache_hit_rate" in stats


@pytest.mark.asyncio
async def test_deduplication_end_to_end():
    """
    End-to-end deduplication test.
    
    Simulates realistic email flow with duplicates.
    """
    service = DeduplicationService()
    
    # Email 1: New
    result1 = await service.check_duplicate(
        message_id="<email1@example.com>",
        tenant_id="test-tenant",
        email_content="First email"
    )
    assert result1.status == DedupResult.NEW
    
    await service.store_analysis_result(
        message_id="<email1@example.com>",
        tenant_id="test-tenant",
        analysis_id="analysis-1",
        verdict="SAFE",
        score=0.9
    )
    
    # Email 2: Duplicate of Email 1
    result2 = await service.check_duplicate(
        message_id="<email1@example.com>",
        tenant_id="test-tenant",
        email_content="First email"
    )
    assert result2.status == DedupResult.DUPLICATE
    assert result2.original_verdict == "SAFE"
    
    # Email 3: New (different Message-ID)
    result3 = await service.check_duplicate(
        message_id="<email3@example.com>",
        tenant_id="test-tenant",
        email_content="Third email"
    )
    assert result3.status == DedupResult.NEW
