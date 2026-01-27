"""
Enterprise Deduplication Service
================================
Prevents re-analysis of identical content to save:
- API quota (VirusTotal, Gemini)
- Compute resources
- Latency

Hash-based deduplication on:
1. Message-ID (primary key)
2. Attachment hashes (SHA-256)
3. URL hashes (normalized)
4. Content fingerprint (simhash for near-duplicates)

Enterprise pattern: Check before analyze, cache results.
"""

import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from beanie import Document, Indexed
from pydantic import Field
from pymongo import IndexModel, ASCENDING

from app.config.logging import get_logger

logger = get_logger(__name__)


class DedupResult(str, Enum):
    """Result of deduplication check"""
    NEW = "new"                    # Never seen, process it
    DUPLICATE = "duplicate"        # Exact match, reuse result
    NEAR_DUPLICATE = "near_dup"    # Similar content, may reuse


@dataclass
class DedupCheckResult:
    """Result of a deduplication check"""
    status: DedupResult
    original_analysis_id: Optional[str] = None
    original_verdict: Optional[str] = None
    original_score: Optional[float] = None
    match_type: Optional[str] = None  # message_id, attachment_hash, url_hash, content_fingerprint
    cached_at: Optional[datetime] = None


class ContentHash(Document):
    """
    Stores content hashes for deduplication.
    
    Indexes:
    - message_id_hash: For exact email matching
    - attachment_hash: For file-based matching
    - url_hash: For link-based matching
    - content_fingerprint: For near-duplicate detection
    """
    # Hash identifiers
    message_id_hash: Optional[Indexed(str)] = None
    attachment_hashes: List[str] = Field(default_factory=list)
    url_hashes: List[str] = Field(default_factory=list)
    content_fingerprint: Optional[str] = None
    
    # Original analysis reference
    analysis_id: Indexed(str)
    tenant_id: Optional[str] = None
    
    # Cached verdict (to avoid DB lookup)
    verdict: str
    score: float
    confidence: float
    
    # Metadata
    original_subject: Optional[str] = None
    original_sender: Optional[str] = None
    
    # Reference counting
    reference_count: int = 1
    
    # Timestamps
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Settings:
        name = "content_hashes"
        indexes = [
            IndexModel([("message_id_hash", ASCENDING)]),
            IndexModel([("attachment_hashes", ASCENDING)]),
            IndexModel([("url_hashes", ASCENDING)]),
            IndexModel([("content_fingerprint", ASCENDING)]),
            IndexModel([("analysis_id", ASCENDING)]),
            IndexModel([("tenant_id", ASCENDING)]),
            # TTL index for automatic cleanup (90 days)
            IndexModel([("last_seen", ASCENDING)], expireAfterSeconds=90*24*60*60),
        ]


class DeduplicationService:
    """
    Enterprise-grade deduplication service.
    
    Usage:
        dedup = DeduplicationService()
        result = await dedup.check(message_id, attachments, urls)
        if result.status == DedupResult.DUPLICATE:
            return cached_result
        else:
            # Proceed with analysis
            ...
            await dedup.store(...)
    """
    
    def __init__(self, cache_ttl_days: int = 90):
        self.cache_ttl = timedelta(days=cache_ttl_days)
    
    # ═══════════════════════════════════════════════════════════════════════
    # HASH COMPUTATION
    # ═══════════════════════════════════════════════════════════════════════
    
    def hash_message_id(self, message_id: str) -> str:
        """Hash Message-ID header for dedup lookup"""
        if not message_id:
            return ""
        # Normalize: strip whitespace, angle brackets
        normalized = message_id.strip().strip('<>').lower()
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def hash_attachment(self, content: bytes) -> str:
        """Compute SHA-256 of attachment content"""
        return hashlib.sha256(content).hexdigest()
    
    def hash_url(self, url: str) -> str:
        """
        Hash normalized URL.
        
        Normalization:
        - Lowercase scheme and host
        - Sort query parameters
        - Remove tracking parameters (utm_*, fbclid, etc.)
        """
        try:
            parsed = urlparse(url)
            
            # Normalize components
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path.rstrip('/')
            
            # Sort and filter query params
            params = parse_qsl(parsed.query)
            tracking_params = {'utm_source', 'utm_medium', 'utm_campaign', 
                              'utm_term', 'utm_content', 'fbclid', 'gclid'}
            filtered_params = [(k, v) for k, v in params if k.lower() not in tracking_params]
            sorted_params = sorted(filtered_params)
            query = urlencode(sorted_params)
            
            # Reconstruct
            normalized = urlunparse((scheme, netloc, path, '', query, ''))
            return hashlib.sha256(normalized.encode()).hexdigest()
            
        except Exception:
            # Fallback to raw hash
            return hashlib.sha256(url.encode()).hexdigest()
    
    def compute_content_fingerprint(self, text: str) -> str:
        """
        Compute simhash-like fingerprint for near-duplicate detection.
        
        This is a simplified implementation. For production, consider:
        - SimHash with n-grams
        - MinHash for set similarity
        - LSH (Locality Sensitive Hashing)
        """
        if not text:
            return ""
        
        # Normalize text
        normalized = ' '.join(text.lower().split())
        
        # Simple fingerprint: hash of sorted words (not production-grade)
        words = sorted(set(normalized.split()))
        fingerprint = ' '.join(words[:100])  # Top 100 unique words
        return hashlib.sha256(fingerprint.encode()).hexdigest()
    
    # ═══════════════════════════════════════════════════════════════════════
    # DEDUPLICATION CHECK
    # ═══════════════════════════════════════════════════════════════════════
    
    async def check(
        self,
        message_id: Optional[str] = None,
        attachments: Optional[List[bytes]] = None,
        urls: Optional[List[str]] = None,
        content: Optional[str] = None,
        tenant_id: Optional[str] = None
    ) -> DedupCheckResult:
        """
        Check if this content has been analyzed before.
        
        Priority order:
        1. Message-ID (exact email match)
        2. Attachment hash (same file)
        3. URL hash (same link)
        4. Content fingerprint (similar body)
        
        Args:
            message_id: Email Message-ID header
            attachments: List of attachment bytes
            urls: List of URLs from email
            content: Email body text
            tenant_id: Optional tenant for scoping
        
        Returns:
            DedupCheckResult with status and cached data
        """
        # 1. Check Message-ID (strongest match)
        if message_id:
            msg_hash = self.hash_message_id(message_id)
            existing = await ContentHash.find_one(
                ContentHash.message_id_hash == msg_hash
            )
            if existing:
                # Update reference counter and last_seen
                existing.reference_count += 1
                existing.last_seen = datetime.now(timezone.utc)
                await existing.save()
                
                logger.info(f"Dedup: Message-ID match found (refs: {existing.reference_count})")
                return DedupCheckResult(
                    status=DedupResult.DUPLICATE,
                    original_analysis_id=existing.analysis_id,
                    original_verdict=existing.verdict,
                    original_score=existing.score,
                    match_type="message_id",
                    cached_at=existing.first_seen
                )
        
        # 2. Check attachment hashes
        if attachments:
            for att_content in attachments:
                att_hash = self.hash_attachment(att_content)
                existing = await ContentHash.find_one(
                    {"attachment_hashes": att_hash}
                )
                if existing:
                    existing.reference_count += 1
                    existing.last_seen = datetime.now(timezone.utc)
                    await existing.save()
                    
                    logger.info(f"Dedup: Attachment hash match found")
                    return DedupCheckResult(
                        status=DedupResult.DUPLICATE,
                        original_analysis_id=existing.analysis_id,
                        original_verdict=existing.verdict,
                        original_score=existing.score,
                        match_type="attachment_hash",
                        cached_at=existing.first_seen
                    )
        
        # 3. Check URL hashes (all URLs must match for duplicate)
        if urls and len(urls) > 0:
            url_hashes = [self.hash_url(u) for u in urls]
            # Find any document that has ALL these URL hashes
            existing = await ContentHash.find_one({
                "url_hashes": {"$all": url_hashes}
            })
            if existing:
                existing.reference_count += 1
                existing.last_seen = datetime.now(timezone.utc)
                await existing.save()
                
                logger.info(f"Dedup: URL set match found")
                return DedupCheckResult(
                    status=DedupResult.DUPLICATE,
                    original_analysis_id=existing.analysis_id,
                    original_verdict=existing.verdict,
                    original_score=existing.score,
                    match_type="url_hash",
                    cached_at=existing.first_seen
                )
        
        # 4. Check content fingerprint (near-duplicate)
        if content:
            fingerprint = self.compute_content_fingerprint(content)
            existing = await ContentHash.find_one(
                ContentHash.content_fingerprint == fingerprint
            )
            if existing:
                existing.reference_count += 1
                existing.last_seen = datetime.now(timezone.utc)
                await existing.save()
                
                logger.info(f"Dedup: Content fingerprint match (near-duplicate)")
                return DedupCheckResult(
                    status=DedupResult.NEAR_DUPLICATE,
                    original_analysis_id=existing.analysis_id,
                    original_verdict=existing.verdict,
                    original_score=existing.score,
                    match_type="content_fingerprint",
                    cached_at=existing.first_seen
                )
        
        # No match found
        return DedupCheckResult(status=DedupResult.NEW)
    
    # ═══════════════════════════════════════════════════════════════════════
    # STORE ANALYSIS FOR FUTURE DEDUP
    # ═══════════════════════════════════════════════════════════════════════
    
    async def store(
        self,
        analysis_id: str,
        verdict: str,
        score: float,
        confidence: float,
        message_id: Optional[str] = None,
        attachments: Optional[List[bytes]] = None,
        urls: Optional[List[str]] = None,
        content: Optional[str] = None,
        tenant_id: Optional[str] = None,
        subject: Optional[str] = None,
        sender: Optional[str] = None
    ) -> ContentHash:
        """
        Store content hashes after successful analysis.
        
        Args:
            analysis_id: ID of the completed analysis
            verdict: Final verdict (SAFE/SUSPICIOUS/PHISHING)
            score: Numeric score (0-100)
            confidence: Confidence level (0-1)
            message_id: Email Message-ID
            attachments: List of attachment bytes
            urls: List of extracted URLs
            content: Email body text
            tenant_id: Tenant identifier
            subject: Email subject
            sender: Email sender
        
        Returns:
            Created ContentHash document
        """
        # Compute all hashes
        msg_hash = self.hash_message_id(message_id) if message_id else None
        att_hashes = [self.hash_attachment(a) for a in (attachments or [])]
        url_hashes = [self.hash_url(u) for u in (urls or [])]
        fingerprint = self.compute_content_fingerprint(content) if content else None
        
        # Create document
        doc = ContentHash(
            message_id_hash=msg_hash,
            attachment_hashes=att_hashes,
            url_hashes=url_hashes,
            content_fingerprint=fingerprint,
            analysis_id=analysis_id,
            tenant_id=tenant_id,
            verdict=verdict,
            score=score,
            confidence=confidence,
            original_subject=subject,
            original_sender=sender
        )
        
        await doc.save()
        logger.info(f"Dedup: Stored hashes for analysis {analysis_id}")
        
        return doc
    
    # ═══════════════════════════════════════════════════════════════════════
    # STATISTICS
    # ═══════════════════════════════════════════════════════════════════════
    
    async def get_stats(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Get deduplication statistics"""
        query = {}
        if tenant_id:
            query["tenant_id"] = tenant_id
        
        total = await ContentHash.find(query).count()
        
        # Count by verdict
        phishing = await ContentHash.find({**query, "verdict": "PHISHING"}).count()
        suspicious = await ContentHash.find({**query, "verdict": "SUSPICIOUS"}).count()
        safe = await ContentHash.find({**query, "verdict": "SAFE"}).count()
        
        # Total references (dedup hits)
        pipeline = [
            {"$match": query},
            {"$group": {"_id": None, "total_refs": {"$sum": "$reference_count"}}}
        ]
        ref_result = await ContentHash.aggregate(pipeline).to_list()
        total_refs = ref_result[0]["total_refs"] if ref_result else 0
        
        return {
            "total_entries": total,
            "by_verdict": {
                "phishing": phishing,
                "suspicious": suspicious,
                "safe": safe
            },
            "total_references": total_refs,
            "dedup_savings": total_refs - total if total_refs > total else 0
        }


# Singleton instance
_dedup_service: Optional[DeduplicationService] = None


def get_deduplication_service() -> DeduplicationService:
    """Get singleton deduplication service"""
    global _dedup_service
    if _dedup_service is None:
        _dedup_service = DeduplicationService()
    return _dedup_service
