"""
Service Unit Tests for Inbox System

Tests business logic in service layer including:
- Threading service (thread ID generation, subject normalization)
- Search service (query parsing, filter application)
- Label service (validation, nesting)
"""

import pytest
from datetime import datetime, timezone, timedelta

from app.services.inbox_service import ThreadingService, SearchService, LabelService
from app.models.inbox_models import EmailParticipant


# ==================== Threading Service Tests ====================

class TestThreadingService:
    """Tests for email threading logic."""
    
    def test_normalize_subject_basic(self):
        """Test basic subject normalization."""
        assert ThreadingService.normalize_subject("Hello World") == "hello world"
        assert ThreadingService.normalize_subject("HELLO WORLD") == "hello world"
    
    def test_normalize_subject_with_re(self):
        """Test normalization removes Re: prefix."""
        assert ThreadingService.normalize_subject("Re: Meeting") == "meeting"
        assert ThreadingService.normalize_subject("RE: Meeting") == "meeting"
        assert ThreadingService.normalize_subject("re: Meeting") == "meeting"
    
    def test_normalize_subject_with_fwd(self):
        """Test normalization removes Fwd: prefix."""
        assert ThreadingService.normalize_subject("Fwd: Report") == "report"
        assert ThreadingService.normalize_subject("FWD: Report") == "report"
        assert ThreadingService.normalize_subject("fwd: Report") == "report"
    
    def test_normalize_subject_with_multiple_prefixes(self):
        """Test normalization removes multiple prefixes."""
        assert ThreadingService.normalize_subject("Re: Fwd: Meeting") == "meeting"
        assert ThreadingService.normalize_subject("Fwd: Re: Report") == "report"
        assert ThreadingService.normalize_subject("Re: Re: Re: Hello") == "hello"
    
    def test_normalize_subject_with_brackets(self):
        """Test normalization removes bracketed prefixes."""
        assert ThreadingService.normalize_subject("[EXTERNAL] Meeting") == "meeting"
        assert ThreadingService.normalize_subject("[Spam?] Offer") == "offer"
    
    def test_generate_thread_id_consistency(self):
        """Test thread ID generation is consistent for same inputs."""
        subject = "Project Update"
        participants = [
            EmailParticipant(email="alice@example.com", name="Alice"),
            EmailParticipant(email="bob@example.com", name="Bob")
        ]
        
        thread_id_1 = ThreadingService.generate_thread_id(subject, participants)
        thread_id_2 = ThreadingService.generate_thread_id(subject, participants)
        
        assert thread_id_1 == thread_id_2
        assert len(thread_id_1) == 16  # Should be 16 characters
    
    def test_generate_thread_id_with_re_prefix(self):
        """Test thread ID is same for Re: prefixed subjects."""
        participants = [
            EmailParticipant(email="alice@example.com"),
            EmailParticipant(email="bob@example.com")
        ]
        
        thread_id_1 = ThreadingService.generate_thread_id("Meeting Tomorrow", participants)
        thread_id_2 = ThreadingService.generate_thread_id("Re: Meeting Tomorrow", participants)
        thread_id_3 = ThreadingService.generate_thread_id("Fwd: Meeting Tomorrow", participants)
        
        assert thread_id_1 == thread_id_2 == thread_id_3
    
    def test_generate_thread_id_participant_order_independent(self):
        """Test thread ID is same regardless of participant order."""
        subject = "Discussion"
        
        participants_1 = [
            EmailParticipant(email="alice@example.com"),
            EmailParticipant(email="bob@example.com"),
            EmailParticipant(email="charlie@example.com")
        ]
        
        participants_2 = [
            EmailParticipant(email="charlie@example.com"),
            EmailParticipant(email="alice@example.com"),
            EmailParticipant(email="bob@example.com")
        ]
        
        thread_id_1 = ThreadingService.generate_thread_id(subject, participants_1)
        thread_id_2 = ThreadingService.generate_thread_id(subject, participants_2)
        
        assert thread_id_1 == thread_id_2
    
    def test_generate_thread_id_different_subjects(self):
        """Test different subjects generate different thread IDs."""
        participants = [EmailParticipant(email="alice@example.com")]
        
        thread_id_1 = ThreadingService.generate_thread_id("Subject A", participants)
        thread_id_2 = ThreadingService.generate_thread_id("Subject B", participants)
        
        assert thread_id_1 != thread_id_2
    
    def test_generate_thread_id_different_participants(self):
        """Test different participants generate different thread IDs."""
        subject = "Same Subject"
        
        participants_1 = [EmailParticipant(email="alice@example.com")]
        participants_2 = [EmailParticipant(email="bob@example.com")]
        
        thread_id_1 = ThreadingService.generate_thread_id(subject, participants_1)
        thread_id_2 = ThreadingService.generate_thread_id(subject, participants_2)
        
        assert thread_id_1 != thread_id_2


# ==================== Search Service Tests ====================

class TestSearchService:
    """Tests for search query parsing and filtering."""
    
    def test_parse_simple_query(self):
        """Test parsing simple text query."""
        query = "meeting notes"
        filters = SearchService.parse_search_query(query)
        
        assert "text" in filters
        assert filters["text"] == "meeting notes"
    
    def test_parse_from_filter(self):
        """Test parsing from: filter."""
        query = "from:alice@example.com"
        filters = SearchService.parse_search_query(query)
        
        assert "from" in filters
        assert filters["from"] == "alice@example.com"
    
    def test_parse_to_filter(self):
        """Test parsing to: filter."""
        query = "to:bob@example.com"
        filters = SearchService.parse_search_query(query)
        
        assert "to" in filters
        assert filters["to"] == "bob@example.com"
    
    def test_parse_subject_filter(self):
        """Test parsing subject: filter."""
        query = "subject:quarterly report"
        filters = SearchService.parse_search_query(query)
        
        assert "subject" in filters
        assert filters["subject"] == "quarterly report"
    
    def test_parse_has_attachment_filter(self):
        """Test parsing has:attachment filter."""
        query = "has:attachment"
        filters = SearchService.parse_search_query(query)
        
        assert "has_attachment" in filters
        assert filters["has_attachment"] is True
    
    def test_parse_is_read_filter(self):
        """Test parsing is:read filter."""
        query = "is:read"
        filters = SearchService.parse_search_query(query)
        
        assert "is_read" in filters
        assert filters["is_read"] is True
    
    def test_parse_is_unread_filter(self):
        """Test parsing is:unread filter."""
        query = "is:unread"
        filters = SearchService.parse_search_query(query)
        
        assert "is_read" in filters
        assert filters["is_read"] is False
    
    def test_parse_is_starred_filter(self):
        """Test parsing is:starred filter."""
        query = "is:starred"
        filters = SearchService.parse_search_query(query)
        
        assert "is_starred" in filters
        assert filters["is_starred"] is True
    
    def test_parse_before_filter(self):
        """Test parsing before: date filter."""
        query = "before:2024-01-15"
        filters = SearchService.parse_search_query(query)
        
        assert "before" in filters
        assert isinstance(filters["before"], datetime)
    
    def test_parse_after_filter(self):
        """Test parsing after: date filter."""
        query = "after:2024-01-01"
        filters = SearchService.parse_search_query(query)
        
        assert "after" in filters
        assert isinstance(filters["after"], datetime)
    
    def test_parse_multiple_filters(self):
        """Test parsing query with multiple filters."""
        query = "from:alice@example.com subject:report is:unread has:attachment"
        filters = SearchService.parse_search_query(query)
        
        assert filters["from"] == "alice@example.com"
        assert filters["subject"] == "report"
        assert filters["is_read"] is False
        assert filters["has_attachment"] is True
    
    def test_parse_mixed_filters_and_text(self):
        """Test parsing query with filters and free text."""
        query = "from:alice@example.com important meeting"
        filters = SearchService.parse_search_query(query)
        
        assert filters["from"] == "alice@example.com"
        assert "text" in filters
        assert "important meeting" in filters["text"]
    
    def test_parse_quoted_text(self):
        """Test parsing quoted text in filters."""
        query = 'subject:"quarterly financial report"'
        filters = SearchService.parse_search_query(query)
        
        assert filters["subject"] == "quarterly financial report"
    
    def test_parse_invalid_date_format(self):
        """Test parsing invalid date format."""
        query = "before:invalid-date"
        filters = SearchService.parse_search_query(query)
        
        # Should skip invalid date filter
        assert "before" not in filters or filters["before"] is None
    
    def test_build_mongo_query_from_filters(self):
        """Test building MongoDB query from parsed filters."""
        filters = {
            "from": "alice@example.com",
            "is_read": False,
            "has_attachment": True
        }
        
        mongo_query = SearchService.build_mongo_query(filters, user_id="user123")
        
        assert mongo_query["user_id"] == "user123"
        assert mongo_query["sender.email"] == "alice@example.com"
        assert mongo_query["is_read"] is False
        assert mongo_query["has_attachment"] is True
    
    def test_build_mongo_query_with_date_range(self):
        """Test building MongoDB query with date filters."""
        now = datetime.now(timezone.utc)
        before_date = now
        after_date = now - timedelta(days=7)
        
        filters = {
            "before": before_date,
            "after": after_date
        }
        
        mongo_query = SearchService.build_mongo_query(filters, user_id="user123")
        
        assert "received_at" in mongo_query
        assert "$lt" in mongo_query["received_at"]
        assert "$gt" in mongo_query["received_at"]


# ==================== Label Service Tests ====================

class TestLabelService:
    """Tests for label management logic."""
    
    def test_validate_label_name_valid(self):
        """Test validation accepts valid label names."""
        assert LabelService.validate_label_name("Work") is True
        assert LabelService.validate_label_name("Personal Projects") is True
        assert LabelService.validate_label_name("2024-Goals") is True
    
    def test_validate_label_name_empty(self):
        """Test validation rejects empty names."""
        assert LabelService.validate_label_name("") is False
        assert LabelService.validate_label_name("   ") is False
    
    def test_validate_label_name_too_long(self):
        """Test validation rejects names over 50 characters."""
        long_name = "a" * 51
        assert LabelService.validate_label_name(long_name) is False
    
    def test_validate_label_name_special_characters(self):
        """Test validation rejects invalid special characters."""
        assert LabelService.validate_label_name("Work/Personal") is False  # Slash not allowed
        assert LabelService.validate_label_name("Label<script>") is False  # HTML not allowed
    
    def test_validate_color_valid_hex(self):
        """Test validation accepts valid hex colors."""
        assert LabelService.validate_color("#FF5722") is True
        assert LabelService.validate_color("#2196F3") is True
        assert LabelService.validate_color("#000000") is True
        assert LabelService.validate_color("#FFFFFF") is True
    
    def test_validate_color_invalid_format(self):
        """Test validation rejects invalid color formats."""
        assert LabelService.validate_color("FF5722") is False  # Missing #
        assert LabelService.validate_color("#FF57") is False  # Too short
        assert LabelService.validate_color("#FF57222") is False  # Too long
        assert LabelService.validate_color("#GGGGGG") is False  # Invalid hex
    
    def test_validate_nesting_depth_valid(self):
        """Test validation accepts valid nesting (max 2 levels)."""
        # Top level (no parent)
        assert LabelService.validate_nesting_depth(parent_label_id=None, current_depth=0) is True
        
        # First level nesting
        assert LabelService.validate_nesting_depth(parent_label_id="parent1", current_depth=0) is True
        
        # Second level nesting (max allowed)
        assert LabelService.validate_nesting_depth(parent_label_id="parent2", current_depth=1) is True
    
    def test_validate_nesting_depth_invalid(self):
        """Test validation rejects nesting beyond 2 levels."""
        # Third level nesting (not allowed)
        assert LabelService.validate_nesting_depth(parent_label_id="parent3", current_depth=2) is False
    
    def test_generate_label_id(self):
        """Test label ID generation."""
        label_id = LabelService.generate_label_id("Work")
        
        assert label_id.startswith("label_")
        assert len(label_id) > 6  # Should have hash appended
    
    def test_generate_label_id_consistency(self):
        """Test label ID generation is consistent for same name."""
        label_id_1 = LabelService.generate_label_id("Work")
        label_id_2 = LabelService.generate_label_id("Work")
        
        # Should be same (deterministic based on name)
        assert label_id_1 == label_id_2
    
    def test_generate_label_id_uniqueness(self):
        """Test label ID generation is unique for different names."""
        label_id_1 = LabelService.generate_label_id("Work")
        label_id_2 = LabelService.generate_label_id("Personal")
        
        assert label_id_1 != label_id_2


# ==================== Integration Tests ====================

class TestServiceIntegration:
    """Integration tests combining multiple services."""
    
    def test_search_and_threading_integration(self):
        """Test search results can be grouped by threads."""
        # This would test that search results maintain thread_id
        # and can be grouped using ThreadingService
        pass
    
    def test_label_application_with_search(self):
        """Test applying labels to search results."""
        # This would test bulk label application to filtered emails
        pass


# ==================== Performance Tests ====================

class TestServicePerformance:
    """Performance tests for service operations."""
    
    def test_thread_id_generation_performance(self):
        """Test thread ID generation is fast."""
        import time
        
        participants = [
            EmailParticipant(email=f"user{i}@example.com")
            for i in range(10)
        ]
        
        start = time.time()
        for i in range(1000):
            ThreadingService.generate_thread_id(f"Subject {i}", participants)
        end = time.time()
        
        # Should complete 1000 generations in under 1 second
        assert (end - start) < 1.0
    
    def test_search_query_parsing_performance(self):
        """Test search query parsing is fast."""
        import time
        
        query = "from:alice@example.com to:bob@example.com subject:meeting is:unread has:attachment before:2024-01-15"
        
        start = time.time()
        for _ in range(1000):
            SearchService.parse_search_query(query)
        end = time.time()
        
        # Should complete 1000 parses in under 0.5 seconds
        assert (end - start) < 0.5
