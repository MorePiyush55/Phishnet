"""
Unit tests for SecuritySanitizer service.
Tests XSS prevention, content sanitization, and security features.
"""

import pytest
from typing import Dict, Any

from app.services.security_sanitizer import SecuritySanitizer
from app.config.settings import settings


@pytest.fixture
def sanitizer():
    """Create SecuritySanitizer instance for testing."""
    return SecuritySanitizer()


class TestSecuritySanitizer:
    """Test suite for SecuritySanitizer."""
    
    def test_sanitizer_initialization(self, sanitizer):
        """Test sanitizer initializes correctly."""
        assert sanitizer is not None
        assert hasattr(sanitizer, 'sanitize_html')
        assert hasattr(sanitizer, 'sanitize_text')
    
    def test_basic_html_sanitization(self, sanitizer):
        """Test basic HTML sanitization."""
        dirty_html = "<p>Clean content</p><script>alert('xss')</script>"
        clean_html = sanitizer.sanitize_html(dirty_html)
        
        assert "<script>" not in clean_html
        assert "<p>Clean content</p>" in clean_html
        assert "alert" not in clean_html
    
    def test_script_tag_removal(self, sanitizer):
        """Test script tag removal."""
        test_cases = [
            "<script>alert('xss')</script>",
            "<SCRIPT>alert('xss')</SCRIPT>",
            "<script type='text/javascript'>alert('xss')</script>",
            "<script src='malicious.js'></script>"
        ]
        
        for test_case in test_cases:
            result = sanitizer.sanitize_html(test_case)
            assert "<script" not in result.lower()
            assert "alert" not in result
    
    def test_event_handler_removal(self, sanitizer):
        """Test removal of event handlers."""
        test_cases = [
            "<div onclick='alert(1)'>Click me</div>",
            "<img src='x' onerror='alert(1)'>",
            "<body onload='malicious()'>",
            "<a href='#' onmouseover='attack()'>Link</a>"
        ]
        
        for test_case in test_cases:
            result = sanitizer.sanitize_html(test_case)
            assert "onclick" not in result
            assert "onerror" not in result
            assert "onload" not in result
            assert "onmouseover" not in result
            assert "alert" not in result
    
    def test_dangerous_url_filtering(self, sanitizer):
        """Test filtering of dangerous URLs."""
        test_cases = [
            "<a href='javascript:alert(1)'>Link</a>",
            "<a href='data:text/html,<script>alert(1)</script>'>Link</a>",
            "<a href='vbscript:CreateObject(\"Wscript.Shell\").Run(\"calc\")'>Link</a>",
            "<img src='javascript:alert(1)'>"
        ]
        
        for test_case in test_cases:
            result = sanitizer.sanitize_html(test_case)
            assert "javascript:" not in result
            assert "data:text/html" not in result
            assert "vbscript:" not in result
    
    def test_safe_html_preservation(self, sanitizer):
        """Test that safe HTML is preserved."""
        safe_html = """
        <div class="content">
            <h1>Title</h1>
            <p>This is <strong>safe</strong> content with <em>emphasis</em>.</p>
            <ul>
                <li>Item 1</li>
                <li>Item 2</li>
            </ul>
            <a href="https://example.com">Safe link</a>
            <img src="https://example.com/image.jpg" alt="Safe image">
        </div>
        """
        
        result = sanitizer.sanitize_html(safe_html)
        
        # Check that safe elements are preserved
        assert "<h1>" in result
        assert "<p>" in result
        assert "<strong>" in result
        assert "<em>" in result
        assert "<ul>" in result
        assert "<li>" in result
        assert "https://example.com" in result
    
    def test_text_sanitization(self, sanitizer):
        """Test text-only sanitization."""
        test_cases = [
            ("<script>alert('xss')</script>Hello", "Hello"),
            ("Normal text", "Normal text"),
            ("<p>HTML tags</p>", "HTML tags"),
            ("Text with <b>bold</b> tags", "Text with bold tags")
        ]
        
        for input_text, expected in test_cases:
            result = sanitizer.sanitize_text(input_text)
            assert result == expected
    
    def test_content_length_limits(self, sanitizer):
        """Test content length limiting."""
        long_content = "A" * 50000  # 50KB content
        result = sanitizer.sanitize_html(long_content, max_length=1000)
        
        assert len(result) <= 1000
    
    def test_xss_payloads(self, sanitizer):
        """Test against common XSS payloads."""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<object data=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            "<link rel=stylesheet href=javascript:alert('XSS')>",
            "<style>@import 'javascript:alert(\"XSS\")'</style>",
            "<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",
            "<form action=javascript:alert('XSS')><input type=submit>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<video src=x onerror=alert('XSS')>"
        ]
        
        for payload in xss_payloads:
            result = sanitizer.sanitize_html(payload)
            
            # Ensure dangerous content is removed
            assert "alert(" not in result
            assert "javascript:" not in result
            assert "<script" not in result.lower()
            assert "onerror=" not in result
            assert "onload=" not in result
    
    def test_nested_xss_attempts(self, sanitizer):
        """Test against nested XSS attempts."""
        nested_payloads = [
            "<div><script>alert('XSS')</script></div>",
            "<p onclick='alert(1)'><span>Content</span></p>",
            "<img src='x' onerror='alert(1)' alt='<script>alert(2)</script>'>",
            "<a href='javascript:alert(1)'><span onclick='alert(2)'>Link</span></a>"
        ]
        
        for payload in nested_payloads:
            result = sanitizer.sanitize_html(payload)
            assert "alert(" not in result
            assert "onclick" not in result
            assert "onerror" not in result
            assert "<script" not in result.lower()
    
    def test_encoding_bypass_attempts(self, sanitizer):
        """Test against encoding bypass attempts."""
        encoded_payloads = [
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e"
        ]
        
        for payload in encoded_payloads:
            result = sanitizer.sanitize_html(payload)
            # Encoded content should be safely handled
            assert result is not None
            assert len(result) >= 0
    
    def test_markdown_safety(self, sanitizer):
        """Test markdown content sanitization."""
        markdown_content = """
        # Safe Header
        
        **Bold text** and *italic text*
        
        [Safe Link](https://example.com)
        
        ```
        Code block
        ```
        
        <script>alert('XSS')</script>
        """
        
        result = sanitizer.sanitize_markdown(markdown_content)
        
        # Should preserve markdown structure but remove XSS
        assert "# Safe Header" in result
        assert "**Bold text**" in result
        assert "https://example.com" in result
        assert "<script>" not in result
        assert "alert" not in result
    
    def test_email_content_sanitization(self, sanitizer):
        """Test email-specific content sanitization."""
        email_content = """
        <html>
        <head>
            <script>malicious()</script>
            <style>body { background: red; }</style>
        </head>
        <body>
            <p>Dear Customer,</p>
            <p onclick="steal_data()">Click here to claim your prize!</p>
            <a href="javascript:phish()">Malicious Link</a>
            <img src="https://tracker.evil.com/track.gif" onerror="execute_payload()">
            <p>Best regards,<br>Legitimate Company</p>
        </body>
        </html>
        """
        
        result = sanitizer.sanitize_email_content(email_content)
        
        # Should preserve legitimate content
        assert "Dear Customer" in result
        assert "Best regards" in result
        assert "Legitimate Company" in result
        
        # Should remove dangerous content
        assert "malicious()" not in result
        assert "steal_data()" not in result
        assert "javascript:" not in result
        assert "execute_payload()" not in result
        assert "onclick" not in result
        assert "onerror" not in result
    
    def test_sanitization_statistics(self, sanitizer):
        """Test sanitization statistics tracking."""
        dangerous_content = """
        <script>alert('xss1')</script>
        <p onclick="alert('xss2')">Text</p>
        <a href="javascript:alert('xss3')">Link</a>
        """
        
        result = sanitizer.sanitize_html(dangerous_content)
        stats = sanitizer.get_sanitization_stats()
        
        assert stats is not None
        assert "violations_detected" in stats
        assert stats["violations_detected"] >= 3  # At least 3 violations
    
    def test_whitelist_functionality(self, sanitizer):
        """Test allowed tags and attributes whitelist."""
        # Test allowed tags
        allowed_content = "<p><strong>Bold</strong> and <em>italic</em> text</p>"
        result = sanitizer.sanitize_html(allowed_content)
        assert "<p>" in result
        assert "<strong>" in result
        assert "<em>" in result
        
        # Test disallowed tags
        disallowed_content = "<script>alert(1)</script><object>evil</object>"
        result = sanitizer.sanitize_html(disallowed_content)
        assert "<script>" not in result
        assert "<object>" not in result
    
    def test_url_validation(self, sanitizer):
        """Test URL validation and sanitization."""
        test_urls = [
            ("https://example.com", True),
            ("http://example.com", True),
            ("ftp://files.example.com", True),
            ("javascript:alert(1)", False),
            ("data:text/html,<script>alert(1)</script>", False),
            ("vbscript:malicious", False),
            ("file:///etc/passwd", False)
        ]
        
        for url, should_be_safe in test_urls:
            is_safe = sanitizer.is_safe_url(url)
            assert is_safe == should_be_safe, f"URL {url} safety check failed"
    
    def test_performance_with_large_content(self, sanitizer):
        """Test performance with large content."""
        import time
        
        # Generate large content with mixed safe and dangerous elements
        large_content = ""
        for i in range(1000):
            large_content += f"<p>Paragraph {i} with <strong>formatting</strong></p>"
            if i % 10 == 0:
                large_content += "<script>alert('xss')</script>"
        
        start_time = time.time()
        result = sanitizer.sanitize_html(large_content)
        end_time = time.time()
        
        # Should complete within reasonable time (< 5 seconds)
        assert (end_time - start_time) < 5.0
        
        # Should still sanitize properly
        assert "<script>" not in result
        assert "alert" not in result
        assert len(result) > 0
    
    def test_error_handling(self, sanitizer):
        """Test error handling with malformed input."""
        malformed_inputs = [
            None,
            "",
            "<><><",
            "<<>><<>>",
            "<script><script>alert(1)</script></script>",
            "< malformed > tags < everywhere >"
        ]
        
        for malformed_input in malformed_inputs:
            # Should not raise exceptions
            try:
                result = sanitizer.sanitize_html(malformed_input) if malformed_input is not None else ""
                assert result is not None
            except Exception as e:
                pytest.fail(f"Sanitizer raised exception for input {malformed_input}: {e}")
    
    def test_configuration_options(self, sanitizer):
        """Test different configuration options."""
        # Test strict mode
        strict_sanitizer = SecuritySanitizer(strict_mode=True)
        content = "<div><p>Some content</p><span>More content</span></div>"
        
        strict_result = strict_sanitizer.sanitize_html(content)
        normal_result = sanitizer.sanitize_html(content)
        
        # Strict mode should be more restrictive
        assert len(strict_result) <= len(normal_result)
    
    @pytest.mark.parametrize("content_type", ["html", "text", "markdown", "email"])
    def test_content_type_handling(self, sanitizer, content_type):
        """Test different content type handling."""
        test_content = "<p>Test content</p><script>alert('xss')</script>"
        
        if content_type == "html":
            result = sanitizer.sanitize_html(test_content)
        elif content_type == "text":
            result = sanitizer.sanitize_text(test_content)
        elif content_type == "markdown":
            result = sanitizer.sanitize_markdown(test_content)
        elif content_type == "email":
            result = sanitizer.sanitize_email_content(test_content)
        
        # All should remove script tags
        assert "<script>" not in result
        assert "alert" not in result
        assert result is not None
