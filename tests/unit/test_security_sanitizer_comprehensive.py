"""
Comprehensive unit tests for SecuritySanitizer - XSS prevention and content sanitization.
Tests cover all sanitization methods, configuration options, and security edge cases.
"""

import pytest
from unittest.mock import Mock, patch
from typing import Dict, List

from app.services.security_sanitizer import (
    SecuritySanitizer, SanitizationResult, SanitizationConfig
)


class TestSecuritySanitizer:
    """Test suite for SecuritySanitizer with comprehensive XSS protection testing."""
    
    @pytest.fixture
    def sanitizer(self):
        """Create sanitizer instance with default configuration."""
        return SecuritySanitizer()
    
    @pytest.fixture
    def strict_config(self):
        """Create strict sanitization configuration."""
        return SanitizationConfig(
            allowed_tags=['p', 'br', 'strong', 'em'],
            allowed_attributes={'strong': ['class'], 'em': ['class']},
            allowed_protocols=['http', 'https'],
            strip_comments=True,
            strip_unknown_tags=True,
            allow_safe_markdown=False,
            max_content_length=1000
        )
    
    def test_basic_html_sanitization(self, sanitizer):
        """Test basic HTML sanitization removes dangerous elements."""
        malicious_html = '<script>alert("XSS")</script><p>Safe content</p>'
        result = sanitizer.sanitize_html(malicious_html)
        
        assert isinstance(result, SanitizationResult)
        assert '<script>' not in result.sanitized_content
        assert 'alert("XSS")' not in result.sanitized_content
        assert 'Safe content' in result.sanitized_content
        assert 'script' in result.removed_elements
        assert not result.is_safe if 'script' in malicious_html else True
    
    def test_xss_script_injection_prevention(self, sanitizer):
        """Test prevention of various XSS script injection techniques."""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src="x" onerror="alert(\'XSS\')">',
            '<svg onload="alert(\'XSS\')">',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<object data="javascript:alert(\'XSS\')"></object>',
            '<embed src="javascript:alert(\'XSS\')">',
            '<form><input type="submit" formaction="javascript:alert(\'XSS\')" value="Click">',
            '<a href="javascript:alert(\'XSS\')">Click</a>',
            '<<SCRIPT>alert("XSS")<</SCRIPT>',  # Nested tags
            '<SCRIPT SRC=http://xss.example.com/xss.js></SCRIPT>',
        ]
        
        for payload in xss_payloads:
            result = sanitizer.sanitize_html(payload)
            
            # Should not contain any script execution
            assert 'alert(' not in result.sanitized_content
            assert 'javascript:' not in result.sanitized_content
            assert '<script' not in result.sanitized_content.lower()
            assert 'onerror=' not in result.sanitized_content.lower()
            assert 'onload=' not in result.sanitized_content.lower()
            
            # Should record security violations
            assert len(result.security_violations) > 0
    
    def test_css_injection_prevention(self, sanitizer):
        """Test prevention of CSS-based attacks."""
        css_attacks = [
            '<style>body { background: url("javascript:alert(\'XSS\')"); }</style>',
            '<div style="background: url(javascript:alert(\'XSS\'))">test</div>',
            '<p style="expression(alert(\'XSS\'))">test</p>',
            '<span style="behavior: url(xss.htc)">test</span>',
        ]
        
        for attack in css_attacks:
            result = sanitizer.sanitize_html(attack)
            
            assert 'javascript:' not in result.sanitized_content
            assert 'expression(' not in result.sanitized_content.lower()
            assert 'behavior:' not in result.sanitized_content.lower()
    
    def test_attribute_injection_prevention(self, sanitizer):
        """Test prevention of attribute-based XSS."""
        attribute_attacks = [
            '<img src="valid.jpg" onload="alert(\'XSS\')">',
            '<input type="text" onfocus="alert(\'XSS\')" autofocus>',
            '<video autoplay controls oncanplay="alert(\'XSS\')">',
            '<audio autoplay oncanplay="alert(\'XSS\')">',
            '<details open ontoggle="alert(\'XSS\')">',
        ]
        
        for attack in attribute_attacks:
            result = sanitizer.sanitize_html(attack)
            
            # Check that event handlers are removed
            assert 'onload=' not in result.sanitized_content.lower()
            assert 'onfocus=' not in result.sanitized_content.lower()
            assert 'oncanplay=' not in result.sanitized_content.lower()
            assert 'ontoggle=' not in result.sanitized_content.lower()
            
            # Should have removed dangerous attributes
            assert len(result.removed_attributes) > 0
    
    def test_url_protocol_sanitization(self, sanitizer):
        """Test sanitization of dangerous URL protocols."""
        dangerous_urls = [
            '<a href="javascript:alert(\'XSS\')">Click</a>',
            '<a href="data:text/html,<script>alert(\'XSS\')</script>">Click</a>',
            '<a href="vbscript:alert(\'XSS\')">Click</a>',
            '<img src="data:image/svg+xml,<svg onload=alert(\'XSS\')/>">',
        ]
        
        for url_attack in dangerous_urls:
            result = sanitizer.sanitize_html(url_attack)
            
            assert 'javascript:' not in result.sanitized_content
            assert 'vbscript:' not in result.sanitized_content
            # data: URLs should be carefully validated
            if 'data:' in url_attack and 'script' in url_attack:
                assert 'data:' not in result.sanitized_content or 'script' not in result.sanitized_content
    
    def test_encoding_bypass_prevention(self, sanitizer):
        """Test prevention of encoding-based XSS bypasses."""
        encoded_attacks = [
            # URL encoding
            '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',
            # HTML entity encoding
            '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
            # Mixed encoding
            '&#60;script&#62;alert(&#34;XSS&#34;)&#60;/script&#62;',
            # Hex encoding
            '&#x3C;script&#x3E;alert(&#x22;XSS&#x22;)&#x3C;/script&#x3E;',
        ]
        
        for encoded_attack in encoded_attacks:
            result = sanitizer.sanitize_html(encoded_attack)
            
            # After decoding and sanitization, should not contain dangerous content
            assert 'alert(' not in result.sanitized_content
            assert '<script' not in result.sanitized_content.lower()
    
    def test_email_content_sanitization(self, sanitizer):
        """Test sanitization of email-specific content."""
        email_content = '''
        <html>
        <body>
            <p>Hello! Check this <a href="http://phishing-site.com" onclick="steal_data()">legitimate link</a></p>
            <img src="http://tracker.com/pixel.gif" style="display:none">
            <script>document.location="http://malicious.com"</script>
            <form action="http://data-collector.com" method="post">
                <input type="hidden" name="victim_email" value="user@example.com">
            </form>
        </body>
        </html>
        '''
        
        result = sanitizer.sanitize_email_content(email_content)
        
        # Should preserve legitimate content
        assert 'Hello!' in result.sanitized_content
        
        # Should remove dangerous elements
        assert 'onclick=' not in result.sanitized_content
        assert '<script>' not in result.sanitized_content
        assert 'document.location' not in result.sanitized_content
        assert '<form' not in result.sanitized_content.lower()
        
        # Should track what was removed
        assert len(result.security_violations) > 0
        assert any('script' in violation.lower() for violation in result.security_violations)
    
    def test_safe_content_preservation(self, sanitizer):
        """Test that safe content is preserved correctly."""
        safe_content = '''
        <div>
            <h1>Safe Title</h1>
            <p>This is <strong>safe</strong> content with <em>emphasis</em>.</p>
            <ul>
                <li>Safe list item 1</li>
                <li>Safe list item 2</li>
            </ul>
            <a href="https://legitimate-site.com">Safe link</a>
            <img src="https://example.com/safe-image.jpg" alt="Safe image">
        </div>
        '''
        
        result = sanitizer.sanitize_html(safe_content)
        
        # Safe content should be mostly preserved
        assert 'Safe Title' in result.sanitized_content
        assert '<strong>safe</strong>' in result.sanitized_content
        assert '<em>emphasis</em>' in result.sanitized_content
        assert 'Safe list item' in result.sanitized_content
        assert 'https://legitimate-site.com' in result.sanitized_content
        
        # Should have minimal removals
        assert len(result.security_violations) == 0
        assert result.is_safe
    
    def test_custom_configuration(self, sanitizer, strict_config):
        """Test sanitizer with custom configuration."""
        html_content = '''
        <div>
            <p>Allowed paragraph</p>
            <h1>Not allowed header</h1>
            <script>alert('XSS')</script>
            <strong class="allowed">Strong text</strong>
            <span class="not-allowed">Span text</span>
        </div>
        '''
        
        result = sanitizer.sanitize_html(html_content, config=strict_config)
        
        # Should only allow configured tags
        assert '<p>' in result.sanitized_content
        assert '<strong class="allowed">' in result.sanitized_content
        assert '<h1>' not in result.sanitized_content
        assert '<div>' not in result.sanitized_content
        assert '<span>' not in result.sanitized_content
        assert '<script>' not in result.sanitized_content
        
        # Should track removed elements
        assert 'h1' in result.removed_elements
        assert 'div' in result.removed_elements
        assert 'span' in result.removed_elements
        assert 'script' in result.removed_elements
    
    def test_content_length_limits(self, sanitizer):
        """Test content length limitations."""
        # Create content exceeding default limits
        large_content = '<p>' + 'A' * 200000 + '</p>'  # 200KB content
        
        result = sanitizer.sanitize_html(large_content)
        
        # Should be truncated or rejected
        assert len(result.sanitized_content) <= sanitizer.max_content_length
        
        # Should record the truncation
        if len(large_content) > sanitizer.max_content_length:
            assert 'length' in str(result.security_violations).lower()
    
    def test_markdown_sanitization(self, sanitizer):
        """Test markdown content sanitization."""
        malicious_markdown = '''
        # Safe Title
        
        This is safe **bold** text.
        
        [Safe link](https://example.com)
        
        ![Safe image](https://example.com/image.jpg)
        
        <script>alert('XSS')</script>
        
        <img src="x" onerror="alert('XSS')">
        
        [Dangerous link](javascript:alert('XSS'))
        '''
        
        result = sanitizer.sanitize_markdown(malicious_markdown)
        
        # Should preserve safe markdown
        assert '# Safe Title' in result.sanitized_content or '<h1>' in result.sanitized_content
        assert 'bold' in result.sanitized_content
        assert 'https://example.com' in result.sanitized_content
        
        # Should remove dangerous content
        assert '<script>' not in result.sanitized_content
        assert 'javascript:' not in result.sanitized_content
        assert 'onerror=' not in result.sanitized_content
    
    def test_sanitization_result_metadata(self, sanitizer):
        """Test that sanitization results include proper metadata."""
        test_content = '<script>alert("XSS")</script><p>Safe content</p><img src="x" onerror="evil()">'
        
        result = sanitizer.sanitize_html(test_content)
        
        # Check result structure
        assert isinstance(result, SanitizationResult)
        assert isinstance(result.sanitized_content, str)
        assert isinstance(result.original_length, int)
        assert isinstance(result.sanitized_length, int)
        assert isinstance(result.removed_elements, list)
        assert isinstance(result.removed_attributes, list)
        assert isinstance(result.security_violations, list)
        assert isinstance(result.is_safe, bool)
        
        # Check metadata accuracy
        assert result.original_length == len(test_content)
        assert result.sanitized_length == len(result.sanitized_content)
        assert len(result.removed_elements) > 0
        assert len(result.security_violations) > 0
        assert not result.is_safe  # Should be marked unsafe due to XSS content
    
    @pytest.mark.asyncio
    async def test_async_sanitization(self, sanitizer):
        """Test asynchronous sanitization operations."""
        test_contents = [
            '<script>alert("XSS1")</script><p>Content 1</p>',
            '<img src="x" onerror="alert(\'XSS2\')">Content 2',
            '<p>Safe content 3</p>',
        ]
        
        # Test concurrent sanitization
        tasks = [sanitizer.sanitize_html_async(content) for content in test_contents]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 3
        
        for i, result in enumerate(results):
            assert isinstance(result, SanitizationResult)
            assert f'Content {i+1}' in result.sanitized_content or 'content' in result.sanitized_content.lower()
            
            # First two should have security violations
            if i < 2:
                assert len(result.security_violations) > 0
                assert not result.is_safe
            else:
                # Third should be safe
                assert result.is_safe
    
    def test_performance_benchmarks(self, sanitizer):
        """Test sanitization performance for various content sizes."""
        import time
        
        # Test different content sizes
        sizes = [1000, 10000, 50000]  # 1KB, 10KB, 50KB
        
        for size in sizes:
            content = '<p>' + 'Safe content. ' * (size // 15) + '</p>'
            
            start_time = time.time()
            result = sanitizer.sanitize_html(content)
            end_time = time.time()
            
            processing_time = end_time - start_time
            
            # Should complete within reasonable time (adjust based on requirements)
            assert processing_time < 1.0  # Should complete within 1 second
            assert len(result.sanitized_content) > 0
            
            print(f"Sanitized {size} bytes in {processing_time:.3f} seconds")
    
    def test_error_handling(self, sanitizer):
        """Test error handling for invalid inputs."""
        # Test None input
        result = sanitizer.sanitize_html(None)
        assert result.sanitized_content == ''
        assert result.is_safe
        
        # Test empty string
        result = sanitizer.sanitize_html('')
        assert result.sanitized_content == ''
        assert result.is_safe
        
        # Test malformed HTML
        malformed_html = '<div><p>Unclosed tags<span>text</div>'
        result = sanitizer.sanitize_html(malformed_html)
        assert isinstance(result, SanitizationResult)
        assert len(result.sanitized_content) > 0
        
        # Test non-string input
        with pytest.raises((TypeError, ValueError)):
            sanitizer.sanitize_html(12345)
    
    def test_logging_and_monitoring(self, sanitizer):
        """Test that sanitization events are properly logged."""
        with patch('app.services.security_sanitizer.logger') as mock_logger:
            malicious_content = '<script>alert("XSS")</script>'
            
            result = sanitizer.sanitize_html(malicious_content)
            
            # Should log security violations
            assert mock_logger.warning.called or mock_logger.info.called
            
            # Check that important information is logged
            log_calls = mock_logger.warning.call_args_list + mock_logger.info.call_args_list
            assert any('script' in str(call).lower() for call in log_calls)
