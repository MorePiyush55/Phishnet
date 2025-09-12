"""
SecuritySanitizer - Comprehensive HTML/text sanitization for XSS prevention and safe UI rendering.

This service provides robust sanitization of user content to prevent XSS attacks,
script injection, and other security vulnerabilities in web UI display.
"""

import re
import html
import urllib.parse
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
import bleach
from bleach.css_sanitizer import CSSSanitizer
import markdown
from markdown.extensions import codehilite, fenced_code, tables
import logging

from app.config.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SanitizationResult:
    """Result of sanitization operation with details about what was removed."""
    sanitized_content: str
    original_length: int
    sanitized_length: int
    removed_elements: List[str]
    removed_attributes: List[str]
    security_violations: List[str]
    is_safe: bool


@dataclass
class SanitizationConfig:
    """Configuration for sanitization behavior."""
    allowed_tags: List[str]
    allowed_attributes: Dict[str, List[str]]
    allowed_protocols: List[str]
    strip_comments: bool = True
    strip_unknown_tags: bool = True
    allow_safe_markdown: bool = True
    max_content_length: int = 100000  # 100KB limit


class SecuritySanitizer:
    """
    Comprehensive security sanitizer for HTML/text content.
    
    Features:
    - XSS prevention through tag/attribute filtering
    - Script injection blocking
    - Safe markdown rendering
    - URL sanitization and rewriting
    - Content length limits
    - Detailed security violation reporting
    """
    
    # Dangerous patterns that should never be allowed
    DANGEROUS_PATTERNS = [
        r'javascript:',
        r'data:(?!image/)',  # Block data URIs except images
        r'vbscript:',
        r'on\w+\s*=',  # onclick, onload, etc.
        r'<\s*script',
        r'<\s*iframe(?!\s+src=["\']https?://)',  # Block iframes except safe external
        r'expression\s*\(',  # CSS expressions
        r'url\s*\(\s*["\']?javascript:',
        r'import\s+',  # ES6 imports
        r'@import',  # CSS imports
    ]
    
    # Safe HTML tags for email content display
    SAFE_TAGS = [
        'p', 'br', 'div', 'span', 'strong', 'b', 'em', 'i', 'u', 'ul', 'ol', 'li',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'pre', 'code',
        'a', 'img', 'table', 'thead', 'tbody', 'tr', 'td', 'th', 'hr'
    ]
    
    # Safe attributes for allowed tags
    SAFE_ATTRIBUTES = {
        '*': ['class', 'id', 'title'],
        'a': ['href', 'target', 'rel'],
        'img': ['src', 'alt', 'width', 'height'],
        'table': ['border', 'cellpadding', 'cellspacing'],
        'td': ['colspan', 'rowspan'],
        'th': ['colspan', 'rowspan'],
    }
    
    # Safe protocols for URLs
    SAFE_PROTOCOLS = ['http', 'https', 'mailto']
    
    def __init__(self, config: Optional[SanitizationConfig] = None):
        """Initialize sanitizer with configuration."""
        self.config = config or SanitizationConfig(
            allowed_tags=self.SAFE_TAGS.copy(),
            allowed_attributes=self.SAFE_ATTRIBUTES.copy(),
            allowed_protocols=self.SAFE_PROTOCOLS.copy()
        )
        
        # Initialize CSS sanitizer for safe inline styles
        self.css_sanitizer = CSSSanitizer(
            allowed_css_properties=[
                'color', 'background-color', 'font-size', 'font-weight',
                'text-align', 'margin', 'padding', 'border', 'width', 'height'
            ],
            allowed_svg_properties=[]  # No SVG allowed
        )
        
        # Compile dangerous pattern regex
        self.dangerous_regex = re.compile(
            '|'.join(self.DANGEROUS_PATTERNS),
            re.IGNORECASE | re.MULTILINE
        )
        
        logger.info("SecuritySanitizer initialized with safe configuration")
    
    def sanitize_html(self, content: str, context: str = "general") -> SanitizationResult:
        """
        Sanitize HTML content for safe display.
        
        Args:
            content: Raw HTML content to sanitize
            context: Context for sanitization (email, comment, etc.)
            
        Returns:
            SanitizationResult with sanitized content and violation details
        """
        if not content or not isinstance(content, str):
            return SanitizationResult(
                sanitized_content="",
                original_length=0,
                sanitized_length=0,
                removed_elements=[],
                removed_attributes=[],
                security_violations=[],
                is_safe=True
            )
        
        original_length = len(content)
        removed_elements = []
        removed_attributes = []
        security_violations = []
        
        # Check for dangerous patterns first
        dangerous_matches = self.dangerous_regex.findall(content)
        if dangerous_matches:
            security_violations.extend([f"Dangerous pattern: {match}" for match in dangerous_matches])
            logger.warning(f"Detected dangerous patterns in {context}: {dangerous_matches}")
        
        # Check content length
        if original_length > self.config.max_content_length:
            content = content[:self.config.max_content_length]
            security_violations.append(f"Content truncated from {original_length} to {self.config.max_content_length} chars")
        
        try:
            # Use bleach for HTML sanitization
            sanitized = bleach.clean(
                content,
                tags=self.config.allowed_tags,
                attributes=self.config.allowed_attributes,
                protocols=self.config.allowed_protocols,
                strip=self.config.strip_unknown_tags,
                strip_comments=self.config.strip_comments
            )
            
            # Additional URL rewriting for safety
            sanitized = self._rewrite_urls(sanitized)
            
            # Validate final result
            final_violations = self._validate_sanitized_content(sanitized)
            security_violations.extend(final_violations)
            
            sanitized_length = len(sanitized)
            is_safe = len(security_violations) == 0
            
            if not is_safe:
                logger.warning(f"Content sanitization found {len(security_violations)} violations in {context}")
            
            return SanitizationResult(
                sanitized_content=sanitized,
                original_length=original_length,
                sanitized_length=sanitized_length,
                removed_elements=removed_elements,
                removed_attributes=removed_attributes,
                security_violations=security_violations,
                is_safe=is_safe
            )
            
        except Exception as e:
            logger.error(f"Sanitization failed for {context}: {e}")
            # Fall back to plain text
            return self.sanitize_text(content, context)
    
    def sanitize_text(self, content: str, context: str = "general") -> SanitizationResult:
        """
        Sanitize plain text content, HTML-escaping and checking for dangerous patterns.
        
        Args:
            content: Plain text content to sanitize
            context: Context for sanitization
            
        Returns:
            SanitizationResult with safely escaped text
        """
        if not content or not isinstance(content, str):
            return SanitizationResult(
                sanitized_content="",
                original_length=0,
                sanitized_length=0,
                removed_elements=[],
                removed_attributes=[],
                security_violations=[],
                is_safe=True
            )
        
        original_length = len(content)
        security_violations = []
        
        # Check for dangerous patterns
        dangerous_matches = self.dangerous_regex.findall(content)
        if dangerous_matches:
            security_violations.extend([f"Dangerous pattern in text: {match}" for match in dangerous_matches])
        
        # HTML escape the content
        sanitized = html.escape(content, quote=True)
        
        # Check length
        if original_length > self.config.max_content_length:
            sanitized = sanitized[:self.config.max_content_length] + "..."
            security_violations.append(f"Text truncated from {original_length} chars")
        
        return SanitizationResult(
            sanitized_content=sanitized,
            original_length=original_length,
            sanitized_length=len(sanitized),
            removed_elements=[],
            removed_attributes=[],
            security_violations=security_violations,
            is_safe=len(security_violations) == 0
        )
    
    def sanitize_markdown(self, content: str, context: str = "general") -> SanitizationResult:
        """
        Safely render markdown content with XSS protection.
        
        Args:
            content: Markdown content to render
            context: Context for sanitization
            
        Returns:
            SanitizationResult with safely rendered markdown as HTML
        """
        if not content or not self.config.allow_safe_markdown:
            return self.sanitize_text(content, context)
        
        try:
            # Render markdown to HTML
            md = markdown.Markdown(
                extensions=['fenced_code', 'tables', 'codehilite'],
                extension_configs={
                    'codehilite': {
                        'css_class': 'highlight',
                        'use_pygments': False  # Avoid external dependencies
                    }
                }
            )
            
            html_content = md.convert(content)
            
            # Sanitize the resulting HTML
            return self.sanitize_html(html_content, f"markdown-{context}")
            
        except Exception as e:
            logger.error(f"Markdown rendering failed for {context}: {e}")
            return self.sanitize_text(content, context)
    
    def sanitize_url(self, url: str) -> str:
        """
        Sanitize URL for safe use in links.
        
        Args:
            url: URL to sanitize
            
        Returns:
            Safely sanitized URL or empty string if dangerous
        """
        if not url or not isinstance(url, str):
            return ""
        
        url = url.strip()
        
        # Check for dangerous patterns
        if self.dangerous_regex.search(url):
            logger.warning(f"Dangerous URL blocked: {url[:100]}")
            return ""
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Only allow safe protocols
            if parsed.scheme.lower() not in self.config.allowed_protocols:
                logger.warning(f"Unsafe protocol blocked: {parsed.scheme}")
                return ""
            
            # Validate the URL structure
            if not parsed.netloc and parsed.scheme in ['http', 'https']:
                return ""  # Invalid HTTP/HTTPS URL
            
            # Reconstruct clean URL
            clean_url = urllib.parse.urlunparse(parsed)
            return clean_url
            
        except Exception as e:
            logger.warning(f"URL parsing failed: {e}")
            return ""
    
    def sanitize_email_content(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensively sanitize all content in an email data structure.
        
        Args:
            email_data: Dictionary containing email content
            
        Returns:
            Dictionary with all content sanitized
        """
        sanitized_email = email_data.copy()
        violations = []
        
        # Sanitize text content
        if 'text_content' in sanitized_email:
            result = self.sanitize_text(sanitized_email['text_content'], "email-text")
            sanitized_email['text_content'] = result.sanitized_content
            violations.extend(result.security_violations)
        
        # Sanitize HTML content
        if 'html_content' in sanitized_email:
            result = self.sanitize_html(sanitized_email['html_content'], "email-html")
            sanitized_email['html_content'] = result.sanitized_content
            violations.extend(result.security_violations)
        
        # Sanitize headers
        if 'headers' in sanitized_email:
            sanitized_headers = {}
            for key, value in sanitized_email['headers'].items():
                if isinstance(value, str):
                    result = self.sanitize_text(value, f"email-header-{key}")
                    sanitized_headers[key] = result.sanitized_content
                    violations.extend(result.security_violations)
                else:
                    sanitized_headers[key] = value
            sanitized_email['headers'] = sanitized_headers
        
        # Sanitize links
        if 'links' in sanitized_email:
            safe_links = []
            for link in sanitized_email['links']:
                safe_url = self.sanitize_url(link)
                if safe_url:
                    safe_links.append(safe_url)
                else:
                    violations.append(f"Unsafe link removed: {link[:50]}")
            sanitized_email['links'] = safe_links
        
        # Add sanitization metadata
        sanitized_email['_sanitization'] = {
            'sanitized': True,
            'violations_count': len(violations),
            'violations': violations[:10],  # Limit to first 10 for brevity
            'sanitized_at': logger.handlers[0].formatter.formatTime() if logger.handlers else None
        }
        
        if violations:
            logger.warning(f"Email sanitization found {len(violations)} violations")
        
        return sanitized_email
    
    def _rewrite_urls(self, content: str) -> str:
        """Rewrite URLs in content to use safe click-through endpoint."""
        # URL pattern matching
        url_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
        
        def rewrite_url(match):
            original_url = match.group(1)
            safe_url = self.sanitize_url(original_url)
            
            if not safe_url:
                return 'href="#" data-blocked="true"'
            
            # Rewrite to click-through endpoint
            encoded_url = urllib.parse.quote(safe_url, safe='')
            click_through_url = f"/api/click-through?url={encoded_url}"
            
            return f'href="{click_through_url}" target="_blank" rel="noopener noreferrer"'
        
        return re.sub(url_pattern, rewrite_url, content, flags=re.IGNORECASE)
    
    def _validate_sanitized_content(self, content: str) -> List[str]:
        """Final validation check for sanitized content."""
        violations = []
        
        # Check for any remaining dangerous patterns
        dangerous_matches = self.dangerous_regex.findall(content)
        if dangerous_matches:
            violations.extend([f"Post-sanitization violation: {match}" for match in dangerous_matches])
        
        # Check for unescaped script tags
        if re.search(r'<\s*script', content, re.IGNORECASE):
            violations.append("Script tag found after sanitization")
        
        # Check for event handlers
        if re.search(r'on\w+\s*=', content, re.IGNORECASE):
            violations.append("Event handler found after sanitization")
        
        return violations
    
    def get_security_report(self, content: str, context: str = "general") -> Dict[str, Any]:
        """
        Generate detailed security report for content.
        
        Args:
            content: Content to analyze
            context: Context for analysis
            
        Returns:
            Detailed security analysis report
        """
        result = self.sanitize_html(content, context)
        
        return {
            'context': context,
            'content_length': result.original_length,
            'sanitized_length': result.sanitized_length,
            'reduction_ratio': 1 - (result.sanitized_length / max(result.original_length, 1)),
            'is_safe': result.is_safe,
            'violation_count': len(result.security_violations),
            'violations': result.security_violations,
            'removed_elements': result.removed_elements,
            'removed_attributes': result.removed_attributes,
            'dangerous_patterns_found': len(self.dangerous_regex.findall(content)),
            'sanitization_config': {
                'allowed_tags': len(self.config.allowed_tags),
                'allowed_protocols': self.config.allowed_protocols,
                'max_length': self.config.max_content_length
            }
        }


# Singleton instance for global use
_sanitizer_instance: Optional[SecuritySanitizer] = None


def get_security_sanitizer() -> SecuritySanitizer:
    """Get the global SecuritySanitizer instance."""
    global _sanitizer_instance
    
    if _sanitizer_instance is None:
        _sanitizer_instance = SecuritySanitizer()
    
    return _sanitizer_instance


def create_security_sanitizer(config: Optional[SanitizationConfig] = None) -> SecuritySanitizer:
    """Create a new SecuritySanitizer instance with custom configuration."""
    return SecuritySanitizer(config)


# Convenience functions for common sanitization tasks
def sanitize_user_input(content: str, content_type: str = "html") -> str:
    """Quickly sanitize user input content."""
    sanitizer = get_security_sanitizer()
    
    if content_type == "html":
        result = sanitizer.sanitize_html(content, "user-input")
    elif content_type == "markdown":
        result = sanitizer.sanitize_markdown(content, "user-input")
    else:
        result = sanitizer.sanitize_text(content, "user-input")
    
    return result.sanitized_content


def sanitize_email_for_display(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize email data for safe UI display."""
    sanitizer = get_security_sanitizer()
    return sanitizer.sanitize_email_content(email_data)


def validate_content_security(content: str, context: str = "general") -> bool:
    """Check if content is safe without sanitizing."""
    sanitizer = get_security_sanitizer()
    result = sanitizer.sanitize_html(content, context)
    return result.is_safe


# Security test vectors for validation
SECURITY_TEST_VECTORS = [
    # XSS attempts
    '<script>alert("XSS")</script>',
    '<img src="x" onerror="alert(1)">',
    '<a href="javascript:alert(1)">Click</a>',
    '<div onclick="alert(1)">Click</div>',
    '<iframe src="javascript:alert(1)"></iframe>',
    
    # CSS injection
    '<div style="background: url(javascript:alert(1))">Test</div>',
    '<div style="expression(alert(1))">Test</div>',
    
    # Data URI attacks
    '<img src="data:text/html,<script>alert(1)</script>">',
    
    # Protocol variations
    '<a href="vbscript:alert(1)">Click</a>',
    '<a href="data:text/html,<script>alert(1)</script>">Click</a>',
]


def run_security_validation() -> Dict[str, Any]:
    """Run security validation tests against known attack vectors."""
    sanitizer = get_security_sanitizer()
    results = {
        'total_tests': len(SECURITY_TEST_VECTORS),
        'passed_tests': 0,
        'failed_tests': 0,
        'test_results': []
    }
    
    for i, test_vector in enumerate(SECURITY_TEST_VECTORS):
        result = sanitizer.sanitize_html(test_vector, f"test-{i}")
        
        # Check if dangerous content was properly neutralized
        is_safe = result.is_safe and not sanitizer.dangerous_regex.search(result.sanitized_content)
        
        test_result = {
            'test_id': i,
            'input': test_vector,
            'output': result.sanitized_content,
            'passed': is_safe,
            'violations': result.security_violations
        }
        
        results['test_results'].append(test_result)
        
        if is_safe:
            results['passed_tests'] += 1
        else:
            results['failed_tests'] += 1
    
    results['pass_rate'] = results['passed_tests'] / results['total_tests']
    
    return results
