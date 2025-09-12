"""Content sanitization service for safe HTML rendering."""

import re
import urllib.parse
from typing import Dict, List, Optional, Set
from html import escape, unescape
from urllib.parse import urlparse, urljoin
import bleach
from bs4 import BeautifulSoup, Comment

from app.config.settings import settings
from app.config.logging import get_logger

logger = get_logger(__name__)


class ContentSanitizer:
    """Content sanitization service for safe HTML rendering."""
    
    # Allowed HTML tags for email content
    ALLOWED_TAGS = {
        'p', 'br', 'div', 'span', 'strong', 'b', 'em', 'i', 'u', 'ul', 'ol', 'li',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'pre', 'code',
        'table', 'thead', 'tbody', 'tr', 'td', 'th', 'img', 'a'
    }
    
    # Allowed HTML attributes
    ALLOWED_ATTRIBUTES = {
        '*': ['class', 'id'],
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'title', 'width', 'height'],
        'table': ['border', 'cellpadding', 'cellspacing'],
        'td': ['colspan', 'rowspan'],
        'th': ['colspan', 'rowspan']
    }
    
    # Dangerous URL schemes
    DANGEROUS_SCHEMES = {
        'javascript', 'data', 'vbscript', 'file', 'about'
    }
    
    # Safe URL schemes
    SAFE_SCHEMES = {
        'http', 'https', 'mailto', 'tel'
    }
    
    def __init__(self):
        """Initialize sanitizer."""
        self.max_content_length = settings.MAX_EMAIL_CONTENT_LENGTH
        self.enable_link_rewriting = settings.ENABLE_LINK_REWRITING
    
    def sanitize_html(self, html_content: str) -> str:
        """Sanitize HTML content for safe display."""
        try:
            if not html_content:
                return ""
            
            # Check content length
            if len(html_content) > self.max_content_length:
                html_content = html_content[:self.max_content_length] + "...[content truncated]"
            
            # Parse HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Remove comments
            for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                comment.extract()
            
            # Remove dangerous elements
            self._remove_dangerous_elements(soup)
            
            # Sanitize attributes
            self._sanitize_attributes(soup)
            
            # Rewrite links if enabled
            if self.enable_link_rewriting:
                self._rewrite_links(soup)
            
            # Use bleach for final sanitization
            sanitized_html = bleach.clean(
                str(soup),
                tags=self.ALLOWED_TAGS,
                attributes=self.ALLOWED_ATTRIBUTES,
                strip=True,
                strip_comments=True
            )
            
            return sanitized_html
            
        except Exception as e:
            logger.error(f"HTML sanitization failed: {e}")
            # Return escaped plain text as fallback
            return escape(html_content)
    
    def extract_urls(self, content: str) -> List[Dict[str, str]]:
        """Extract all URLs from content."""
        urls = []
        
        try:
            # Parse HTML if present
            if '<' in content and '>' in content:
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract from href attributes
                for link in soup.find_all('a', href=True):
                    urls.append({
                        'url': link['href'],
                        'text': link.get_text(strip=True),
                        'type': 'link'
                    })
                
                # Extract from img src attributes
                for img in soup.find_all('img', src=True):
                    urls.append({
                        'url': img['src'],
                        'text': img.get('alt', ''),
                        'type': 'image'
                    })
            
            # Extract URLs from plain text using regex
            url_pattern = re.compile(
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            )
            
            for match in url_pattern.finditer(content):
                urls.append({
                    'url': match.group(),
                    'text': match.group(),
                    'type': 'text'
                })
            
            # Deduplicate URLs
            seen_urls = set()
            unique_urls = []
            for url_info in urls:
                if url_info['url'] not in seen_urls:
                    seen_urls.add(url_info['url'])
                    unique_urls.append(url_info)
            
            return unique_urls
            
        except Exception as e:
            logger.error(f"URL extraction failed: {e}")
            return []
    
    def is_safe_url(self, url: str) -> bool:
        """Check if URL is safe."""
        try:
            parsed = urlparse(url.lower())
            
            # Check scheme
            if parsed.scheme in self.DANGEROUS_SCHEMES:
                return False
            
            if parsed.scheme not in self.SAFE_SCHEMES:
                return False
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'javascript:',
                r'data:',
                r'vbscript:',
                r'about:',
                r'file:',
                r'<script',
                r'onload=',
                r'onerror=',
                r'onclick='
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def create_safe_redirect_url(self, target_url: str) -> str:
        """Create safe redirect URL for link wrapping."""
        if not self.is_safe_url(target_url):
            return "#"  # Return safe placeholder
        
        # Encode the target URL
        encoded_url = urllib.parse.quote(target_url, safe='')
        
        # Create redirect URL
        redirect_url = f"{settings.BASE_URL}/safe-redirect?target={encoded_url}"
        
        return redirect_url
    
    def _remove_dangerous_elements(self, soup: BeautifulSoup):
        """Remove dangerous HTML elements."""
        dangerous_tags = [
            'script', 'style', 'iframe', 'frame', 'frameset', 'object', 'embed',
            'applet', 'form', 'input', 'button', 'textarea', 'select', 'option',
            'meta', 'link', 'base'
        ]
        
        for tag_name in dangerous_tags:
            for tag in soup.find_all(tag_name):
                tag.decompose()
    
    def _sanitize_attributes(self, soup: BeautifulSoup):
        """Sanitize HTML attributes."""
        for tag in soup.find_all():
            # Get current attributes
            attrs_to_remove = []
            
            for attr_name, attr_value in tag.attrs.items():
                attr_name_lower = attr_name.lower()
                
                # Remove event handlers
                if attr_name_lower.startswith('on'):
                    attrs_to_remove.append(attr_name)
                    continue
                
                # Check attribute values
                if isinstance(attr_value, str):
                    attr_value_lower = attr_value.lower()
                    
                    # Remove javascript: URLs
                    if 'javascript:' in attr_value_lower:
                        attrs_to_remove.append(attr_name)
                        continue
                    
                    # Remove data: URLs (except safe image formats)
                    if attr_value_lower.startswith('data:') and attr_name_lower not in ['src']:
                        attrs_to_remove.append(attr_name)
                        continue
                
                # Check if attribute is allowed for this tag
                if (attr_name_lower not in self.ALLOWED_ATTRIBUTES.get('*', []) and 
                    attr_name_lower not in self.ALLOWED_ATTRIBUTES.get(tag.name, [])):
                    attrs_to_remove.append(attr_name)
            
            # Remove dangerous attributes
            for attr_name in attrs_to_remove:
                del tag.attrs[attr_name]
    
    def _rewrite_links(self, soup: BeautifulSoup):
        """Rewrite links for click-through protection."""
        for link in soup.find_all('a', href=True):
            original_url = link['href']
            
            # Skip mailto and tel links
            if original_url.startswith(('mailto:', 'tel:')):
                continue
            
            # Skip relative links (internal)
            if not original_url.startswith(('http://', 'https://')):
                continue
            
            # Rewrite external links
            safe_url = self.create_safe_redirect_url(original_url)
            link['href'] = safe_url
            
            # Add warning attributes
            link['target'] = '_blank'
            link['rel'] = 'noopener noreferrer'
            
            # Add visual indicator for external links
            if not link.get_text(strip=True).endswith(' [External]'):
                link.string = link.get_text() + ' [External]'
    
    def sanitize_text(self, text: str) -> str:
        """Sanitize plain text content."""
        if not text:
            return ""
        
        # Remove null bytes and control characters
        text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
        
        # Limit length
        if len(text) > self.max_content_length:
            text = text[:self.max_content_length] + "...[content truncated]"
        
        return text.strip()
    
    def get_content_security_policy(self) -> str:
        """Get Content Security Policy header value."""
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",  # Adjust based on needs
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self'",
            "connect-src 'self' wss: ws:",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "object-src 'none'"
        ]
        
        return "; ".join(csp_directives)


# Global sanitizer instance
content_sanitizer = ContentSanitizer()
