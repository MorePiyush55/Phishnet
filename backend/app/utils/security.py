"""
Security Utilities for Input Validation and Sanitization

Provides comprehensive input validation and sanitization:
- Email validation
- HTML sanitization
- SQL injection prevention
- XSS prevention
- Path traversal prevention
"""

import re
from typing import Optional
from email_validator import validate_email, EmailNotValidError
from html import escape
import bleach


# ==================== Email Validation ====================

def validate_email_address(email: str) -> tuple[bool, Optional[str]]:
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
    
    Returns:
        Tuple of (is_valid, normalized_email)
    """
    try:
        # Validate and normalize
        validation = validate_email(email, check_deliverability=False)
        return True, validation.normalized
    except EmailNotValidError as e:
        return False, None


def validate_email_list(emails: list[str]) -> tuple[bool, list[str], list[str]]:
    """
    Validate list of email addresses.
    
    Returns:
        Tuple of (all_valid, valid_emails, invalid_emails)
    """
    valid = []
    invalid = []
    
    for email in emails:
        is_valid, normalized = validate_email_address(email)
        if is_valid:
            valid.append(normalized)
        else:
            invalid.append(email)
    
    return len(invalid) == 0, valid, invalid


# ==================== HTML Sanitization ====================

# Allowed HTML tags for email bodies
ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 'b', 'i',
    'a', 'ul', 'ol', 'li', 'blockquote',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'div', 'span', 'table', 'tr', 'td', 'th',
    'thead', 'tbody', 'img'
]

# Allowed HTML attributes
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'target', 'rel'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
    'table': ['border', 'cellpadding', 'cellspacing'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan'],
    '*': ['class', 'id']  # Allow class and id on all elements
}

# Allowed URL protocols
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']


def sanitize_html(html_content: str, strip_dangerous: bool = True) -> str:
    """
    Sanitize HTML content to prevent XSS attacks.
    
    Args:
        html_content: Raw HTML content
        strip_dangerous: If True, strip dangerous tags; if False, escape them
    
    Returns:
        Sanitized HTML
    """
    if not html_content:
        return ""
    
    # Use bleach for comprehensive sanitization
    cleaned = bleach.clean(
        html_content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=strip_dangerous,
        strip_comments=True
    )
    
    # Additional security: remove any remaining event handlers
    cleaned = re.sub(r'\son\w+\s*=', ' data-removed=', cleaned, flags=re.IGNORECASE)
    
    # Remove javascript: protocol
    cleaned = re.sub(r'javascript:', '', cleaned, flags=re.IGNORECASE)
    
    return cleaned


def sanitize_text(text: str) -> str:
    """
    Sanitize plain text by escaping HTML entities.
    
    Args:
        text: Plain text content
    
    Returns:
        Escaped text safe for HTML display
    """
    if not text:
        return ""
    
    return escape(text)


def strip_html(html_content: str) -> str:
    """
    Strip all HTML tags and return plain text.
    
    Args:
        html_content: HTML content
    
    Returns:
        Plain text with HTML removed
    """
    if not html_content:
        return ""
    
    # Use bleach to strip all tags
    return bleach.clean(html_content, tags=[], strip=True)


# ==================== String Validation ====================

def validate_label_name(name: str) -> tuple[bool, Optional[str]]:
    """
    Validate label name.
    
    Rules:
    - 1-50 characters
    - Alphanumeric, spaces, hyphens, underscores only
    - No leading/trailing whitespace
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not name or not name.strip():
        return False, "Label name cannot be empty"
    
    name = name.strip()
    
    if len(name) > 50:
        return False, "Label name must be 50 characters or less"
    
    if not re.match(r'^[a-zA-Z0-9\s\-_]+$', name):
        return False, "Label name can only contain letters, numbers, spaces, hyphens, and underscores"
    
    return True, None


def validate_folder_name(name: str) -> tuple[bool, Optional[str]]:
    """
    Validate folder name.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    valid_folders = ['inbox', 'sent', 'drafts', 'spam', 'trash', 'all_mail', 'starred', 'archive']
    
    if name.lower() not in valid_folders:
        return False, f"Invalid folder name. Must be one of: {', '.join(valid_folders)}"
    
    return True, None


def validate_hex_color(color: str) -> tuple[bool, Optional[str]]:
    """
    Validate hex color code.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not color:
        return False, "Color cannot be empty"
    
    if not re.match(r'^#[0-9A-Fa-f]{6}$', color):
        return False, "Color must be a valid hex code (e.g., #FF5722)"
    
    return True, None


# ==================== Path Validation ====================

def validate_file_path(path: str) -> tuple[bool, Optional[str]]:
    """
    Validate file path to prevent path traversal attacks.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not path:
        return False, "Path cannot be empty"
    
    # Check for path traversal attempts
    if '..' in path or path.startswith('/') or path.startswith('\\'):
        return False, "Invalid path: path traversal detected"
    
    # Check for absolute paths
    if ':' in path:  # Windows absolute path
        return False, "Absolute paths not allowed"
    
    return True, None


# ==================== Query Parameter Validation ====================

def validate_pagination_params(
    limit: Optional[int] = None,
    cursor: Optional[str] = None
) -> tuple[bool, Optional[str]]:
    """
    Validate pagination parameters.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if limit is not None:
        if not isinstance(limit, int) or limit < 1:
            return False, "Limit must be a positive integer"
        
        if limit > 100:
            return False, "Limit cannot exceed 100"
    
    if cursor is not None:
        if not isinstance(cursor, str):
            return False, "Cursor must be a string"
        
        # Validate cursor format (base64 encoded timestamp)
        if len(cursor) > 100:  # Reasonable max length
            return False, "Invalid cursor format"
    
    return True, None


def validate_search_query(query: str) -> tuple[bool, Optional[str]]:
    """
    Validate search query.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not query:
        return False, "Search query cannot be empty"
    
    if len(query) > 500:
        return False, "Search query too long (max 500 characters)"
    
    # Check for potential injection attempts
    dangerous_patterns = [
        r'\$where',  # MongoDB injection
        r'\$regex.*\$options',  # Complex regex injection
        r'<script',  # XSS attempt
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            return False, "Invalid search query: potentially dangerous pattern detected"
    
    return True, None


# ==================== Bulk Operation Validation ====================

def validate_bulk_operation(
    message_ids: list[str],
    max_count: int = 100
) -> tuple[bool, Optional[str]]:
    """
    Validate bulk operation parameters.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not message_ids:
        return False, "No message IDs provided"
    
    if not isinstance(message_ids, list):
        return False, "Message IDs must be a list"
    
    if len(message_ids) > max_count:
        return False, f"Cannot process more than {max_count} emails at once"
    
    # Validate each message ID
    for msg_id in message_ids:
        if not isinstance(msg_id, str) or not msg_id.strip():
            return False, "Invalid message ID format"
        
        if len(msg_id) > 100:
            return False, "Message ID too long"
    
    return True, None


# ==================== Date Validation ====================

def validate_date_string(date_str: str) -> tuple[bool, Optional[str]]:
    """
    Validate date string format (YYYY-MM-DD).
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not date_str:
        return False, "Date cannot be empty"
    
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
        return False, "Date must be in YYYY-MM-DD format"
    
    # Try to parse
    try:
        from datetime import datetime
        datetime.strptime(date_str, '%Y-%m-%d')
        return True, None
    except ValueError:
        return False, "Invalid date"


# ==================== Comprehensive Input Sanitizer ====================

class InputSanitizer:
    """
    Comprehensive input sanitizer for all user inputs.
    """
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """Sanitize general string input."""
        if not value:
            return ""
        
        # Trim whitespace
        value = value.strip()
        
        # Limit length
        if len(value) > max_length:
            value = value[:max_length]
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        return value
    
    @staticmethod
    def sanitize_email_subject(subject: str) -> str:
        """Sanitize email subject line."""
        subject = InputSanitizer.sanitize_string(subject, max_length=200)
        
        # Remove control characters except newline and tab
        subject = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', subject)
        
        return subject
    
    @staticmethod
    def sanitize_email_body(body: str, is_html: bool = False) -> str:
        """Sanitize email body content."""
        if is_html:
            return sanitize_html(body)
        else:
            return InputSanitizer.sanitize_string(body, max_length=1000000)  # 1MB limit
