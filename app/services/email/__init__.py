"""Email services package - handles email processing, Gmail integration."""

from .processor import EmailProcessor
from .gmail_service import gmail_service

__all__ = ["EmailProcessor", "gmail_service"]
