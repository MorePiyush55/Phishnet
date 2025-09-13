"""Core models package - fundamental data models."""

from .user import User
from .email import Email, EmailStatus

__all__ = ["User", "Email", "EmailStatus"]
