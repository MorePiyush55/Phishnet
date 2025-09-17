"""Compatibility shim re-exporting core Email model for tests.

Some tests import `app.models.email.Email` while the canonical model
is defined in `app.models.core.email`. Re-export here to avoid changing
the import surface and reduce duplicate model definitions.
"""

from app.models.core.email import Email, EmailStatus

__all__ = ["Email", "EmailStatus"]
