"""Minimal Gmail service shim for tests.

Provides a GmailService that wraps GmailClient; tests patch methods as needed.
"""

from typing import Any
from app.integrations.gmail_client import GmailClient

class GmailService:
    def __init__(self, client: GmailClient | None = None):
        self.client = client or GmailClient()

    def apply_label(self, message_id: str, label: str) -> bool:
        return self.client.apply_label(message_id, label)

    def move_to_folder(self, message_id: str, folder: str) -> bool:
        return self.client.move_to_folder(message_id, folder)

    def send_quarantine_message(self, to: str, subject: str, body: str) -> Any:
        return self.client.send_message(to, subject, body)

__all__ = ["GmailService"]
