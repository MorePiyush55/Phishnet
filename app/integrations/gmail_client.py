"""Minimal Gmail client shim used for tests and collection.

Tests usually patch this class, so implement a tiny interface with the
methods that tests expect: apply_label, move_to_folder, send_message.
"""

from typing import Any, Dict, Optional

class GmailClient:
    def __init__(self, *args, **kwargs):
        # No real Google API interaction in tests; keep lightweight.
        self._connected = False

    def connect(self) -> bool:
        self._connected = True
        return True

    def apply_label(self, message_id: str, label: str) -> bool:
        return True

    def move_to_folder(self, message_id: str, folder: str) -> bool:
        return True

    def send_message(self, to: str, subject: str, body: str) -> Dict[str, Any]:
        return {"status": "sent", "to": to, "subject": subject}

__all__ = ["GmailClient"]
