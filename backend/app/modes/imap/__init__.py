"""
Mode 1: IMAP Bulk Forward
=========================
Automatic email analysis for forwarded emails.

Users forward suspicious emails to a central inbox (e.g., phishnet@company.com).
The system polls the inbox, analyzes emails, and sends back reports.

Components:
- service.py: IMAPEmailService - IMAP connection and email fetching
- orchestrator.py: IMAPOrchestrator - Processing pipeline coordinator
- poller.py: IMAPPollingService - Background polling logic
- worker.py: IMAPPollingWorker - Background worker process
- models.py: IMAP-specific data models
- handlers.py: Event handlers for IMAP events

Configuration:
- IMAP_HOST: IMAP server hostname
- IMAP_USER: IMAP username/email
- IMAP_PASSWORD: IMAP password or app password
- IMAP_FOLDER: Folder to monitor (default: INBOX)
- IMAP_POLL_INTERVAL: Seconds between polls (default: 60)
"""

from app.modes.base import ModeType

MODE = ModeType.IMAP_BULK

# Lazy imports to avoid circular dependencies
def get_service():
    from app.modes.imap.service import IMAPEmailService
    return IMAPEmailService()

def get_orchestrator():
    from app.modes.imap.orchestrator import IMAPOrchestrator
    return IMAPOrchestrator()

__all__ = [
    "MODE",
    "get_service",
    "get_orchestrator",
]
