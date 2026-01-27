"""
Mode 2: Gmail On-Demand Check
=============================
Privacy-first email analysis via Gmail API.

Users click a button to check specific suspicious emails.
Only the selected email is fetched and analyzed.
Results are NOT stored unless user explicitly consents.

Components:
- service.py: GmailAPIService - Gmail API integration
- orchestrator.py: GmailOrchestrator - On-demand processing
- oauth.py: GmailOAuthHandler - OAuth token management
- models.py: Gmail-specific data models

Configuration:
- GMAIL_CLIENT_ID: OAuth client ID
- GMAIL_CLIENT_SECRET: OAuth client secret
- Required scope: gmail.readonly (minimal access)

Privacy Features:
- Short-lived tokens (no refresh tokens by default)
- No storage without consent
- Minimal scope (read-only, single message)
"""

from app.modes.base import ModeType

MODE = ModeType.GMAIL_ONDEMAND

# Lazy imports to avoid circular dependencies
def get_service():
    from app.modes.gmail.service import GmailAPIService
    return GmailAPIService()

def get_orchestrator():
    from app.modes.gmail.orchestrator import GmailOrchestrator
    return GmailOrchestrator()

__all__ = [
    "MODE",
    "get_service",
    "get_orchestrator",
]
