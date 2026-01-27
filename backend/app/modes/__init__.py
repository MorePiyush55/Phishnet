"""
PhishNet Operating Modes
========================

This package contains cleanly separated implementations for each operating mode:

Mode 1 - IMAP Bulk Forward (Enterprise)
---------------------------------------
- Location: modes/imap/
- Purpose: Polls shared inbox for forwarded suspicious emails
- Target: Enterprise security teams
- Trigger: Background polling + manual inbox scan
- Data flow: IMAP → Parse → Analyze → Store → Alert

Mode 2 - Gmail API On-Demand (Consumer)
---------------------------------------
- Location: modes/gmail/
- Purpose: User-initiated email verification via OAuth
- Target: Individual Gmail users
- Trigger: User clicks "Check this email"
- Data flow: OAuth → Gmail API → Analyze → Display result

Each mode is fully isolated with its own:
- Email fetching service (implements EmailFetcher)
- Orchestrator (implements ModeOrchestrator)
- API routes (in api/v1/imap/ and api/v2/gmail/)

Shared components (analyzers, AI, notifications) live in core/

Usage:
    # Import base classes
    from app.modes import ModeType, ModeOrchestrator
    
    # Use dependency injection
    from app.modes.dependencies import get_orchestrator
    orchestrator = get_orchestrator(ModeType.IMAP_BULK)
    
    # Or import specific implementations
    from app.modes.imap import get_orchestrator as get_imap_orchestrator
    from app.modes.gmail import get_orchestrator as get_gmail_orchestrator
"""

from .base import (
    ModeType,
    AnalysisStatus,
    Verdict,
    EmailMetadata,
    AnalysisRequest,
    AnalysisResult,
    FetchedEmail,
    EmailFetcher,
    ModeOrchestrator,
    AnalysisEngine,
)

from .dependencies import (
    get_service,
    get_orchestrator,
    get_imap_service,
    get_gmail_service,
    get_imap_orchestrator,
    get_gmail_orchestrator,
    get_imap_orchestrator_dep,
    get_gmail_orchestrator_dep,
    clear_caches,
)

__all__ = [
    # Enums and types
    "ModeType",
    "AnalysisStatus",
    "Verdict",
    
    # Data classes
    "EmailMetadata",
    "AnalysisRequest",
    "AnalysisResult",
    "FetchedEmail",
    
    # Abstract base classes
    "EmailFetcher",
    "ModeOrchestrator",
    "AnalysisEngine",
    
    # Factory functions
    "get_service",
    "get_orchestrator",
    "get_imap_service",
    "get_gmail_service",
    "get_imap_orchestrator",
    "get_gmail_orchestrator",
    
    # FastAPI dependencies
    "get_imap_orchestrator_dep",
    "get_gmail_orchestrator_dep",
    
    # Utilities
    "clear_caches",
]
