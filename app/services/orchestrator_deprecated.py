"""
DEPRECATED: This orchestrator has been deprecated.

Use app.core.orchestrator.PhishNetOrchestrator instead.
This is the single source of truth orchestrator.

Import from:
- from app.orchestrator import PhishNetOrchestrator, get_orchestrator
- from app.orchestrator.utils import email_orchestrator, process_email_comprehensive

This file will be removed in a future version.
"""

import warnings
from app.orchestrator.utils import (
    EmailOrchestratorAdapter,
    AnalysisOrchestrator,
    email_orchestrator,
    process_email_comprehensive
)

warnings.warn(
    "app.services.orchestrator is deprecated. "
    "Use app.core.orchestrator.PhishNetOrchestrator instead. "
    "Import from app.orchestrator.utils for compatibility functions.",
    DeprecationWarning,
    stacklevel=2
)

# Backward compatibility exports
EnhancedEmailOrchestrator = EmailOrchestratorAdapter
__all__ = [
    "EnhancedEmailOrchestrator", 
    "AnalysisOrchestrator", 
    "email_orchestrator",
    "process_email_comprehensive"
]
