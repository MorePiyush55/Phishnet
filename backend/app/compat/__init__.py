"""
Backward Compatibility Layer
============================
Provides aliases for old import paths during migration.

This module allows existing code to continue working while
we migrate to the new modes/ structure.

DEPRECATION NOTICE:
These aliases will be removed in a future version.
Please update your imports to use the new paths:

OLD: from app.services.quick_imap import QuickIMAPService
NEW: from app.modes.imap.service import IMAPEmailService

OLD: from app.services.gmail_ondemand import GmailOnDemandService
NEW: from app.modes.gmail.service import GmailAPIService

OLD: from app.services.ondemand_orchestrator import OnDemandOrchestrator
NEW: from app.modes.imap.orchestrator import IMAPOrchestrator
"""

import warnings
from functools import wraps

# Emit deprecation warnings when using old imports
def _deprecated_import(old_name: str, new_path: str):
    """Emit deprecation warning for old import."""
    warnings.warn(
        f"{old_name} is deprecated. Use {new_path} instead.",
        DeprecationWarning,
        stacklevel=3
    )

# ============================================================================
# IMAP Mode Aliases (Mode 1)
# ============================================================================

# QuickIMAPService -> IMAPEmailService
try:
    from app.modes.imap.service import IMAPEmailService as _IMAPEmailService
    from app.modes.imap.service import get_imap_service as _get_imap_service
    
    class QuickIMAPService(_IMAPEmailService):
        """
        DEPRECATED: Use app.modes.imap.service.IMAPEmailService instead.
        """
        def __init__(self, *args, **kwargs):
            _deprecated_import("QuickIMAPService", "app.modes.imap.service.IMAPEmailService")
            super().__init__(*args, **kwargs)
    
    def get_quick_imap_service():
        """DEPRECATED: Use app.modes.imap.service.get_imap_service instead."""
        _deprecated_import("get_quick_imap_service", "app.modes.imap.service.get_imap_service")
        return _get_imap_service()

except ImportError:
    # Fallback if new module not available yet
    pass


# Mode1Orchestrator -> IMAPOrchestrator
try:
    from app.modes.imap.orchestrator import IMAPOrchestrator as _IMAPOrchestrator
    from app.modes.imap.orchestrator import get_imap_orchestrator as _get_imap_orchestrator
    
    class Mode1Orchestrator(_IMAPOrchestrator):
        """
        DEPRECATED: Use app.modes.imap.orchestrator.IMAPOrchestrator instead.
        """
        def __init__(self, *args, **kwargs):
            _deprecated_import("Mode1Orchestrator", "app.modes.imap.orchestrator.IMAPOrchestrator")
            super().__init__(*args, **kwargs)
    
    def get_mode1_orchestrator():
        """DEPRECATED: Use app.modes.imap.orchestrator.get_imap_orchestrator instead."""
        _deprecated_import("get_mode1_orchestrator", "app.modes.imap.orchestrator.get_imap_orchestrator")
        return _get_imap_orchestrator()

except ImportError:
    pass


# OnDemandOrchestrator (the IMAP-based one) -> IMAPOrchestrator
try:
    from app.modes.imap.orchestrator import IMAPOrchestrator as _IMAPOrchestrator2
    from app.modes.imap.orchestrator import get_imap_orchestrator as _get_imap_orchestrator2
    
    class OnDemandOrchestrator(_IMAPOrchestrator2):
        """
        DEPRECATED: Use app.modes.imap.orchestrator.IMAPOrchestrator instead.
        
        Note: Despite the name, this was actually used for IMAP-based processing.
        """
        def __init__(self, *args, **kwargs):
            _deprecated_import("OnDemandOrchestrator", "app.modes.imap.orchestrator.IMAPOrchestrator")
            super().__init__(*args, **kwargs)
    
    def get_ondemand_orchestrator():
        """DEPRECATED: Use app.modes.imap.orchestrator.get_imap_orchestrator instead."""
        _deprecated_import("get_ondemand_orchestrator", "app.modes.imap.orchestrator.get_imap_orchestrator")
        return _get_imap_orchestrator2()

except ImportError:
    pass


# ============================================================================
# Gmail Mode Aliases (Mode 2)
# ============================================================================

# GmailOnDemandService -> GmailAPIService
try:
    from app.modes.gmail.service import GmailAPIService as _GmailAPIService
    from app.modes.gmail.service import get_gmail_service as _get_gmail_service
    
    class GmailOnDemandService(_GmailAPIService):
        """
        DEPRECATED: Use app.modes.gmail.service.GmailAPIService instead.
        """
        def __init__(self, *args, **kwargs):
            _deprecated_import("GmailOnDemandService", "app.modes.gmail.service.GmailAPIService")
            super().__init__(*args, **kwargs)
    
    def get_gmail_ondemand_service():
        """DEPRECATED: Use app.modes.gmail.service.get_gmail_service instead."""
        _deprecated_import("get_gmail_ondemand_service", "app.modes.gmail.service.get_gmail_service")
        return _get_gmail_service()
    
    # Also provide as singleton instance for direct import
    gmail_ondemand_service = _get_gmail_service()

except ImportError:
    pass


# GmailOrchestrator
try:
    from app.modes.gmail.orchestrator import GmailOrchestrator as _GmailOrchestrator
    from app.modes.gmail.orchestrator import get_gmail_orchestrator as _get_gmail_orchestrator
    
    # Re-export directly (no wrapper needed, name is the same)
    GmailOrchestrator = _GmailOrchestrator
    get_gmail_orchestrator = _get_gmail_orchestrator

except ImportError:
    pass


# ============================================================================
# Base Classes and Types
# ============================================================================

try:
    from app.modes.base import (
        ModeType,
        AnalysisRequest,
        AnalysisResult,
        AnalysisStatus,
        Verdict,
        EmailMetadata,
        FetchedEmail,
        EmailFetcher,
        ModeOrchestrator,
    )
except ImportError:
    pass


# ============================================================================
# Analysis Engine Aliases
# ============================================================================

try:
    # EnhancedPhishingAnalyzer will eventually move to core/analysis
    # For now, keep the original import working
    from app.services.enhanced_phishing_analyzer import (
        EnhancedPhishingAnalyzer,
        ComprehensivePhishingAnalysis,
    )
except ImportError:
    pass


# ============================================================================
# Export All Aliases
# ============================================================================

__all__ = [
    # IMAP Mode (Mode 1)
    "QuickIMAPService",
    "get_quick_imap_service",
    "Mode1Orchestrator",
    "get_mode1_orchestrator",
    "OnDemandOrchestrator",
    "get_ondemand_orchestrator",
    
    # Gmail Mode (Mode 2)
    "GmailOnDemandService",
    "get_gmail_ondemand_service",
    "gmail_ondemand_service",
    "GmailOrchestrator",
    "get_gmail_orchestrator",
    
    # Base Types
    "ModeType",
    "AnalysisRequest",
    "AnalysisResult",
    "AnalysisStatus",
    "Verdict",
    "EmailMetadata",
    "FetchedEmail",
    "EmailFetcher",
    "ModeOrchestrator",
    
    # Analysis (temporary)
    "EnhancedPhishingAnalyzer",
    "ComprehensivePhishingAnalysis",
]
