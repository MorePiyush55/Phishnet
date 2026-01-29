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
# Analysis Engine Aliases (PHASE 4: Core Extraction)
# ============================================================================

try:
    # NEW: Import from core/analysis
    from app.core.analysis.phishing_analyzer import (
        EnhancedPhishingAnalyzer as _EnhancedPhishingAnalyzer,
        ComprehensivePhishingAnalysis,
        SenderAnalysis,
        ContentAnalysis,
        LinkAnalysis,
        AuthenticationAnalysis,
        AttachmentAnalysis,
    )
    
    # Provide backward compatibility for old import path
    class EnhancedPhishingAnalyzer(_EnhancedPhishingAnalyzer):
        """
        DEPRECATED: Use app.core.analysis.phishing_analyzer.EnhancedPhishingAnalyzer instead.
        """
        def __init__(self, *args, **kwargs):
            _deprecated_import("app.services.enhanced_phishing_analyzer", "app.core.analysis.phishing_analyzer")
            super().__init__(*args, **kwargs)
    
except ImportError:
    # Fallback to old location if core/ migration not complete
    try:
        from app.services.enhanced_phishing_analyzer import (
            EnhancedPhishingAnalyzer,
            ComprehensivePhishingAnalysis,
            SenderAnalysis,
            ContentAnalysis,
            LinkAnalysis,
            AuthenticationAnalysis,
            AttachmentAnalysis,
        )
    except ImportError:
        pass


# ============================================================================
# AI Services Aliases (PHASE 4: Core Extraction)
# ============================================================================

try:
    # NEW: Import from core/ai
    from app.core.ai.gemini import GeminiClient as _GeminiClient
    
    class GeminiClient(_GeminiClient):
        """
        DEPRECATED: Use app.core.ai.gemini.GeminiClient instead.
        """
        def __init__(self, *args, **kwargs):
            _deprecated_import("app.services.gemini", "app.core.ai.gemini")
            super().__init__(*args, **kwargs)
    
    # Alias for backward compatibility
    GeminiAI = GeminiClient
    
except ImportError:
    # Fallback to old location
    try:
        from app.services.gemini import GeminiClient
        GeminiAI = GeminiClient
    except ImportError:
        pass


# ============================================================================
# Messaging Services Aliases (PHASE 4: Core Extraction)
# ============================================================================

try:
    # NEW: Import from core/messaging (these are functions, not classes)
    from app.core.messaging.sender import (
        send_email,
        send_email_sync,
        send_email_smtp_with_fallback,
        send_email_via_resend,
        send_email_via_brevo,
    )
    
    # Log deprecation warning when module is imported
    import warnings
    warnings.warn(
        "Importing from app.services.email_sender is deprecated. Use app.core.messaging.sender instead.",
        DeprecationWarning,
        stacklevel=2
    )
    
except ImportError:
    # Fallback to old location
    try:
        from app.services.email_sender import (
            send_email,
            send_email_sync,
            send_email_smtp_with_fallback,
            send_email_via_resend,
            send_email_via_brevo,
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
    
    # Core Services (Phase 4)
    "EnhancedPhishingAnalyzer",
    "ComprehensivePhishingAnalysis",
    "SenderAnalysis",
    "ContentAnalysis",
    "LinkAnalysis",
    "AuthenticationAnalysis",
    "AttachmentAnalysis",
    "GeminiClient",
    "GeminiAI",
    # Email sender functions
    "send_email",
    "send_email_sync",
    "send_email_smtp_with_fallback",
    "send_email_via_resend",
    "send_email_via_brevo",
]
