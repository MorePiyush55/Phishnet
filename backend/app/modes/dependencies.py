"""
Mode Dependencies
=================
Dependency injection and factory functions for mode components.

This module provides a clean interface for obtaining mode-specific
services and orchestrators without tight coupling.

Usage:
    from app.modes.dependencies import get_orchestrator, ModeType
    
    # Get specific mode orchestrator
    imap_orch = get_orchestrator(ModeType.IMAP_BULK)
    gmail_orch = get_orchestrator(ModeType.GMAIL_ONDEMAND)
    
    # Or use FastAPI dependency injection
    @router.post("/analyze")
    async def analyze(orchestrator = Depends(get_imap_orchestrator_dep)):
        ...
"""

from functools import lru_cache
from typing import Union

from app.modes.base import ModeType, ModeOrchestrator, EmailFetcher


# ============================================================================
# Singleton Factories (Cached)
# ============================================================================

@lru_cache()
def get_imap_service():
    """Get singleton IMAP email service."""
    from app.modes.imap.service import IMAPEmailService
    return IMAPEmailService()


@lru_cache()
def get_gmail_service():
    """Get singleton Gmail API service."""
    from app.modes.gmail.service import GmailAPIService
    return GmailAPIService()


@lru_cache()
def get_imap_orchestrator():
    """Get singleton IMAP orchestrator."""
    from app.modes.imap.orchestrator import IMAPOrchestrator
    return IMAPOrchestrator(imap_service=get_imap_service())


@lru_cache()
def get_gmail_orchestrator():
    """Get singleton Gmail orchestrator."""
    from app.modes.gmail.orchestrator import GmailOrchestrator
    return GmailOrchestrator(gmail_service=get_gmail_service())


# ============================================================================
# Generic Factories
# ============================================================================

def get_service(mode: ModeType) -> EmailFetcher:
    """
    Get email fetcher service for specified mode.
    
    Args:
        mode: The operating mode
        
    Returns:
        EmailFetcher implementation for the mode
        
    Raises:
        ValueError: If mode is not supported
    """
    if mode == ModeType.IMAP_BULK:
        return get_imap_service()
    elif mode == ModeType.GMAIL_ONDEMAND:
        return get_gmail_service()
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def get_orchestrator(mode: ModeType) -> ModeOrchestrator:
    """
    Get orchestrator for specified mode.
    
    Args:
        mode: The operating mode
        
    Returns:
        ModeOrchestrator implementation for the mode
        
    Raises:
        ValueError: If mode is not supported
    """
    if mode == ModeType.IMAP_BULK:
        return get_imap_orchestrator()
    elif mode == ModeType.GMAIL_ONDEMAND:
        return get_gmail_orchestrator()
    else:
        raise ValueError(f"Unsupported mode: {mode}")


# ============================================================================
# FastAPI Dependencies
# ============================================================================

async def get_imap_orchestrator_dep():
    """FastAPI dependency for IMAP orchestrator."""
    return get_imap_orchestrator()


async def get_gmail_orchestrator_dep():
    """FastAPI dependency for Gmail orchestrator."""
    return get_gmail_orchestrator()


async def get_imap_service_dep():
    """FastAPI dependency for IMAP service."""
    return get_imap_service()


async def get_gmail_service_dep():
    """FastAPI dependency for Gmail service."""
    return get_gmail_service()


# ============================================================================
# Shared Components
# ============================================================================

@lru_cache()
def get_phishing_analyzer():
    """Get singleton phishing analyzer (shared by all modes)."""
    try:
        from app.services.enhanced_phishing_analyzer import EnhancedPhishingAnalyzer
        return EnhancedPhishingAnalyzer()
    except ImportError:
        # Will be moved to app.core.analysis later
        raise ImportError("EnhancedPhishingAnalyzer not available")


@lru_cache()
def get_gemini_client():
    """Get singleton Gemini AI client (shared by all modes)."""
    try:
        from app.services.gemini import GeminiClient
        return GeminiClient()
    except ImportError:
        raise ImportError("GeminiClient not available")


@lru_cache()
def get_email_sender():
    """Get email sender service (shared by all modes)."""
    try:
        from app.services.email_sender import send_email
        return send_email
    except ImportError:
        raise ImportError("Email sender not available")


# ============================================================================
# Cleanup
# ============================================================================

def clear_caches():
    """
    Clear all cached singleton instances.
    
    Useful for testing or when configuration changes.
    """
    get_imap_service.cache_clear()
    get_gmail_service.cache_clear()
    get_imap_orchestrator.cache_clear()
    get_gmail_orchestrator.cache_clear()
    get_phishing_analyzer.cache_clear()
    get_gemini_client.cache_clear()
    get_email_sender.cache_clear()


__all__ = [
    # Mode enum
    "ModeType",
    
    # Service factories
    "get_imap_service",
    "get_gmail_service",
    "get_service",
    
    # Orchestrator factories
    "get_imap_orchestrator",
    "get_gmail_orchestrator",
    "get_orchestrator",
    
    # FastAPI dependencies
    "get_imap_orchestrator_dep",
    "get_gmail_orchestrator_dep",
    "get_imap_service_dep",
    "get_gmail_service_dep",
    
    # Shared components
    "get_phishing_analyzer",
    "get_gemini_client",
    "get_email_sender",
    
    # Utilities
    "clear_caches",
]
