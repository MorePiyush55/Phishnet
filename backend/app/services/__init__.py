"""Services module for PhishNet application - organized into packages."""

# Import from organized packages
from .email import EmailProcessor, gmail_service
from .analysis import ai_analyzer, analyze_email_with_ai, analyze_email_links, ScoringEngine
from .threat_intel import analyze_email_threat_intel, threat_intel_service, AuditService

# Backward compatibility imports removed to prevent circular imports
# Use: from app.orchestrator import get_orchestrator instead

__all__ = [
    # Email services
    "EmailProcessor", "gmail_service",
    # Analysis services  
    "ai_analyzer", "analyze_email_with_ai", "analyze_email_links", "ScoringEngine",
    # Threat intelligence services
    "analyze_email_threat_intel", "threat_intel_service", "AuditService"
]

