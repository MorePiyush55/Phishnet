"""Models module for PhishNet application - MongoDB Only."""

# Import MongoDB document models only
from .mongodb_models import (
    User,
    EmailAnalysis, 
    ThreatIntelligence,
    AnalysisJob,
    AuditLog,
    DOCUMENT_MODELS
)

__all__ = [
    "User",
    "EmailAnalysis", 
    "ThreatIntelligence",
    "AnalysisJob",
    "AuditLog",
    "DOCUMENT_MODELS"
]

