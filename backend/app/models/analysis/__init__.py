"""Analysis models package - detection and analysis results."""

from .detection import Detection
from .scoring import EmailAction, AuditLog, ScoringRule, EmailScore
from .link_analysis import LinkAnalysis, EmailAIResults, EmailIndicators

__all__ = [
    "Detection",
    "EmailAction", 
    "AuditLog",
    "ScoringRule",
    "EmailScore",
    "LinkAnalysis",
    "EmailAIResults", 
    "EmailIndicators"
]
