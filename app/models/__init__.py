"""Models module for PhishNet application - organized into packages."""

# Import all models to ensure they are registered with SQLAlchemy
# Import from organized packages
from .core import User, Email, EmailStatus
from .analysis import Detection, EmailAction, AuditLog, ScoringRule, EmailScore, LinkAnalysis, EmailAIResults, EmailIndicators  
from .security import FederatedModel, FederatedClient, FederatedTrainingRound, RefreshToken

# Import UserRole from centralized constants
from src.common.constants import UserRole

# Backward compatibility will be added later once old files are removed

__all__ = [
    "User", "UserRole", 
    "Email", "EmailStatus",
    "Detection",
    "FederatedModel", "FederatedClient", "FederatedTrainingRound",
    "LinkAnalysis", "EmailAIResults", "EmailIndicators",
    "EmailAction", "AuditLog", "ScoringRule", "EmailScore", 
    "RefreshToken"
]

