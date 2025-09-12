"""Common utilities and interfaces for PhishNet."""

from .constants import *
from .interfaces import *

__all__ = [
    # Constants
    "ThreatLevel", "UserRole", "OperationType", "OperationStatus", "Constants", "StatusMessages", "ErrorCodes",
    
    # Data structures  
    "AnalysisResult", "EmailContent", "ActionRequest", "ActionResult", "ProcessingStatus",
    
    # Interfaces
    "IEmailProcessor", "IThreatAnalyzer", "IResponseHandler", "IOrchestrator",
    "IDataStore", "INotificationService", "IAuditLogger", "IConfigurationManager", "IHealthMonitor",
    
    # Base classes
    "BaseProcessor", "BaseAnalyzer", "BaseHandler",
    "ValidationMessages"
]
