"""Abstract base classes and interfaces for PhishNet architecture."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union, AsyncIterator
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

from src.common.constants import ThreatLevel, OperationType


@dataclass
class AnalysisResult:
    """Standard analysis result structure."""
    confidence: float  # 0.0 to 1.0
    threat_level: ThreatLevel
    risk_score: float  # 0.0 to 1.0
    indicators: List[str]
    metadata: Dict[str, Any]
    timestamp: datetime
    processing_time_ms: Optional[int] = None
    

@dataclass
class EmailContent:
    """Standardized email content structure."""
    subject: str
    sender: str
    recipients: List[str]
    body_text: str
    body_html: Optional[str] = None
    headers: Dict[str, str] = None
    attachments: List[Dict[str, Any]] = None
    

@dataclass 
class ActionRequest:
    """Standardized action request structure."""
    action_type: str
    email_id: int
    user_id: int
    parameters: Dict[str, Any]
    reason: Optional[str] = None


@dataclass
class ActionResult:
    """Standardized action result structure."""
    success: bool
    message: str
    action_id: Optional[int] = None
    metadata: Dict[str, Any] = None


class ProcessingStatus(Enum):
    """Email processing status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class IEmailProcessor(ABC):
    """Abstract interface for email processing."""
    
    @abstractmethod
    async def process_email(self, email_content: EmailContent) -> Dict[str, Any]:
        """Process a single email and return analysis results."""
        pass
    
    @abstractmethod
    async def batch_process(self, emails: List[EmailContent]) -> List[Dict[str, Any]]:
        """Process multiple emails in batch."""
        pass
    
    @abstractmethod
    def get_processing_status(self, email_id: int) -> ProcessingStatus:
        """Get the current processing status of an email."""
        pass
    
    @abstractmethod
    async def extract_features(self, email_content: EmailContent) -> Dict[str, Any]:
        """Extract features from email for analysis."""
        pass


class IThreatAnalyzer(ABC):
    """Abstract interface for threat analysis."""
    
    @abstractmethod
    async def analyze_content(self, content: str, content_type: str = "text") -> AnalysisResult:
        """Analyze content for threats."""
        pass
    
    @abstractmethod
    async def analyze_urls(self, urls: List[str]) -> Dict[str, AnalysisResult]:
        """Analyze URLs for threats."""
        pass
    
    @abstractmethod
    async def analyze_attachments(self, attachments: List[Dict[str, Any]]) -> Dict[str, AnalysisResult]:
        """Analyze email attachments."""
        pass
    
    @abstractmethod
    def get_threat_indicators(self, analysis: AnalysisResult) -> List[str]:
        """Extract threat indicators from analysis."""
        pass
    
    @abstractmethod
    async def update_threat_intelligence(self) -> bool:
        """Update threat intelligence data."""
        pass


class IResponseHandler(ABC):
    """Abstract interface for response handling."""
    
    @abstractmethod
    async def execute_action(self, action: ActionRequest) -> ActionResult:
        """Execute a response action."""
        pass
    
    @abstractmethod
    async def batch_execute(self, actions: List[ActionRequest]) -> List[ActionResult]:
        """Execute multiple actions in batch."""
        pass
    
    @abstractmethod
    def validate_action(self, action: ActionRequest) -> bool:
        """Validate if an action can be executed."""
        pass
    
    @abstractmethod
    async def rollback_action(self, action_id: int) -> ActionResult:
        """Rollback a previously executed action."""
        pass
    
    @abstractmethod
    def get_available_actions(self, email_id: int) -> List[str]:
        """Get available actions for an email."""
        pass


class IOrchestrator(ABC):
    """Abstract interface for orchestration."""
    
    @abstractmethod
    async def orchestrate_email_analysis(self, email_content: EmailContent) -> Dict[str, Any]:
        """Orchestrate complete email analysis pipeline."""
        pass
    
    @abstractmethod
    async def orchestrate_response(self, email_id: int, response_type: str, **kwargs) -> ActionResult:
        """Orchestrate response actions."""
        pass
    
    @abstractmethod
    def register_processor(self, processor: IEmailProcessor) -> None:
        """Register an email processor."""
        pass
    
    @abstractmethod
    def register_analyzer(self, analyzer: IThreatAnalyzer) -> None:
        """Register a threat analyzer."""
        pass
    
    @abstractmethod
    def register_handler(self, handler: IResponseHandler) -> None:
        """Register a response handler."""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, bool]:
        """Check health of all components."""
        pass


class IDataStore(ABC):
    """Abstract interface for data storage."""
    
    @abstractmethod
    async def store_email(self, email_content: EmailContent) -> int:
        """Store email and return email ID."""
        pass
    
    @abstractmethod
    async def store_analysis(self, email_id: int, analysis: AnalysisResult) -> int:
        """Store analysis results."""
        pass
    
    @abstractmethod
    async def store_action(self, action: ActionRequest, result: ActionResult) -> int:
        """Store action execution record."""
        pass
    
    @abstractmethod
    async def get_email(self, email_id: int) -> Optional[EmailContent]:
        """Retrieve email by ID."""
        pass
    
    @abstractmethod
    async def get_analysis(self, email_id: int) -> Optional[AnalysisResult]:
        """Retrieve analysis for email."""
        pass
    
    @abstractmethod
    async def query_emails(self, filters: Dict[str, Any], limit: int = 100) -> List[Dict[str, Any]]:
        """Query emails with filters."""
        pass


class INotificationService(ABC):
    """Abstract interface for notifications."""
    
    @abstractmethod
    async def send_alert(self, level: ThreatLevel, message: str, recipients: List[str]) -> bool:
        """Send threat alert notification."""
        pass
    
    @abstractmethod
    async def send_report(self, report_type: str, data: Dict[str, Any], recipients: List[str]) -> bool:
        """Send analysis report."""
        pass
    
    @abstractmethod
    def configure_channels(self, channels: Dict[str, Dict[str, Any]]) -> None:
        """Configure notification channels."""
        pass


class IAuditLogger(ABC):
    """Abstract interface for audit logging."""
    
    @abstractmethod
    async def log_operation(self, operation: OperationType, details: Dict[str, Any], user_id: Optional[int] = None) -> None:
        """Log system operation."""
        pass
    
    @abstractmethod
    async def log_access(self, resource: str, user_id: int, operation: str, success: bool) -> None:
        """Log access attempt."""
        pass
    
    @abstractmethod
    async def get_audit_trail(self, filters: Dict[str, Any]) -> AsyncIterator[Dict[str, Any]]:
        """Retrieve audit trail."""
        pass


class IConfigurationManager(ABC):
    """Abstract interface for configuration management."""
    
    @abstractmethod
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get configuration setting."""
        pass
    
    @abstractmethod
    def set_setting(self, key: str, value: Any) -> bool:
        """Set configuration setting."""
        pass
    
    @abstractmethod
    def validate_configuration(self) -> List[str]:
        """Validate configuration and return errors."""
        pass
    
    @abstractmethod
    def reload_configuration(self) -> bool:
        """Reload configuration from source."""
        pass


class IHealthMonitor(ABC):
    """Abstract interface for health monitoring."""
    
    @abstractmethod
    async def check_component_health(self, component_name: str) -> Dict[str, Any]:
        """Check health of specific component."""
        pass
    
    @abstractmethod
    async def check_system_health(self) -> Dict[str, Any]:
        """Check overall system health."""
        pass
    
    @abstractmethod
    def register_health_check(self, name: str, check_func: callable) -> None:
        """Register a health check function."""
        pass


# Utility base classes for common functionality

class BaseProcessor:
    """Base class with common processor functionality."""
    
    def __init__(self):
        self._initialized = False
        self._stats = {"processed": 0, "errors": 0, "start_time": datetime.now()}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        uptime = (datetime.now() - self._stats["start_time"]).total_seconds()
        return {
            **self._stats,
            "uptime_seconds": uptime,
            "success_rate": (self._stats["processed"] - self._stats["errors"]) / max(1, self._stats["processed"])
        }
    
    def _increment_stat(self, stat_name: str, amount: int = 1) -> None:
        """Increment a statistic counter."""
        self._stats[stat_name] = self._stats.get(stat_name, 0) + amount


class BaseAnalyzer:
    """Base class with common analyzer functionality."""
    
    def __init__(self):
        self._confidence_threshold = 0.5
        self._cache = {}
        self._cache_ttl = 300  # 5 minutes
    
    def set_confidence_threshold(self, threshold: float) -> None:
        """Set minimum confidence threshold.""" 
        if 0.0 <= threshold <= 1.0:
            self._confidence_threshold = threshold
        else:
            raise ValueError("Confidence threshold must be between 0.0 and 1.0")
    
    def _is_high_confidence(self, result: AnalysisResult) -> bool:
        """Check if analysis result meets confidence threshold."""
        return result.confidence >= self._confidence_threshold
    
    def _cache_result(self, key: str, result: Any, ttl: Optional[int] = None) -> None:
        """Cache analysis result."""
        cache_time = datetime.now()
        self._cache[key] = {
            "result": result, 
            "timestamp": cache_time,
            "ttl": ttl or self._cache_ttl
        }
    
    def _get_cached_result(self, key: str) -> Optional[Any]:
        """Get cached result if valid."""
        if key in self._cache:
            cached = self._cache[key]
            age = (datetime.now() - cached["timestamp"]).total_seconds()
            if age < cached["ttl"]:
                return cached["result"]
            else:
                del self._cache[key]
        return None


class BaseHandler:
    """Base class with common handler functionality."""
    
    def __init__(self):
        self._action_history = []
        self._max_history = 1000
    
    def _record_action(self, action: ActionRequest, result: ActionResult) -> None:
        """Record action execution."""
        record = {
            "action": action,
            "result": result, 
            "timestamp": datetime.now()
        }
        self._action_history.append(record)
        
        # Keep history within limits
        if len(self._action_history) > self._max_history:
            self._action_history = self._action_history[-self._max_history:]
    
    def get_action_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get action execution history."""
        history = self._action_history
        if limit:
            history = history[-limit:]
        return history
    
    def _validate_action_request(self, action: ActionRequest) -> List[str]:
        """Validate action request and return errors."""
        errors = []
        
        if not action.action_type:
            errors.append("Action type is required")
        
        if action.email_id <= 0:
            errors.append("Valid email ID is required")
        
        if action.user_id <= 0:
            errors.append("Valid user ID is required")
        
        return errors
