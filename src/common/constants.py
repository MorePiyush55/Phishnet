"""
Single source of truth constants and enums to prevent circular imports.
All enums and constants used across the PhishNet application.
"""

from enum import Enum


# User and Authentication Enums
class UserRole(Enum):
    USER = "user"
    VIEWER = "viewer"  # Basic read-only access
    ANALYST = "analyst"
    ADMIN = "admin"
    SYSTEM = "system"


class UserStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"


# Threat and Security Enums
class ThreatLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class RiskScore(Enum):
    SAFE = 0
    LOW_RISK = 1
    MEDIUM_RISK = 2
    HIGH_RISK = 3
    CRITICAL_RISK = 4


class DetectionStatus(Enum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    QUARANTINED = "quarantined"


# Email Processing Enums
class EmailStatus(Enum):
    RECEIVED = "received"
    PROCESSING = "processing"
    ANALYZED = "analyzed"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    QUARANTINED = "quarantined"


class EmailPriority(Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


# Link Analysis Enums
class LinkStatus(Enum):
    PENDING = "pending"
    ANALYZING = "analyzing" 
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    BLOCKED = "blocked"


class LinkType(Enum):
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    EMAIL = "email"
    FILE = "file"
    OTHER = "other"


# Feature Flag Enums
class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class FeatureStatus(Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    TESTING = "testing"
    DEPRECATED = "deprecated"


# Orchestrator and Processing Enums
class OperationType(Enum):
    EMAIL_INGEST = "email_ingest"
    EMAIL_ANALYSIS = "email_analysis"
    LINK_EXTRACTION = "link_extraction"
    THREAT_INTEL = "threat_intel"
    RISK_SCORING = "risk_scoring"
    RESPONSE_ACTION = "response_action"


class OperationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Circuit Breaker States
class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


# Cache Strategy Enums
class CacheStrategy(Enum):
    TTL = "ttl"
    LRU = "lru"
    LFU = "lfu"
    WRITE_THROUGH = "write_through"
    WRITE_BACK = "write_back"


# Retry Strategy Enums
class RetryStrategy(Enum):
    FIXED_DELAY = "fixed_delay"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    JITTERED_BACKOFF = "jittered_backoff"


# API Response Status
class APIStatus(Enum):
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


# Logging Levels
class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# ML Model Status
class ModelStatus(Enum):
    TRAINING = "training"
    READY = "ready"
    DEPLOYED = "deployed"
    DEPRECATED = "deprecated"
    ERROR = "error"


# Sandbox Analysis Results
class SandboxResult(Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"
    TIMEOUT = "timeout"


# External API Status
class ExternalAPIStatus(Enum):
    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"


# Constants
class Constants:
    """Application-wide constants"""
    
    # Security
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRE_MINUTES = 60
    BCRYPT_ROUNDS = 12
    
    # Rate Limiting
    DEFAULT_RATE_LIMIT = "100/minute"
    AUTH_RATE_LIMIT = "5/minute"
    
    # Cache TTL (seconds)
    DEFAULT_CACHE_TTL = 3600  # 1 hour
    THREAT_INTEL_TTL = 7200   # 2 hours
    LINK_ANALYSIS_TTL = 1800  # 30 minutes
    EMAIL_ANALYSIS_TTL = 600  # 10 minutes
    
    # File Sizes
    MAX_EMAIL_SIZE = 25 * 1024 * 1024  # 25MB
    MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10MB
    
    # Timeouts (seconds)
    DEFAULT_TIMEOUT = 30
    EXTERNAL_API_TIMEOUT = 60
    DATABASE_TIMEOUT = 10
    
    # Retry Configuration
    MAX_RETRIES = 3
    RETRY_BACKOFF_FACTOR = 2.0
    
    # Circuit Breaker
    CIRCUIT_FAILURE_THRESHOLD = 5
    CIRCUIT_RECOVERY_TIMEOUT = 60
    
    # Feature Flags
    FEATURE_FLAG_CACHE_TTL = 300  # 5 minutes
    
    # Database
    DATABASE_POOL_SIZE = 20
    DATABASE_MAX_OVERFLOW = 30
    
    # Security Headers
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
    }
    
    # CORS Settings
    CORS_ORIGINS = [
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080"
    ]
    
    # Content Security Policy
    CSP_POLICY = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' https:; "
        "connect-src 'self' ws: wss:;"
    )


# Status Messages
class StatusMessages:
    """Standard status messages"""
    
    # Success Messages
    SUCCESS_LOGIN = "Login successful"
    SUCCESS_LOGOUT = "Logout successful" 
    SUCCESS_ANALYSIS = "Analysis completed successfully"
    SUCCESS_QUARANTINE = "Email quarantined successfully"
    
    # Error Messages
    ERROR_INVALID_CREDENTIALS = "Invalid username or password"
    ERROR_TOKEN_EXPIRED = "Token has expired"
    ERROR_ACCESS_DENIED = "Access denied"
    ERROR_ANALYSIS_FAILED = "Analysis failed"
    ERROR_RATE_LIMITED = "Rate limit exceeded"
    ERROR_INVALID_INPUT = "Invalid input provided"
    
    # Warning Messages
    WARNING_SUSPICIOUS_EMAIL = "Suspicious email detected"
    WARNING_HIGH_RISK_LINK = "High risk link detected"
    WARNING_QUOTA_EXCEEDED = "API quota nearly exceeded"


# Error Codes
class ErrorCodes:
    """Standardized error codes"""
    
    # Authentication Errors (1000-1099)
    AUTH_INVALID_CREDENTIALS = 1001
    AUTH_TOKEN_EXPIRED = 1002
    AUTH_TOKEN_INVALID = 1003
    AUTH_ACCESS_DENIED = 1004
    
    # Validation Errors (1100-1199)
    VALIDATION_INVALID_INPUT = 1101
    VALIDATION_MISSING_FIELD = 1102
    VALIDATION_INVALID_FORMAT = 1103
    
    # Processing Errors (1200-1299)
    PROCESSING_ANALYSIS_FAILED = 1201
    PROCESSING_TIMEOUT = 1202
    PROCESSING_QUEUE_FULL = 1203
    
    # External API Errors (1300-1399)
    API_RATE_LIMITED = 1301
    API_UNAVAILABLE = 1302
    API_INVALID_RESPONSE = 1303
    
    # Database Errors (1400-1499)
    DB_CONNECTION_FAILED = 1401
    DB_QUERY_FAILED = 1402
    DB_CONSTRAINT_VIOLATION = 1403
    
    # System Errors (1500-1599)
    SYSTEM_INTERNAL_ERROR = 1501
    SYSTEM_SERVICE_UNAVAILABLE = 1502
    SYSTEM_CONFIGURATION_ERROR = 1503


# Validation Messages
class ValidationMessages:
    """Standard validation messages"""
    
    # Email Validation
    INVALID_EMAIL_FORMAT = "Invalid email format"
    EMAIL_TOO_LARGE = "Email size exceeds maximum limit"
    
    # User Validation
    INVALID_USERNAME = "Username must be 3-50 characters"
    INVALID_PASSWORD = "Password must be at least 8 characters"
    
    # General Validation
    REQUIRED_FIELD = "This field is required"
    INVALID_UUID = "Invalid UUID format"
    INVALID_DATE = "Invalid date format"
