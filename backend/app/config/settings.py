"""Application settings and configuration."""

import os
import secrets
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic_settings import BaseSettings
from pydantic import EmailStr, Field, field_validator


class Environment(str, Enum):
    """Environment types for deployment."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Application settings."""
    
    # Environment
    ENVIRONMENT: Environment = Environment.DEVELOPMENT
    
    # Application
    APP_NAME: str = "PhishNet"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    BASE_URL: str = "http://localhost:8000"
    
    # Security - Critical: Must be set via environment variables
    SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="JWT secret key - must be at least 32 chars"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ROTATE_REFRESH_TOKENS: bool = True
    
    # Password Security
    MIN_PASSWORD_LENGTH: int = 8
    REQUIRE_SPECIAL_CHARS: bool = True
    BCRYPT_ROUNDS: int = 12
    
    # Database - MongoDB Only
    MONGODB_URI: Optional[str] = None
    MONGODB_DATABASE: str = "phishnet"
    MONGODB_PASSWORD: Optional[str] = None
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None
    
    # Gmail API
    GMAIL_CLIENT_ID: Optional[str] = None
    GMAIL_CLIENT_SECRET: Optional[str] = None
    GMAIL_REDIRECT_URI: str = "https://phishnet-backend-iuoc.onrender.com/api/v1/auth/gmail/callback"
    GOOGLE_CLOUD_PROJECT: Optional[str] = None
    
    # IMAP Configuration (ThePhish-style email forwarding)
    IMAP_ENABLED: bool = False
    IMAP_HOST: str = "imap.gmail.com"
    IMAP_PORT: int = 993
    IMAP_USER: Optional[str] = None
    IMAP_PASSWORD: Optional[str] = None
    IMAP_FOLDER: str = "INBOX"
    IMAP_POLL_INTERVAL: int = 60  # Poll every 60 seconds
    
    # SMTP Configuration (For sending replies - blocked on Render free tier)
    SMTP_ENABLED: bool = False
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM_EMAIL: str = "noreply@phishnet.ai"
    SMTP_FROM_NAME: str = "PhishNet Security"
    
    # Brevo (Sendinblue) Email API - Works on Render free tier
    BREVO_API_KEY: Optional[str] = None
    
    # OAuth Security Settings
    OAUTH_RATE_LIMIT_REQUESTS: int = 20
    OAUTH_RATE_LIMIT_WINDOW: int = 3600  # 1 hour
    OAUTH_MAX_ATTEMPTS_PER_USER: int = 5
    OAUTH_ATTEMPT_WINDOW: int = 900  # 15 minutes
    
    # Content Security
    MAX_EMAIL_CONTENT_LENGTH: int = 1000000  # 1MB
    ENABLE_LINK_REWRITING: bool = True
    
    # Rate Limiting
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_API: str = "100/minute"
    
    # Email Processing
    EMAIL_SCAN_INTERVAL: int = 300  # 5 minutes
    
    # API Key Security Configuration
    # NOTE: API keys are now managed securely via APIKeyManager
    # These settings control behavior but actual keys are encrypted
    API_KEY_ROTATION_DAYS: int = 90
    API_KEY_VALIDATION_ENABLED: bool = True
    API_KEY_ENCRYPTION_ENABLED: bool = True
    
    # External Service Timeouts
    VIRUSTOTAL_TIMEOUT: int = 30
    ABUSEIPDB_TIMEOUT: int = 30
    GOOGLE_API_TIMEOUT: int = 60
    
    # Retry Configuration
    API_RETRY_COUNT: int = 3
    API_RETRY_DELAY: int = 1
    
    # Secret Management Configuration
    AWS_REGION: Optional[str] = Field(None, description="AWS region for Secrets Manager")
    AWS_SECRET_NAME: Optional[str] = Field(None, description="AWS Secrets Manager secret name")
    GCP_PROJECT_ID: Optional[str] = Field(None, description="GCP project ID for Secret Manager")
    GCP_SECRET_NAME: Optional[str] = Field(None, description="GCP Secret Manager secret name")
    VAULT_URL: Optional[str] = Field(None, description="HashiCorp Vault URL")
    VAULT_TOKEN: Optional[str] = Field(None, description="HashiCorp Vault token")
    
    # Analysis Configuration
    ENABLE_AI_ANALYSIS: bool = True
    ENABLE_LINK_ANALYSIS: bool = True
    ENABLE_THREAT_INTEL: bool = True
    
    # Gemini AI Configuration
    GEMINI_API_KEY: Optional[str] = None
    GOOGLE_GEMINI_API_KEY: Optional[str] = None  # Alternative env var name
    
    # Email Polling Worker Configuration
    EMAIL_POLL_INTERVAL: int = 30  # seconds between IMAP polls
    
    # Playwright Configuration
    PLAYWRIGHT_HEADLESS: bool = True
    PLAYWRIGHT_TIMEOUT: int = 30000  # 30 seconds
    
    # Analysis Limits
    MAX_URLS_PER_EMAIL: int = 10
    MAX_ANALYSIS_TIME: int = 300  # 5 minutes
    LINK_ANALYSIS_TIMEOUT: int = 15  # 15 seconds per link
    MAX_EMAILS_PER_SCAN: int = 50
    
    # Sandbox Configuration
    SANDBOX_ENABLED: bool = True
    SANDBOX_TIMEOUT: int = 300  # 5 minutes for sandbox analysis
    MAX_SANDBOX_URLS: int = 5  # Maximum URLs to analyze in sandbox per request
    SANDBOX_REDIS_DB: int = 2  # Separate Redis database for sandbox jobs
    SANDBOX_WORKER_COUNT: int = 2  # Number of sandbox workers
    SANDBOX_JOB_RETRY_COUNT: int = 2  # Number of retries for failed sandbox jobs
    SANDBOX_STORAGE_RETENTION_DAYS: int = 7  # How long to keep sandbox artifacts
    
    # Security Hardening for Sandbox
    SANDBOX_SECCOMP_ENABLED: bool = True
    SANDBOX_APPARMOR_ENABLED: bool = True
    SANDBOX_NETWORK_ISOLATION: bool = True
    SANDBOX_MAX_MEMORY: str = "512m"  # Maximum memory per sandbox container
    SANDBOX_MAX_CPU: str = "0.5"  # Maximum CPU per sandbox container
    ENABLE_REAL_TIME_ALERTS: bool = True
    
    # Celery (Background Tasks)
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000", 
        "http://localhost:8080",
        "http://localhost:5173",
        "https://phishnet-1ed1.onrender.com",
        "https://phishnet-frontend.vercel.app"
    ]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]
    
    # Additional Configuration
    LOG_FILE: Optional[str] = None
    PROMETHEUS_PORT: int = 9090
    MOCK_EXTERNAL_APIS: bool = False
    SKIP_BROWSER_INSTALL: bool = False
    CORS_ALLOW_HEADERS: List[str] = ["*"]
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    RATE_LIMIT_PER_HOUR: int = 1000
    
    # Email Analysis
    MAX_EMAIL_SIZE: int = 10 * 1024 * 1024  # 10MB
    SUPPORTED_EMAIL_FORMATS: List[str] = [".eml", ".msg", ".txt"]
    
    # ML Models
    MODEL_PATH: str = "models/"
    MODEL_UPDATE_INTERVAL: int = 3600  # 1 hour
    CONFIDENCE_THRESHOLD: float = 0.7
    
    # Federated Learning
    FL_MIN_CLIENTS: int = 3
    FL_MAX_CLIENTS: int = 10
    FL_TRAINING_ROUNDS: int = 100
    FL_LOCAL_EPOCHS: int = 5
    FL_BATCH_SIZE: int = 32
    
    # Gmail API
    GMAIL_CLIENT_ID: Optional[str] = None
    GMAIL_CLIENT_SECRET: Optional[str] = None
    GMAIL_REDIRECT_URI: str = "https://phishnet-backend-iuoc.onrender.com/api/auth/gmail/callback"
    
    # Monitoring
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 9090
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    
    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Validate secret key length."""
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v
    
    @field_validator("MONGODB_URI")
    @classmethod
    def validate_mongodb_uri(cls, v: Optional[str]) -> Optional[str]:
        """Validate MongoDB URI format."""
        if v and not v.startswith(("mongodb://", "mongodb+srv://")):
            raise ValueError("MONGODB_URI must be a valid MongoDB connection string")
        return v
    
    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: Environment) -> Environment:
        """Validate environment setting."""
        if v == Environment.PRODUCTION:
            # In production, warn about using default values
            pass
        return v
    
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.ENVIRONMENT == Environment.PRODUCTION
    
    def is_development(self) -> bool:
        """Check if running in development."""
        return self.ENVIRONMENT == Environment.DEVELOPMENT
    
    def get_mongodb_uri(self) -> Optional[str]:
        """Get MongoDB URI with password substituted if needed."""
        if not self.MONGODB_URI:
            return None
        
        # If URI already contains credentials, return as-is
        if "@" in self.MONGODB_URI and not ("<db_password>" in self.MONGODB_URI or "your-actual-password-here" in self.MONGODB_URI):
            return self.MONGODB_URI
        
        # If URI contains password placeholder, substitute with actual password
        if self.MONGODB_PASSWORD:
            if "<db_password>" in self.MONGODB_URI:
                return self.MONGODB_URI.replace("<db_password>", self.MONGODB_PASSWORD)
            elif "your-actual-password-here" in self.MONGODB_URI:
                return self.MONGODB_URI.replace("your-actual-password-here", self.MONGODB_PASSWORD)
        
        return self.MONGODB_URI
    
    def get_virustotal_api_key(self) -> Optional[str]:
        """Get VirusTotal API key securely."""
        try:
            from app.services.api_key_manager import get_virustotal_api_key
            return get_virustotal_api_key()
        except ImportError:
            # Fallback to environment variable if key manager not available
            return os.getenv('VIRUSTOTAL_API_KEY')
    
    def get_abuseipdb_api_key(self) -> Optional[str]:
        """Get AbuseIPDB API key securely."""
        try:
            from app.services.api_key_manager import get_abuseipdb_api_key
            return get_abuseipdb_api_key()
        except ImportError:
            # Fallback to environment variable if key manager not available
            return os.getenv('ABUSEIPDB_API_KEY')
    
    def get_google_api_key(self) -> Optional[str]:
        """Get Google API key securely."""
        try:
            from app.services.api_key_manager import get_google_api_key
            return get_google_api_key()
        except ImportError:
            # Fallback to environment variable if key manager not available
            return os.getenv('GOOGLE_API_KEY')
    
    def get_gemini_api_key(self) -> Optional[str]:
        """Get Gemini API key securely."""
        # Check settings first, then environment variables
        if self.GEMINI_API_KEY:
            return self.GEMINI_API_KEY
        if self.GOOGLE_GEMINI_API_KEY:
            return self.GOOGLE_GEMINI_API_KEY
        # Fallback to environment variables
        return os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_GEMINI_API_KEY')
    
    def validate_api_keys(self) -> Dict[str, bool]:
        """Validate all required API keys are available."""
        try:
            from app.services.api_key_manager import validate_all_api_keys
            return validate_all_api_keys()
        except ImportError:
            # Fallback validation using environment variables
            return {
                'virustotal': bool(os.getenv('VIRUSTOTAL_API_KEY')),
                'abuseipdb': bool(os.getenv('ABUSEIPDB_API_KEY')),
                'google_api': bool(os.getenv('GOOGLE_API_KEY')),
                'redis': True,  # Redis password is optional
                'mongodb': bool(self.MONGODB_URI)  # MongoDB URI is required
            }
    
    model_config = {
        "env_file": ".env", 
        "case_sensitive": True,
        "extra": "ignore"  # Ignore extra environment variables
    }


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings."""
    return settings

