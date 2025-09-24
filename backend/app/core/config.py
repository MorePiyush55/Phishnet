"""
Enhanced configuration settings for OAuth and privacy features.
"""

import os
from typing import Optional, List
try:
    from pydantic_settings import BaseSettings
    from pydantic import validator
except ImportError:
    from pydantic import BaseSettings, validator

class Settings(BaseSettings):
    """Application settings with OAuth and privacy configuration"""
    
    # Basic app settings
    app_name: str = "PhishNet"
    app_url: str = "http://localhost:8000"
    debug: bool = False
    secret_key: str = "your-secret-key-here"
    
    # Database
    database_url: str = "sqlite:///./phishnet.db"
    
    # Redis
    redis_url: str = "redis://localhost:6379"
    redis_password: Optional[str] = None
    
    # Google OAuth Configuration
    google_client_id: str = ""
    google_client_secret: str = ""
    oauth_redirect_uri: str = "http://localhost:8000/api/v1/oauth/callback"
    
    # JWT Configuration
    jwt_secret_key: str = "jwt-secret-key"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 30
    
    # Rate limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_burst: int = 10
    
    # Privacy and consent settings
    default_retention_days: int = 30
    max_retention_days: int = 365
    min_retention_days: int = 1
    
    # Data processing regions
    allowed_data_regions: List[str] = ["US", "EU", "CA"]
    default_data_region: str = "US"
    
    # Privacy policy URLs
    privacy_policy_url: str = "/privacy"
    terms_of_service_url: str = "/terms"
    data_processing_agreement_url: str = "/dpa"
    
    # Email scanning configuration
    max_emails_per_scan: int = 100
    scan_batch_size: int = 10
    max_attachment_size_mb: int = 25
    
    # AI/ML settings
    enable_llm_processing: bool = True
    llm_provider: str = "openai"  # openai, anthropic, local
    llm_model: str = "gpt-3.5-turbo"
    max_llm_tokens: int = 4000
    
    # Threat intelligence
    enable_threat_intel: bool = True
    threat_intel_providers: List[str] = ["virustotal", "urlvoid"]
    threat_intel_cache_hours: int = 24
    
    # Security settings
    enable_audit_logging: bool = True
    audit_log_retention_days: int = 90
    require_mfa: bool = False
    session_timeout_minutes: int = 60
    
    # Background tasks
    cleanup_interval_hours: int = 6
    token_refresh_interval_minutes: int = 55
    health_check_interval_seconds: int = 30
    
    # Monitoring and observability
    enable_metrics: bool = True
    metrics_endpoint: str = "/metrics"
    enable_tracing: bool = False
    log_level: str = "INFO"
    
    # Observability Configuration
    sentry_dsn: Optional[str] = None
    sentry_traces_sample_rate: float = 0.1
    jaeger_host: str = "localhost"  
    jaeger_port: int = 6831
    log_file: Optional[str] = None
    tracing_enabled: bool = True
    slow_request_threshold_ms: float = 1000.0
    slow_scan_threshold_ms: float = 30000.0
    slow_ml_threshold_ms: float = 5000.0
    
    # Privacy and Compliance Configuration
    privacy_encryption_key: str = "change-this-in-production-please"
    data_retention_default_days: int = 90
    gdpr_compliance_enabled: bool = True
    ccpa_compliance_enabled: bool = True
    privacy_policy_version: str = "1.0"
    terms_of_service_version: str = "1.0"
    dpo_email: str = "privacy@phishnet.com"
    data_breach_notification_hours: int = 72  # GDPR requirement
    
    @validator('google_client_id')
    def validate_google_client_id(cls, v):
        if not v:
            raise ValueError('Google Client ID is required for OAuth functionality')
        return v
    
    @validator('google_client_secret')
    def validate_google_client_secret(cls, v):
        if not v:
            raise ValueError('Google Client Secret is required for OAuth functionality')
        return v
    
    @validator('default_retention_days')
    def validate_retention_days(cls, v, values):
        min_days = values.get('min_retention_days', 1)
        max_days = values.get('max_retention_days', 365)
        if v < min_days or v > max_days:
            raise ValueError(f'Default retention days must be between {min_days} and {max_days}')
        return v
    
    @validator('oauth_redirect_uri')
    def validate_redirect_uri(cls, v, values):
        app_url = values.get('app_url', '')
        if not v.startswith(app_url):
            raise ValueError('OAuth redirect URI must be on the same domain as app_url')
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
_settings = None

def get_settings() -> Settings:
    """Get application settings singleton"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings

def get_oauth_scopes() -> dict:
    """Get OAuth scope configuration"""
    return {
        "required": [
            {
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
                "description": "Read Gmail messages for phishing analysis",
                "privacy_impact": "medium"
            },
            {
                "scope": "https://www.googleapis.com/auth/userinfo.email",
                "description": "Access user email address",
                "privacy_impact": "low"
            },
            {
                "scope": "openid",
                "description": "OpenID Connect authentication",
                "privacy_impact": "low"
            }
        ],
        "optional": [
            {
                "scope": "https://www.googleapis.com/auth/gmail.modify",
                "description": "Label and quarantine suspicious emails",
                "privacy_impact": "low"
            }
        ]
    }

def get_privacy_settings() -> dict:
    """Get privacy configuration"""
    settings = get_settings()
    return {
        "data_retention": {
            "default_days": settings.default_retention_days,
            "min_days": settings.min_retention_days,
            "max_days": settings.max_retention_days,
            "configurable": True
        },
        "data_processing": {
            "allowed_regions": settings.allowed_data_regions,
            "default_region": settings.default_data_region
        },
        "user_controls": {
            "opt_out_ai_analysis": True,
            "opt_out_persistent_storage": True,
            "configure_retention": True,
            "revoke_consent": True,
            "export_data": True,
            "delete_data": True
        },
        "legal_compliance": {
            "gdpr_compliant": True,
            "ccpa_compliant": True,
            "audit_logging": settings.enable_audit_logging,
            "audit_retention_days": settings.audit_log_retention_days
        }
    }

def validate_environment() -> dict:
    """Validate required environment variables and configuration"""
    settings = get_settings()
    issues = []
    
    # Check required OAuth settings
    if not settings.google_client_id:
        issues.append("GOOGLE_CLIENT_ID environment variable is required")
    
    if not settings.google_client_secret:
        issues.append("GOOGLE_CLIENT_SECRET environment variable is required")
    
    # Check database configuration
    if not settings.database_url:
        issues.append("DATABASE_URL is required")
    
    # Check Redis configuration
    if not settings.redis_url:
        issues.append("REDIS_URL is required")
    
    # Check security settings
    if settings.secret_key == "your-secret-key-here":
        issues.append("SECRET_KEY should be changed from default value")
    
    if settings.jwt_secret_key == "jwt-secret-key":
        issues.append("JWT_SECRET_KEY should be changed from default value")
    
    # Check URL configurations
    if not settings.app_url.startswith(("http://", "https://")):
        issues.append("APP_URL must include protocol (http:// or https://)")
    
    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "environment": "development" if settings.debug else "production"
    }
