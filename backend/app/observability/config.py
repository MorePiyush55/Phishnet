"""
Configuration settings for observability infrastructure.
"""

from pydantic import BaseModel
from typing import Optional

class ObservabilitySettings(BaseModel):
    """Observability configuration settings."""
    
    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    LOG_FILE: Optional[str] = None
    
    # Sentry Configuration
    SENTRY_DSN: Optional[str] = None
    SENTRY_TRACES_SAMPLE_RATE: float = 0.1
    ENVIRONMENT: str = "development"
    
    # OpenTelemetry/Jaeger Configuration
    JAEGER_HOST: str = "localhost"
    JAEGER_PORT: int = 6831
    TRACING_ENABLED: bool = True
    
    # Performance Monitoring
    SLOW_REQUEST_THRESHOLD_MS: float = 1000.0
    SLOW_SCAN_THRESHOLD_MS: float = 30000.0
    SLOW_ML_THRESHOLD_MS: float = 5000.0
    
    # Structured Logging
    ENABLE_JSON_LOGGING: bool = True
    LOG_PII_REDACTION: bool = True
    
    class Config:
        env_prefix = "OBSERVABILITY_"