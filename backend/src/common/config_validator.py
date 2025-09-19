"""
PhishNet Configuration Validator

Validates all application settings at startup with clear error messages.
Ensures proper configuration before the application starts.
"""

import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse
import logging

from pydantic import ValidationError

from app.config.settings import Settings, get_settings
from src.common.constants import ThreatLevel, UserRole, OperationType


logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Configuration validation error."""
    pass


class ConfigValidator:
    """Configuration validator with comprehensive checks."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []
        
    def validate_all(self) -> Tuple[bool, Dict[str, Any]]:
        """Run all validation checks."""
        self.errors.clear()
        self.warnings.clear() 
        self.info.clear()
        
        # Core validation methods
        self._validate_application_config()
        self._validate_security_config()
        self._validate_database_config()
        self._validate_external_services()
        self._validate_api_keys()
        self._validate_analysis_config()
        self._validate_performance_config()
        self._validate_network_config()
        self._validate_file_paths()
        self._validate_environment_specific()
        
        # Generate report
        is_valid = len(self.errors) == 0
        report = {
            'valid': is_valid,
            'errors': self.errors,
            'warnings': self.warnings,
            'info': self.info,
            'settings_summary': self._generate_summary()
        }
        
        return is_valid, report
    
    def _validate_application_config(self):
        """Validate core application settings."""
        # App Name
        if not self.settings.APP_NAME or len(self.settings.APP_NAME.strip()) == 0:
            self.errors.append("APP_NAME cannot be empty")
        
        # Version format
        if not re.match(r'^\d+\.\d+\.\d+', self.settings.APP_VERSION):
            self.warnings.append(f"APP_VERSION '{self.settings.APP_VERSION}' should follow semantic versioning (x.y.z)")
        
        # Base URL
        try:
            parsed = urlparse(self.settings.BASE_URL)
            if not parsed.scheme or not parsed.netloc:
                self.errors.append("BASE_URL must be a valid URL with scheme and netloc")
        except Exception as e:
            self.errors.append(f"Invalid BASE_URL: {e}")
        
        # Debug mode warnings
        if self.settings.DEBUG:
            self.warnings.append("DEBUG mode is enabled - ensure this is not production")
            
    def _validate_security_config(self):
        """Validate security-related settings."""
        # Secret key strength
        if len(self.settings.SECRET_KEY) < 32:
            self.errors.append("SECRET_KEY must be at least 32 characters long")
        
        # Check for default/weak secret keys
        weak_patterns = [
            'secret', 'password', 'changeme', 'default', '123456',
            'your-secret-key', 'your-very-long-secret-key'
        ]
        if any(pattern in self.settings.SECRET_KEY.lower() for pattern in weak_patterns):
            self.errors.append("SECRET_KEY appears to be a default or weak value - change in production")
        
        # Token expiration
        if self.settings.ACCESS_TOKEN_EXPIRE_MINUTES < 5:
            self.warnings.append("ACCESS_TOKEN_EXPIRE_MINUTES is very short (<5 minutes)")
        if self.settings.ACCESS_TOKEN_EXPIRE_MINUTES > 1440:  # 24 hours
            self.warnings.append("ACCESS_TOKEN_EXPIRE_MINUTES is very long (>24 hours)")
            
        if self.settings.REFRESH_TOKEN_EXPIRE_DAYS > 30:
            self.warnings.append("REFRESH_TOKEN_EXPIRE_DAYS is very long (>30 days)")
            
        # Algorithm validation
        if self.settings.ALGORITHM not in ['HS256', 'HS384', 'HS512', 'RS256']:
            self.warnings.append(f"JWT algorithm '{self.settings.ALGORITHM}' may not be secure")
    
    def _validate_database_config(self):
        """Validate database configuration."""
        # URL format
        db_url = self.settings.DATABASE_URL
        if not db_url:
            self.errors.append("DATABASE_URL is required")
            return
            
        # Parse URL
        try:
            parsed = urlparse(db_url)
            if parsed.scheme not in ['postgresql', 'postgres', 'sqlite']:
                self.errors.append(f"Unsupported database scheme: {parsed.scheme}")
        except Exception as e:
            self.errors.append(f"Invalid DATABASE_URL format: {e}")
        
        # SQLite specific checks
        if db_url.startswith('sqlite:'):
            db_path = db_url.replace('sqlite:///', '')
            if not os.path.dirname(db_path):
                self.warnings.append("SQLite database in root directory - consider using a data/ subdirectory")
        
        # Pool configuration
        if self.settings.DATABASE_POOL_SIZE < 1:
            self.errors.append("DATABASE_POOL_SIZE must be at least 1")
        if self.settings.DATABASE_POOL_SIZE > 100:
            self.warnings.append("DATABASE_POOL_SIZE is very high (>100) - may cause resource issues")
            
        if self.settings.DATABASE_MAX_OVERFLOW < 0:
            self.errors.append("DATABASE_MAX_OVERFLOW must be non-negative")
    
    def _validate_external_services(self):
        """Validate external service configurations."""
        # Redis
        if self.settings.REDIS_URL:
            try:
                parsed = urlparse(self.settings.REDIS_URL)
                if parsed.scheme != 'redis':
                    self.errors.append("REDIS_URL must use redis:// scheme")
            except Exception as e:
                self.errors.append(f"Invalid REDIS_URL format: {e}")
        
        # Celery
        if self.settings.CELERY_BROKER_URL:
            try:
                parsed = urlparse(self.settings.CELERY_BROKER_URL)
                if parsed.scheme not in ['redis', 'amqp']:
                    self.warnings.append("CELERY_BROKER_URL should use redis:// or amqp:// scheme")
            except Exception as e:
                self.errors.append(f"Invalid CELERY_BROKER_URL format: {e}")
    
    def _validate_api_keys(self):
        """Validate API key configurations."""
        api_keys = {
            'GEMINI_API_KEY': self.settings.GEMINI_API_KEY,
            'VIRUSTOTAL_API_KEY': self.settings.VIRUSTOTAL_API_KEY,
            'ABUSEIPDB_API_KEY': self.settings.ABUSEIPDB_API_KEY,
            'GMAIL_CLIENT_ID': self.settings.GMAIL_CLIENT_ID,
            'GMAIL_CLIENT_SECRET': self.settings.GMAIL_CLIENT_SECRET,
        }
        
        missing_keys = []
        for key_name, key_value in api_keys.items():
            if not key_value and not self.settings.MOCK_EXTERNAL_APIS:
                missing_keys.append(key_name)
        
        if missing_keys and not self.settings.MOCK_EXTERNAL_APIS:
            self.warnings.append(f"Missing API keys (set MOCK_EXTERNAL_APIS=true for development): {', '.join(missing_keys)}")
        
        # Gmail OAuth validation
        if self.settings.GMAIL_CLIENT_ID and not self.settings.GMAIL_CLIENT_SECRET:
            self.errors.append("GMAIL_CLIENT_SECRET is required when GMAIL_CLIENT_ID is set")
        
        # API key format validation
        if self.settings.VIRUSTOTAL_API_KEY and len(self.settings.VIRUSTOTAL_API_KEY) != 64:
            self.warnings.append("VIRUSTOTAL_API_KEY should be 64 characters long")
    
    def _validate_analysis_config(self):
        """Validate analysis and processing configuration."""
        # Limits validation
        if self.settings.MAX_EMAIL_SIZE <= 0:
            self.errors.append("MAX_EMAIL_SIZE must be positive")
        if self.settings.MAX_EMAIL_SIZE > 100 * 1024 * 1024:  # 100MB
            self.warnings.append("MAX_EMAIL_SIZE is very large (>100MB) - may cause memory issues")
        
        if self.settings.MAX_URLS_PER_EMAIL <= 0:
            self.errors.append("MAX_URLS_PER_EMAIL must be positive")
        if self.settings.MAX_URLS_PER_EMAIL > 100:
            self.warnings.append("MAX_URLS_PER_EMAIL is very high (>100)")
        
        # Timeout validation
        if self.settings.MAX_ANALYSIS_TIME <= 0:
            self.errors.append("MAX_ANALYSIS_TIME must be positive")
        if self.settings.LINK_ANALYSIS_TIMEOUT <= 0:
            self.errors.append("LINK_ANALYSIS_TIMEOUT must be positive")
        if self.settings.PLAYWRIGHT_TIMEOUT <= 0:
            self.errors.append("PLAYWRIGHT_TIMEOUT must be positive")
        
        # ML configuration
        if self.settings.CONFIDENCE_THRESHOLD < 0 or self.settings.CONFIDENCE_THRESHOLD > 1:
            self.errors.append("CONFIDENCE_THRESHOLD must be between 0 and 1")
        
        # Federated learning
        if self.settings.FL_MIN_CLIENTS > self.settings.FL_MAX_CLIENTS:
            self.errors.append("FL_MIN_CLIENTS cannot be greater than FL_MAX_CLIENTS")
        if self.settings.FL_MIN_CLIENTS < 1:
            self.errors.append("FL_MIN_CLIENTS must be at least 1")
    
    def _validate_performance_config(self):
        """Validate performance-related settings."""
        # Rate limiting
        if self.settings.RATE_LIMIT_PER_MINUTE <= 0:
            self.errors.append("RATE_LIMIT_PER_MINUTE must be positive")
        if self.settings.RATE_LIMIT_PER_HOUR <= 0:
            self.errors.append("RATE_LIMIT_PER_HOUR must be positive")
        
        if self.settings.RATE_LIMIT_PER_HOUR < self.settings.RATE_LIMIT_PER_MINUTE:
            self.warnings.append("RATE_LIMIT_PER_HOUR should be >= RATE_LIMIT_PER_MINUTE")
        
        # Processing limits
        if self.settings.MAX_EMAILS_PER_SCAN <= 0:
            self.errors.append("MAX_EMAILS_PER_SCAN must be positive")
        if self.settings.EMAIL_SCAN_INTERVAL < 30:
            self.warnings.append("EMAIL_SCAN_INTERVAL is very short (<30 seconds)")
        
        # Model update interval
        if self.settings.MODEL_UPDATE_INTERVAL < 300:  # 5 minutes
            self.warnings.append("MODEL_UPDATE_INTERVAL is very short (<5 minutes)")
    
    def _validate_network_config(self):
        """Validate network-related configuration."""
        # CORS validation
        if '*' in self.settings.CORS_ORIGINS and len(self.settings.CORS_ORIGINS) > 1:
            self.warnings.append("CORS_ORIGINS contains '*' with other origins - '*' will override")
        
        # Port validation
        if self.settings.PROMETHEUS_PORT == self.settings.METRICS_PORT:
            self.warnings.append("PROMETHEUS_PORT and METRICS_PORT are the same")
        
        # Check common port conflicts
        common_ports = [80, 443, 3000, 5432, 6379, 8000, 8080, 9000]
        if self.settings.PROMETHEUS_PORT in common_ports:
            self.info.append(f"PROMETHEUS_PORT {self.settings.PROMETHEUS_PORT} is a commonly used port")
    
    def _validate_file_paths(self):
        """Validate file paths and directories."""
        # Model path
        if self.settings.MODEL_PATH:
            model_path = Path(self.settings.MODEL_PATH)
            if not model_path.exists():
                self.info.append(f"MODEL_PATH '{self.settings.MODEL_PATH}' does not exist - will be created if needed")
        
        # Log file
        if self.settings.LOG_FILE:
            log_path = Path(self.settings.LOG_FILE)
            log_dir = log_path.parent
            if not log_dir.exists():
                self.warnings.append(f"Log directory '{log_dir}' does not exist")
        
        # Email format validation
        for fmt in self.settings.SUPPORTED_EMAIL_FORMATS:
            if not fmt.startswith('.'):
                self.warnings.append(f"Email format '{fmt}' should start with '.'")
    
    def _validate_environment_specific(self):
        """Validate environment-specific settings."""
        # Production checks
        if not self.settings.DEBUG:
            if self.settings.SECRET_KEY == 'your-very-long-secret-key-change-in-production-make-it-at-least-32-characters':
                self.errors.append("Default SECRET_KEY detected in production mode")
            
            if 'localhost' in self.settings.BASE_URL:
                self.warnings.append("BASE_URL contains localhost in production mode")
            
            if self.settings.DATABASE_ECHO:
                self.warnings.append("DATABASE_ECHO enabled in production mode - may impact performance")
        
        # Development checks
        if self.settings.DEBUG:
            if not self.settings.MOCK_EXTERNAL_APIS and not any([
                self.settings.GEMINI_API_KEY,
                self.settings.VIRUSTOTAL_API_KEY,
                self.settings.ABUSEIPDB_API_KEY
            ]):
                self.info.append("Consider setting MOCK_EXTERNAL_APIS=true for development")
        
        # Log level validation
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.settings.LOG_LEVEL not in valid_log_levels:
            self.errors.append(f"Invalid LOG_LEVEL '{self.settings.LOG_LEVEL}'. Must be one of: {valid_log_levels}")
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate configuration summary."""
        return {
            'app_name': self.settings.APP_NAME,
            'version': self.settings.APP_VERSION,
            'debug_mode': self.settings.DEBUG,
            'database_type': self.settings.DATABASE_URL.split('://')[0] if self.settings.DATABASE_URL else 'unknown',
            'external_apis_mocked': self.settings.MOCK_EXTERNAL_APIS,
            'ai_analysis_enabled': self.settings.ENABLE_AI_ANALYSIS,
            'link_analysis_enabled': self.settings.ENABLE_LINK_ANALYSIS,
            'threat_intel_enabled': self.settings.ENABLE_THREAT_INTEL,
            'real_time_alerts_enabled': self.settings.ENABLE_REAL_TIME_ALERTS,
        }
    
    def print_report(self, report: Dict[str, Any], show_summary: bool = True):
        """Print formatted validation report."""
        if report['valid']:
            print("✅ Configuration validation passed!")
        else:
            print("❌ Configuration validation failed!")
        
        # Errors
        if report['errors']:
            print(f"\n🔴 Errors ({len(report['errors'])}):")
            for error in report['errors']:
                print(f"  • {error}")
        
        # Warnings
        if report['warnings']:
            print(f"\n🟡 Warnings ({len(report['warnings'])}):")
            for warning in report['warnings']:
                print(f"  • {warning}")
        
        # Info
        if report['info']:
            print(f"\n🔵 Info ({len(report['info'])}):")
            for info in report['info']:
                print(f"  • {info}")
        
        # Summary
        if show_summary and report['settings_summary']:
            print(f"\n📋 Configuration Summary:")
            summary = report['settings_summary']
            print(f"  • App: {summary['app_name']} v{summary['version']}")
            print(f"  • Mode: {'DEBUG' if summary['debug_mode'] else 'PRODUCTION'}")
            print(f"  • Database: {summary['database_type']}")
            print(f"  • External APIs: {'MOCKED' if summary['external_apis_mocked'] else 'REAL'}")
            print(f"  • AI Analysis: {'✓' if summary['ai_analysis_enabled'] else '✗'}")
            print(f"  • Link Analysis: {'✓' if summary['link_analysis_enabled'] else '✗'}")
            print(f"  • Threat Intel: {'✓' if summary['threat_intel_enabled'] else '✗'}")


def validate_configuration(settings: Optional[Settings] = None, 
                         print_report: bool = True, 
                         raise_on_error: bool = False) -> Tuple[bool, Dict[str, Any]]:
    """
    Validate PhishNet configuration.
    
    Args:
        settings: Settings instance to validate (default: get_settings())
        print_report: Whether to print validation report
        raise_on_error: Whether to raise exception on validation errors
        
    Returns:
        Tuple of (is_valid, report_dict)
        
    Raises:
        ConfigurationError: If validation fails and raise_on_error is True
    """
    if settings is None:
        settings = get_settings()
    
    validator = ConfigValidator(settings)
    is_valid, report = validator.validate_all()
    
    if print_report:
        validator.print_report(report)
    
    if not is_valid and raise_on_error:
        error_msg = "Configuration validation failed:\n" + "\n".join(report['errors'])
        raise ConfigurationError(error_msg)
    
    return is_valid, report


def validate_configuration_on_startup():
    """Validate configuration during application startup."""
    try:
        is_valid, report = validate_configuration(print_report=False, raise_on_error=False)
        
        if not is_valid:
            print("❌ Configuration validation failed during startup!")
            validator = ConfigValidator(get_settings())
            validator.print_report(report)
            
            if not os.getenv('PHISHNET_IGNORE_CONFIG_ERRORS'):
                print("\n💡 Set PHISHNET_IGNORE_CONFIG_ERRORS=1 to start anyway (not recommended)")
                sys.exit(1)
            else:
                print("\n⚠️  Starting anyway due to PHISHNET_IGNORE_CONFIG_ERRORS=1")
        else:
            logger.info("✅ Configuration validation passed")
            
    except Exception as e:
        print(f"❌ Configuration validation error: {e}")
        if not os.getenv('PHISHNET_IGNORE_CONFIG_ERRORS'):
            sys.exit(1)


if __name__ == "__main__":
    # CLI usage
    validate_configuration(print_report=True, raise_on_error=False)
