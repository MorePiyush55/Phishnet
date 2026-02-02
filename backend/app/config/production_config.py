"""Production configuration for PhishNet with MongoDB Atlas integration."""

import os
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import timedelta

@dataclass
class MongoDBConfig:
    """MongoDB Atlas configuration."""
    uri: str
    database: str
    connection_timeout: int = 10000
    server_selection_timeout: int = 5000
    max_pool_size: int = 20
    min_pool_size: int = 5
    retry_writes: bool = True
    write_concern: str = "majority"

@dataclass
class RedisConfig:
    """Redis configuration for caching."""
    url: str = "redis://localhost:6379"
    max_connections: int = 10
    retry_on_timeout: bool = True

@dataclass
class SecurityConfig:
    """Security configuration."""
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    password_hash_rounds: int = 12
    session_expire_hours: int = 24
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30

@dataclass
class OAuthConfig:
    """OAuth configuration."""
    google_client_id: str
    google_client_secret: str
    gmail_scopes: list = None
    
    def __post_init__(self):
        if self.gmail_scopes is None:
            self.gmail_scopes = [
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile"
            ]

@dataclass
class ProductionConfig:
    """Production configuration for PhishNet."""
    
    # Environment
    environment: str = "production"
    debug: bool = False
    testing: bool = False
    
    # Database
    mongodb: MongoDBConfig = None
    redis: RedisConfig = None
    
    # Security
    security: SecurityConfig = None
    oauth: OAuthConfig = None
    
    # API Configuration
    api_title: str = "PhishNet API"
    api_version: str = "2.0.0"
    api_description: str = "Production PhishNet Email Security Analysis API"
    cors_origins: list = None
    rate_limit_per_minute: int = 60
    max_request_size: int = 10485760  # 10MB
    
    # Analysis Configuration
    max_concurrent_analyses: int = 10
    analysis_timeout_seconds: int = 300
    email_retention_days: int = 90
    threat_data_retention_days: int = 365
    
    # Monitoring
    enable_metrics: bool = True
    enable_health_checks: bool = True
    log_level: str = "INFO"
    
    # Background Tasks
    cleanup_interval_hours: int = 24
    session_cleanup_interval_hours: int = 6
    
    def __post_init__(self):
        """Initialize configuration from environment variables."""
        
        # MongoDB Configuration
        mongodb_uri = os.getenv("MONGODB_URI")
        if not mongodb_uri:
            raise ValueError("MONGODB_URI environment variable is required for production")
        
        self.mongodb = MongoDBConfig(
            uri=mongodb_uri,
            database=os.getenv("MONGODB_DATABASE", "phishnet"),
            connection_timeout=int(os.getenv("MONGODB_CONNECTION_TIMEOUT", "10000")),
            server_selection_timeout=int(os.getenv("MONGODB_SERVER_SELECTION_TIMEOUT", "5000")),
            max_pool_size=int(os.getenv("MONGODB_MAX_POOL_SIZE", "20")),
            min_pool_size=int(os.getenv("MONGODB_MIN_POOL_SIZE", "5"))
        )
        
        # Redis Configuration (optional)
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            self.redis = RedisConfig(
                url=redis_url,
                max_connections=int(os.getenv("REDIS_MAX_CONNECTIONS", "10"))
            )
        
        # Security Configuration
        secret_key = os.getenv("SECRET_KEY")
        if not secret_key:
            raise ValueError("SECRET_KEY environment variable is required for production")
        
        self.security = SecurityConfig(
            secret_key=secret_key,
            algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
            access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")),
            refresh_token_expire_days=int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7")),
            password_hash_rounds=int(os.getenv("PASSWORD_HASH_ROUNDS", "12")),
            session_expire_hours=int(os.getenv("SESSION_EXPIRE_HOURS", "24")),
            max_login_attempts=int(os.getenv("MAX_LOGIN_ATTEMPTS", "5")),
            lockout_duration_minutes=int(os.getenv("LOCKOUT_DURATION_MINUTES", "30"))
        )
        
        # OAuth Configuration
        google_client_id = os.getenv("GOOGLE_CLIENT_ID")
        google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        
        if not google_client_id or not google_client_secret:
            raise ValueError("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required for production")
        
        self.oauth = OAuthConfig(
            google_client_id=google_client_id,
            google_client_secret=google_client_secret
        )
        
        # CORS Origins
        cors_origins_str = os.getenv("CORS_ORIGINS", "")
        if cors_origins_str:
            self.cors_origins = [origin.strip() for origin in cors_origins_str.split(",")]
        else:
            self.cors_origins = ["*"]  # Not recommended for production
        
        # Optional overrides from environment
        self.debug = os.getenv("DEBUG", "false").lower() == "true"
        self.log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        self.rate_limit_per_minute = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
        self.max_concurrent_analyses = int(os.getenv("MAX_CONCURRENT_ANALYSES", "10"))
        self.analysis_timeout_seconds = int(os.getenv("ANALYSIS_TIMEOUT_SECONDS", "300"))
        self.email_retention_days = int(os.getenv("EMAIL_RETENTION_DAYS", "90"))
        self.threat_data_retention_days = int(os.getenv("THREAT_DATA_RETENTION_DAYS", "365"))
        self.enable_metrics = os.getenv("ENABLE_METRICS", "true").lower() == "true"
        self.enable_health_checks = os.getenv("ENABLE_HEALTH_CHECKS", "true").lower() == "true"

# Configuration validation
def validate_production_config(config: ProductionConfig) -> Dict[str, Any]:
    """Validate production configuration and return status."""
    
    issues = []
    warnings = []
    
    # Check critical configuration
    if not config.mongodb or not config.mongodb.uri:
        issues.append("MongoDB URI is not configured")
    
    if not config.security or not config.security.secret_key:
        issues.append("Secret key is not configured")
    
    if not config.oauth or not config.oauth.google_client_id:
        issues.append("Google OAuth is not configured")
    
    # Check security warnings
    if config.debug:
        warnings.append("Debug mode is enabled in production")
    
    if "*" in config.cors_origins:
        warnings.append("CORS is configured to allow all origins")
    
    if config.security and config.security.password_hash_rounds < 10:
        warnings.append("Password hash rounds are below recommended minimum (10)")
    
    # Check MongoDB Atlas requirements
    if config.mongodb and config.mongodb.uri:
        if "mongodb+srv://" not in config.mongodb.uri and "localhost" not in config.mongodb.uri:
            warnings.append("MongoDB URI does not appear to be MongoDB Atlas or localhost")
    
    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "warnings": warnings,
        "mongodb_configured": bool(config.mongodb and config.mongodb.uri),
        "oauth_configured": bool(config.oauth and config.oauth.google_client_id),
        "security_configured": bool(config.security and config.security.secret_key),
        "redis_configured": bool(config.redis and config.redis.url)
    }

# Default production configuration instance
production_config = ProductionConfig()

# Configuration for different environments
def get_config_for_environment(env: str = "production") -> ProductionConfig:
    """Get configuration for specific environment."""
    
    if env == "production":
        return production_config
    elif env == "staging":
        # Staging configuration with relaxed settings
        staging_config = ProductionConfig()
        staging_config.environment = "staging"
        staging_config.debug = True
        staging_config.log_level = "DEBUG"
        return staging_config
    elif env == "development":
        # Development configuration
        dev_config = ProductionConfig()
        dev_config.environment = "development"
        dev_config.debug = True
        dev_config.testing = True
        dev_config.log_level = "DEBUG"
        dev_config.cors_origins = ["*"]
        return dev_config
    else:
        raise ValueError(f"Unknown environment: {env}")

# Environment variables template for production deployment
PRODUCTION_ENV_TEMPLATE = """
# PhishNet Production Environment Configuration

# Database Configuration (Required)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/phishnet
MONGODB_DATABASE=phishnet
MONGODB_CONNECTION_TIMEOUT=10000
MONGODB_SERVER_SELECTION_TIMEOUT=5000
MONGODB_MAX_POOL_SIZE=20
MONGODB_MIN_POOL_SIZE=5

# Optional Redis for Caching
REDIS_URL=redis://localhost:6379
REDIS_MAX_CONNECTIONS=10

# Security Configuration (Required)
SECRET_KEY=your-super-secure-secret-key-here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
PASSWORD_HASH_ROUNDS=12
SESSION_EXPIRE_HOURS=24
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=30

# OAuth Configuration (Required)
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret

# API Configuration
CORS_ORIGINS=https://your-frontend-domain.com,https://another-domain.com
RATE_LIMIT_PER_MINUTE=60
MAX_CONCURRENT_ANALYSES=10
ANALYSIS_TIMEOUT_SECONDS=300

# Data Retention
EMAIL_RETENTION_DAYS=90
THREAT_DATA_RETENTION_DAYS=365

# Monitoring
DEBUG=false
LOG_LEVEL=INFO
ENABLE_METRICS=true
ENABLE_HEALTH_CHECKS=true
"""

def generate_env_file(filepath: str = ".env.production") -> None:
    """Generate a template .env file for production."""
    
    with open(filepath, 'w') as f:
        f.write(PRODUCTION_ENV_TEMPLATE)
    
    print(f"✅ Production environment template created: {filepath}")
    print("📝 Please update the values with your actual configuration")

if __name__ == "__main__":
    """Configuration validation and setup."""
    
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "generate-env":
        generate_env_file()
        sys.exit(0)
    
    try:
        config = production_config
        validation = validate_production_config(config)
        
        print("🔧 PhishNet Production Configuration Validation")
        print("=" * 55)
        
        if validation["valid"]:
            print("✅ Configuration is valid for production deployment")
        else:
            print("❌ Configuration issues found:")
            for issue in validation["issues"]:
                print(f"   • {issue}")
        
        if validation["warnings"]:
            print("\n⚠️  Configuration warnings:")
            for warning in validation["warnings"]:
                print(f"   • {warning}")
        
        print(f"\n📊 Configuration Status:")
        print(f"   MongoDB: {'✅' if validation['mongodb_configured'] else '❌'}")
        print(f"   OAuth: {'✅' if validation['oauth_configured'] else '❌'}")
        print(f"   Security: {'✅' if validation['security_configured'] else '❌'}")
        print(f"   Redis: {'✅' if validation['redis_configured'] else '⚠️  Optional'}")
        
        if not validation["valid"]:
            print("\n📝 To generate a template .env file, run:")
            print("   python production_config.py generate-env")
            sys.exit(1)
        
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        print("\n📝 To generate a template .env file, run:")
        print("   python production_config.py generate-env")
        sys.exit(1)