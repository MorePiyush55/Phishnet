"""
Mode 1 - IMAP Configuration & Tenant Mapping
=============================================

Enterprise-grade tenant isolation and mailbox configuration.
Prevents cross-tenant data leakage.

CRITICAL: Every tenant MUST have isolated mailbox credentials.
Never share IMAP connections across tenants.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, List
from enum import Enum
import os

from app.config.logging import get_logger

logger = get_logger(__name__)


class TenantTier(str, Enum):
    """Tenant service tiers with different limits."""
    FREE = "free"
    STARTER = "starter"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


@dataclass
class IMAPConfig:
    """IMAP connection configuration for a single mailbox."""
    host: str
    port: int = 993
    use_ssl: bool = True
    username: str = ""
    password: str = ""  # App password, never user password
    folder: str = "INBOX"
    timeout_seconds: int = 30
    
    def __post_init__(self):
        """Validate configuration."""
        if not self.host:
            raise ValueError("IMAP host is required")
        if not self.use_ssl and self.port == 993:
            logger.warning("Using port 993 without SSL - this may fail")


@dataclass
class TenantMailboxConfig:
    """
    Per-tenant mailbox configuration.
    
    Each tenant gets:
    - Dedicated IMAP credentials
    - Isolated processing queue
    - Own rate limits
    - Separate audit trail
    """
    tenant_id: str
    tenant_name: str
    tier: TenantTier = TenantTier.STARTER
    
    # IMAP Configuration
    imap_config: Optional[IMAPConfig] = None
    
    # Processing limits (per tier)
    max_batch_size: int = 50
    poll_interval_seconds: int = 60
    max_emails_per_hour: int = 500
    max_attachment_size_mb: int = 25
    
    # Feature flags
    enable_sandbox: bool = False
    enable_ai_analysis: bool = True
    enable_threat_intel: bool = True
    
    # Notification settings
    soc_email: Optional[str] = None
    webhook_url: Optional[str] = None
    slack_webhook: Optional[str] = None
    
    # Retention
    retention_days: int = 90
    
    def __post_init__(self):
        """Apply tier-based defaults."""
        tier_limits = {
            TenantTier.FREE: {
                "max_batch_size": 10,
                "max_emails_per_hour": 50,
                "enable_sandbox": False,
                "enable_ai_analysis": False,
                "retention_days": 7
            },
            TenantTier.STARTER: {
                "max_batch_size": 25,
                "max_emails_per_hour": 200,
                "enable_sandbox": False,
                "retention_days": 30
            },
            TenantTier.BUSINESS: {
                "max_batch_size": 50,
                "max_emails_per_hour": 1000,
                "enable_sandbox": True,
                "retention_days": 90
            },
            TenantTier.ENTERPRISE: {
                "max_batch_size": 100,
                "max_emails_per_hour": 10000,
                "enable_sandbox": True,
                "retention_days": 365
            }
        }
        
        limits = tier_limits.get(self.tier, {})
        for key, value in limits.items():
            if not hasattr(self, key) or getattr(self, key) is None:
                setattr(self, key, value)


class TenantRegistry:
    """
    Central registry for tenant configurations.
    
    In production, this would be backed by a database.
    For now, supports environment-based and in-memory configuration.
    """
    
    _instance = None
    _tenants: Dict[str, TenantMailboxConfig] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._tenants = {}
            cls._instance._load_default_tenant()
        return cls._instance
    
    def _load_default_tenant(self):
        """Load default tenant from environment variables."""
        imap_host = os.getenv("IMAP_HOST", "imap.gmail.com")
        imap_user = os.getenv("IMAP_USER", "")
        imap_pass = os.getenv("IMAP_PASSWORD", "")
        
        if imap_user and imap_pass:
            default_config = TenantMailboxConfig(
                tenant_id="default",
                tenant_name="Default Tenant",
                tier=TenantTier.BUSINESS,
                imap_config=IMAPConfig(
                    host=imap_host,
                    username=imap_user,
                    password=imap_pass
                )
            )
            self._tenants["default"] = default_config
            logger.info("Loaded default tenant from environment")
    
    def register_tenant(self, config: TenantMailboxConfig) -> None:
        """Register a new tenant configuration."""
        if config.tenant_id in self._tenants:
            logger.warning(f"Overwriting existing tenant: {config.tenant_id}")
        
        self._tenants[config.tenant_id] = config
        logger.info(f"Registered tenant: {config.tenant_id} (tier: {config.tier.value})")
    
    def get_tenant(self, tenant_id: str) -> Optional[TenantMailboxConfig]:
        """Get tenant configuration by ID."""
        return self._tenants.get(tenant_id)
    
    def get_all_tenants(self) -> List[TenantMailboxConfig]:
        """Get all registered tenants."""
        return list(self._tenants.values())
    
    def remove_tenant(self, tenant_id: str) -> bool:
        """Remove a tenant configuration."""
        if tenant_id in self._tenants:
            del self._tenants[tenant_id]
            logger.info(f"Removed tenant: {tenant_id}")
            return True
        return False
    
    def tenant_exists(self, tenant_id: str) -> bool:
        """Check if tenant exists."""
        return tenant_id in self._tenants


def get_tenant_registry() -> TenantRegistry:
    """Get singleton tenant registry."""
    return TenantRegistry()


# ============================================================================
# Processing Configuration
# ============================================================================

@dataclass
class ProcessingConfig:
    """
    Global processing configuration.
    Controls worker behavior and resource limits.
    """
    
    # Worker settings
    worker_count: int = 4
    max_concurrent_emails: int = 10
    
    # Timeouts (seconds)
    imap_connect_timeout: int = 30
    imap_fetch_timeout: int = 60
    analysis_timeout: int = 120
    module_timeout: int = 30
    
    # Retry settings
    max_retries: int = 3
    retry_backoff_base: float = 2.0
    retry_backoff_max: int = 300
    
    # Rate limiting
    api_rate_limit_per_minute: int = 60
    external_api_timeout: int = 10
    
    # Resource limits
    max_email_size_mb: int = 50
    max_attachment_count: int = 20
    max_links_to_analyze: int = 50
    max_body_length: int = 1_000_000  # 1MB text
    
    # Feature flags
    enable_parallel_analysis: bool = True
    enable_deduplication: bool = True
    enable_caching: bool = True
    
    @classmethod
    def from_env(cls) -> "ProcessingConfig":
        """Load configuration from environment variables."""
        return cls(
            worker_count=int(os.getenv("MODE1_WORKER_COUNT", "4")),
            max_concurrent_emails=int(os.getenv("MODE1_MAX_CONCURRENT", "10")),
            analysis_timeout=int(os.getenv("MODE1_ANALYSIS_TIMEOUT", "120")),
            enable_parallel_analysis=os.getenv("MODE1_PARALLEL", "true").lower() == "true"
        )


# Global processing config
_processing_config: Optional[ProcessingConfig] = None


def get_processing_config() -> ProcessingConfig:
    """Get global processing configuration."""
    global _processing_config
    if _processing_config is None:
        _processing_config = ProcessingConfig.from_env()
    return _processing_config
