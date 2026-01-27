"""
Enterprise Tenant & Mailbox Management
======================================
Multi-tenant support for Mode 1 pipeline.

Features:
1. Tenant-to-Mailbox mapping (prevents cross-org data leakage)
2. Per-tenant IMAP credentials
3. Tenant isolation in processing
4. Mailbox health monitoring
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

from beanie import Document, Indexed
from pydantic import Field, EmailStr
from pymongo import IndexModel, ASCENDING

from app.config.logging import get_logger

logger = get_logger(__name__)


class MailboxStatus(str, Enum):
    """Mailbox connection status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    CREDENTIALS_EXPIRED = "credentials_expired"


class MailboxConfig(Document):
    """
    IMAP mailbox configuration for a tenant.
    
    Security:
    - Credentials encrypted at rest (use secrets manager in production)
    - One mailbox per tenant (no sharing)
    - Connection pooling per mailbox
    """
    # Identity
    tenant_id: Indexed(str, unique=True)
    tenant_domain: Indexed(str)
    
    # IMAP Configuration
    imap_host: str
    imap_port: int = 993
    imap_user: str
    imap_password: str  # In production: reference to secrets manager
    imap_folder: str = "INBOX"
    use_ssl: bool = True
    
    # OAuth (alternative to password)
    oauth_enabled: bool = False
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    oauth_refresh_token: Optional[str] = None
    oauth_token_expiry: Optional[datetime] = None
    
    # Processing config
    poll_interval_seconds: int = 60
    batch_size: int = 50
    max_retries: int = 3
    
    # Status
    status: MailboxStatus = MailboxStatus.INACTIVE
    last_poll_at: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_errors: int = 0
    
    # Health metrics
    emails_processed_today: int = 0
    emails_processed_total: int = 0
    avg_processing_time_ms: float = 0.0
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Settings:
        name = "mailbox_configs"
        indexes = [
            IndexModel([("tenant_id", ASCENDING)], unique=True),
            IndexModel([("tenant_domain", ASCENDING)]),
            IndexModel([("status", ASCENDING)]),
        ]


class TenantMailboxService:
    """
    Service for managing tenant mailbox configurations.
    
    Usage:
        service = TenantMailboxService()
        config = await service.get_mailbox_for_tenant(tenant_id)
        await service.record_poll_success(tenant_id)
    """
    
    async def get_mailbox_for_tenant(self, tenant_id: str) -> Optional[MailboxConfig]:
        """Get mailbox configuration for a tenant"""
        return await MailboxConfig.find_one(MailboxConfig.tenant_id == tenant_id)
    
    async def get_mailbox_by_domain(self, domain: str) -> Optional[MailboxConfig]:
        """Get mailbox configuration by tenant domain"""
        return await MailboxConfig.find_one(MailboxConfig.tenant_domain == domain)
    
    async def get_all_active_mailboxes(self) -> List[MailboxConfig]:
        """Get all mailboxes ready for polling"""
        return await MailboxConfig.find(
            MailboxConfig.status == MailboxStatus.ACTIVE
        ).to_list()
    
    async def create_mailbox(
        self,
        tenant_id: str,
        tenant_domain: str,
        imap_host: str,
        imap_user: str,
        imap_password: str,
        imap_port: int = 993,
        imap_folder: str = "INBOX",
        poll_interval: int = 60,
        batch_size: int = 50
    ) -> MailboxConfig:
        """Create a new mailbox configuration"""
        config = MailboxConfig(
            tenant_id=tenant_id,
            tenant_domain=tenant_domain,
            imap_host=imap_host,
            imap_port=imap_port,
            imap_user=imap_user,
            imap_password=imap_password,
            imap_folder=imap_folder,
            poll_interval_seconds=poll_interval,
            batch_size=batch_size,
            status=MailboxStatus.INACTIVE
        )
        await config.save()
        logger.info(f"Created mailbox config for tenant {tenant_id}")
        return config
    
    async def activate_mailbox(self, tenant_id: str) -> bool:
        """Activate a mailbox for polling"""
        config = await self.get_mailbox_for_tenant(tenant_id)
        if not config:
            return False
        
        config.status = MailboxStatus.ACTIVE
        config.updated_at = datetime.now(timezone.utc)
        await config.save()
        logger.info(f"Activated mailbox for tenant {tenant_id}")
        return True
    
    async def deactivate_mailbox(self, tenant_id: str, reason: Optional[str] = None) -> bool:
        """Deactivate a mailbox"""
        config = await self.get_mailbox_for_tenant(tenant_id)
        if not config:
            return False
        
        config.status = MailboxStatus.INACTIVE
        config.last_error = reason
        config.updated_at = datetime.now(timezone.utc)
        await config.save()
        logger.info(f"Deactivated mailbox for tenant {tenant_id}: {reason}")
        return True
    
    async def record_poll_success(
        self,
        tenant_id: str,
        emails_processed: int,
        processing_time_ms: float
    ):
        """Record successful poll metrics"""
        config = await self.get_mailbox_for_tenant(tenant_id)
        if not config:
            return
        
        config.last_poll_at = datetime.now(timezone.utc)
        config.consecutive_errors = 0
        config.emails_processed_today += emails_processed
        config.emails_processed_total += emails_processed
        
        # Rolling average of processing time
        if config.avg_processing_time_ms == 0:
            config.avg_processing_time_ms = processing_time_ms
        else:
            config.avg_processing_time_ms = (
                config.avg_processing_time_ms * 0.9 + processing_time_ms * 0.1
            )
        
        config.updated_at = datetime.now(timezone.utc)
        await config.save()
    
    async def record_poll_error(self, tenant_id: str, error: str):
        """Record poll failure"""
        config = await self.get_mailbox_for_tenant(tenant_id)
        if not config:
            return
        
        config.last_error = error
        config.consecutive_errors += 1
        config.updated_at = datetime.now(timezone.utc)
        
        # Auto-deactivate after too many errors
        if config.consecutive_errors >= config.max_retries:
            config.status = MailboxStatus.ERROR
            logger.warning(f"Mailbox {tenant_id} deactivated after {config.consecutive_errors} errors")
        
        await config.save()
    
    async def reset_daily_counters(self):
        """Reset daily email counters (call from cron)"""
        await MailboxConfig.find().update_many({"$set": {"emails_processed_today": 0}})
        logger.info("Reset daily email counters for all mailboxes")
    
    async def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary of all mailboxes"""
        all_configs = await MailboxConfig.find().to_list()
        
        summary = {
            "total_mailboxes": len(all_configs),
            "by_status": {},
            "total_emails_today": 0,
            "total_emails_all_time": 0,
            "unhealthy_mailboxes": []
        }
        
        for config in all_configs:
            # Count by status
            status = config.status.value
            summary["by_status"][status] = summary["by_status"].get(status, 0) + 1
            
            # Sum emails
            summary["total_emails_today"] += config.emails_processed_today
            summary["total_emails_all_time"] += config.emails_processed_total
            
            # Track unhealthy
            if config.status in [MailboxStatus.ERROR, MailboxStatus.CREDENTIALS_EXPIRED]:
                summary["unhealthy_mailboxes"].append({
                    "tenant_id": config.tenant_id,
                    "status": config.status.value,
                    "last_error": config.last_error,
                    "consecutive_errors": config.consecutive_errors
                })
        
        return summary


# Singleton
_mailbox_service: Optional[TenantMailboxService] = None


def get_tenant_mailbox_service() -> TenantMailboxService:
    """Get singleton mailbox service"""
    global _mailbox_service
    if _mailbox_service is None:
        _mailbox_service = TenantMailboxService()
    return _mailbox_service
