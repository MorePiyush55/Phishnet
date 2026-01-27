"""
Enterprise Tenancy and Policy Models
===================================
Defines the structure for multi-tenant support and configurable security policies.
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum
from beanie import Document, Indexed
from pydantic import Field, EmailStr, BaseModel
from pymongo import IndexModel, ASCENDING, DESCENDING

class TenantStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"

class PolicyAction(str, Enum):
    """Actions the Policy Engine can take"""
    ALLOW = "allow"             # Do nothing / Log only
    REPLY_USER = "reply_user"   # Send email back to reporter
    QUARANTINE = "quarantine"   # API call to move message
    DELETE = "delete"           # API call to delete message
    NOTIFY_SOC = "notify_soc"   # Email/Webhook to SOC
    WEBHOOK = "webhook"         # Generic webhook

class ThreatConditions(BaseModel):
    """
    Conditions for triggering a policy.
    e.g., If score >= 80 AND credential_harvesting=True
    
    Note: This is a Pydantic BaseModel for embedded use within Tenant documents,
    not a separate MongoDB collection.
    """
    min_score: int = 0
    max_score: int = 100
    risk_level: Optional[str] = None # LOW, MEDIUM, HIGH, CRITICAL
    keyword_match: Optional[List[str]] = None
    
    # Advanced logic could go here

class PolicyRule(BaseModel):
    """A single rule within a policy
    
    Note: This is a Pydantic BaseModel for embedded use within Tenant documents,
    not a separate MongoDB collection.
    """
    name: str
    priority: int = 10
    conditions: ThreatConditions
    actions: List[PolicyAction]
    
    # Custom configuration for actions
    action_config: Dict[str, Any] = Field(default_factory=dict)
    # e.g. {"notify_soc": {"email": "soc@acme.com"}}

class Tenant(Document):
    """
    Represents a Customer Organization.
    """
    name: str
    domain: Indexed(str, unique=True) # e.g. "acme.com"
    status: TenantStatus = TenantStatus.ACTIVE
    
    # Contact info
    admin_email: EmailStr
    
    # Security Policy
    # Simpler implementation: Embedded policy configuration
    policies: List[PolicyRule] = Field(default_factory=list)
    
    # IMAP/API Configuration (for remediation actions)
    service_account_config: Optional[Dict[str, Any]] = None
    
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "tenants"
        indexes = [
            IndexModel([("domain", ASCENDING)], unique=True),
            IndexModel([("status", ASCENDING)])
        ]

class PolicyEvaluationResult(Document):
    """Records which policy was applied to a specific analysis job"""
    job_id: Indexed(str)
    tenant_id: Indexed(str)
    rule_name: str
    actions_taken: List[str]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Settings:
        name = "policy_evaluations"
        expireAfterSeconds = 90 * 24 * 60 * 60 # 90 days retention
