"""
Configuration management service for ThreatAggregator.

Provides functionality to manage aggregator configurations, including
per-tenant customization, A/B testing, and configuration templates.
"""

import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from app.config.logging import get_logger
from app.core.database import SessionLocal
from app.models.aggregator import (
    AggregatorConfig, ConfigurationTemplate, AggregatorAuditLog,
    ThreatAssessment, ThreatAction
)
from app.models.core.user import User
from app.schemas.threat_result import (
    AggregationConfig, ComponentType, ThreatLevel,
    DEFAULT_CONFIG, CONSERVATIVE_CONFIG, AGGRESSIVE_CONFIG
)

logger = get_logger(__name__)


class ConfigurationManager:
    """Manages aggregator configurations and templates."""
    
    def __init__(self):
        self.logger = logger
    
    def get_config_for_context(
        self,
        db: Session,
        user_id: Optional[int] = None,
        tenant_id: Optional[str] = None,
        scope: str = "global"
    ) -> AggregationConfig:
        """
        Get the appropriate configuration for a given context.
        
        Priority order:
        1. User-specific config (if user_id provided)
        2. Tenant-specific config (if tenant_id provided)  
        3. Global default config
        4. Hardcoded DEFAULT_CONFIG
        """
        config = None
        
        # Try user-specific config first
        if user_id:
            config = db.query(AggregatorConfig).filter(
                and_(
                    AggregatorConfig.user_id == user_id,
                    AggregatorConfig.is_active == True
                )
            ).first()
        
        # Try tenant-specific config
        if not config and tenant_id:
            config = db.query(AggregatorConfig).filter(
                and_(
                    AggregatorConfig.tenant_id == tenant_id,
                    AggregatorConfig.scope == "tenant",
                    AggregatorConfig.is_active == True
                )
            ).first()
        
        # Try global default config
        if not config:
            config = db.query(AggregatorConfig).filter(
                and_(
                    AggregatorConfig.scope == "global",
                    AggregatorConfig.is_default == True,
                    AggregatorConfig.is_active == True
                )
            ).first()
        
        # Return converted config or fallback to hardcoded default
        if config:
            try:
                return config.to_aggregation_config()
            except Exception as e:
                self.logger.error(f"Error converting stored config: {e}")
        
        return DEFAULT_CONFIG
    
    def create_config(
        self,
        db: Session,
        name: str,
        component_weights: Dict[ComponentType, float],
        threat_thresholds: Dict[ThreatLevel, float],
        description: Optional[str] = None,
        user_id: Optional[int] = None,
        tenant_id: Optional[str] = None,
        scope: str = "global",
        confidence_boost_threshold: float = 0.8,
        rule_overrides_enabled: bool = True,
        minimum_components: int = 2,
        created_by: Optional[int] = None
    ) -> AggregatorConfig:
        """Create a new aggregator configuration."""
        
        # Convert enum keys to strings for JSON storage
        weights_json = {comp_type.value: weight for comp_type, weight in component_weights.items()}
        thresholds_json = {level.value: threshold for level, threshold in threat_thresholds.items()}
        
        # Validate configuration
        try:
            test_config = AggregationConfig(
                component_weights=component_weights,
                threat_thresholds=threat_thresholds,
                confidence_boost_threshold=confidence_boost_threshold,
                rule_overrides_enabled=rule_overrides_enabled,
                minimum_components=minimum_components
            )
        except ValueError as e:
            raise ValueError(f"Invalid configuration: {e}")
        
        config = AggregatorConfig(
            name=name,
            description=description,
            tenant_id=tenant_id,
            scope=scope,
            user_id=user_id,
            component_weights=weights_json,
            threat_thresholds=thresholds_json,
            confidence_boost_threshold=confidence_boost_threshold,
            rule_overrides_enabled=rule_overrides_enabled,
            minimum_components=minimum_components,
            created_by=created_by
        )
        
        db.add(config)
        db.commit()
        db.refresh(config)
        
        # Log the creation
        self._log_event(
            db,
            event_type="config_created",
            event_data={
                "config_id": config.id,
                "name": name,
                "scope": scope,
                "tenant_id": tenant_id,
                "user_id": user_id
            },
            user_id=created_by,
            tenant_id=tenant_id,
            config_id=config.id
        )
        
        self.logger.info(f"Created aggregator config: {name} (ID: {config.id})")
        return config
    
    def update_config(
        self,
        db: Session,
        config_id: int,
        updates: Dict[str, Any],
        updated_by: Optional[int] = None
    ) -> AggregatorConfig:
        """Update an existing configuration."""
        
        config = db.query(AggregatorConfig).filter(AggregatorConfig.id == config_id).first()
        if not config:
            raise ValueError(f"Configuration {config_id} not found")
        
        # Store original values for audit
        original_values = {
            "component_weights": config.component_weights,
            "threat_thresholds": config.threat_thresholds,
            "confidence_boost_threshold": config.confidence_boost_threshold,
            "rule_overrides_enabled": config.rule_overrides_enabled,
            "minimum_components": config.minimum_components
        }
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(config, key):
                # Convert enum dicts to JSON for storage
                if key == "component_weights" and isinstance(value, dict):
                    if isinstance(list(value.keys())[0], ComponentType):
                        value = {comp_type.value: weight for comp_type, weight in value.items()}
                elif key == "threat_thresholds" and isinstance(value, dict):
                    if isinstance(list(value.keys())[0], ThreatLevel):
                        value = {level.value: threshold for level, threshold in value.items()}
                
                setattr(config, key, value)
            else:
                self.logger.warning(f"Attempted to update unknown field: {key}")
        
        config.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(config)
        
        # Log the update
        self._log_event(
            db,
            event_type="config_updated",
            event_data={
                "config_id": config_id,
                "updates": updates,
                "original_values": original_values
            },
            user_id=updated_by,
            tenant_id=config.tenant_id,
            config_id=config_id
        )
        
        self.logger.info(f"Updated aggregator config: {config.name} (ID: {config_id})")
        return config
    
    def delete_config(
        self,
        db: Session,
        config_id: int,
        deleted_by: Optional[int] = None
    ) -> bool:
        """Soft delete a configuration (mark as inactive)."""
        
        config = db.query(AggregatorConfig).filter(AggregatorConfig.id == config_id).first()
        if not config:
            return False
        
        config.is_active = False
        config.updated_at = datetime.utcnow()
        db.commit()
        
        # Log the deletion
        self._log_event(
            db,
            event_type="config_deleted",
            event_data={
                "config_id": config_id,
                "name": config.name
            },
            user_id=deleted_by,
            tenant_id=config.tenant_id,
            config_id=config_id
        )
        
        self.logger.info(f"Deleted aggregator config: {config.name} (ID: {config_id})")
        return True
    
    def list_configs(
        self,
        db: Session,
        tenant_id: Optional[str] = None,
        user_id: Optional[int] = None,
        scope: Optional[str] = None,
        active_only: bool = True
    ) -> List[AggregatorConfig]:
        """List configurations matching the criteria."""
        
        query = db.query(AggregatorConfig)
        
        if active_only:
            query = query.filter(AggregatorConfig.is_active == True)
        
        if tenant_id:
            query = query.filter(AggregatorConfig.tenant_id == tenant_id)
        
        if user_id:
            query = query.filter(AggregatorConfig.user_id == user_id)
        
        if scope:
            query = query.filter(AggregatorConfig.scope == scope)
        
        return query.order_by(AggregatorConfig.updated_at.desc()).all()
    
    def create_from_template(
        self,
        db: Session,
        template_name: str,
        config_name: str,
        description: Optional[str] = None,
        user_id: Optional[int] = None,
        tenant_id: Optional[str] = None,
        scope: str = "tenant",
        created_by: Optional[int] = None
    ) -> AggregatorConfig:
        """Create a configuration from a template."""
        
        template = db.query(ConfigurationTemplate).filter(
            and_(
                ConfigurationTemplate.name == template_name,
                ConfigurationTemplate.is_active == True
            )
        ).first()
        
        if not template:
            raise ValueError(f"Template '{template_name}' not found")
        
        # Convert template JSON to enum dictionaries
        component_weights = {}
        for comp_str, weight in template.component_weights.items():
            try:
                component_weights[ComponentType(comp_str)] = weight
            except ValueError:
                continue
        
        threat_thresholds = {}
        for level_str, threshold in template.threat_thresholds.items():
            try:
                threat_thresholds[ThreatLevel(level_str)] = threshold
            except ValueError:
                continue
        
        return self.create_config(
            db=db,
            name=config_name,
            component_weights=component_weights,
            threat_thresholds=threat_thresholds,
            description=description or f"Created from template: {template_name}",
            user_id=user_id,
            tenant_id=tenant_id,
            scope=scope,
            confidence_boost_threshold=template.confidence_boost_threshold,
            rule_overrides_enabled=template.rule_overrides_enabled,
            minimum_components=template.minimum_components,
            created_by=created_by
        )
    
    def initialize_default_configs(self, db: Session) -> None:
        """Initialize default configurations and templates."""
        
        # Check if default config already exists
        existing_default = db.query(AggregatorConfig).filter(
            and_(
                AggregatorConfig.scope == "global",
                AggregatorConfig.is_default == True,
                AggregatorConfig.is_active == True
            )
        ).first()
        
        if existing_default:
            self.logger.info("Default configuration already exists")
            return
        
        # Create default global configuration
        default_config = self.create_config(
            db=db,
            name="Default Global Configuration",
            component_weights=DEFAULT_CONFIG.component_weights,
            threat_thresholds=DEFAULT_CONFIG.threat_thresholds,
            description="Default configuration for all threat assessments",
            scope="global",
            confidence_boost_threshold=DEFAULT_CONFIG.confidence_boost_threshold,
            rule_overrides_enabled=DEFAULT_CONFIG.rule_overrides_enabled,
            minimum_components=DEFAULT_CONFIG.minimum_components
        )
        
        default_config.is_default = True
        db.commit()
        
        # Create configuration templates
        self._create_default_templates(db)
        
        self.logger.info("Initialized default configurations and templates")
    
    def _create_default_templates(self, db: Session) -> None:
        """Create default configuration templates."""
        
        templates = [
            {
                "name": "Conservative Security",
                "description": "Lower false positives, higher manual review threshold",
                "category": "security_level",
                "config": CONSERVATIVE_CONFIG,
                "recommended_for": ["Financial", "Healthcare", "Government"],
                "tags": ["conservative", "low-false-positive", "high-threshold"]
            },
            {
                "name": "Aggressive Security", 
                "description": "Higher sensitivity, more aggressive blocking",
                "category": "security_level",
                "config": AGGRESSIVE_CONFIG,
                "recommended_for": ["High-risk environments", "Automated response"],
                "tags": ["aggressive", "high-sensitivity", "automated"]
            },
            {
                "name": "ML-Focused",
                "description": "Emphasis on machine learning components",
                "category": "component_focus",
                "config": AggregationConfig(
                    component_weights={
                        ComponentType.ML_SCORE: 0.60,
                        ComponentType.LLM_VERDICT: 0.20,
                        ComponentType.VIRUSTOTAL: 0.15,
                        ComponentType.ABUSEIPDB: 0.05
                    },
                    threat_thresholds={
                        ThreatLevel.SAFE: 0.0,
                        ThreatLevel.SUSPICIOUS: 0.4,
                        ThreatLevel.MALICIOUS: 0.7
                    }
                ),
                "recommended_for": ["ML-mature organizations", "High volume processing"],
                "tags": ["ml-focused", "automated", "high-volume"]
            },
            {
                "name": "Human-Assisted",
                "description": "Balance of automated and human judgment",
                "category": "workflow",
                "config": AggregationConfig(
                    component_weights={
                        ComponentType.ML_SCORE: 0.30,
                        ComponentType.LLM_VERDICT: 0.40,
                        ComponentType.VIRUSTOTAL: 0.20,
                        ComponentType.ABUSEIPDB: 0.10
                    },
                    threat_thresholds={
                        ThreatLevel.SAFE: 0.0,
                        ThreatLevel.SUSPICIOUS: 0.3,
                        ThreatLevel.MALICIOUS: 0.6
                    }
                ),
                "recommended_for": ["SOC teams", "Manual review workflows"],
                "tags": ["human-assisted", "soc", "manual-review"]
            }
        ]
        
        for template_data in templates:
            config = template_data["config"]
            
            # Convert enum keys to strings
            weights_json = {comp_type.value: weight for comp_type, weight in config.component_weights.items()}
            thresholds_json = {level.value: threshold for level, threshold in config.threat_thresholds.items()}
            
            template = ConfigurationTemplate(
                name=template_data["name"],
                description=template_data["description"],
                category=template_data["category"],
                component_weights=weights_json,
                threat_thresholds=thresholds_json,
                confidence_boost_threshold=config.confidence_boost_threshold,
                rule_overrides_enabled=config.rule_overrides_enabled,
                minimum_components=config.minimum_components,
                recommended_for=template_data["recommended_for"],
                tags=template_data["tags"]
            )
            
            db.add(template)
        
        db.commit()
        self.logger.info("Created default configuration templates")
    
    def _log_event(
        self,
        db: Session,
        event_type: str,
        event_data: Dict[str, Any],
        user_id: Optional[int] = None,
        tenant_id: Optional[str] = None,
        target: Optional[str] = None,
        config_id: Optional[int] = None,
        assessment_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """Log an event to the audit trail."""
        
        audit_log = AggregatorAuditLog(
            event_type=event_type,
            event_data=event_data,
            user_id=user_id,
            tenant_id=tenant_id,
            target=target,
            config_id=config_id,
            assessment_id=assessment_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        db.add(audit_log)
        db.commit()


# Global instance
_config_manager = None


def get_config_manager() -> ConfigurationManager:
    """Get or create the global configuration manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigurationManager()
    return _config_manager


def get_config_for_user(
    db: Session,
    user_id: Optional[int] = None,
    tenant_id: Optional[str] = None
) -> AggregationConfig:
    """Convenience function to get configuration for a user/tenant."""
    manager = get_config_manager()
    return manager.get_config_for_context(
        db=db,
        user_id=user_id,
        tenant_id=tenant_id
    )


def initialize_default_configurations(db: Session) -> None:
    """Initialize default configurations if they don't exist."""
    manager = get_config_manager()
    manager.initialize_default_configs(db)
