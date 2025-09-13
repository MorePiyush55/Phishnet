"""
Database models for ThreatAggregator configuration and results storage.

Provides persistent storage for aggregation configurations, threat results,
and audit trails for threat assessment decisions.
"""

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from typing import Dict, Any, Optional

from app.core.database import Base
from app.models.core.user import User


class AggregatorConfig(Base):
    """
    Stores aggregator configuration for different tenants/use cases.
    Allows per-tenant customization of weights, thresholds, and rules.
    """
    __tablename__ = "aggregator_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Tenant/scope information
    tenant_id = Column(String(50), nullable=True, index=True)  # For multi-tenant support
    scope = Column(String(50), default="global", index=True)  # global, tenant, user, etc.
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Component weights (JSON)
    component_weights = Column(JSON, nullable=False)
    
    # Threat thresholds (JSON)
    threat_thresholds = Column(JSON, nullable=False)
    
    # Configuration parameters
    confidence_boost_threshold = Column(Float, default=0.8)
    rule_overrides_enabled = Column(Boolean, default=True)
    minimum_components = Column(Integer, default=2)
    
    # Metadata
    is_active = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    assigned_user = relationship("User", foreign_keys=[user_id])
    threat_results = relationship("ThreatAssessment", back_populates="config")
    
    def to_aggregation_config(self):
        """Convert to AggregationConfig dataclass."""
        from app.schemas.threat_result import AggregationConfig, ComponentType, ThreatLevel
        
        # Convert JSON component weights to enum keys
        component_weights = {}
        for comp_str, weight in self.component_weights.items():
            try:
                component_weights[ComponentType(comp_str)] = weight
            except ValueError:
                continue  # Skip invalid component types
        
        # Convert JSON threat thresholds to enum keys
        threat_thresholds = {}
        for level_str, threshold in self.threat_thresholds.items():
            try:
                threat_thresholds[ThreatLevel(level_str)] = threshold
            except ValueError:
                continue  # Skip invalid threat levels
        
        return AggregationConfig(
            component_weights=component_weights,
            threat_thresholds=threat_thresholds,
            confidence_boost_threshold=self.confidence_boost_threshold,
            rule_overrides_enabled=self.rule_overrides_enabled,
            minimum_components=self.minimum_components
        )


class ThreatAssessment(Base):
    """
    Stores complete threat assessment results from the aggregator.
    Provides audit trail and enables historical analysis.
    """
    __tablename__ = "threat_assessments"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(50), unique=True, nullable=False, index=True)
    
    # Target information
    target = Column(String(2000), nullable=False, index=True)
    target_type = Column(String(50), nullable=False, index=True)
    
    # Assessment results
    score = Column(Float, nullable=False, index=True)
    level = Column(String(20), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    
    # Component data (JSON)
    components = Column(JSON, nullable=False)
    
    # Explanation data (JSON)
    explanation = Column(JSON, nullable=False)
    
    # Rule overrides (JSON)
    rule_overrides = Column(JSON, nullable=True)
    
    # Quality metrics
    component_count = Column(Integer, nullable=False)
    component_agreement = Column(Float, nullable=False)
    coverage_score = Column(Float, nullable=False)
    processing_time_ms = Column(Integer, nullable=False)
    
    # Configuration used
    config_id = Column(Integer, ForeignKey("aggregator_configs.id"), nullable=True)
    
    # User/tenant context
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    tenant_id = Column(String(50), nullable=True, index=True)
    
    # Metadata
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    config = relationship("AggregatorConfig", back_populates="threat_results")
    user = relationship("User")
    actions = relationship("ThreatAction", back_populates="assessment")
    
    def to_threat_result(self):
        """Convert to ThreatResult dataclass."""
        from app.schemas.threat_result import ThreatResult, ThreatLevel, ComponentType, ComponentScore, ThreatExplanation, Evidence, EvidenceType, RuleOverride
        
        # Reconstruct components
        components = {}
        for comp_type_str, comp_data in self.components.items():
            try:
                comp_type = ComponentType(comp_type_str)
                components[comp_type] = ComponentScore(
                    component_type=comp_type,
                    score=comp_data["score"],
                    confidence=comp_data["confidence"],
                    weight=comp_data["weight"],
                    explanation=comp_data["explanation"],
                    evidence_urls=comp_data.get("evidence_urls", []),
                    timestamp=comp_data.get("timestamp", self.created_at.timestamp()),
                    raw_data=comp_data.get("raw_data", {})
                )
            except (ValueError, KeyError):
                continue  # Skip invalid components
        
        # Reconstruct explanation
        explanation_data = self.explanation
        evidence_list = []
        for ev_data in explanation_data.get("supporting_evidence", []):
            try:
                evidence = Evidence(
                    evidence_type=EvidenceType(ev_data["type"]),
                    url=ev_data["url"],
                    description=ev_data["description"],
                    metadata=ev_data.get("metadata", {}),
                    component_source=ComponentType(ev_data["component_source"]) if ev_data.get("component_source") else None,
                    timestamp=ev_data.get("timestamp", self.created_at.timestamp())
                )
                evidence_list.append(evidence)
            except (ValueError, KeyError):
                continue  # Skip invalid evidence
        
        explanation = ThreatExplanation(
            primary_reasons=explanation_data.get("primary_reasons", []),
            supporting_evidence=evidence_list,
            component_breakdown=explanation_data.get("component_breakdown", ""),
            confidence_reasoning=explanation_data.get("confidence_reasoning", ""),
            recommendations=explanation_data.get("recommendations", [])
        )
        
        # Reconstruct rule overrides
        rule_overrides = []
        for rule_data in (self.rule_overrides or []):
            try:
                rule = RuleOverride(
                    rule_name=rule_data["rule_name"],
                    condition=rule_data["condition"],
                    triggered=rule_data["triggered"],
                    original_score=rule_data["original_score"],
                    override_level=ThreatLevel(rule_data["override_level"]),
                    explanation=rule_data["explanation"],
                    priority=rule_data.get("priority", 0)
                )
                rule_overrides.append(rule)
            except (ValueError, KeyError):
                continue  # Skip invalid rules
        
        return ThreatResult(
            target=self.target,
            target_type=self.target_type,
            score=self.score,
            level=ThreatLevel(self.level),
            confidence=self.confidence,
            components=components,
            explanation=explanation,
            analysis_id=self.analysis_id,
            timestamp=self.created_at.timestamp(),
            processing_time_ms=self.processing_time_ms,
            rule_overrides=rule_overrides
        )


class ThreatAction(Base):
    """
    Tracks actions taken based on threat assessments.
    Enables downstream action tracking and audit trails.
    """
    __tablename__ = "threat_actions"
    
    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("threat_assessments.id"), nullable=False)
    
    # Action details
    action_type = Column(String(50), nullable=False, index=True)  # block, quarantine, alert, etc.
    action_status = Column(String(20), nullable=False, default="pending")  # pending, completed, failed
    
    # Action configuration
    action_config = Column(JSON, nullable=True)  # Configuration for the action
    
    # Results
    result_data = Column(JSON, nullable=True)  # Results from action execution
    error_message = Column(Text, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    assessment = relationship("ThreatAssessment", back_populates="actions")
    creator = relationship("User")


class ConfigurationTemplate(Base):
    """
    Predefined configuration templates for common use cases.
    Provides starting points for new aggregator configurations.
    """
    __tablename__ = "configuration_templates"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    category = Column(String(50), nullable=False, index=True)  # security_level, industry, etc.
    
    # Template configuration
    component_weights = Column(JSON, nullable=False)
    threat_thresholds = Column(JSON, nullable=False)
    confidence_boost_threshold = Column(Float, default=0.8)
    rule_overrides_enabled = Column(Boolean, default=True)
    minimum_components = Column(Integer, default=2)
    
    # Additional template data
    recommended_for = Column(JSON, nullable=True)  # List of recommended use cases
    tags = Column(JSON, nullable=True)  # Searchable tags
    
    # Metadata
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    creator = relationship("User")


class AggregatorAuditLog(Base):
    """
    Audit log for aggregator configuration changes and decisions.
    Provides compliance and debugging capabilities.
    """
    __tablename__ = "aggregator_audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Event information
    event_type = Column(String(50), nullable=False, index=True)  # config_change, assessment, action, etc.
    event_data = Column(JSON, nullable=False)
    
    # Context
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    tenant_id = Column(String(50), nullable=True, index=True)
    target = Column(String(2000), nullable=True, index=True)
    
    # Related records
    config_id = Column(Integer, ForeignKey("aggregator_configs.id"), nullable=True)
    assessment_id = Column(Integer, ForeignKey("threat_assessments.id"), nullable=True)
    
    # Metadata
    timestamp = Column(DateTime, default=func.now())
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    
    # Relationships
    user = relationship("User")
    config = relationship("AggregatorConfig")
    assessment = relationship("ThreatAssessment")
