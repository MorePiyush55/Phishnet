"""
Persistence and action management for ThreatAggregator results.

Handles storage of threat assessments, execution of downstream actions
(webhooks, quarantine, notifications), and audit trails.
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import asdict

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from app.config.logging import get_logger
from app.core.database import SessionLocal, get_db
from app.models.aggregator import ThreatAssessment, ThreatAction, AggregatorAuditLog
from app.schemas.threat_result import ThreatResult, ThreatLevel
from app.services.config_manager import get_config_manager
from app.services.quarantine_manager import QuarantineManager
from app.services.webhook_server import WebhookService

logger = get_logger(__name__)


class ThreatPersistenceService:
    """Handles persistence of threat assessment results."""
    
    def __init__(self):
        self.logger = logger
        self.config_manager = get_config_manager()
    
    def save_threat_result(
        self,
        db: Session,
        threat_result: ThreatResult,
        user_id: Optional[int] = None,
        tenant_id: Optional[str] = None
    ) -> ThreatAssessment:
        """Save a ThreatResult to the database."""
        
        try:
            # Convert ThreatResult to database model
            assessment = ThreatAssessment(
                analysis_id=threat_result.analysis_id,
                target=threat_result.target,
                target_type=threat_result.target_type,
                score=threat_result.score,
                level=threat_result.level.value,
                confidence=threat_result.confidence,
                components=self._serialize_components(threat_result.components),
                explanation=self._serialize_explanation(threat_result.explanation),
                rule_overrides=self._serialize_rule_overrides(threat_result.rule_overrides),
                component_count=threat_result.component_count,
                component_agreement=threat_result.component_agreement,
                coverage_score=threat_result.coverage_score,
                processing_time_ms=threat_result.processing_time_ms,
                user_id=user_id,
                tenant_id=tenant_id
            )
            
            # Link to configuration if available
            if threat_result.config:
                # Find matching config in database
                config = db.query(AggregatorConfig).filter(
                    and_(
                        AggregatorConfig.tenant_id == tenant_id,
                        AggregatorConfig.is_active == True
                    )
                ).first()
                if config:
                    assessment.config_id = config.id
            
            db.add(assessment)
            db.commit()
            db.refresh(assessment)
            
            # Log the save
            self.config_manager._log_event(
                db,
                event_type="assessment_saved",
                event_data={
                    "assessment_id": assessment.id,
                    "analysis_id": threat_result.analysis_id,
                    "target": threat_result.target,
                    "score": threat_result.score,
                    "level": threat_result.level.value,
                    "component_count": threat_result.component_count
                },
                user_id=user_id,
                tenant_id=tenant_id,
                target=threat_result.target,
                assessment_id=assessment.id
            )
            
            self.logger.info(
                f"Saved threat assessment: {threat_result.analysis_id}, "
                f"target={threat_result.target}, score={threat_result.score:.3f}"
            )
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Error saving threat result: {e}")
            db.rollback()
            raise
    
    def get_threat_result(
        self,
        db: Session,
        analysis_id: str
    ) -> Optional[ThreatResult]:
        """Retrieve a threat result by analysis ID."""
        
        assessment = db.query(ThreatAssessment).filter(
            ThreatAssessment.analysis_id == analysis_id
        ).first()
        
        if assessment:
            return assessment.to_threat_result()
        return None
    
    def get_recent_assessments(
        self,
        db: Session,
        limit: int = 100,
        user_id: Optional[int] = None,
        tenant_id: Optional[str] = None,
        target_type: Optional[str] = None,
        min_score: Optional[float] = None
    ) -> List[ThreatAssessment]:
        """Get recent threat assessments with optional filtering."""
        
        query = db.query(ThreatAssessment)
        
        if user_id:
            query = query.filter(ThreatAssessment.user_id == user_id)
        
        if tenant_id:
            query = query.filter(ThreatAssessment.tenant_id == tenant_id)
        
        if target_type:
            query = query.filter(ThreatAssessment.target_type == target_type)
        
        if min_score is not None:
            query = query.filter(ThreatAssessment.score >= min_score)
        
        return query.order_by(desc(ThreatAssessment.created_at)).limit(limit).all()
    
    def get_assessment_statistics(
        self,
        db: Session,
        tenant_id: Optional[str] = None,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get statistics about threat assessments."""
        
        from sqlalchemy import func
        from datetime import timedelta
        
        # Base query
        query = db.query(ThreatAssessment)
        
        if tenant_id:
            query = query.filter(ThreatAssessment.tenant_id == tenant_id)
        
        # Filter by date range
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(ThreatAssessment.created_at >= cutoff_date)
        
        # Get basic stats
        total_assessments = query.count()
        
        # Level distribution
        level_stats = db.query(
            ThreatAssessment.level,
            func.count(ThreatAssessment.id).label('count')
        ).filter(ThreatAssessment.created_at >= cutoff_date)
        
        if tenant_id:
            level_stats = level_stats.filter(ThreatAssessment.tenant_id == tenant_id)
        
        level_distribution = {
            row.level: row.count for row in level_stats.group_by(ThreatAssessment.level).all()
        }
        
        # Average scores
        avg_score = query.with_entities(func.avg(ThreatAssessment.score)).scalar() or 0.0
        avg_confidence = query.with_entities(func.avg(ThreatAssessment.confidence)).scalar() or 0.0
        avg_processing_time = query.with_entities(func.avg(ThreatAssessment.processing_time_ms)).scalar() or 0.0
        
        return {
            "total_assessments": total_assessments,
            "level_distribution": level_distribution,
            "average_score": float(avg_score),
            "average_confidence": float(avg_confidence),
            "average_processing_time_ms": float(avg_processing_time),
            "days_analyzed": days
        }
    
    def _serialize_components(self, components) -> Dict[str, Any]:
        """Serialize components for database storage."""
        result = {}
        for comp_type, comp_score in components.items():
            result[comp_type.value] = {
                "score": comp_score.score,
                "confidence": comp_score.confidence,
                "weight": comp_score.weight,
                "explanation": comp_score.explanation,
                "evidence_urls": comp_score.evidence_urls,
                "timestamp": comp_score.timestamp,
                "raw_data": comp_score.raw_data
            }
        return result
    
    def _serialize_explanation(self, explanation) -> Dict[str, Any]:
        """Serialize explanation for database storage."""
        return {
            "primary_reasons": explanation.primary_reasons,
            "component_breakdown": explanation.component_breakdown,
            "confidence_reasoning": explanation.confidence_reasoning,
            "recommendations": explanation.recommendations,
            "supporting_evidence": [
                {
                    "type": ev.evidence_type.value,
                    "url": ev.url,
                    "description": ev.description,
                    "metadata": ev.metadata,
                    "component_source": ev.component_source.value if ev.component_source else None,
                    "timestamp": ev.timestamp
                }
                for ev in explanation.supporting_evidence
            ]
        }
    
    def _serialize_rule_overrides(self, rule_overrides) -> List[Dict[str, Any]]:
        """Serialize rule overrides for database storage."""
        return [
            {
                "rule_name": rule.rule_name,
                "condition": rule.condition,
                "triggered": rule.triggered,
                "original_score": rule.original_score,
                "override_level": rule.override_level.value,
                "explanation": rule.explanation,
                "priority": rule.priority
            }
            for rule in rule_overrides
        ]


class ThreatActionService:
    """Handles execution of downstream actions based on threat assessments."""
    
    def __init__(self):
        self.logger = logger
        self.quarantine_manager = QuarantineManager()
        self.webhook_service = WebhookService()
        self.action_handlers = {
            "quarantine": self._handle_quarantine,
            "block": self._handle_block,
            "alert": self._handle_alert,
            "webhook": self._handle_webhook,
            "notify": self._handle_notify
        }
    
    async def execute_actions(
        self,
        threat_result: ThreatResult,
        assessment_id: int,
        user_id: Optional[int] = None,
        tenant_id: Optional[str] = None
    ) -> List[ThreatAction]:
        """Execute appropriate actions based on threat result."""
        
        actions_executed = []
        
        try:
            # Determine actions based on threat level and score
            required_actions = self._determine_actions(threat_result)
            
            for action_config in required_actions:
                action = await self._execute_single_action(
                    action_config,
                    threat_result,
                    assessment_id,
                    user_id,
                    tenant_id
                )
                if action:
                    actions_executed.append(action)
            
            self.logger.info(
                f"Executed {len(actions_executed)} actions for assessment {assessment_id}"
            )
            
        except Exception as e:
            self.logger.error(f"Error executing actions for assessment {assessment_id}: {e}")
        
        return actions_executed
    
    def _determine_actions(self, threat_result: ThreatResult) -> List[Dict[str, Any]]:
        """Determine what actions should be taken based on threat result."""
        actions = []
        
        # Always send alert for any assessment
        actions.append({
            "type": "alert",
            "config": {
                "severity": threat_result.level.value,
                "message": f"Threat detected: {threat_result.target}",
                "score": threat_result.score
            }
        })
        
        # Quarantine for malicious content
        if threat_result.level == ThreatLevel.MALICIOUS:
            actions.append({
                "type": "quarantine",
                "config": {
                    "reason": "Malicious content detected",
                    "auto_quarantine": True,
                    "severity": "high"
                }
            })
            
            # Block for high-confidence malicious
            if threat_result.confidence > 0.8:
                actions.append({
                    "type": "block",
                    "config": {
                        "block_type": "permanent",
                        "reason": "High-confidence malicious detection"
                    }
                })
        
        # Enhanced monitoring for suspicious content
        elif threat_result.level == ThreatLevel.SUSPICIOUS:
            actions.append({
                "type": "notify",
                "config": {
                    "channels": ["email", "dashboard"],
                    "priority": "medium",
                    "message": "Suspicious content requires review"
                }
            })
        
        # Webhook for all significant threats
        if threat_result.score > 0.5:
            actions.append({
                "type": "webhook",
                "config": {
                    "endpoint": "threat_detected",
                    "include_evidence": True
                }
            })
        
        return actions
    
    async def _execute_single_action(
        self,
        action_config: Dict[str, Any],
        threat_result: ThreatResult,
        assessment_id: int,
        user_id: Optional[int],
        tenant_id: Optional[str]
    ) -> Optional[ThreatAction]:
        """Execute a single action and record the result."""
        
        action_type = action_config["type"]
        config = action_config.get("config", {})
        
        # Create action record
        with SessionLocal() as db:
            action = ThreatAction(
                assessment_id=assessment_id,
                action_type=action_type,
                action_config=config,
                created_by=user_id
            )
            db.add(action)
            db.commit()
            db.refresh(action)
        
        try:
            # Execute the action
            handler = self.action_handlers.get(action_type)
            if handler:
                result = await handler(threat_result, config)
                
                # Update action with result
                with SessionLocal() as db:
                    db_action = db.query(ThreatAction).filter(ThreatAction.id == action.id).first()
                    if db_action:
                        db_action.action_status = "completed"
                        db_action.result_data = result
                        db_action.completed_at = datetime.utcnow()
                        db.commit()
                
                self.logger.info(f"Action {action_type} completed for assessment {assessment_id}")
                return action
            else:
                # Unknown action type
                with SessionLocal() as db:
                    db_action = db.query(ThreatAction).filter(ThreatAction.id == action.id).first()
                    if db_action:
                        db_action.action_status = "failed"
                        db_action.error_message = f"Unknown action type: {action_type}"
                        db_action.completed_at = datetime.utcnow()
                        db.commit()
                
                self.logger.error(f"Unknown action type: {action_type}")
                return None
                
        except Exception as e:
            # Update action with error
            with SessionLocal() as db:
                db_action = db.query(ThreatAction).filter(ThreatAction.id == action.id).first()
                if db_action:
                    db_action.action_status = "failed"
                    db_action.error_message = str(e)
                    db_action.completed_at = datetime.utcnow()
                    db.commit()
            
            self.logger.error(f"Action {action_type} failed for assessment {assessment_id}: {e}")
            return action
    
    async def _handle_quarantine(
        self,
        threat_result: ThreatResult,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle quarantine action."""
        
        reason = config.get("reason", "Threat detected")
        auto_quarantine = config.get("auto_quarantine", False)
        
        # Extract target details for quarantine
        target_info = {
            "target": threat_result.target,
            "target_type": threat_result.target_type,
            "threat_score": threat_result.score,
            "threat_level": threat_result.level.value,
            "analysis_id": threat_result.analysis_id
        }
        
        if threat_result.target_type == "url":
            # Quarantine URL-based content
            result = await self.quarantine_manager.quarantine_url(
                url=threat_result.target,
                reason=reason,
                auto_quarantine=auto_quarantine,
                metadata=target_info
            )
        elif threat_result.target_type == "email":
            # Quarantine email
            result = await self.quarantine_manager.quarantine_email(
                email_id=threat_result.target,
                reason=reason,
                auto_quarantine=auto_quarantine,
                metadata=target_info
            )
        else:
            result = {"status": "skipped", "reason": f"Unsupported target type: {threat_result.target_type}"}
        
        return result
    
    async def _handle_block(
        self,
        threat_result: ThreatResult,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle block action."""
        
        block_type = config.get("block_type", "temporary")
        reason = config.get("reason", "Malicious content blocked")
        
        # This would integrate with firewall/blocking systems
        # For now, return a placeholder result
        result = {
            "status": "success",
            "block_type": block_type,
            "target": threat_result.target,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.logger.info(f"Blocked {threat_result.target} ({block_type}): {reason}")
        return result
    
    async def _handle_alert(
        self,
        threat_result: ThreatResult,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle alert action."""
        
        severity = config.get("severity", threat_result.level.value)
        message = config.get("message", f"Threat detected: {threat_result.target}")
        
        # This would integrate with alerting systems (PagerDuty, Slack, etc.)
        # For now, log the alert
        alert_data = {
            "severity": severity,
            "message": message,
            "target": threat_result.target,
            "score": threat_result.score,
            "confidence": threat_result.confidence,
            "primary_reasons": threat_result.explanation.get_top_reasons(3),
            "analysis_id": threat_result.analysis_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.logger.warning(f"THREAT ALERT [{severity.upper()}]: {message}")
        return alert_data
    
    async def _handle_webhook(
        self,
        threat_result: ThreatResult,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle webhook action."""
        
        endpoint = config.get("endpoint", "threat_detected")
        include_evidence = config.get("include_evidence", False)
        
        # Prepare webhook payload
        payload = {
            "event": "threat_detected",
            "analysis_id": threat_result.analysis_id,
            "target": threat_result.target,
            "target_type": threat_result.target_type,
            "threat_level": threat_result.level.value,
            "score": threat_result.score,
            "confidence": threat_result.confidence,
            "primary_reasons": threat_result.explanation.get_top_reasons(5),
            "recommendations": threat_result.explanation.recommendations,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if include_evidence:
            payload["evidence"] = [
                {
                    "type": ev.evidence_type.value,
                    "url": ev.url,
                    "description": ev.description
                }
                for ev in threat_result.get_primary_evidence(3)
            ]
        
        # Send webhook
        result = await self.webhook_service.send_webhook(endpoint, payload)
        return result
    
    async def _handle_notify(
        self,
        threat_result: ThreatResult,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle notification action."""
        
        channels = config.get("channels", ["dashboard"])
        priority = config.get("priority", "medium")
        message = config.get("message", f"Suspicious content detected: {threat_result.target}")
        
        # This would integrate with notification systems
        # For now, return a placeholder result
        result = {
            "status": "success",
            "channels": channels,
            "priority": priority,
            "message": message,
            "target": threat_result.target,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.logger.info(f"Notification sent [{priority}]: {message}")
        return result


class ThreatResultManager:
    """Combined service for threat result persistence and action execution."""
    
    def __init__(self):
        self.persistence_service = ThreatPersistenceService()
        self.action_service = ThreatActionService()
        self.logger = logger
    
    async def process_threat_result(
        self,
        threat_result: ThreatResult,
        user_id: Optional[int] = None,
        tenant_id: Optional[str] = None,
        execute_actions: bool = True
    ) -> Tuple[ThreatAssessment, List[ThreatAction]]:
        """
        Complete processing of a threat result: save to database and execute actions.
        
        Returns:
            Tuple of (saved_assessment, executed_actions)
        """
        
        try:
            # Save threat result to database
            with SessionLocal() as db:
                assessment = self.persistence_service.save_threat_result(
                    db, threat_result, user_id, tenant_id
                )
            
            # Execute actions if enabled
            actions = []
            if execute_actions:
                actions = await self.action_service.execute_actions(
                    threat_result, assessment.id, user_id, tenant_id
                )
            
            self.logger.info(
                f"Processed threat result {threat_result.analysis_id}: "
                f"saved assessment {assessment.id}, executed {len(actions)} actions"
            )
            
            return assessment, actions
            
        except Exception as e:
            self.logger.error(f"Error processing threat result {threat_result.analysis_id}: {e}")
            raise


# Global instance
_threat_result_manager = None


def get_threat_result_manager() -> ThreatResultManager:
    """Get or create the global threat result manager."""
    global _threat_result_manager
    if _threat_result_manager is None:
        _threat_result_manager = ThreatResultManager()
    return _threat_result_manager


async def process_and_store_threat_result(
    threat_result: ThreatResult,
    user_id: Optional[int] = None,
    tenant_id: Optional[str] = None,
    execute_actions: bool = True
) -> Tuple[ThreatAssessment, List[ThreatAction]]:
    """Convenience function for processing threat results."""
    manager = get_threat_result_manager()
    return await manager.process_threat_result(
        threat_result, user_id, tenant_id, execute_actions
    )
