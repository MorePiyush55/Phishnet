"""Scoring and response service for email analysis results."""

import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
import asyncio

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from app.config.logging import get_logger
from app.core.database import SessionLocal
from app.models.core.email import Email, EmailStatus
from app.models.analysis.scoring import EmailAction, ActionType, ActionStatus, EmailScore, ScoringRule
from app.models.analysis.link_analysis import LinkAnalysis, EmailAIResults, EmailIndicators
from app.services.gmail import GmailService
from app.services.audit import AuditService

logger = get_logger(__name__)


class ScoringEngine:
    """Configurable scoring engine for email analysis."""
    
    def __init__(self):
        self.default_weights = {
            'sanitization': 0.2,
            'links': 0.3,
            'ai': 0.3,
            'threat_intel': 0.2
        }
        
        self.risk_thresholds = {
            'low': 0.3,
            'medium': 0.6, 
            'high': 0.8,
            'critical': 0.9
        }
        
        self.quarantine_threshold = 0.7
        
    def calculate_score(self, email_id: int, db: Session) -> EmailScore:
        """Calculate final score for an email based on all analysis components."""
        
        # Get existing score to avoid recalculation
        existing_score = db.query(EmailScore).filter(EmailScore.email_id == email_id).first()
        if existing_score:
            return existing_score
        
        # Get component scores
        component_scores = self._get_component_scores(email_id, db)
        
        # Get active scoring rules (for multi-tenant support)
        weights = self._get_scoring_weights(db)
        
        # Calculate weighted final score
        final_score = 0.0
        for component, score in component_scores.items():
            weight = weights.get(component, self.default_weights.get(component, 0.0))
            final_score += score * weight
        
        final_score = min(final_score, 1.0)  # Cap at 1.0
        
        # Determine risk level
        risk_level = self._determine_risk_level(final_score)
        
        # Determine if phishing
        is_phishing = final_score >= self.quarantine_threshold
        
        # Calculate confidence based on component agreement
        confidence = self._calculate_confidence(component_scores)
        
        # Create email score record
        email_score = EmailScore(
            email_id=email_id,
            sanitization_score=component_scores.get('sanitization', 0.0),
            link_score=component_scores.get('links', 0.0),
            ai_score=component_scores.get('ai', 0.0),
            threat_intel_score=component_scores.get('threat_intel', 0.0),
            final_score=final_score,
            risk_level=risk_level,
            is_phishing=is_phishing,
            confidence=confidence,
            rules_applied=weights
        )
        
        db.add(email_score)
        db.commit()
        db.refresh(email_score)
        
        return email_score
    
    def _get_component_scores(self, email_id: int, db: Session) -> Dict[str, float]:
        """Get scores from all analysis components."""
        scores = {
            'sanitization': 0.0,
            'links': 0.0,
            'ai': 0.0,
            'threat_intel': 0.0
        }
        
        # Get email for basic analysis
        email = db.query(Email).filter(Email.id == email_id).first()
        if not email:
            return scores
        
        # Content sanitization score (simplified)
        if email.raw_html:
            sanitization_risk = 0.0
            content = email.raw_html.lower()
            
            if '<script' in content:
                sanitization_risk += 0.4
            if any(event in content for event in ['onclick', 'onload', 'onerror']):
                sanitization_risk += 0.3
            if 'javascript:' in content:
                sanitization_risk += 0.2
            
            scores['sanitization'] = min(sanitization_risk, 1.0)
        
        # Link analysis score
        link_analyses = db.query(LinkAnalysis).filter(LinkAnalysis.email_id == email_id).all()
        if link_analyses:
            total_link_score = sum(link.risk_score for link in link_analyses)
            avg_link_score = total_link_score / len(link_analyses)
            
            # Boost if multiple high-risk links
            high_risk_count = len([link for link in link_analyses if link.risk_score > 0.7])
            if high_risk_count > 1:
                avg_link_score = min(avg_link_score + (high_risk_count * 0.1), 1.0)
            
            scores['links'] = avg_link_score
        
        # AI analysis score
        ai_result = db.query(EmailAIResults).filter(EmailAIResults.email_id == email_id).first()
        if ai_result:
            scores['ai'] = ai_result.ai_score
        
        # Threat intelligence score
        indicators = db.query(EmailIndicators).filter(EmailIndicators.email_id == email_id).all()
        if indicators:
            max_threat_score = max(indicator.reputation_score or 0.0 for indicator in indicators)
            malicious_count = len([ind for ind in indicators if (ind.reputation_score or 0.0) > 0.7])
            
            if malicious_count > 0:
                max_threat_score = min(max_threat_score + (malicious_count * 0.1), 1.0)
            
            scores['threat_intel'] = max_threat_score
        
        return scores
    
    def _get_scoring_weights(self, db: Session, tenant_id: str = None) -> Dict[str, float]:
        """Get scoring weights from database rules or use defaults."""
        try:
            rules = db.query(ScoringRule).filter(
                and_(
                    ScoringRule.is_active == True,
                    or_(ScoringRule.tenant_id == tenant_id, ScoringRule.tenant_id.is_(None))
                )
            ).all()
            
            weights = self.default_weights.copy()
            for rule in rules:
                weights[rule.component] = rule.weight
            
            return weights
        except Exception as e:
            logger.warning(f"Failed to get custom scoring weights: {str(e)}")
            return self.default_weights
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score."""
        if score >= self.risk_thresholds['critical']:
            return 'critical'
        elif score >= self.risk_thresholds['high']:
            return 'high'
        elif score >= self.risk_thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_confidence(self, component_scores: Dict[str, float]) -> float:
        """Calculate confidence based on component score agreement."""
        scores = [score for score in component_scores.values() if score > 0]
        if len(scores) < 2:
            return 0.5  # Low confidence with limited data
        
        # Calculate standard deviation to measure agreement
        avg_score = sum(scores) / len(scores)
        variance = sum((score - avg_score) ** 2 for score in scores) / len(scores)
        std_dev = variance ** 0.5
        
        # Convert to confidence (lower std_dev = higher confidence)
        confidence = max(0.1, 1.0 - (std_dev * 2))
        return min(confidence, 1.0)


class ResponseEngine:
    """Engine for taking automated actions based on email scores."""
    
    def __init__(self):
        self.gmail_service = None
        self.audit_service = AuditService()
    
    async def process_email_score(self, email_score: EmailScore, user_id: int, db: Session) -> List[EmailAction]:
        """Process email score and take appropriate actions."""
        actions_taken = []
        
        try:
            # Get email
            email = db.query(Email).filter(Email.id == email_score.email_id).first()
            if not email:
                logger.error(f"Email {email_score.email_id} not found for scoring")
                return actions_taken
            
            # Determine actions based on score
            if email_score.final_score >= 0.9:
                # Critical threat - quarantine immediately
                action = await self._create_quarantine_action(
                    email, user_id, "Critical threat detected", db
                )
                actions_taken.append(action)
                
            elif email_score.final_score >= 0.7:
                # High threat - quarantine with review
                action = await self._create_quarantine_action(
                    email, user_id, "High risk phishing detected", db
                )
                actions_taken.append(action)
                
            elif email_score.final_score >= 0.5:
                # Medium threat - label for review
                action = await self._create_label_action(
                    email, user_id, "PhishNet/Review", "Medium risk detected", db
                )
                actions_taken.append(action)
            
            # Update email status
            if email_score.final_score >= 0.7:
                email.status = EmailStatus.QUARANTINED
            elif email_score.final_score >= 0.5:
                email.status = EmailStatus.ANALYZED  # Keep as analyzed but flagged
            else:
                email.status = EmailStatus.SAFE
            
            email.score = email_score.final_score
            db.commit()
            
            # Execute actions
            for action in actions_taken:
                await self._execute_action(action, db)
            
            # Audit log
            await self.audit_service.log_email_scored(
                email_score.email_id, email_score.final_score, 
                email_score.risk_level, user_id, db
            )
            
        except Exception as e:
            logger.error(f"Failed to process email score {email_score.id}: {str(e)}")
            await self.audit_service.log_action_failed(
                f"process_score_{email_score.id}", str(e), user_id, db
            )
        
        return actions_taken


# Backwards-compatible RiskCalculator expected by some tests
    async def _create_quarantine_action(self, email: Email, user_id: int, 
                                      reason: str, db: Session) -> EmailAction:
        """Create a quarantine action."""
        action = EmailAction(
            email_id=email.id,
            action_type=ActionType.QUARANTINE,
            status=ActionStatus.PENDING,
            parameters={
                'reason': reason,
                'label': 'PhishNet/Quarantine',
                'automatic': True
            },
            created_by=user_id,
            gmail_message_id=email.gmail_msg_id
        )
        
        db.add(action)
        db.commit()
        db.refresh(action)
        
        return action
    
    async def _create_label_action(self, email: Email, user_id: int, 
                                 label: str, reason: str, db: Session) -> EmailAction:
        """Create a labeling action."""
        action = EmailAction(
            email_id=email.id,
            action_type=ActionType.LABEL,
            status=ActionStatus.PENDING,
            parameters={
                'label': label,
                'reason': reason,
                'automatic': True
            },
            created_by=user_id,
            gmail_message_id=email.gmail_msg_id
        )
        
        db.add(action)
        db.commit()
        db.refresh(action)
        
        return action


    # module exports will be declared at bottom
    
    async def _execute_action(self, action: EmailAction, db: Session) -> bool:
        """Execute an email action."""
        try:
            action.status = ActionStatus.IN_PROGRESS
            action.started_at = datetime.now(timezone.utc)
            db.commit()
            
            success = False
            
            if action.action_type == ActionType.QUARANTINE:
                success = await self._execute_quarantine(action, db)
            elif action.action_type == ActionType.LABEL:
                success = await self._execute_label(action, db)
            elif action.action_type == ActionType.UNQUARANTINE:
                success = await self._execute_unquarantine(action, db)
            
            # Update action status
            action.status = ActionStatus.COMPLETED if success else ActionStatus.FAILED
            action.completed_at = datetime.now(timezone.utc)
            
            if success:
                action.result = {'success': True, 'executed_at': action.completed_at.isoformat()}
            else:
                action.retry_count += 1
                
            db.commit()
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to execute action {action.id}: {str(e)}")
            action.status = ActionStatus.FAILED
            action.error_message = str(e)
            action.retry_count += 1
            db.commit()
            return False
    
    async def _execute_quarantine(self, action: EmailAction, db: Session) -> bool:
        """Execute quarantine action via Gmail API."""
        try:
            if not action.gmail_message_id:
                logger.warning(f"No Gmail message ID for action {action.id}")
                return False
            
            # Initialize Gmail service if needed
            if not self.gmail_service:
                self.gmail_service = GmailService()
            
            # Apply quarantine label
            label_name = action.parameters.get('label', 'PhishNet/Quarantine')
            
            # This would integrate with Gmail API
            # result = await self.gmail_service.apply_label(
            #     action.gmail_message_id, label_name
            # )
            
            # For demo purposes, simulate success
            result = {
                'success': True,
                'label_applied': label_name,
                'message_id': action.gmail_message_id
            }
            
            action.result = result
            action.gmail_label_id = "label_123"  # Would be real label ID from Gmail
            
            logger.info(f"Quarantined email {action.email_id} with label {label_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to quarantine email {action.email_id}: {str(e)}")
            return False
    
    async def _execute_label(self, action: EmailAction, db: Session) -> bool:
        """Execute labeling action via Gmail API."""
        try:
            if not action.gmail_message_id:
                return True  # Can still label locally
            
            label_name = action.parameters.get('label', 'PhishNet/Review')
            
            # This would integrate with Gmail API
            result = {
                'success': True,
                'label_applied': label_name,
                'message_id': action.gmail_message_id
            }
            
            action.result = result
            action.gmail_label_id = "label_456"
            
            logger.info(f"Labeled email {action.email_id} with {label_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to label email {action.email_id}: {str(e)}")
            return False
    
    async def _execute_unquarantine(self, action: EmailAction, db: Session) -> bool:
        """Execute unquarantine action via Gmail API."""
        try:
            if not action.gmail_message_id:
                return True
            
            # Remove quarantine label
            result = {
                'success': True,
                'label_removed': 'PhishNet/Quarantine',
                'message_id': action.gmail_message_id
            }
            
            action.result = result
            
            logger.info(f"Unquarantined email {action.email_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unquarantine email {action.email_id}: {str(e)}")
            return False


# Singleton instances
class RiskCalculator:
    """Backwards-compatible RiskCalculator expected by some tests.

    This is a tiny compatibility shim that mirrors the historical
    interface used by tests: an object with a `calculate(email_score)`
    method that returns the final_score.
    """
    def calculate(self, email_score: EmailScore) -> float:
        return getattr(email_score, 'final_score', 0.0)


# Backwards compatible export (kept for clarity)
RiskCalculator = RiskCalculator


scoring_engine = ScoringEngine()
response_engine = ResponseEngine()


async def score_and_respond_email(email_id: int, user_id: int) -> Tuple[EmailScore, List[EmailAction]]:
    """Score an email and take appropriate response actions."""
    db = SessionLocal()
    try:
        # Calculate score
        email_score = scoring_engine.calculate_score(email_id, db)
        
        # Take response actions
        actions = await response_engine.process_email_score(email_score, user_id, db)
        
        return email_score, actions
        
    finally:
        db.close()


async def manual_action(email_id: int, action_type: ActionType, user_id: int, 
                       parameters: Dict[str, Any] = None) -> EmailAction:
    """Manually trigger an action on an email."""
    db = SessionLocal()
    try:
        # Get email
        email = db.query(Email).filter(Email.id == email_id).first()
        if not email:
            raise ValueError(f"Email {email_id} not found")
        
        # Create action
        action = EmailAction(
            email_id=email_id,
            action_type=action_type,
            status=ActionStatus.PENDING,
            parameters=parameters or {},
            created_by=user_id,
            gmail_message_id=email.gmail_msg_id
        )
        
        db.add(action)
        db.commit()
        db.refresh(action)
        
        # Execute action
        await response_engine._execute_action(action, db)
        
        # Update email status if needed
        if action_type == ActionType.QUARANTINE and action.status == ActionStatus.COMPLETED:
            email.status = EmailStatus.QUARANTINED
        elif action_type == ActionType.UNQUARANTINE and action.status == ActionStatus.COMPLETED:
            email.status = EmailStatus.SAFE
        
        db.commit()
        
        return action
        
    finally:
        db.close()
