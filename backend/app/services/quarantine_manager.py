"""Auto-quarantine system for handling Gmail message actions."""

import json
import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List
import traceback

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db
from app.core.redis_client import redis_client
from app.models.email_scan import (
    EmailScanRequest, QuarantineAction, AuditLog, ThreatLevel
)
from app.services.gmail_secure import gmail_service
from app.services.websocket_manager import websocket_manager
from app.core.metrics import quarantine_metrics

logger = get_logger(__name__)


class QuarantineManager:
    """Manages email quarantine and approval actions."""
    
    def __init__(self):
        """Initialize quarantine manager."""
        self.quarantine_label = "PHISHNET_QUARANTINED"
        self.approved_label = "PHISHNET_APPROVED" 
        self.processing = False
    
    async def start_processor(self):
        """Start the quarantine action processor."""
        self.processing = True
        logger.info("Starting quarantine action processor")
        
        try:
            while self.processing:
                await self._process_quarantine_batch()
                await asyncio.sleep(2)  # Brief pause
        except Exception as e:
            logger.error(f"Quarantine processor crashed: {e}")
            logger.error(traceback.format_exc())
        finally:
            self.processing = False
    
    async def stop_processor(self):
        """Stop the quarantine action processor."""
        self.processing = False
        logger.info("Stopping quarantine action processor")
    
    async def _process_quarantine_batch(self):
        """Process a batch of quarantine actions."""
        try:
            # Get job from Redis queue
            job_data = await redis_client.brpop("quarantine_actions_queue", timeout=5)
            
            if not job_data:
                return  # No jobs available
            
            queue_name, job_json = job_data
            job = json.loads(job_json.decode())
            
            await self._process_quarantine_action(job)
            
        except Exception as e:
            logger.error(f"Quarantine batch processing error: {e}")
    
    async def _process_quarantine_action(self, job: Dict[str, Any]):
        """Process individual quarantine action."""
        scan_request_id = job.get("scan_request_id")
        user_id = job.get("user_id")
        gmail_message_id = job.get("gmail_message_id")
        action_type = job.get("action_type")  # "quarantine", "approve", "label"
        action_method = job.get("action_method")  # "auto", "manual", "policy"
        
        if not all([scan_request_id, user_id, gmail_message_id, action_type]):
            logger.error(f"Invalid quarantine job: {job}")
            return
        
        logger.info(f"Processing {action_type} action for email {gmail_message_id}")
        
        try:
            # Get scan request
            async with get_db() as db:
                scan_request = db.query(EmailScanRequest).filter(
                    EmailScanRequest.id == scan_request_id
                ).first()
                
                if not scan_request:
                    logger.error(f"Scan request {scan_request_id} not found")
                    return
            
            # Execute the action
            success = await self._execute_gmail_action(
                user_id, gmail_message_id, action_type, job
            )
            
            # Record the action
            await self._record_quarantine_action(
                scan_request, action_type, action_method, job, success
            )
            
            # Send WebSocket notification
            await self._send_action_notification(scan_request, action_type, success)
            
            # Update metrics
            if success:
                quarantine_metrics.actions_successful.labels(action_type=action_type).inc()
            else:
                quarantine_metrics.actions_failed.labels(action_type=action_type).inc()
            
        except Exception as e:
            logger.error(f"Quarantine action processing failed: {e}")
            logger.error(traceback.format_exc())
    
    async def _execute_gmail_action(
        self,
        user_id: int,
        gmail_message_id: str,
        action_type: str,
        job: Dict[str, Any]
    ) -> bool:
        """Execute the Gmail API action."""
        try:
            if action_type == "quarantine":
                return await gmail_service.apply_label(
                    user_id, gmail_message_id, self.quarantine_label, "quarantine"
                )
            
            elif action_type == "approve":
                # Remove quarantine label if present, add approved label
                success1 = await gmail_service.remove_label(
                    user_id, gmail_message_id, self.quarantine_label
                )
                success2 = await gmail_service.apply_label(
                    user_id, gmail_message_id, self.approved_label, "approve"
                )
                return success1 and success2
            
            elif action_type == "label":
                custom_label = job.get("label", "PHISHNET_PROCESSED")
                return await gmail_service.apply_label(
                    user_id, gmail_message_id, custom_label, "label"
                )
            
            else:
                logger.error(f"Unknown action type: {action_type}")
                return False
                
        except Exception as e:
            logger.error(f"Gmail action execution failed: {e}")
            return False
    
    async def _record_quarantine_action(
        self,
        scan_request: EmailScanRequest,
        action_type: str,
        action_method: str,
        job: Dict[str, Any],
        success: bool
    ):
        """Record quarantine action in database."""
        try:
            async with get_db() as db:
                # Create quarantine action record
                quarantine_action = QuarantineAction(
                    scan_request_id=scan_request.id,
                    user_id=scan_request.user_id,
                    action_type=action_type,
                    action_method=action_method,
                    gmail_message_id=scan_request.gmail_message_id,
                    gmail_labels_applied=[job.get("label", self.quarantine_label)],
                    gmail_action_successful=success,
                    policy_rule=job.get("policy_rule"),
                    threat_level_at_action=job.get("threat_level"),
                    executed_at=datetime.utcnow() if success else None
                )
                
                db.add(quarantine_action)
                
                # Create audit log
                audit = AuditLog(
                    user_id=scan_request.user_id,
                    scan_request_id=scan_request.id,
                    action=f"gmail_{action_type}",
                    resource_type="email",
                    resource_id=scan_request.gmail_message_id,
                    success=success,
                    details={
                        "action_type": action_type,
                        "action_method": action_method,
                        "threat_level": job.get("threat_level"),
                        "threat_score": job.get("threat_score"),
                        "policy_rule": job.get("policy_rule"),
                        "labels_applied": [job.get("label", self.quarantine_label)]
                    },
                    legal_basis="legitimate_interest"
                )
                
                db.add(audit)
                db.commit()
                
                logger.info(f"Recorded {action_type} action for email {scan_request.gmail_message_id}")
                
        except Exception as e:
            logger.error(f"Failed to record quarantine action: {e}")
    
    async def _send_action_notification(
        self,
        scan_request: EmailScanRequest,
        action_type: str,
        success: bool
    ):
        """Send WebSocket notification about the action."""
        try:
            notification = {
                "type": "quarantine_action",
                "scan_request_id": str(scan_request.id),
                "gmail_message_id": scan_request.gmail_message_id,
                "action_type": action_type,
                "success": success,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await websocket_manager.send_to_user(scan_request.user_id, notification)
            
        except Exception as e:
            logger.error(f"Failed to send action notification: {e}")
    
    async def queue_manual_action(
        self,
        scan_request_id: str,
        user_id: int,
        action_type: str,
        user_override: bool = True
    ) -> bool:
        """Queue a manual quarantine action."""
        try:
            async with get_db() as db:
                scan_request = db.query(EmailScanRequest).filter(
                    EmailScanRequest.id == scan_request_id,
                    EmailScanRequest.user_id == user_id
                ).first()
                
                if not scan_request:
                    logger.error(f"Scan request {scan_request_id} not found for user {user_id}")
                    return False
                
                # Create manual action job
                job = {
                    "scan_request_id": scan_request_id,
                    "user_id": user_id,
                    "gmail_message_id": scan_request.gmail_message_id,
                    "action_type": action_type,
                    "action_method": "manual",
                    "user_override": user_override,
                    "requested_at": datetime.utcnow().isoformat()
                }
                
                # Add to high-priority queue
                await redis_client.lpush("quarantine_actions_queue", json.dumps(job))
                
                logger.info(f"Queued manual {action_type} for scan {scan_request_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to queue manual action: {e}")
            return False
    
    async def get_quarantine_stats(self, user_id: int) -> Dict[str, Any]:
        """Get quarantine statistics for a user."""
        try:
            async with get_db() as db:
                # Get recent actions
                recent_actions = db.query(QuarantineAction).filter(
                    QuarantineAction.user_id == user_id
                ).order_by(QuarantineAction.requested_at.desc()).limit(100).all()
                
                # Calculate stats
                total_actions = len(recent_actions)
                successful_actions = sum(1 for action in recent_actions if action.gmail_action_successful)
                
                action_counts = {}
                for action in recent_actions:
                    action_type = action.action_type
                    action_counts[action_type] = action_counts.get(action_type, 0) + 1
                
                return {
                    "total_actions": total_actions,
                    "successful_actions": successful_actions,
                    "success_rate": successful_actions / total_actions if total_actions > 0 else 0,
                    "action_counts": action_counts,
                    "recent_actions": [
                        {
                            "id": str(action.id),
                            "action_type": action.action_type,
                            "action_method": action.action_method,
                            "successful": action.gmail_action_successful,
                            "requested_at": action.requested_at.isoformat(),
                            "executed_at": action.executed_at.isoformat() if action.executed_at else None
                        }
                        for action in recent_actions[:10]
                    ]
                }
                
        except Exception as e:
            logger.error(f"Failed to get quarantine stats for user {user_id}: {e}")
            return {"error": str(e)}


class PolicyEngine:
    """Policy engine for auto-quarantine decisions."""
    
    def __init__(self):
        """Initialize policy engine."""
        self.policies = self._load_default_policies()
    
    def _load_default_policies(self) -> List[Dict[str, Any]]:
        """Load default quarantine policies."""
        return [
            {
                "name": "critical_threat_auto_quarantine",
                "description": "Auto-quarantine emails with CRITICAL threat level",
                "conditions": {
                    "threat_level": ["CRITICAL"],
                    "confidence": {"min": 0.7}
                },
                "action": "quarantine",
                "enabled": True,
                "priority": 1
            },
            {
                "name": "high_score_auto_quarantine", 
                "description": "Auto-quarantine emails with high threat score",
                "conditions": {
                    "threat_score": {"min": 0.8},
                    "confidence": {"min": 0.6}
                },
                "action": "quarantine",
                "enabled": True,
                "priority": 2
            },
            {
                "name": "multiple_malicious_links",
                "description": "Auto-quarantine emails with multiple malicious links",
                "conditions": {
                    "malicious_links": {"min": 2},
                    "threat_level": ["HIGH", "CRITICAL"]
                },
                "action": "quarantine",
                "enabled": True,
                "priority": 3
            },
            {
                "name": "known_phishing_domains",
                "description": "Auto-quarantine emails from known phishing domains",
                "conditions": {
                    "phishing_indicators": {"contains": ["known_phishing_domain"]},
                    "confidence": {"min": 0.8}
                },
                "action": "quarantine",
                "enabled": True,
                "priority": 4
            }
        ]
    
    def evaluate_policies(
        self,
        threat_result: Dict[str, Any],
        scan_request: EmailScanRequest
    ) -> Optional[Dict[str, Any]]:
        """Evaluate policies against threat result."""
        try:
            # Sort policies by priority
            sorted_policies = sorted(
                [p for p in self.policies if p["enabled"]],
                key=lambda x: x["priority"]
            )
            
            for policy in sorted_policies:
                if self._evaluate_policy_conditions(policy["conditions"], threat_result):
                    logger.info(f"Policy '{policy['name']}' triggered for scan {scan_request.id}")
                    return {
                        "policy_name": policy["name"],
                        "policy_description": policy["description"],
                        "action": policy["action"],
                        "priority": policy["priority"],
                        "matched_conditions": policy["conditions"]
                    }
            
            return None  # No policies matched
            
        except Exception as e:
            logger.error(f"Policy evaluation failed: {e}")
            return None
    
    def _evaluate_policy_conditions(
        self,
        conditions: Dict[str, Any],
        threat_result: Dict[str, Any]
    ) -> bool:
        """Evaluate policy conditions against threat result."""
        try:
            for condition_key, condition_value in conditions.items():
                result_value = threat_result.get(condition_key)
                
                if not self._check_condition(result_value, condition_value):
                    return False
            
            return True  # All conditions met
            
        except Exception as e:
            logger.error(f"Condition evaluation failed: {e}")
            return False
    
    def _check_condition(self, result_value: Any, condition: Any) -> bool:
        """Check individual condition."""
        try:
            if isinstance(condition, list):
                # Check if result_value is in the list
                return result_value in condition
            
            elif isinstance(condition, dict):
                if "min" in condition:
                    return isinstance(result_value, (int, float)) and result_value >= condition["min"]
                
                elif "max" in condition:
                    return isinstance(result_value, (int, float)) and result_value <= condition["max"]
                
                elif "contains" in condition:
                    if isinstance(result_value, list):
                        return any(item in condition["contains"] for item in result_value)
                    elif isinstance(result_value, str):
                        return any(item in result_value for item in condition["contains"])
                
                elif "equals" in condition:
                    return result_value == condition["equals"]
            
            else:
                # Direct equality check
                return result_value == condition
            
            return False
            
        except Exception as e:
            logger.error(f"Condition check failed: {e}")
            return False


# Global instances
quarantine_manager = QuarantineManager()
policy_engine = PolicyEngine()


async def start_quarantine_service():
    """Start the quarantine service."""
    logger.info("Starting quarantine service")
    await quarantine_manager.start_processor()


async def stop_quarantine_service():
    """Stop the quarantine service."""
    logger.info("Stopping quarantine service")
    await quarantine_manager.stop_processor()


if __name__ == "__main__":
    asyncio.run(start_quarantine_service())
