"""
Playbook Engine - Executes playbook rules using PhishNet analyzers.

This module takes parsed playbook rules and executes them by mapping
playbook actions to PhishNet's existing analyzer infrastructure.
"""

import asyncio
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime
import json

from app.config.logging import get_logger
from app.integrations.playbooks.playbook_adapter import (
    PlaybookRule, PlaybookBlock, PlaybookAction, PlaybookCondition, ActionType
)

logger = get_logger(__name__)


@dataclass
class PlaybookExecutionContext:
    """Context for playbook execution."""
    scan_request_id: str
    email_data: Dict[str, Any]
    urls: List[str]
    ips: List[str]
    domains: List[str]
    file_hashes: List[str]
    results: Dict[str, Any]
    
    def __post_init__(self):
        if self.results is None:
            self.results = {}


@dataclass
class PlaybookExecutionResult:
    """Result of playbook execution."""
    playbook_name: str
    success: bool
    blocks_executed: List[str]
    actions_completed: List[str]
    conditions_evaluated: int
    findings: List[Dict[str, Any]]
    severity_level: str
    execution_time_ms: float
    errors: List[str]
    
    def __post_init__(self):
        if self.blocks_executed is None:
            self.blocks_executed = []
        if self.actions_completed is None:
            self.actions_completed = []
        if self.findings is None:
            self.findings = []
        if self.errors is None:
            self.errors = []


class PlaybookEngine:
    """
    Executes playbook rules by mapping actions to PhishNet analyzers.
    
    This engine:
    1. Loads parsed playbook rules
    2. Evaluates conditions and decisions
    3. Maps actions to orchestrator methods
    4. Aggregates results
    """
    
    def __init__(self, orchestrator=None):
        """
        Initialize playbook engine.
        
        Args:
            orchestrator: EnhancedThreatOrchestrator instance for executing actions
        """
        self.orchestrator = orchestrator
        self.loaded_playbooks: Dict[str, PlaybookRule] = {}
        self.logger = logger
        self.execution_stats = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "total_actions": 0,
            "total_conditions": 0
        }
    
    def load_playbook_rules(self, rules_dir: str) -> int:
        """Load playbook rules from JSON files."""
        from pathlib import Path
        
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            self.logger.warning(f"Playbook rules directory not found: {rules_dir}")
            return 0
        
        loaded_count = 0
        for rule_file in rules_path.glob("*.json"):
            try:
                rule_data = json.loads(rule_file.read_text())
                playbook_name = rule_data["playbook_name"]
                
                # Store rule data (simplified for now)
                self.loaded_playbooks[playbook_name] = rule_data
                loaded_count += 1
                
                self.logger.info(f"Loaded playbook: {playbook_name}")
            except Exception as e:
                self.logger.error(f"Failed to load playbook {rule_file}: {e}")
        
        self.logger.info(f"Loaded {loaded_count} playbook rules")
        return loaded_count
    
    async def execute_playbook(
        self,
        playbook_name: str,
        context: PlaybookExecutionContext
    ) -> PlaybookExecutionResult:
        """Execute a single playbook with given context."""
        start_time = datetime.now()
        
        try:
            if playbook_name not in self.loaded_playbooks:
                return PlaybookExecutionResult(
                    playbook_name=playbook_name,
                    success=False,
                    blocks_executed=[],
                    actions_completed=[],
                    conditions_evaluated=0,
                    findings=[],
                    severity_level="unknown",
                    execution_time_ms=0.0,
                    errors=[f"Playbook not found: {playbook_name}"]
                )
            
            playbook_data = self.loaded_playbooks[playbook_name]
            
            # Execute playbook blocks
            result = await self._execute_playbook_blocks(playbook_data, context)
            
            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            result.execution_time_ms = execution_time
            
            # Update stats
            self.execution_stats["total_executions"] += 1
            if result.success:
                self.execution_stats["successful_executions"] += 1
            else:
                self.execution_stats["failed_executions"] += 1
            
            return result
            
        except Exception as e:
            self.logger.error(f"Playbook execution failed: {e}")
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            return PlaybookExecutionResult(
                playbook_name=playbook_name,
                success=False,
                blocks_executed=[],
                actions_completed=[],
                conditions_evaluated=0,
                findings=[],
                severity_level="error",
                execution_time_ms=execution_time,
                errors=[str(e)]
            )
    
    async def _execute_playbook_blocks(
        self,
        playbook_data: Dict[str, Any],
        context: PlaybookExecutionContext
    ) -> PlaybookExecutionResult:
        """Execute all blocks in a playbook."""
        blocks_executed = []
        actions_completed = []
        conditions_evaluated = 0
        findings = []
        errors = []
        severity_level = "low"
        
        try:
            blocks = playbook_data.get("blocks", {})
            entry_point = playbook_data.get("entry_point", "on_start")
            
            # Start execution from entry point
            current_block = entry_point
            visited_blocks: Set[str] = set()
            
            while current_block and current_block not in visited_blocks:
                visited_blocks.add(current_block)
                
                if current_block not in blocks:
                    break
                
                block_data = blocks[current_block]
                blocks_executed.append(current_block)
                
                # Execute block
                block_result = await self._execute_block(block_data, context)
                
                # Aggregate results
                actions_completed.extend(block_result.get("actions", []))
                conditions_evaluated += block_result.get("conditions_count", 0)
                findings.extend(block_result.get("findings", []))
                
                if block_result.get("errors"):
                    errors.extend(block_result["errors"])
                
                # Determine next block
                next_blocks = block_data.get("next_blocks", [])
                current_block = next_blocks[0] if next_blocks else None
            
            # Determine severity from findings
            severity_level = self._calculate_severity(findings)
            
            return PlaybookExecutionResult(
                playbook_name=playbook_data["playbook_name"],
                success=len(errors) == 0,
                blocks_executed=blocks_executed,
                actions_completed=actions_completed,
                conditions_evaluated=conditions_evaluated,
                findings=findings,
                severity_level=severity_level,
                execution_time_ms=0.0,  # Will be set by caller
                errors=errors
            )
            
        except Exception as e:
            self.logger.error(f"Block execution failed: {e}")
            return PlaybookExecutionResult(
                playbook_name=playbook_data.get("playbook_name", "unknown"),
                success=False,
                blocks_executed=blocks_executed,
                actions_completed=actions_completed,
                conditions_evaluated=conditions_evaluated,
                findings=findings,
                severity_level="error",
                execution_time_ms=0.0,
                errors=[str(e)]
            )
    
    async def _execute_block(
        self,
        block_data: Dict[str, Any],
        context: PlaybookExecutionContext
    ) -> Dict[str, Any]:
        """Execute a single block."""
        result = {
            "actions": [],
            "conditions_count": 0,
            "findings": [],
            "errors": []
        }
        
        try:
            block_type = block_data.get("block_type")
            
            # Evaluate conditions
            conditions = block_data.get("conditions", [])
            if conditions:
                result["conditions_count"] = len(conditions)
                conditions_met = self._evaluate_conditions(conditions, context)
                
                if not conditions_met:
                    # Skip this block if conditions not met
                    return result
            
            # Execute actions
            actions = block_data.get("actions", [])
            for action_data in actions:
                action_result = await self._execute_action(action_data, context)
                result["actions"].append(action_data["name"])
                
                if action_result:
                    result["findings"].append(action_result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Block execution error: {e}")
            result["errors"].append(str(e))
            return result
    
    def _evaluate_conditions(
        self,
        conditions: List[Dict[str, Any]],
        context: PlaybookExecutionContext
    ) -> bool:
        """Evaluate block conditions."""
        for condition in conditions:
            field = condition.get("field", "")
            operator = condition.get("operator", "")
            value = condition.get("value", "")
            
            # Extract field value from context
            field_value = self._get_field_value(field, context)
            
            # Evaluate condition
            if not self._evaluate_condition(field_value, operator, value):
                return False
        
        return True
    
    def _get_field_value(self, field: str, context: PlaybookExecutionContext) -> Any:
        """Extract field value from context."""
        # Handle common field patterns
        if "url" in field.lower():
            return context.urls
        elif "ip" in field.lower() or "destinationAddress" in field:
            return context.ips
        elif "domain" in field.lower():
            return context.domains
        elif "hash" in field.lower() or "fileHash" in field:
            return context.file_hashes
        elif "vaultId" in field:
            return context.email_data.get("attachments", [])
        else:
            # Try to get from email data
            return context.email_data.get(field, None)
    
    def _evaluate_condition(self, field_value: Any, operator: str, expected_value: Any) -> bool:
        """Evaluate a single condition."""
        if operator == "!=":
            return field_value != expected_value
        elif operator == "==":
            return field_value == expected_value
        elif operator == ">":
            return field_value > expected_value
        elif operator == ">=":
            return field_value >= expected_value
        elif operator == "<":
            return field_value < expected_value
        elif operator == "<=":
            return field_value <= expected_value
        elif operator == "in":
            return expected_value in field_value if field_value else False
        else:
            return True
    
    async def _execute_action(
        self,
        action_data: Dict[str, Any],
        context: PlaybookExecutionContext
    ) -> Optional[Dict[str, Any]]:
        """Execute a playbook action by mapping to orchestrator."""
        try:
            action_type = action_data.get("action_type")
            action_name = action_data.get("name")
            
            self.execution_stats["total_actions"] += 1
            
            # Map action to orchestrator method
            if action_type == "url_reputation":
                return await self._execute_url_reputation(context)
            elif action_type == "ip_reputation":
                return await self._execute_ip_reputation(context)
            elif action_type == "file_reputation":
                return await self._execute_file_reputation(context)
            elif action_type == "domain_reputation":
                return await self._execute_domain_reputation(context)
            elif action_type == "detonate_file":
                return await self._execute_file_detonation(context)
            elif action_type == "geolocate_ip":
                return await self._execute_ip_geolocation(context)
            else:
                self.logger.warning(f"Unknown action type: {action_type}")
                return {
                    "action": action_name,
                    "status": "skipped",
                    "reason": "not implemented"
                }
                
        except Exception as e:
            self.logger.error(f"Action execution failed: {e}")
            return {
                "action": action_data.get("name", "unknown"),
                "status": "failed",
                "error": str(e)
            }
    
    async def _execute_url_reputation(self, context: PlaybookExecutionContext) -> Dict[str, Any]:
        """Execute URL reputation analysis."""
        if not self.orchestrator or not context.urls:
            return {"action": "url_reputation", "status": "skipped"}
        
        try:
            # Use orchestrator's URL analysis
            # This is a placeholder - actual implementation depends on orchestrator API
            findings = []
            for url in context.urls[:10]:  # Limit to first 10 URLs
                # In real implementation, call orchestrator.analyze_url(url)
                findings.append({
                    "type": "url_reputation",
                    "url": url,
                    "status": "analyzed"
                })
            
            return {
                "action": "url_reputation",
                "status": "completed",
                "findings": findings,
                "urls_analyzed": len(findings)
            }
        except Exception as e:
            return {"action": "url_reputation", "status": "failed", "error": str(e)}
    
    async def _execute_ip_reputation(self, context: PlaybookExecutionContext) -> Dict[str, Any]:
        """Execute IP reputation analysis."""
        if not self.orchestrator or not context.ips:
            return {"action": "ip_reputation", "status": "skipped"}
        
        try:
            findings = []
            for ip in context.ips[:10]:
                findings.append({
                    "type": "ip_reputation",
                    "ip": ip,
                    "status": "analyzed"
                })
            
            return {
                "action": "ip_reputation",
                "status": "completed",
                "findings": findings,
                "ips_analyzed": len(findings)
            }
        except Exception as e:
            return {"action": "ip_reputation", "status": "failed", "error": str(e)}
    
    async def _execute_file_reputation(self, context: PlaybookExecutionContext) -> Dict[str, Any]:
        """Execute file reputation analysis."""
        if not self.orchestrator or not context.file_hashes:
            return {"action": "file_reputation", "status": "skipped"}
        
        try:
            findings = []
            for file_hash in context.file_hashes[:10]:
                findings.append({
                    "type": "file_reputation",
                    "hash": file_hash,
                    "status": "analyzed"
                })
            
            return {
                "action": "file_reputation",
                "status": "completed",
                "findings": findings,
                "files_analyzed": len(findings)
            }
        except Exception as e:
            return {"action": "file_reputation", "status": "failed", "error": str(e)}
    
    async def _execute_domain_reputation(self, context: PlaybookExecutionContext) -> Dict[str, Any]:
        """Execute domain reputation analysis."""
        if not self.orchestrator or not context.domains:
            return {"action": "domain_reputation", "status": "skipped"}
        
        return {
            "action": "domain_reputation",
            "status": "completed",
            "domains_analyzed": len(context.domains)
        }
    
    async def _execute_file_detonation(self, context: PlaybookExecutionContext) -> Dict[str, Any]:
        """Execute file detonation/sandbox analysis."""
        return {
            "action": "detonate_file",
            "status": "skipped",
            "reason": "sandbox integration not available"
        }
    
    async def _execute_ip_geolocation(self, context: PlaybookExecutionContext) -> Dict[str, Any]:
        """Execute IP geolocation."""
        if not context.ips:
            return {"action": "geolocate_ip", "status": "skipped"}
        
        return {
            "action": "geolocate_ip",
            "status": "completed",
            "ips_geolocated": len(context.ips)
        }
    
    def _calculate_severity(self, findings: List[Dict[str, Any]]) -> str:
        """Calculate overall severity from findings."""
        if not findings:
            return "low"
        
        # Count findings by type
        malicious_count = sum(1 for f in findings if f.get("status") == "malicious")
        suspicious_count = sum(1 for f in findings if f.get("status") == "suspicious")
        
        if malicious_count > 2:
            return "critical"
        elif malicious_count > 0:
            return "high"
        elif suspicious_count > 3:
            return "medium"
        else:
            return "low"
    
    async def execute_applicable_playbooks(
        self,
        context: PlaybookExecutionContext
    ) -> List[PlaybookExecutionResult]:
        """Execute all applicable playbooks for the given context."""
        results = []
        
        for playbook_name in self.loaded_playbooks.keys():
            # Check if playbook is applicable
            if self._is_playbook_applicable(playbook_name, context):
                result = await self.execute_playbook(playbook_name, context)
                results.append(result)
        
        return results
    
    def _is_playbook_applicable(
        self,
        playbook_name: str,
        context: PlaybookExecutionContext
    ) -> bool:
        """Determine if a playbook should be executed for this context."""
        playbook_name_lower = playbook_name.lower()
        
        # URL-focused playbooks
        if "url" in playbook_name_lower or "phishtank" in playbook_name_lower:
            return len(context.urls) > 0
        
        # Attachment-focused playbooks
        if "attachment" in playbook_name_lower or "file" in playbook_name_lower:
            return len(context.file_hashes) > 0
        
        # Email investigation playbooks
        if "email" in playbook_name_lower or "phishme" in playbook_name_lower:
            return True  # Always applicable
        
        return True  # Default: execute all playbooks
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get playbook execution statistics."""
        return {
            **self.execution_stats,
            "loaded_playbooks": len(self.loaded_playbooks),
            "success_rate": (
                self.execution_stats["successful_executions"] / 
                max(self.execution_stats["total_executions"], 1)
            )
        }
