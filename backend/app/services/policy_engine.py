"""
Enterprise Policy Engine Service
================================
Decides what actions to take based on:
1. Analysis Results (Verdict, Score, Metadata)
2. Tenant Policy Configuration
3. Risk Indicators and Threat Context

This is the "Brain" of the response system.

Enterprise Features:
- Priority-based rule evaluation
- Condition composability (AND/OR)
- Per-department policies (optional)
- Policy versioning
- Dry-run mode for testing
- Audit trail integration
"""

from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from app.config.logging import get_logger
from app.models.tenant import Tenant, PolicyRule, PolicyAction, PolicyEvaluationResult, ThreatConditions
from app.models.mongodb_models import ForwardedEmailAnalysis, ThreatLevel

logger = get_logger(__name__)


class PolicyEvalMode(str, Enum):
    """Policy evaluation modes"""
    EXECUTE = "execute"      # Normal mode - execute actions
    DRY_RUN = "dry_run"      # Test mode - evaluate but don't execute
    AUDIT_ONLY = "audit"     # Log only - no actions


@dataclass
class PolicyDecision:
    """Represents a single policy decision"""
    rule_name: str
    priority: int
    matched: bool
    conditions_met: Dict[str, bool]
    actions: List[PolicyAction]
    action_config: Dict[str, Any]
    evaluation_time_ms: float = 0.0


@dataclass
class PolicyEvaluationContext:
    """Context for policy evaluation"""
    job_id: str
    tenant_id: str
    analysis: ForwardedEmailAnalysis
    mode: PolicyEvalMode = PolicyEvalMode.EXECUTE
    
    # Computed fields
    score: int = 0
    verdict: str = ""
    risk_factors: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        self.score = int(self.analysis.threat_score * 100)
        self.verdict = self.analysis.risk_level
        if hasattr(self.analysis, 'analysis_result') and self.analysis.analysis_result:
            self.risk_factors = self.analysis.analysis_result.get('risk_factors', [])


class EnhancedPolicyEngine:
    """
    Enterprise-grade policy engine with advanced features.
    
    Evaluation Order:
    1. Sort rules by priority (lower = higher priority)
    2. Evaluate conditions for each rule
    3. Collect actions from all matching rules
    4. Deduplicate actions
    5. Return ordered action list
    
    Special Rules:
    - Priority 0: Critical overrides (e.g., known malware hash)
    - Priority 1-10: High priority (e.g., PHISHING verdict)
    - Priority 11-50: Normal policies
    - Priority 51+: Fallback policies
    """
    
    def __init__(self):
        self.default_policies = self._build_default_policies()
    
    def _build_default_policies(self) -> List[PolicyRule]:
        """Build default policy set for tenants without custom policies"""
        return [
            # Critical: Always notify SOC for confirmed phishing
            PolicyRule(
                name="Critical Phishing Alert",
                priority=1,
                conditions=ThreatConditions(min_score=0, max_score=30, risk_level="PHISHING"),
                actions=[PolicyAction.REPLY_USER, PolicyAction.NOTIFY_SOC, PolicyAction.QUARANTINE]
            ),
            # High: Suspicious emails get reply + SOC notification
            PolicyRule(
                name="Suspicious Email Alert",
                priority=10,
                conditions=ThreatConditions(min_score=31, max_score=60, risk_level="SUSPICIOUS"),
                actions=[PolicyAction.REPLY_USER, PolicyAction.NOTIFY_SOC]
            ),
            # Normal: Safe emails just get reply
            PolicyRule(
                name="Safe Email Response",
                priority=50,
                conditions=ThreatConditions(min_score=61, max_score=100, risk_level="SAFE"),
                actions=[PolicyAction.REPLY_USER]
            ),
            # Fallback: Always reply
            PolicyRule(
                name="Default Reply Policy",
                priority=100,
                conditions=ThreatConditions(min_score=0, max_score=100),
                actions=[PolicyAction.REPLY_USER]
            )
        ]
    
    async def evaluate(
        self, 
        tenant: Tenant, 
        analysis: ForwardedEmailAnalysis, 
        job_id: str,
        mode: PolicyEvalMode = PolicyEvalMode.EXECUTE
    ) -> List[PolicyEvaluationResult]:
        """
        Evaluate analysis against tenant policies.
        
        Args:
            tenant: Tenant configuration with policies
            analysis: Completed email analysis
            job_id: Job identifier for tracking
            mode: Evaluation mode (execute, dry_run, audit)
        
        Returns:
            List of policy evaluation results with actions
        """
        context = PolicyEvaluationContext(
            job_id=job_id,
            tenant_id=str(tenant.id) if tenant.id else "public",
            analysis=analysis,
            mode=mode
        )
        
        # Get policies (tenant-specific or defaults)
        policies = tenant.policies if tenant.policies else self.default_policies
        
        # Sort by priority
        sorted_policies = sorted(policies, key=lambda p: p.priority)
        
        # Evaluate all policies
        decisions: List[PolicyDecision] = []
        for policy in sorted_policies:
            start_time = datetime.now(timezone.utc)
            
            matched, conditions_met = self._evaluate_conditions(policy, context)
            
            elapsed_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            decision = PolicyDecision(
                rule_name=policy.name,
                priority=policy.priority,
                matched=matched,
                conditions_met=conditions_met,
                actions=policy.actions if matched else [],
                action_config=policy.action_config if matched else {},
                evaluation_time_ms=elapsed_ms
            )
            decisions.append(decision)
            
            if matched:
                logger.info(
                    f"[Job {job_id}] Policy matched: {policy.name} "
                    f"(priority={policy.priority}, actions={[a.value for a in policy.actions]})"
                )
        
        # Collect all actions from matched policies
        matched_decisions = [d for d in decisions if d.matched]
        
        # If no matches, use fallback
        if not matched_decisions:
            logger.info(f"[Job {job_id}] No policy matched, using fallback")
            fallback = self._get_fallback_decision(context)
            matched_decisions.append(fallback)
        
        # Aggregate and deduplicate actions
        all_actions = self._aggregate_actions(matched_decisions)
        
        # Build results
        results = []
        for decision in matched_decisions:
            result = PolicyEvaluationResult(
                job_id=job_id,
                tenant_id=context.tenant_id,
                rule_name=decision.rule_name,
                actions_taken=[a.value for a in decision.actions]
            )
            results.append(result)
            
            # Persist (unless dry-run)
            if mode != PolicyEvalMode.DRY_RUN:
                await result.save()
        
        return results
    
    def _evaluate_conditions(
        self, 
        policy: PolicyRule, 
        context: PolicyEvaluationContext
    ) -> Tuple[bool, Dict[str, bool]]:
        """
        Evaluate all conditions for a policy.
        
        Returns:
            (matched, conditions_met_dict)
        """
        conditions_met = {}
        cond = policy.conditions
        
        # Score range check
        in_score_range = cond.min_score <= context.score <= cond.max_score
        conditions_met["score_range"] = in_score_range
        
        # Risk level check (if specified)
        if cond.risk_level:
            risk_match = context.verdict == cond.risk_level
            conditions_met["risk_level"] = risk_match
        else:
            conditions_met["risk_level"] = True  # Not required
        
        # Keyword match (if specified)
        if cond.keyword_match:
            # Check if any keyword in risk_factors or subject
            subject = context.analysis.original_subject or ""
            keyword_found = any(
                kw.lower() in subject.lower() or 
                any(kw.lower() in rf.lower() for rf in context.risk_factors)
                for kw in cond.keyword_match
            )
            conditions_met["keyword_match"] = keyword_found
        else:
            conditions_met["keyword_match"] = True  # Not required
        
        # All conditions must be met (AND logic)
        all_matched = all(conditions_met.values())
        
        return all_matched, conditions_met
    
    def _aggregate_actions(self, decisions: List[PolicyDecision]) -> List[PolicyAction]:
        """
        Aggregate and deduplicate actions from all matched policies.
        
        Priority rules:
        - QUARANTINE takes precedence over DELETE
        - NOTIFY_SOC is always included if any policy requires it
        - REPLY_USER is default if no other communication action
        """
        action_set = set()
        
        for decision in decisions:
            for action in decision.actions:
                action_set.add(action)
        
        # Convert to list and sort by action priority
        action_priority = {
            PolicyAction.QUARANTINE: 1,
            PolicyAction.DELETE: 2,
            PolicyAction.NOTIFY_SOC: 3,
            PolicyAction.WEBHOOK: 4,
            PolicyAction.REPLY_USER: 5,
            PolicyAction.ALLOW: 10
        }
        
        sorted_actions = sorted(
            action_set, 
            key=lambda a: action_priority.get(a, 50)
        )
        
        return sorted_actions
    
    def _get_fallback_decision(self, context: PolicyEvaluationContext) -> PolicyDecision:
        """Get fallback decision when no policy matches"""
        return PolicyDecision(
            rule_name="Fallback: Reply User",
            priority=999,
            matched=True,
            conditions_met={"fallback": True},
            actions=[PolicyAction.REPLY_USER],
            action_config={}
        )
    
    async def get_policy_summary(self, tenant_id: str, days: int = 30) -> Dict[str, Any]:
        """Get summary of policy evaluations for a tenant"""
        from datetime import timedelta
        
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Query policy evaluations
        evaluations = await PolicyEvaluationResult.find(
            PolicyEvaluationResult.tenant_id == tenant_id,
            PolicyEvaluationResult.timestamp >= cutoff
        ).to_list()
        
        # Aggregate
        summary = {
            "total_evaluations": len(evaluations),
            "by_rule": {},
            "by_action": {}
        }
        
        for eval in evaluations:
            # Count by rule
            rule = eval.rule_name
            summary["by_rule"][rule] = summary["by_rule"].get(rule, 0) + 1
            
            # Count by action
            for action in eval.actions_taken:
                summary["by_action"][action] = summary["by_action"].get(action, 0) + 1
        
        return summary


# Singleton instance
# Singleton instance
_engine: Optional[EnhancedPolicyEngine] = None


def get_policy_engine() -> EnhancedPolicyEngine:
    """Get singleton policy engine"""
    global _engine
    if _engine is None:
        _engine = EnhancedPolicyEngine()
    return _engine
