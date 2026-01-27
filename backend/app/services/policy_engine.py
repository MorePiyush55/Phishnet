"""
Policy Engine Service
=====================
Decides what actions to take based on:
1. Analysis Results (Verdict, Score, Metadata)
2. Tenant Policy Configuration

This is the "Brain" of the response system.
"""

from typing import List, Optional
from app.config.logging import get_logger
from app.models.tenant import Tenant, PolicyRule, PolicyAction, PolicyEvaluationResult
from app.models.mongodb_models import ForwardedEmailAnalysis, ThreatLevel

logger = get_logger(__name__)

class PolicyEngine:
    async def evaluate(self, tenant: Tenant, analysis: ForwardedEmailAnalysis, job_id: str) -> List[PolicyEvaluationResult]:
        """
        Evaluate the analysis against the tenant's policies.
        Returns a list of actions taken (wrapped in evaluation results).
        """
        
        # 1. Default Policy (if no rules match)
        # For now, default is always REPLY_USER
        matched_rules = []
        
        # 2. Iterate through configured rules (sorted by priority?)
        # Simple implementation: Check all rules
        if tenant.policies:
            for rule in tenant.policies:
                if self._check_condition(rule, analysis):
                    matched_rules.append(rule)
                    logger.info(f"[Job {job_id}] Matched Policy Rule: {rule.name}")
        
        # If no rules match, use a sensible default based on verdict
        if not matched_rules:
            logger.info(f"[Job {job_id}] No specific policy matched. Using Default Fallback.")
            default_rule = self._get_default_fallback_rule(analysis)
            matched_rules.append(default_rule)

        # 3. Aggregate Actions
        results = []
        for rule in matched_rules:
            # We will return the decision record, the Orchestrator will EXECUTE it
            # Or we execute it here? 
            # Better architecture: Orchestrator executes. Policy Engine decides.
            
            result = PolicyEvaluationResult(
                job_id=job_id,
                tenant_id=str(tenant.id),
                rule_name=rule.name,
                actions_taken=[action.value for action in rule.actions]
            )
            results.append(result)
            
            # Persist decision for audit
            await result.save()
            
        return results

    def _check_condition(self, rule: PolicyRule, analysis: ForwardedEmailAnalysis) -> bool:
        """Check if a rule matches the analysis"""
        cond = rule.conditions
        
        # Check Score Range
        score_val = int(analysis.threat_score * 100)
        if score_val < cond.min_score or score_val > cond.max_score:
            return False
            
        # Check Risk Level
        if cond.risk_level and analysis.risk_level != cond.risk_level:
            return False
            
        # Check Keywords (Optional)
        # ... logic ...
        
        return True

    def _get_default_fallback_rule(self, analysis: ForwardedEmailAnalysis) -> PolicyRule:
        """Hardcoded default: Always reply to user"""
        from app.models.tenant import ThreatConditions
        
        return PolicyRule(
            name="Default Reply Policy",
            conditions=ThreatConditions(min_score=0, max_score=100),
            actions=[PolicyAction.REPLY_USER]
        )

# Singleton
_engine = PolicyEngine()

def get_policy_engine():
    return _engine
