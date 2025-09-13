"""
ThreatAggregator service for combining multiple analysis components into
a unified, explainable threat assessment.

This service normalizes inputs from ML models, LLM verdicts, threat intelligence
feeds, and redirect analysis, applies configurable weights, and produces 
defensible threat scores with detailed explanations.
"""

import asyncio
import json
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import asdict

from app.config.logging import get_logger
from app.schemas.threat_result import (
    ThreatResult, ThreatLevel, ComponentType, ComponentScore, 
    ThreatExplanation, Evidence, EvidenceType, RuleOverride,
    AggregationConfig, DEFAULT_CONFIG
)
from app.services.interfaces import AnalysisResult, AnalysisType

logger = get_logger(__name__)


class InputNormalizer:
    """Normalizes diverse input formats to standard ComponentScore objects."""
    
    @staticmethod
    def normalize_ml_score(
        score: float, 
        features: Dict[str, Any], 
        model_confidence: float,
        weight: float = 0.4
    ) -> ComponentScore:
        """Normalize ML model output to ComponentScore."""
        # Extract key features for explanation
        top_features = sorted(
            features.items(), 
            key=lambda x: abs(x[1]) if isinstance(x[1], (int, float)) else 0, 
            reverse=True
        )[:3]
        
        explanation = f"ML model detected threat indicators: {', '.join([f'{k}={v}' for k, v in top_features])}"
        
        return ComponentScore(
            component_type=ComponentType.ML_SCORE,
            score=max(0.0, min(1.0, score)),  # Clamp to valid range
            confidence=model_confidence,
            weight=weight,
            raw_data={"features": features, "model_output": score},
            explanation=explanation
        )
    
    @staticmethod
    def normalize_llm_verdict(
        verdict: str,
        reasoning: str,
        confidence: float,
        raw_response: Dict[str, Any],
        weight: float = 0.3
    ) -> ComponentScore:
        """Normalize LLM analysis to ComponentScore."""
        # Convert textual verdict to score
        verdict_lower = verdict.lower()
        if "malicious" in verdict_lower or "phishing" in verdict_lower:
            score = 0.9
        elif "suspicious" in verdict_lower or "risky" in verdict_lower:
            score = 0.6
        elif "safe" in verdict_lower or "legitimate" in verdict_lower:
            score = 0.1
        else:
            score = 0.5  # Unknown/neutral
        
        explanation = f"LLM analysis: {verdict}. {reasoning[:200]}{'...' if len(reasoning) > 200 else ''}"
        
        return ComponentScore(
            component_type=ComponentType.LLM_VERDICT,
            score=score,
            confidence=confidence,
            weight=weight,
            raw_data={"verdict": verdict, "reasoning": reasoning, "raw_response": raw_response},
            explanation=explanation
        )
    
    @staticmethod
    def normalize_virustotal(
        positives: int,
        total: int,
        scan_date: str,
        permalink: str,
        weight: float = 0.15
    ) -> ComponentScore:
        """Normalize VirusTotal results to ComponentScore."""
        if total == 0:
            score = 0.5  # No data available
            confidence = 0.3
        else:
            score = positives / total
            # Higher confidence with more scanners and recent scans
            confidence = min(1.0, (total / 50) * 0.7 + 0.3)
        
        explanation = f"VirusTotal: {positives}/{total} engines flagged as malicious"
        
        evidence_urls = [permalink] if permalink else []
        
        return ComponentScore(
            component_type=ComponentType.VIRUSTOTAL,
            score=score,
            confidence=confidence,
            weight=weight,
            raw_data={
                "positives": positives,
                "total": total,
                "scan_date": scan_date,
                "permalink": permalink
            },
            explanation=explanation,
            evidence_urls=evidence_urls
        )
    
    @staticmethod
    def normalize_abuseipdb(
        abuse_confidence: int,
        usage_type: str,
        isp: str,
        country: str,
        is_whitelisted: bool,
        weight: float = 0.1
    ) -> ComponentScore:
        """Normalize AbuseIPDB results to ComponentScore."""
        # Convert percentage to 0-1 scale
        score = abuse_confidence / 100.0
        
        # Adjust for whitelisting
        if is_whitelisted:
            score = max(0.0, score - 0.3)
        
        # Higher confidence for higher abuse confidence scores
        confidence = min(1.0, (abuse_confidence / 100.0) * 0.8 + 0.2)
        
        explanation = f"AbuseIPDB: {abuse_confidence}% abuse confidence, ISP: {isp}, Country: {country}"
        if is_whitelisted:
            explanation += " (whitelisted)"
        
        return ComponentScore(
            component_type=ComponentType.ABUSEIPDB,
            score=score,
            confidence=confidence,
            weight=weight,
            raw_data={
                "abuse_confidence": abuse_confidence,
                "usage_type": usage_type,
                "isp": isp,
                "country": country,
                "is_whitelisted": is_whitelisted
            },
            explanation=explanation
        )
    
    @staticmethod
    def normalize_redirect_analysis(
        redirect_chain: List[Dict[str, Any]],
        suspicious_patterns: List[str],
        cloaking_detected: bool,
        final_url: str,
        weight: float = 0.05
    ) -> ComponentScore:
        """Normalize redirect analysis to ComponentScore."""
        score = 0.0
        
        # Base score on redirect chain length and suspicious patterns
        if len(redirect_chain) > 3:
            score += 0.3
        if len(redirect_chain) > 6:
            score += 0.2
        
        # Add score for suspicious patterns
        score += min(0.4, len(suspicious_patterns) * 0.1)
        
        # Major score increase for cloaking
        if cloaking_detected:
            score += 0.5
        
        score = min(1.0, score)
        
        # Higher confidence with more redirects analyzed
        confidence = min(1.0, len(redirect_chain) / 10.0 + 0.5)
        
        explanation = f"Redirect analysis: {len(redirect_chain)} redirects"
        if suspicious_patterns:
            explanation += f", suspicious patterns: {', '.join(suspicious_patterns[:3])}"
        if cloaking_detected:
            explanation += ", CLOAKING DETECTED"
        
        return ComponentScore(
            component_type=ComponentType.REDIRECT_ANALYSIS,
            score=score,
            confidence=confidence,
            weight=weight,
            raw_data={
                "redirect_chain": redirect_chain,
                "suspicious_patterns": suspicious_patterns,
                "cloaking_detected": cloaking_detected,
                "final_url": final_url
            },
            explanation=explanation
        )


class RulesEngine:
    """Implements rule-based overrides for threat assessment."""
    
    def __init__(self):
        self.rules = [
            self._virustotal_high_positives_rule,
            self._cloaking_detection_rule,
            self._known_safe_domain_rule,
            self._multiple_redirects_rule,
            self._high_abuse_confidence_rule
        ]
    
    def apply_rules(
        self, 
        components: Dict[ComponentType, ComponentScore], 
        preliminary_score: float
    ) -> List[RuleOverride]:
        """Apply all rules and return any triggered overrides."""
        overrides = []
        
        for rule_func in self.rules:
            override = rule_func(components, preliminary_score)
            if override and override.triggered:
                overrides.append(override)
        
        # Sort by priority (higher priority first)
        overrides.sort(key=lambda x: x.priority, reverse=True)
        return overrides
    
    def _virustotal_high_positives_rule(
        self, 
        components: Dict[ComponentType, ComponentScore], 
        score: float
    ) -> Optional[RuleOverride]:
        """Rule: If VirusTotal positives > 10, mark as malicious."""
        vt_component = components.get(ComponentType.VIRUSTOTAL)
        if not vt_component:
            return None
        
        positives = vt_component.raw_data.get("positives", 0)
        total = vt_component.raw_data.get("total", 0)
        
        if positives > 10 and total > 20:
            return RuleOverride(
                rule_name="virustotal_high_positives",
                condition="VirusTotal positives > 10 with sufficient scanners",
                triggered=True,
                original_score=score,
                override_level=ThreatLevel.MALICIOUS,
                explanation=f"High VirusTotal detection rate: {positives}/{total} engines",
                priority=10
            )
        
        return RuleOverride(
            rule_name="virustotal_high_positives",
            condition="VirusTotal positives > 10 with sufficient scanners",
            triggered=False,
            original_score=score,
            override_level=ThreatLevel.MALICIOUS,
            explanation="Rule not triggered",
            priority=10
        )
    
    def _cloaking_detection_rule(
        self, 
        components: Dict[ComponentType, ComponentScore], 
        score: float
    ) -> Optional[RuleOverride]:
        """Rule: If cloaking detected, mark as malicious."""
        redirect_component = components.get(ComponentType.REDIRECT_ANALYSIS)
        if not redirect_component:
            return None
        
        cloaking_detected = redirect_component.raw_data.get("cloaking_detected", False)
        
        if cloaking_detected:
            return RuleOverride(
                rule_name="cloaking_detection",
                condition="Cloaking behavior detected",
                triggered=True,
                original_score=score,
                override_level=ThreatLevel.MALICIOUS,
                explanation="Site shows different content to bots vs. real users",
                priority=15
            )
        
        return RuleOverride(
            rule_name="cloaking_detection",
            condition="Cloaking behavior detected",
            triggered=False,
            original_score=score,
            override_level=ThreatLevel.MALICIOUS,
            explanation="Rule not triggered",
            priority=15
        )
    
    def _known_safe_domain_rule(
        self, 
        components: Dict[ComponentType, ComponentScore], 
        score: float
    ) -> Optional[RuleOverride]:
        """Rule: Known safe domains should not be marked malicious."""
        # This would typically check against a whitelist
        # For now, implement basic logic for common safe domains
        safe_domains = [
            "google.com", "microsoft.com", "apple.com", "amazon.com",
            "github.com", "stackoverflow.com", "wikipedia.org"
        ]
        
        # Would need target URL to implement properly
        # This is a placeholder implementation
        return RuleOverride(
            rule_name="known_safe_domain",
            condition="Domain is in safe list",
            triggered=False,
            original_score=score,
            override_level=ThreatLevel.SAFE,
            explanation="Rule not triggered",
            priority=5
        )
    
    def _multiple_redirects_rule(
        self, 
        components: Dict[ComponentType, ComponentScore], 
        score: float
    ) -> Optional[RuleOverride]:
        """Rule: Excessive redirects indicate suspicious behavior."""
        redirect_component = components.get(ComponentType.REDIRECT_ANALYSIS)
        if not redirect_component:
            return None
        
        redirect_chain = redirect_component.raw_data.get("redirect_chain", [])
        
        if len(redirect_chain) > 8:
            return RuleOverride(
                rule_name="excessive_redirects",
                condition="More than 8 redirects detected",
                triggered=True,
                original_score=score,
                override_level=ThreatLevel.SUSPICIOUS,
                explanation=f"Excessive redirect chain: {len(redirect_chain)} redirects",
                priority=8
            )
        
        return RuleOverride(
            rule_name="excessive_redirects",
            condition="More than 8 redirects detected",
            triggered=False,
            original_score=score,
            override_level=ThreatLevel.SUSPICIOUS,
            explanation="Rule not triggered",
            priority=8
        )
    
    def _high_abuse_confidence_rule(
        self, 
        components: Dict[ComponentType, ComponentScore], 
        score: float
    ) -> Optional[RuleOverride]:
        """Rule: High AbuseIPDB confidence indicates malicious IP."""
        abuse_component = components.get(ComponentType.ABUSEIPDB)
        if not abuse_component:
            return None
        
        abuse_confidence = abuse_component.raw_data.get("abuse_confidence", 0)
        is_whitelisted = abuse_component.raw_data.get("is_whitelisted", False)
        
        if abuse_confidence > 80 and not is_whitelisted:
            return RuleOverride(
                rule_name="high_abuse_confidence",
                condition="AbuseIPDB confidence > 80% and not whitelisted",
                triggered=True,
                original_score=score,
                override_level=ThreatLevel.MALICIOUS,
                explanation=f"High abuse confidence: {abuse_confidence}%",
                priority=12
            )
        
        return RuleOverride(
            rule_name="high_abuse_confidence",
            condition="AbuseIPDB confidence > 80% and not whitelisted",
            triggered=False,
            original_score=score,
            override_level=ThreatLevel.MALICIOUS,
            explanation="Rule not triggered",
            priority=12
        )


class ThreatAggregator:
    """
    Core service for aggregating multiple threat analysis components into
    a unified, explainable threat assessment.
    """
    
    def __init__(self, config: Optional[AggregationConfig] = None):
        self.config = config or DEFAULT_CONFIG
        self.normalizer = InputNormalizer()
        self.rules_engine = RulesEngine()
        self.logger = logger
    
    async def aggregate_threat_assessment(
        self,
        target: str,
        target_type: str,
        analysis_results: Dict[str, Any],
        config_override: Optional[AggregationConfig] = None
    ) -> ThreatResult:
        """
        Primary entry point for threat aggregation.
        
        Args:
            target: The analyzed target (URL, email, etc.)
            target_type: Type of target ("url", "email", "ip", etc.)
            analysis_results: Dictionary containing results from various analysis components
            config_override: Optional configuration override for this analysis
            
        Returns:
            ThreatResult with aggregated assessment and explanation
        """
        start_time = time.time()
        analysis_id = str(uuid.uuid4())
        
        # Use override config if provided
        config = config_override or self.config
        
        self.logger.info(f"Starting threat aggregation for {target_type}: {target}")
        
        try:
            # Step 1: Normalize all inputs to ComponentScore objects
            components = await self._normalize_inputs(analysis_results, config)
            
            # Step 2: Validate minimum components requirement
            if len(components) < config.minimum_components:
                raise ValueError(f"Insufficient components: {len(components)} < {config.minimum_components}")
            
            # Step 3: Calculate weighted aggregate score
            aggregate_score = self._calculate_aggregate_score(components, config)
            
            # Step 4: Apply rule-based overrides
            rule_overrides = []
            final_score = aggregate_score
            final_level = self._score_to_level(aggregate_score, config)
            
            if config.rule_overrides_enabled:
                rule_overrides = self.rules_engine.apply_rules(components, aggregate_score)
                if rule_overrides:
                    # Apply highest priority override
                    top_override = rule_overrides[0]
                    if top_override.triggered:
                        final_level = top_override.override_level
                        final_score = self._level_to_score(final_level, config)
            
            # Step 5: Calculate confidence
            confidence = self._calculate_confidence(components, config)
            
            # Step 6: Generate explanation
            explanation = self._generate_explanation(
                components, final_score, confidence, rule_overrides, config
            )
            
            # Step 7: Create ThreatResult
            processing_time = int((time.time() - start_time) * 1000)
            
            result = ThreatResult(
                target=target,
                target_type=target_type,
                score=final_score,
                level=final_level,
                confidence=confidence,
                components=components,
                explanation=explanation,
                analysis_id=analysis_id,
                processing_time_ms=processing_time,
                config=config,
                rule_overrides=rule_overrides
            )
            
            self.logger.info(
                f"Threat aggregation completed for {target}: "
                f"score={final_score:.3f}, level={final_level.value}, "
                f"components={len(components)}, time={processing_time}ms"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in threat aggregation for {target}: {e}")
            raise
    
    async def _normalize_inputs(
        self, 
        analysis_results: Dict[str, Any], 
        config: AggregationConfig
    ) -> Dict[ComponentType, ComponentScore]:
        """Normalize all analysis inputs to ComponentScore objects."""
        components = {}
        
        # Normalize ML score if present
        if "ml_analysis" in analysis_results:
            ml_data = analysis_results["ml_analysis"]
            components[ComponentType.ML_SCORE] = self.normalizer.normalize_ml_score(
                score=ml_data.get("score", 0.0),
                features=ml_data.get("features", {}),
                model_confidence=ml_data.get("confidence", 0.5),
                weight=config.component_weights.get(ComponentType.ML_SCORE, 0.0)
            )
        
        # Normalize LLM verdict if present
        if "llm_analysis" in analysis_results:
            llm_data = analysis_results["llm_analysis"]
            components[ComponentType.LLM_VERDICT] = self.normalizer.normalize_llm_verdict(
                verdict=llm_data.get("verdict", "unknown"),
                reasoning=llm_data.get("reasoning", ""),
                confidence=llm_data.get("confidence", 0.5),
                raw_response=llm_data.get("raw_response", {}),
                weight=config.component_weights.get(ComponentType.LLM_VERDICT, 0.0)
            )
        
        # Normalize VirusTotal if present
        if "virustotal" in analysis_results:
            vt_data = analysis_results["virustotal"]
            components[ComponentType.VIRUSTOTAL] = self.normalizer.normalize_virustotal(
                positives=vt_data.get("positives", 0),
                total=vt_data.get("total", 0),
                scan_date=vt_data.get("scan_date", ""),
                permalink=vt_data.get("permalink", ""),
                weight=config.component_weights.get(ComponentType.VIRUSTOTAL, 0.0)
            )
        
        # Normalize AbuseIPDB if present
        if "abuseipdb" in analysis_results:
            abuse_data = analysis_results["abuseipdb"]
            components[ComponentType.ABUSEIPDB] = self.normalizer.normalize_abuseipdb(
                abuse_confidence=abuse_data.get("abuse_confidence", 0),
                usage_type=abuse_data.get("usage_type", ""),
                isp=abuse_data.get("isp", ""),
                country=abuse_data.get("country", ""),
                is_whitelisted=abuse_data.get("is_whitelisted", False),
                weight=config.component_weights.get(ComponentType.ABUSEIPDB, 0.0)
            )
        
        # Normalize redirect analysis if present
        if "redirect_analysis" in analysis_results:
            redirect_data = analysis_results["redirect_analysis"]
            components[ComponentType.REDIRECT_ANALYSIS] = self.normalizer.normalize_redirect_analysis(
                redirect_chain=redirect_data.get("redirect_chain", []),
                suspicious_patterns=redirect_data.get("suspicious_patterns", []),
                cloaking_detected=redirect_data.get("cloaking_detected", False),
                final_url=redirect_data.get("final_url", ""),
                weight=config.component_weights.get(ComponentType.REDIRECT_ANALYSIS, 0.0)
            )
        
        return components
    
    def _calculate_aggregate_score(
        self, 
        components: Dict[ComponentType, ComponentScore], 
        config: AggregationConfig
    ) -> float:
        """Calculate weighted aggregate score from components."""
        total_score = 0.0
        total_weight = 0.0
        
        for component_type, component in components.items():
            # Use component's weight (which should match config)
            total_score += component.score * component.weight
            total_weight += component.weight
        
        # Normalize by total weight to handle missing components
        if total_weight > 0:
            return total_score / total_weight
        else:
            return 0.0
    
    def _score_to_level(self, score: float, config: AggregationConfig) -> ThreatLevel:
        """Convert numeric score to threat level based on thresholds."""
        if score >= config.threat_thresholds[ThreatLevel.MALICIOUS]:
            return ThreatLevel.MALICIOUS
        elif score >= config.threat_thresholds[ThreatLevel.SUSPICIOUS]:
            return ThreatLevel.SUSPICIOUS
        else:
            return ThreatLevel.SAFE
    
    def _level_to_score(self, level: ThreatLevel, config: AggregationConfig) -> float:
        """Convert threat level back to representative score."""
        if level == ThreatLevel.MALICIOUS:
            return config.threat_thresholds[ThreatLevel.MALICIOUS] + 0.1
        elif level == ThreatLevel.SUSPICIOUS:
            return config.threat_thresholds[ThreatLevel.SUSPICIOUS] + 0.1
        else:
            return config.threat_thresholds[ThreatLevel.SAFE] + 0.1
    
    def _calculate_confidence(
        self, 
        components: Dict[ComponentType, ComponentScore], 
        config: AggregationConfig
    ) -> float:
        """Calculate overall confidence in the assessment."""
        if not components:
            return 0.0
        
        # Base confidence on component confidences weighted by their weights
        weighted_confidence = 0.0
        total_weight = 0.0
        
        for component in components.values():
            weighted_confidence += component.confidence * component.weight
            total_weight += component.weight
        
        base_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.0
        
        # Boost confidence if multiple components agree (high component agreement)
        component_scores = [comp.score for comp in components.values()]
        if len(component_scores) > 1:
            mean_score = sum(component_scores) / len(component_scores)
            variance = sum((score - mean_score) ** 2 for score in component_scores) / len(component_scores)
            agreement = max(0.0, 1.0 - (variance / 0.25))  # Max variance is 0.25
            
            if agreement > 0.8:
                base_confidence = min(1.0, base_confidence + 0.1)
        
        # Boost confidence if score is very high or very low (clear verdict)
        aggregate_score = self._calculate_aggregate_score(components, config)
        if aggregate_score > config.confidence_boost_threshold or aggregate_score < (1.0 - config.confidence_boost_threshold):
            base_confidence = min(1.0, base_confidence + 0.1)
        
        return base_confidence
    
    def _generate_explanation(
        self,
        components: Dict[ComponentType, ComponentScore],
        final_score: float,
        confidence: float,
        rule_overrides: List[RuleOverride],
        config: AggregationConfig
    ) -> ThreatExplanation:
        """Generate human-readable explanation of the threat assessment."""
        
        # Generate primary reasons based on top-scoring components
        primary_reasons = []
        sorted_components = sorted(
            components.items(), 
            key=lambda x: x[1].score * x[1].weight, 
            reverse=True
        )
        
        for component_type, component in sorted_components[:3]:
            if component.score > 0.3:  # Only include significant contributors
                primary_reasons.append(component.explanation)
        
        # Add rule override reasons
        for override in rule_overrides:
            if override.triggered:
                primary_reasons.insert(0, f"RULE OVERRIDE: {override.explanation}")
        
        # Generate component breakdown
        component_breakdown = "Component contributions: "
        breakdown_parts = []
        for component_type, component in sorted_components:
            contribution = component.score * component.weight
            breakdown_parts.append(
                f"{component_type.value}={component.score:.2f}×{component.weight:.2f}={contribution:.3f}"
            )
        component_breakdown += ", ".join(breakdown_parts)
        
        # Generate confidence reasoning
        confidence_reasoning = f"Confidence is {confidence:.1%} based on "
        if len(components) >= 3:
            confidence_reasoning += "multiple component agreement"
        elif len(components) == 2:
            confidence_reasoning += "dual component analysis"
        else:
            confidence_reasoning += "single component analysis"
        
        if final_score > 0.8 or final_score < 0.2:
            confidence_reasoning += " and clear verdict"
        
        # Generate recommendations
        recommendations = []
        if final_score >= 0.8:
            recommendations.append("BLOCK: High threat detected - immediate blocking recommended")
            recommendations.append("INVESTIGATE: Review evidence and consider domain blocking")
        elif final_score >= 0.6:
            recommendations.append("QUARANTINE: Suspicious content - quarantine for review")
            recommendations.append("MONITOR: Enhanced monitoring recommended")
        elif final_score >= 0.4:
            recommendations.append("CAUTION: Some risk indicators present")
            recommendations.append("LOG: Additional logging recommended")
        else:
            recommendations.append("ALLOW: Low risk assessment")
        
        # Collect supporting evidence
        supporting_evidence = []
        for component_type, component in components.items():
            for url in component.evidence_urls:
                evidence = Evidence(
                    evidence_type=EvidenceType.REPUTATION_DATA,  # Default type
                    url=url,
                    description=f"Evidence from {component_type.value}",
                    component_source=component_type
                )
                supporting_evidence.append(evidence)
        
        return ThreatExplanation(
            primary_reasons=primary_reasons,
            supporting_evidence=supporting_evidence,
            component_breakdown=component_breakdown,
            confidence_reasoning=confidence_reasoning,
            recommendations=recommendations
        )


# Convenience functions for common use cases
async def aggregate_url_threat(
    url: str,
    ml_results: Optional[Dict[str, Any]] = None,
    llm_results: Optional[Dict[str, Any]] = None,
    virustotal_results: Optional[Dict[str, Any]] = None,
    abuseipdb_results: Optional[Dict[str, Any]] = None,
    redirect_results: Optional[Dict[str, Any]] = None,
    config: Optional[AggregationConfig] = None
) -> ThreatResult:
    """Convenience function for URL threat aggregation."""
    
    analysis_results = {}
    if ml_results:
        analysis_results["ml_analysis"] = ml_results
    if llm_results:
        analysis_results["llm_analysis"] = llm_results
    if virustotal_results:
        analysis_results["virustotal"] = virustotal_results
    if abuseipdb_results:
        analysis_results["abuseipdb"] = abuseipdb_results
    if redirect_results:
        analysis_results["redirect_analysis"] = redirect_results
    
    aggregator = ThreatAggregator(config)
    return await aggregator.aggregate_threat_assessment(
        target=url,
        target_type="url",
        analysis_results=analysis_results
    )


async def aggregate_email_threat(
    email_id: str,
    analysis_results: Dict[str, Any],
    config: Optional[AggregationConfig] = None
) -> ThreatResult:
    """Convenience function for email threat aggregation."""
    
    aggregator = ThreatAggregator(config)
    return await aggregator.aggregate_threat_assessment(
        target=email_id,
        target_type="email", 
        analysis_results=analysis_results,
        config_override=config
    )
