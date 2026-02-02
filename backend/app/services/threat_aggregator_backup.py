"""
ThreatAggregator: Deterministic scoring with explainability for PhishNet

Provides consistent, reproducible threat scores with detailed explanations
for analyst trust and acceptance. Consumes outputs from all analysis components
and produces weighted, explainable threat assessments.

Enhanced version with:
- Deterministic scoring (same input -> same output)
- Configurable threshold profiles (strict/balanced/lenient)
- Structured explanations with component breakdown
- Reproducible hashing for validation
- Confidence intervals and uncertainty quantification
"""

import time
import asyncio
import hashlib
import json
import math
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
import statistics
import structlog

from app.config.logging import get_logger
from app.services.interfaces import AnalysisResult, AnalysisType
from app.services.virustotal import VirusTotalClient
from app.services.abuseipdb import AbuseIPDBClient
from app.services.gemini import GeminiClient
from app.services.link_redirect_analyzer import LinkRedirectAnalyzer

logger = get_logger(__name__)
struct_logger = structlog.get_logger(__name__)


class ComponentType(Enum):
    """Types of analysis components for deterministic aggregation."""
    LINK_REDIRECT = "link_redirect"
    GEMINI_LLM = "gemini_llm"
    VIRUS_TOTAL = "virus_total"
    ABUSEIPDB = "abuseipdb"
    ML_CONTENT = "ml_content"
    RULE_HEURISTICS = "rule_heuristics"
    REPUTATION = "reputation"
    BEHAVIORAL = "behavioral"


class ThreatLevel(Enum):
    """Threat level classifications."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecommendedAction(Enum):
    """Recommended actions based on threat assessment."""
    ALLOW = "allow"
    NOTIFY = "notify"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    INVESTIGATE = "investigate"


class ThresholdProfile(Enum):
    """Threshold profiles for different risk tolerances."""
    STRICT = "strict"
    BALANCED = "balanced"
    LENIENT = "lenient"


@dataclass
class ComponentScore:
    """Individual component analysis result with deterministic fields."""
    component_type: ComponentType
    score: float  # 0.0 - 1.0 (0 = safe, 1 = malicious)
    confidence: float  # 0.0 - 1.0
    signals: List[str]  # Contributing signals/indicators (sorted for determinism)
    metadata: Dict[str, Any]  # Raw analysis data
    processing_time: float  # Seconds
    timestamp: datetime
    version: str = "1.0"  # Component version for tracking


@dataclass
class ExplanationSignal:
    """Individual explanation signal with weighted contribution."""
    signal_name: str
    component_type: ComponentType
    weight: float
    score: float
    contribution: float  # weight * score
    description: str
    evidence: List[str]  # Supporting evidence


@dataclass
class ConfidenceBand:
    """Confidence interval for threat score."""
    lower_bound: float
    upper_bound: float
    confidence_level: float  # e.g., 0.95 for 95% confidence


@dataclass
class ThreatExplanation:
    """Structured explanation of threat assessment."""
    top_signals: List[ExplanationSignal]  # Top 3-5 contributing signals
    component_breakdown: Dict[str, float]  # Score contribution by component
    confidence_band: ConfidenceBand
    reasoning: str  # Human-readable explanation
    certainty_factors: Dict[str, float]  # Factors affecting confidence
    risk_factors: List[str]  # Key risk indicators found


@dataclass
class AggregatedThreatResult:
    """Final aggregated threat assessment result with deterministic scoring."""
    threat_score: float  # Final aggregated score (0.0 - 1.0)
    threat_level: ThreatLevel
    recommended_action: RecommendedAction
    explanation: ThreatExplanation
    component_scores: List[ComponentScore]
    aggregation_metadata: Dict[str, Any]
    deterministic_hash: str  # For reproducibility verification
    processing_time: float
    timestamp: datetime
    threshold_profile: ThresholdProfile
    
    # Legacy fields for backward compatibility
    confidence: float
    verdict: str
    indicators: List[str]
    recommendations: List[str]
    component_results: Dict[str, Dict[str, Any]]
    metadata: Dict[str, Any]
    version: str = "2.0"


class ThreatAggregatorConfig:
    """Configuration for deterministic threat aggregation."""
    
    def __init__(self, profile: ThresholdProfile = ThresholdProfile.BALANCED):
        self.profile = profile
        self.component_weights = self._get_component_weights()
        self.thresholds = self._get_thresholds()
        self.confidence_factors = self._get_confidence_factors()
    
    def _get_component_weights(self) -> Dict[ComponentType, float]:
        """Get component weights based on profile."""
        base_weights = {
            ComponentType.LINK_REDIRECT: 0.20,
            ComponentType.GEMINI_LLM: 0.25,
            ComponentType.VIRUS_TOTAL: 0.15,
            ComponentType.ABUSEIPDB: 0.10,
            ComponentType.ML_CONTENT: 0.20,
            ComponentType.RULE_HEURISTICS: 0.10,
            ComponentType.REPUTATION: 0.05,
            ComponentType.BEHAVIORAL: 0.15
        }
        
        # Adjust weights based on profile
        if self.profile == ThresholdProfile.STRICT:
            # More weight on automated sources
            base_weights[ComponentType.VIRUS_TOTAL] *= 1.3
            base_weights[ComponentType.ABUSEIPDB] *= 1.2
            base_weights[ComponentType.RULE_HEURISTICS] *= 1.4
        elif self.profile == ThresholdProfile.LENIENT:
            # More weight on LLM and human-like analysis
            base_weights[ComponentType.GEMINI_LLM] *= 1.3
            base_weights[ComponentType.ML_CONTENT] *= 1.2
        
        # Normalize weights to sum to 1.0
        total_weight = sum(base_weights.values())
        return {k: v / total_weight for k, v in base_weights.items()}
    
    def _get_thresholds(self) -> Dict[str, float]:
        """Get action thresholds based on profile."""
        if self.profile == ThresholdProfile.STRICT:
            return {
                "safe": 0.1,
                "notify": 0.2,
                "quarantine": 0.4,
                "block": 0.7,
                "investigate": 0.9
            }
        elif self.profile == ThresholdProfile.LENIENT:
            return {
                "safe": 0.3,
                "notify": 0.5,
                "quarantine": 0.7,
                "block": 0.85,
                "investigate": 0.95
            }
        else:  # BALANCED
            return {
                "safe": 0.2,
                "notify": 0.35,
                "quarantine": 0.6,
                "block": 0.8,
                "investigate": 0.92
            }
    
    def _get_confidence_factors(self) -> Dict[str, float]:
        """Get confidence adjustment factors."""
        return {
            "component_agreement": 0.3,  # How much components agree
            "signal_strength": 0.25,     # Strength of individual signals
            "data_quality": 0.2,         # Quality of input data
            "coverage": 0.15,            # How many components provided data
            "temporal_consistency": 0.1   # Consistency over time
        }


class ThreatAggregator:
    """
    Enhanced threat aggregator with deterministic scoring and explainability.
    
    Provides consistent, reproducible threat scores with detailed explanations
    for analyst trust and acceptance. Same inputs always produce identical outputs.
    """
    
    def __init__(self, config: Optional[ThreatAggregatorConfig] = None):
        self.config = config or ThreatAggregatorConfig()
        self.logger = get_logger(f"{__name__}.ThreatAggregator")
        
        # Legacy service weights for backward compatibility
        self.service_weights = {
            'virustotal': 0.25,
            'abuseipdb': 0.20,
            'gemini': 0.30,
            'link_redirect_analyzer': 0.25
        }
        
        # Legacy confidence thresholds
        self.confidence_thresholds = {
            'minimum_services': 2,
            'high_confidence': 0.8,
            'medium_confidence': 0.6
        }
        
        # Legacy threat level thresholds
        self.threat_thresholds = {
            ThreatLevel.CRITICAL: 0.9,
            ThreatLevel.HIGH: 0.7,
            ThreatLevel.MEDIUM: 0.5,
            ThreatLevel.LOW: 0.3,
            ThreatLevel.SAFE: 0.0
        }
        
        struct_logger.info("ThreatAggregator initialized", 
                          profile=self.config.profile.value,
                          version="2.0")
    
    def aggregate_threat_scores(self, 
                               component_scores: List[ComponentScore],
                               target_identifier: str) -> AggregatedThreatResult:
        """
        Aggregate component scores into final threat assessment with deterministic scoring.
        
        Args:
            component_scores: List of individual component analysis results
            target_identifier: Unique identifier for the target (email, URL, etc.)
            
        Returns:
            AggregatedThreatResult with deterministic scoring and explanation
        """
        start_time = datetime.now(timezone.utc)
        processing_start = start_time.timestamp()
        
        try:
            # Calculate deterministic hash for reproducibility
            deterministic_hash = self._calculate_deterministic_hash(
                component_scores, target_identifier
            )
            
            # Perform weighted aggregation
            weighted_score, component_contributions = self._calculate_weighted_score(
                component_scores
            )
            
            # Calculate confidence band
            confidence_band = self._calculate_confidence_band(
                component_scores, weighted_score
            )
            
            # Determine threat level and recommended action
            threat_level = self._determine_threat_level(weighted_score)
            recommended_action = self._determine_recommended_action(weighted_score)
            
            # Generate explanation
            explanation = self._generate_explanation(
                component_scores, component_contributions, weighted_score, confidence_band
            )
            
            # Create aggregation metadata
            aggregation_metadata = {
                "components_processed": len(component_scores),
                "component_weights": {ct.value: weight for ct, weight in self.config.component_weights.items()},
                "threshold_profile": self.config.profile.value,
                "aggregation_method": "weighted_linear",
                "version": "2.0",
                "target_hash": hashlib.sha256(target_identifier.encode()).hexdigest()[:16]
            }
            
            processing_time = datetime.now(timezone.utc).timestamp() - processing_start
            
            # Create legacy fields for backward compatibility
            legacy_component_results = {}
            legacy_indicators = []
            legacy_recommendations = []
            
            for cs in component_scores:
                legacy_component_results[cs.component_type.value] = {
                    "threat_score": cs.score,
                    "confidence": cs.confidence,
                    "verdict": "malicious" if cs.score > 0.7 else "suspicious" if cs.score > 0.4 else "safe",
                    "indicators": cs.signals,
                    "metadata": cs.metadata
                }
                legacy_indicators.extend(cs.signals)
            
            # Generate legacy recommendations based on threat level
            if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                legacy_recommendations = [
                    "Block and quarantine immediately",
                    "Do not interact with content",
                    "Report to security team"
                ]
            elif threat_level == ThreatLevel.MEDIUM:
                legacy_recommendations = [
                    "Exercise extreme caution",
                    "Verify through alternative channels"
                ]
            
            result = AggregatedThreatResult(
                # New deterministic fields
                threat_score=weighted_score,
                threat_level=threat_level,
                recommended_action=recommended_action,
                explanation=explanation,
                component_scores=component_scores,
                aggregation_metadata=aggregation_metadata,
                deterministic_hash=deterministic_hash,
                processing_time=processing_time,
                timestamp=start_time,
                threshold_profile=self.config.profile,
                
                # Legacy fields for backward compatibility
                confidence=confidence_band.confidence_level,
                verdict=f"{threat_level.value.upper()} ({confidence_band.confidence_level:.1%} confidence)",
                indicators=list(set(legacy_indicators))[:15],  # Deduplicate and limit
                recommendations=legacy_recommendations,
                component_results=legacy_component_results,
                metadata={
                    "aggregation_metadata": aggregation_metadata,
                    "explanation": asdict(explanation),
                    "confidence_band": asdict(confidence_band)
                }
            )
            
            struct_logger.info("Threat aggregation completed",
                              threat_score=weighted_score,
                              threat_level=threat_level.value,
                              recommended_action=recommended_action.value,
                              deterministic_hash=deterministic_hash,
                              processing_time=processing_time)
            
            return result
            
        except Exception as e:
            struct_logger.error("Threat aggregation failed", error=str(e))
            raise ThreatAggregationError(f"Failed to aggregate threat scores: {e}")
    
    def _calculate_deterministic_hash(self, 
                                    component_scores: List[ComponentScore],
                                    target_identifier: str) -> str:
        """Calculate deterministic hash for reproducibility verification."""
        
        # Create normalized input for hashing
        hash_input = {
            "target": target_identifier,
            "config_version": "2.0",
            "threshold_profile": self.config.profile.value,
            "component_weights": {ct.value: weight for ct, weight in self.config.component_weights.items()},
            "components": []
        }
        
        # Sort components by type for deterministic ordering
        sorted_components = sorted(component_scores, key=lambda x: x.component_type.value)
        
        for component in sorted_components:
            hash_input["components"].append({
                "type": component.component_type.value,
                "score": round(component.score, 6),  # Round for floating point consistency
                "confidence": round(component.confidence, 6),
                "signals": sorted(component.signals),  # Sort signals for consistency
                "version": component.version
            })
        
        # Create deterministic hash
        hash_string = json.dumps(hash_input, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(hash_string.encode()).hexdigest()[:16]
    
    def _calculate_weighted_score(self, 
                                component_scores: List[ComponentScore]) -> Tuple[float, Dict[ComponentType, float]]:
        """Calculate weighted aggregated score."""
        
        total_weighted_score = 0.0
        total_weight = 0.0
        component_contributions = {}
        
        for component in component_scores:
            # Get weight for this component type
            weight = self.config.component_weights.get(component.component_type, 0.0)
            
            # Apply confidence adjustment
            confidence_adjusted_score = component.score * component.confidence
            
            # Calculate contribution
            contribution = weight * confidence_adjusted_score
            component_contributions[component.component_type] = contribution
            
            total_weighted_score += contribution
            total_weight += weight * component.confidence
        
        # Normalize if total weight is not 1.0 (due to confidence adjustments)
        if total_weight > 0:
            final_score = total_weighted_score / total_weight
        else:
            final_score = 0.0
        
        # Ensure score is in valid range
        final_score = max(0.0, min(1.0, final_score))
        
    def _calculate_confidence_band(self, 
                                 component_scores: List[ComponentScore],
                                 aggregated_score: float) -> ConfidenceBand:
        """Calculate confidence interval for the aggregated score."""
        
        if not component_scores:
            return ConfidenceBand(
                lower_bound=0.0,
                upper_bound=1.0,
                confidence_level=0.0
            )
        
        # Calculate variance based on component agreement
        component_agreement = self._calculate_component_agreement(component_scores)
        data_quality = self._calculate_data_quality(component_scores)
        coverage = len(component_scores) / len(ComponentType)
        
        # Base confidence calculation
        confidence_factors = {
            "agreement": component_agreement * self.config.confidence_factors["component_agreement"],
            "quality": data_quality * self.config.confidence_factors["data_quality"],
            "coverage": coverage * self.config.confidence_factors["coverage"],
            "signal_strength": self._calculate_signal_strength(component_scores) * self.config.confidence_factors["signal_strength"]
        }
        
        overall_confidence = sum(confidence_factors.values())
        overall_confidence = max(0.1, min(0.95, overall_confidence))
        
        # Calculate uncertainty margin
        uncertainty_margin = (1.0 - overall_confidence) * 0.3
        
        lower_bound = max(0.0, aggregated_score - uncertainty_margin)
        upper_bound = min(1.0, aggregated_score + uncertainty_margin)
        
        return ConfidenceBand(
            lower_bound=lower_bound,
            upper_bound=upper_bound,
            confidence_level=overall_confidence
        )
    
    def _calculate_component_agreement(self, component_scores: List[ComponentScore]) -> float:
        """Calculate how much components agree with each other."""
        if len(component_scores) < 2:
            return 1.0
        
        scores = [cs.score for cs in component_scores]
        mean_score = sum(scores) / len(scores)
        
        # Calculate standard deviation
        variance = sum((score - mean_score) ** 2 for score in scores) / len(scores)
        std_dev = math.sqrt(variance)
        
        # Convert to agreement metric (lower std_dev = higher agreement)
        agreement = max(0.0, 1.0 - (std_dev * 2))
        return agreement
    
    def _calculate_data_quality(self, component_scores: List[ComponentScore]) -> float:
        """Calculate overall data quality score."""
        if not component_scores:
            return 0.0
        
        quality_scores = []
        
        for component in component_scores:
            # Base quality on confidence and number of signals
            signal_count = len(component.signals)
            signal_quality = min(1.0, signal_count / 5.0)  # Assume 5 signals = high quality
            
            component_quality = (component.confidence + signal_quality) / 2
            quality_scores.append(component_quality)
        
        return sum(quality_scores) / len(quality_scores)
    
    def _calculate_signal_strength(self, component_scores: List[ComponentScore]) -> float:
        """Calculate overall signal strength."""
        if not component_scores:
            return 0.0
        
        total_signals = sum(len(cs.signals) for cs in component_scores)
        avg_signals = total_signals / len(component_scores)
        
        # Normalize signal strength (assume 10 total signals = maximum strength)
        return min(1.0, avg_signals / 10.0)
    
    def _determine_threat_level(self, score: float) -> ThreatLevel:
        """Determine threat level based on score."""
        if score >= 0.8:
            return ThreatLevel.CRITICAL
        elif score >= 0.6:
            return ThreatLevel.HIGH
        elif score >= 0.4:
            return ThreatLevel.MEDIUM
        elif score >= 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.SAFE
    
    def _determine_recommended_action(self, score: float) -> RecommendedAction:
        """Determine recommended action based on score and thresholds."""
        thresholds = self.config.thresholds
        
        if score >= thresholds["investigate"]:
            return RecommendedAction.INVESTIGATE
        elif score >= thresholds["block"]:
            return RecommendedAction.BLOCK
        elif score >= thresholds["quarantine"]:
            return RecommendedAction.QUARANTINE
        elif score >= thresholds["notify"]:
            return RecommendedAction.NOTIFY
        else:
            return RecommendedAction.ALLOW
    
    def _generate_explanation(self, 
                            component_scores: List[ComponentScore],
                            component_contributions: Dict[ComponentType, float],
                            final_score: float,
                            confidence_band: ConfidenceBand) -> ThreatExplanation:
        """Generate detailed explanation of the threat assessment."""
        
        # Generate top contributing signals
        top_signals = self._extract_top_signals(component_scores, component_contributions)
        
        # Create component breakdown
        component_breakdown = {
            ct.value: contribution for ct, contribution in component_contributions.items()
        }
        
        # Generate human-readable reasoning
        reasoning = self._generate_reasoning(component_scores, final_score, top_signals)
        
        # Calculate certainty factors
        certainty_factors = {
            "component_agreement": self._calculate_component_agreement(component_scores),
            "data_coverage": len(component_scores) / len(ComponentType),
            "signal_strength": self._calculate_signal_strength(component_scores),
            "confidence_consistency": self._calculate_confidence_consistency(component_scores)
        }
        
        # Extract key risk factors
        risk_factors = self._extract_risk_factors(component_scores)
        
        return ThreatExplanation(
            top_signals=top_signals,
            component_breakdown=component_breakdown,
            confidence_band=confidence_band,
            reasoning=reasoning,
            certainty_factors=certainty_factors,
            risk_factors=risk_factors
        )
    
    def _extract_top_signals(self, 
                           component_scores: List[ComponentScore],
                           component_contributions: Dict[ComponentType, float]) -> List[ExplanationSignal]:
        """Extract top contributing signals for explanation."""
        
        all_signals = []
        
        for component in component_scores:
            component_weight = self.config.component_weights.get(component.component_type, 0.0)
            contribution = component_contributions.get(component.component_type, 0.0)
            
            for signal in component.signals:
                # Calculate signal contribution (simplified - could be more sophisticated)
                signal_contribution = contribution / len(component.signals) if component.signals else 0.0
                
                explanation_signal = ExplanationSignal(
                    signal_name=signal,
                    component_type=component.component_type,
                    weight=component_weight,
                    score=component.score,
                    contribution=signal_contribution,
                    description=self._get_signal_description(signal, component.component_type),
                    evidence=self._extract_signal_evidence(signal, component.metadata)
                )
                
                all_signals.append(explanation_signal)
        
        # Sort by contribution and return top 5
        top_signals = sorted(all_signals, key=lambda x: x.contribution, reverse=True)[:5]
        
        return top_signals
    
    def _get_signal_description(self, signal: str, component_type: ComponentType) -> str:
        """Get human-readable description for a signal."""
        
        signal_descriptions = {
            "malicious_redirect": "Detected malicious redirect chain",
            "suspicious_domain": "Domain flagged by reputation services", 
            "phishing_content": "Content matches phishing patterns",
            "high_risk_tld": "Uses high-risk top-level domain",
            "url_shortener": "Uses URL shortening service",
            "dkim_fail": "DKIM authentication failed",
            "spf_fail": "SPF authentication failed",
            "dmarc_fail": "DMARC policy violation",
            "suspicious_attachment": "Attachment flagged as suspicious",
            "blacklisted_ip": "IP address on threat intelligence blacklist",
            "newly_registered": "Domain registered recently",
            "typosquatting": "Domain appears to be typosquatting",
            "social_engineering": "Contains social engineering tactics"
        }
        
        return signal_descriptions.get(signal, f"Signal detected by {component_type.value}")
    
    def _extract_signal_evidence(self, signal: str, metadata: Dict[str, Any]) -> List[str]:
        """Extract evidence supporting a signal."""
        evidence = []
        
        # Extract relevant evidence from metadata based on signal type
        if signal == "malicious_redirect" and "redirect_chain" in metadata:
            evidence.append(f"Redirect chain: {' -> '.join(metadata['redirect_chain'])}")
        
        if signal == "suspicious_domain" and "domain_age" in metadata:
            evidence.append(f"Domain age: {metadata['domain_age']} days")
        
        if signal == "phishing_content" and "matched_patterns" in metadata:
            evidence.extend(metadata["matched_patterns"][:3])  # Top 3 patterns
        
        if not evidence:
            evidence.append("See detailed analysis data")
        
        return evidence
    
    def _generate_reasoning(self, 
                          component_scores: List[ComponentScore],
                          final_score: float,
                          top_signals: List[ExplanationSignal]) -> str:
        """Generate human-readable reasoning for the threat assessment."""
        
        threat_level = self._determine_threat_level(final_score)
        
        if threat_level == ThreatLevel.CRITICAL:
            base_reasoning = "This content poses a critical security threat."
        elif threat_level == ThreatLevel.HIGH:
            base_reasoning = "This content poses a high security risk."
        elif threat_level == ThreatLevel.MEDIUM:
            base_reasoning = "This content poses a moderate security risk."
        elif threat_level == ThreatLevel.LOW:
            base_reasoning = "This content poses a low security risk."
        else:
            base_reasoning = "This content appears to be safe."
        
        # Add top contributing factors
        if top_signals:
            top_3 = top_signals[:3]
            signal_descriptions = [signal.description for signal in top_3]
            
            reasoning = f"{base_reasoning} Key factors: {', '.join(signal_descriptions[:2])}"
            if len(signal_descriptions) > 2:
                reasoning += f", and {signal_descriptions[2]}"
            reasoning += "."
        else:
            reasoning = base_reasoning
        
        # Add confidence information
        agreement = self._calculate_component_agreement(component_scores)
        if agreement > 0.8:
            reasoning += " Multiple analysis components are in strong agreement."
        elif agreement < 0.5:
            reasoning += " Analysis components show mixed results, indicating uncertainty."
        
        return reasoning
    
    def _calculate_confidence_consistency(self, component_scores: List[ComponentScore]) -> float:
        """Calculate consistency of confidence scores across components."""
        if len(component_scores) < 2:
            return 1.0
        
        confidences = [cs.confidence for cs in component_scores]
        mean_confidence = sum(confidences) / len(confidences)
        
        variance = sum((conf - mean_confidence) ** 2 for conf in confidences) / len(confidences)
        std_dev = math.sqrt(variance)
        
        # Convert to consistency metric
        consistency = max(0.0, 1.0 - (std_dev * 2))
        return consistency
    
    def _extract_risk_factors(self, component_scores: List[ComponentScore]) -> List[str]:
        """Extract key risk factors from component analyses."""
        risk_factors = set()
        
        for component in component_scores:
            if component.score > 0.5:  # Only high-scoring components
                for signal in component.signals:
                    if any(keyword in signal.lower() for keyword in 
                          ["malicious", "phishing", "suspicious", "blacklist", "malware"]):
                        risk_factors.add(signal)
        
        return sorted(list(risk_factors))
    
    def validate_deterministic_behavior(self, 
                                       component_scores: List[ComponentScore],
                                       target_identifier: str,
                                       iterations: int = 3) -> bool:
        """Validate that aggregation produces identical results across iterations."""
        
        results = []
        
        for i in range(iterations):
            result = self.aggregate_threat_scores(component_scores, target_identifier)
            results.append({
                "score": result.threat_score,
                "hash": result.deterministic_hash,
                "threat_level": result.threat_level,
                "action": result.recommended_action
            })
        
        # Check if all results are identical
        first_result = results[0]
        all_identical = all(
            r["score"] == first_result["score"] and
            r["hash"] == first_result["hash"] and
            r["threat_level"] == first_result["threat_level"] and
            r["action"] == first_result["action"]
            for r in results
        )
        
        if not all_identical:
            struct_logger.error("Deterministic validation failed", results=results)
        
    
    # Legacy method for backward compatibility
    async def aggregate_threat_analysis(
        self,
        target: str,
        analysis_results: Dict[str, Dict[str, Any]],
        ml_score: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> AggregatedThreatResult:
        """
        Legacy method for backward compatibility.
        Converts old format to new ComponentScore format and uses new aggregation.
        """
        try:
            # Convert legacy format to new ComponentScore format
            component_scores = self._convert_legacy_results(analysis_results, ml_score)
            
            # Use new deterministic aggregation
            result = self.aggregate_threat_scores(component_scores, target)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Legacy threat aggregation failed for {target}: {e}")
            return self._create_error_result(target, str(e))
    
    def _convert_legacy_results(self, 
                               analysis_results: Dict[str, Dict[str, Any]], 
                               ml_score: Optional[float] = None) -> List[ComponentScore]:
        """Convert legacy analysis results to ComponentScore format."""
        
        component_scores = []
        timestamp = datetime.now(timezone.utc)
        
        # Map legacy service names to ComponentType
        service_mapping = {
            "virustotal": ComponentType.VIRUS_TOTAL,
            "abuseipdb": ComponentType.ABUSEIPDB,
            "gemini": ComponentType.GEMINI_LLM,
            "link_redirect_analyzer": ComponentType.LINK_REDIRECT
        }
        
        for service_name, result in analysis_results.items():
            if service_name not in service_mapping:
                continue
                
            component_type = service_mapping[service_name]
            
            # Extract data with defaults
            score = result.get('threat_score', 0.0)
            confidence = result.get('confidence', 0.5)
            signals = result.get('indicators', [])
            metadata = result.get('raw_data', result)
            
            # Ensure signals are strings and sorted for determinism
            if isinstance(signals, list):
                signals = sorted([str(s) for s in signals])
            else:
                signals = []
            
            component_score = ComponentScore(
                component_type=component_type,
                score=max(0.0, min(1.0, score)),
                confidence=max(0.0, min(1.0, confidence)),
                signals=signals,
                metadata=metadata,
                processing_time=0.0,  # Not available in legacy format
                timestamp=timestamp,
                version="1.0"
            )
            
            component_scores.append(component_score)
        
        # Add ML score as separate component if provided
        if ml_score is not None and 0.0 <= ml_score <= 1.0:
            ml_component = ComponentScore(
                component_type=ComponentType.ML_CONTENT,
                score=ml_score,
                confidence=0.8,  # Assume high confidence for ML
                signals=["ml_prediction"],
                metadata={"ml_score": ml_score},
                processing_time=0.0,
                timestamp=timestamp,
                version="1.0"
            )
            component_scores.append(ml_component)
        
        return component_scores
    
    def _create_error_result(self, target: str, error_message: str) -> AggregatedThreatResult:
        """Create error result when aggregation fails."""
        
        error_time = datetime.now(timezone.utc)
        
        # Create minimal explanation for error case
        error_explanation = ThreatExplanation(
            top_signals=[],
            component_breakdown={},
            confidence_band=ConfidenceBand(0.0, 1.0, 0.0),
            reasoning=f"Threat aggregation failed: {error_message}",
            certainty_factors={},
            risk_factors=[]
        )
        
        return AggregatedThreatResult(
            # New fields
            threat_score=0.0,
            threat_level=ThreatLevel.SAFE,
            recommended_action=RecommendedAction.ALLOW,
            explanation=error_explanation,
            component_scores=[],
            aggregation_metadata={
                "error": error_message,
                "version": "2.0"
            },
            deterministic_hash="error",
            processing_time=0.0,
            timestamp=error_time,
            threshold_profile=self.config.profile,
            
            # Legacy fields
            confidence=0.0,
            verdict="ERROR",
            indicators=[f"aggregation_error: {error_message}"],
            recommendations=["Retry analysis", "Investigate error cause"],
            component_results={},
            metadata={
                'error': error_message,
                'timestamp': error_time.timestamp(),
                'target': target
            }
        )
    
    async def aggregate_threat_analysis(
        self,
        target: str,
        analysis_results: Dict[str, Dict[str, Any]],
        ml_score: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> AggregatedThreatResult:
        """
        Aggregate multiple analysis results into unified threat assessment.
        
        Args:
            target: The analyzed target (URL, email content, etc.)
            analysis_results: Results from various analyzers {service_name: result_dict}
            ml_score: Optional ML-based threat score
            context: Additional context for analysis
            
        Returns:
            Unified threat assessment result
        """
        start_time = time.time()
        
        try:
            # Validate input results
            valid_results = self._validate_results(analysis_results)
            
            if not valid_results:
                return self._create_error_result(target, "No valid analysis results provided")
            
            # Calculate weighted threat score
            threat_score = self._calculate_weighted_threat_score(valid_results, ml_score)
            
            # Determine threat level
            threat_level = self._determine_threat_level(threat_score)
            
            # Calculate confidence
            confidence = self._calculate_confidence(valid_results, threat_score)
            
            # Generate aggregated indicators
            indicators = self._aggregate_indicators(valid_results)
            
            # Generate verdict
            verdict = self._generate_verdict(threat_level, confidence)
            
            # Generate explanation
            explanation = self._generate_explanation(
                threat_level, threat_score, valid_results, indicators
            )
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                threat_level, indicators, valid_results
            )
            
            # Prepare metadata
            metadata = self._prepare_metadata(valid_results, ml_score, context)
            
            return AggregatedThreatResult(
                threat_score=round(threat_score, 3),
                threat_level=threat_level,
                confidence=round(confidence, 3),
                verdict=verdict,
                explanation=explanation,
                indicators=indicators,
                recommendations=recommendations,
                component_results=valid_results,
                metadata=metadata,
                timestamp=start_time
            )
            
        except Exception as e:
            self.logger.error(f"Threat aggregation failed for {target}: {e}")
            return self._create_error_result(target, str(e))
    
    def _validate_results(self, analysis_results: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Validate and filter analysis results."""
        valid_results = {}
        
        for service_name, result in analysis_results.items():
            try:
                # Check if result has required fields
                if isinstance(result, dict) and 'threat_score' in result:
                    threat_score = result.get('threat_score', 0.0)
                    
                    # Validate threat score range
                    if isinstance(threat_score, (int, float)) and 0.0 <= threat_score <= 1.0:
                        valid_results[service_name] = result
                    else:
                        self.logger.warning(f"Invalid threat score for {service_name}: {threat_score}")
                else:
                    self.logger.warning(f"Invalid result format for {service_name}")
                    
            except Exception as e:
                self.logger.error(f"Validation failed for {service_name}: {e}")
        
        return valid_results
    
    def _calculate_weighted_threat_score(
        self,
        valid_results: Dict[str, Dict[str, Any]],
        ml_score: Optional[float] = None
    ) -> float:
        """Calculate weighted threat score from multiple sources."""
        
        total_score = 0.0
        total_weight = 0.0
        
        # Process each service result
        for service_name, result in valid_results.items():
            service_weight = self.service_weights.get(service_name, 0.1)
            service_score = result.get('threat_score', 0.0)
            service_confidence = result.get('confidence', 0.5)
            
            # Adjust weight based on service confidence
            adjusted_weight = service_weight * service_confidence
            
            total_score += service_score * adjusted_weight
            total_weight += adjusted_weight
        
        # Include ML score if provided
        if ml_score is not None and 0.0 <= ml_score <= 1.0:
            ml_weight = 0.2
            total_score += ml_score * ml_weight
            total_weight += ml_weight
        
        # Calculate final weighted average
        if total_weight > 0:
            weighted_score = total_score / total_weight
        else:
            weighted_score = 0.0
        
        # Apply consensus bonus/penalty
        consensus_modifier = self._calculate_consensus_modifier(valid_results)
        adjusted_score = weighted_score + consensus_modifier
        
        return max(0.0, min(1.0, adjusted_score))
    
    def _calculate_consensus_modifier(self, valid_results: Dict[str, Dict[str, Any]]) -> float:
        """Calculate consensus modifier based on agreement between services."""
        
        if len(valid_results) < 2:
            return 0.0
        
        scores = [result.get('threat_score', 0.0) for result in valid_results.values()]
        verdicts = [result.get('verdict', 'unknown') for result in valid_results.values()]
        
        # Calculate score variance
        if len(scores) > 1:
            score_std = statistics.stdev(scores)
            score_mean = statistics.mean(scores)
            
            # Low variance (high consensus) gets bonus
            if score_std < 0.1 and score_mean > 0.5:
                return 0.05  # Consensus on threat
            elif score_std < 0.1 and score_mean < 0.3:
                return -0.05  # Consensus on safety
        
        # Check verdict consensus
        malicious_count = sum(1 for v in verdicts if v == 'malicious')
        suspicious_count = sum(1 for v in verdicts if v == 'suspicious')
        safe_count = sum(1 for v in verdicts if v == 'safe')
        
        total_verdicts = len(verdicts)
        if total_verdicts > 0:
            if malicious_count >= total_verdicts * 0.7:
                return 0.1  # Strong consensus on malicious
            elif safe_count >= total_verdicts * 0.7:
                return -0.1  # Strong consensus on safe
        
        return 0.0
    
    def _determine_threat_level(self, threat_score: float) -> ThreatLevel:
        """Determine threat level based on threat score."""
        
        for level, threshold in self.threat_thresholds.items():
            if threat_score >= threshold:
                return level
        
        return ThreatLevel.SAFE
    
    def _calculate_confidence(
        self,
        valid_results: Dict[str, Dict[str, Any]],
        threat_score: float
    ) -> float:
        """Calculate confidence in the threat assessment."""
        
        confidence_factors = []
        
        # Factor 1: Number of services
        service_count = len(valid_results)
        if service_count >= 4:
            confidence_factors.append(0.9)
        elif service_count >= 3:
            confidence_factors.append(0.8)
        elif service_count >= 2:
            confidence_factors.append(0.6)
        else:
            confidence_factors.append(0.3)
        
        # Factor 2: Service confidence scores
        service_confidences = [
            result.get('confidence', 0.5) for result in valid_results.values()
        ]
        if service_confidences:
            avg_service_confidence = statistics.mean(service_confidences)
            confidence_factors.append(avg_service_confidence)
        
        # Factor 3: Score consensus
        threat_scores = [result.get('threat_score', 0.0) for result in valid_results.values()]
        if len(threat_scores) > 1:
            score_variance = statistics.variance(threat_scores)
            consensus_confidence = max(0.0, 1.0 - (score_variance * 4))  # Scale variance
            confidence_factors.append(consensus_confidence)
        
        # Factor 4: Extreme scores boost confidence
        if threat_score > 0.8 or threat_score < 0.2:
            confidence_factors.append(0.9)
        else:
            confidence_factors.append(0.6)
        
        # Calculate overall confidence
        if confidence_factors:
            overall_confidence = statistics.mean(confidence_factors)
        else:
            overall_confidence = 0.5
        
        return max(0.1, min(0.99, overall_confidence))
    
    def _aggregate_indicators(self, valid_results: Dict[str, Dict[str, Any]]) -> List[str]:
        """Aggregate indicators from all services."""
        
        all_indicators = []
        indicator_counts = {}
        
        for service_name, result in valid_results.items():
            indicators = result.get('indicators', [])
            
            for indicator in indicators:
                if isinstance(indicator, str):
                    # Clean and normalize indicator
                    clean_indicator = indicator.lower().strip()
                    
                    all_indicators.append(clean_indicator)
                    indicator_counts[clean_indicator] = indicator_counts.get(clean_indicator, 0) + 1
        
        # Sort by frequency and select top indicators
        sorted_indicators = sorted(
            indicator_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Return top 15 indicators, prioritizing those seen by multiple services
        top_indicators = []
        for indicator, count in sorted_indicators[:15]:
            if count > 1:  # Seen by multiple services
                top_indicators.append(f"{indicator} (confirmed by {count} services)")
            else:
                top_indicators.append(indicator)
        
        return top_indicators
    
    def _generate_verdict(self, threat_level: ThreatLevel, confidence: float) -> str:
        """Generate human-readable verdict."""
        
        confidence_desc = ""
        if confidence >= 0.8:
            confidence_desc = "high confidence"
        elif confidence >= 0.6:
            confidence_desc = "medium confidence"
        else:
            confidence_desc = "low confidence"
        
        level_descriptions = {
            ThreatLevel.CRITICAL: "CRITICAL THREAT",
            ThreatLevel.HIGH: "HIGH THREAT",
            ThreatLevel.MEDIUM: "MEDIUM THREAT",
            ThreatLevel.LOW: "LOW THREAT",
            ThreatLevel.SAFE: "SAFE"
        }
        
        level_desc = level_descriptions.get(threat_level, "UNKNOWN")
        return f"{level_desc} ({confidence_desc})"
    
    def _generate_explanation(
        self,
        threat_level: ThreatLevel,
        threat_score: float,
        valid_results: Dict[str, Dict[str, Any]],
        indicators: List[str]
    ) -> str:
        """Generate human-readable explanation of the threat assessment."""
        
        explanations = []
        
        # Base explanation
        if threat_level == ThreatLevel.CRITICAL:
            explanations.append("This target poses a critical security threat with strong indicators of malicious intent.")
        elif threat_level == ThreatLevel.HIGH:
            explanations.append("This target shows significant threat indicators and should be treated as highly suspicious.")
        elif threat_level == ThreatLevel.MEDIUM:
            explanations.append("This target exhibits concerning characteristics that warrant caution.")
        elif threat_level == ThreatLevel.LOW:
            explanations.append("This target shows minor suspicious elements but appears relatively safe.")
        else:
            explanations.append("This target appears safe with no significant threat indicators detected.")
        
        # Service-specific findings
        service_findings = []
        
        for service_name, result in valid_results.items():
            verdict = result.get('verdict', 'unknown')
            score = result.get('threat_score', 0.0)
            
            if verdict == 'malicious' or score >= 0.7:
                service_findings.append(f"{service_name} flagged as malicious")
            elif verdict == 'suspicious' or score >= 0.4:
                service_findings.append(f"{service_name} identified suspicious patterns")
        
        if service_findings:
            explanations.append(f"Analysis components: {'; '.join(service_findings)}.")
        
        # Key indicators
        if indicators:
            key_indicators = [ind for ind in indicators[:3] if 'confirmed by' in ind]
            if key_indicators:
                explanations.append(f"Key indicators: {'; '.join(key_indicators)}.")
        
        return " ".join(explanations)
    
    def _generate_recommendations(
        self,
        threat_level: ThreatLevel,
        indicators: List[str],
        valid_results: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """Generate actionable recommendations based on threat assessment."""
        
        recommendations = []
        
        # Base recommendations by threat level
        if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            recommendations.extend([
                "Block and quarantine immediately",
                "Do not interact with any links or attachments",
                "Report to security team for investigation",
                "Consider blocking sender/domain organization-wide"
            ])
        elif threat_level == ThreatLevel.MEDIUM:
            recommendations.extend([
                "Exercise extreme caution",
                "Verify legitimacy through alternative channels",
                "Avoid clicking links or downloading attachments",
                "Consult security team if uncertain"
            ])
        elif threat_level == ThreatLevel.LOW:
            recommendations.extend([
                "Review carefully before taking action",
                "Verify any requests for sensitive information",
                "Monitor for additional suspicious activity"
            ])
        else:
            recommendations.extend([
                "Standard security precautions apply",
                "Remain vigilant for social engineering attempts"
            ])
        
        # Indicator-specific recommendations
        indicator_text = " ".join(indicators).lower()
        
        if 'credential' in indicator_text or 'login' in indicator_text:
            recommendations.append("Never enter credentials via email links - navigate directly to official sites")
        
        if 'redirect' in indicator_text or 'shortener' in indicator_text:
            recommendations.append("Be cautious of redirect chains and URL shorteners")
        
        if 'urgency' in indicator_text or 'time_pressure' in indicator_text:
            recommendations.append("Verify urgent requests through official channels - attackers use time pressure")
        
        if 'impersonation' in indicator_text or 'brand' in indicator_text:
            recommendations.append("Verify sender identity - check official contact information")
        
        # Service-specific recommendations
        for service_name, result in valid_results.items():
            if service_name == 'link_redirect_analyzer' and result.get('cloaking_detected', False):
                recommendations.append("Content cloaking detected - link behavior varies by visitor")
            
            if service_name == 'abuseipdb' and result.get('abuse_confidence', 0) > 50:
                recommendations.append("IP address has history of abuse reports")
        
        # Limit and deduplicate recommendations
        unique_recommendations = list(dict.fromkeys(recommendations))  # Preserve order while removing duplicates
        return unique_recommendations[:8]  # Limit to 8 recommendations
    
    def _prepare_metadata(
        self,
        valid_results: Dict[str, Dict[str, Any]],
        ml_score: Optional[float],
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Prepare metadata about the analysis."""
        
        metadata = {
            'analysis_timestamp': time.time(),
            'services_used': list(valid_results.keys()),
            'service_count': len(valid_results),
            'ml_score_included': ml_score is not None,
            'aggregation_method': 'weighted_consensus',
            'version': '1.0'
        }
        
        # Service-specific metadata
        service_metadata = {}
        for service_name, result in valid_results.items():
            service_metadata[service_name] = {
                'threat_score': result.get('threat_score', 0.0),
                'verdict': result.get('verdict', 'unknown'),
                'confidence': result.get('confidence', 0.5),
                'indicators_count': len(result.get('indicators', [])),
                'analysis_type': result.get('analysis_type', 'unknown')
            }
        
        metadata['service_details'] = service_metadata
        
        # Include context if provided
        if context:
            metadata['context'] = context
        
        return metadata
    
    def _create_error_result(self, target: str, error_message: str) -> AggregatedThreatResult:
        """Create error result when aggregation fails."""
        
        return AggregatedThreatResult(
            threat_score=0.0,
            threat_level=ThreatLevel.SAFE,
            confidence=0.0,
            verdict="ERROR",
            explanation=f"Threat aggregation failed: {error_message}",
            indicators=[f"aggregation_error: {error_message}"],
            recommendations=["Retry analysis", "Investigate error cause"],
            component_results={},
            metadata={
                'error': error_message,
                'timestamp': time.time(),
                'target': target
            },
            timestamp=time.time()
        )
    
    async def scan(self, resource: str, analysis_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Unified scan method for threat aggregation.
        
        Args:
            resource: The target being analyzed
            analysis_results: Results from various analyzers
            
        Returns:
            Dict with normalized aggregated result schema
        """
        try:
            result = await self.aggregate_threat_analysis(resource, analysis_results)
            
            return {
                'threat_score': result.threat_score,
                'verdict': result.verdict,
                'confidence': result.confidence,
                'indicators': result.indicators,
                'raw_data': {
                    'threat_level': result.threat_level.value,
                    'explanation': result.explanation.reasoning if hasattr(result.explanation, 'reasoning') else str(result.explanation),
                    'recommendations': result.recommendations,
                    'component_results': result.component_results,
                    'metadata': result.metadata,
                    'deterministic_hash': result.deterministic_hash,
                    'recommended_action': result.recommended_action.value
                },
                'service': 'threat_aggregator',
                'timestamp': result.timestamp.timestamp() if hasattr(result.timestamp, 'timestamp') else result.timestamp,
                'analysis_type': 'aggregated_threat_analysis'
            }
            
        except Exception as e:
            logger.error(f"Threat aggregation scan failed for {resource}: {e}")
            return {
                'threat_score': 0.0,
                'verdict': 'error',
                'confidence': 0.0,
                'indicators': [f'aggregation_error: {str(e)}'],
                'raw_data': {'error': str(e)},
                'service': 'threat_aggregator',
                'timestamp': time.time(),
                'analysis_type': 'aggregated_threat_analysis'
            }


class ThreatAggregationError(Exception):
    """Exception raised when threat aggregation fails."""
    pass


# Global threat aggregator instances for different profiles
strict_aggregator = ThreatAggregator(ThreatAggregatorConfig(ThresholdProfile.STRICT))
balanced_aggregator = ThreatAggregator(ThreatAggregatorConfig(ThresholdProfile.BALANCED))
lenient_aggregator = ThreatAggregator(ThreatAggregatorConfig(ThresholdProfile.LENIENT))


# Factory function for backward compatibility
def create_threat_aggregator() -> ThreatAggregator:
    """Factory function to create ThreatAggregator."""
    return ThreatAggregator()
