"""
Deterministic Threat Aggregator - Priority 5 Implementation
Provides consistent, reproducible threat scoring with explainable AI output.
"""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple, NamedTuple
from dataclasses import dataclass, asdict
from enum import Enum
import statistics
import math

from app.config.logging import get_logger

logger = get_logger(__name__)


class ThreatCategory(Enum):
    """Standardized threat categories."""
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    SCAM = "scam"
    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"


class ConfidenceLevel(Enum):
    """Confidence levels for threat assessment."""
    VERY_HIGH = "very_high"  # 90-100%
    HIGH = "high"            # 75-89%
    MEDIUM = "medium"        # 50-74%
    LOW = "low"              # 25-49%
    VERY_LOW = "very_low"    # 0-24%


@dataclass
class ThreatIndicator:
    """Structured threat indicator with scoring details."""
    name: str
    category: str
    value: float  # 0.0 to 1.0
    weight: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    evidence: List[str]
    source: str
    timestamp: float


@dataclass
class ExplanationComponent:
    """Component of the threat explanation."""
    component: str
    score: float
    weight: float
    contribution: float
    reasoning: str
    evidence: List[str]


@dataclass
class DeterministicThreatResult:
    """Deterministic threat analysis result with full traceability."""
    # Core scoring
    final_score: float  # 0.0 to 1.0
    threat_category: ThreatCategory
    confidence_level: ConfidenceLevel
    confidence_score: float  # 0.0 to 1.0
    
    # Explainability
    explanation: str
    components: List[ExplanationComponent]
    indicators: List[ThreatIndicator]
    
    # Reproducibility
    algorithm_version: str
    input_hash: str
    computation_trace: Dict[str, Any]
    
    # Metadata
    analysis_timestamp: float
    processing_time: float
    source_data: Dict[str, Any]


class DeterministicThreatAggregator:
    """
    Deterministic threat aggregator providing consistent, explainable threat scoring.
    
    Key features:
    1. Reproducible results for identical inputs
    2. Transparent scoring with detailed explanations
    3. Standardized threat categorization
    4. Confidence quantification
    5. Full audit trail of scoring decisions
    """
    
    VERSION = "2.0.0"
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.DeterministicThreatAggregator")
        
        # Standardized component weights (must sum to 1.0)
        self.component_weights = {
            "url_analysis": 0.35,
            "content_analysis": 0.30,
            "sender_analysis": 0.20,
            "attachment_analysis": 0.10,
            "context_analysis": 0.05
        }
        
        # Threat category thresholds
        self.threat_thresholds = {
            ThreatCategory.LEGITIMATE: 0.0,
            ThreatCategory.SUSPICIOUS: 0.3,
            ThreatCategory.SPAM: 0.5,
            ThreatCategory.SCAM: 0.7,
            ThreatCategory.PHISHING: 0.8,
            ThreatCategory.MALWARE: 0.9
        }
        
        # Confidence level mapping
        self.confidence_levels = {
            (0.9, 1.0): ConfidenceLevel.VERY_HIGH,
            (0.75, 0.9): ConfidenceLevel.HIGH,
            (0.5, 0.75): ConfidenceLevel.MEDIUM,
            (0.25, 0.5): ConfidenceLevel.LOW,
            (0.0, 0.25): ConfidenceLevel.VERY_LOW
        }
        
        # Indicator definitions for consistent scoring
        self.indicator_definitions = {
            "malicious_urls": {"weight": 0.9, "category": "url"},
            "suspicious_urls": {"weight": 0.6, "category": "url"},
            "typosquatting": {"weight": 0.7, "category": "url"},
            "phishing_keywords": {"weight": 0.8, "category": "content"},
            "urgency_language": {"weight": 0.6, "category": "content"},
            "credential_harvesting": {"weight": 0.9, "category": "content"},
            "sender_spoofing": {"weight": 0.8, "category": "sender"},
            "suspicious_attachments": {"weight": 0.7, "category": "attachment"},
            "grammar_anomalies": {"weight": 0.3, "category": "content"}
        }
    
    async def analyze_threat_deterministic(
        self,
        email_data: Dict[str, Any],
        analysis_components: Dict[str, Dict[str, Any]]
    ) -> DeterministicThreatResult:
        """
        Perform deterministic threat analysis with full explainability.
        
        Args:
            email_data: Email metadata and content
            analysis_components: Results from various analyzers
            
        Returns:
            Deterministic threat result with full traceability
        """
        start_time = time.time()
        
        try:
            # Create input hash for reproducibility
            input_hash = self._create_input_hash(email_data, analysis_components)
            
            # Initialize computation trace
            computation_trace = {
                "algorithm_version": self.VERSION,
                "input_hash": input_hash,
                "timestamp": start_time,
                "steps": []
            }
            
            # Step 1: Extract and validate indicators
            indicators = self._extract_threat_indicators(analysis_components)
            computation_trace["steps"].append({
                "step": "extract_indicators",
                "indicators_found": len(indicators),
                "indicator_names": [ind.name for ind in indicators]
            })
            
            # Step 2: Calculate component scores
            component_scores = self._calculate_component_scores(indicators, analysis_components)
            computation_trace["steps"].append({
                "step": "calculate_components",
                "component_scores": component_scores
            })
            
            # Step 3: Aggregate final score deterministically
            final_score = self._aggregate_final_score(component_scores)
            computation_trace["steps"].append({
                "step": "aggregate_score",
                "final_score": final_score,
                "calculation_method": "weighted_sum"
            })
            
            # Step 4: Determine threat category
            threat_category = self._determine_threat_category(final_score, indicators)
            computation_trace["steps"].append({
                "step": "categorize_threat",
                "category": threat_category.value,
                "threshold_used": self._get_threshold_for_category(threat_category)
            })
            
            # Step 5: Calculate confidence
            confidence_score, confidence_level = self._calculate_confidence(
                indicators, component_scores, analysis_components
            )
            computation_trace["steps"].append({
                "step": "calculate_confidence",
                "confidence_score": confidence_score,
                "confidence_level": confidence_level.value
            })
            
            # Step 6: Generate explanation
            explanation, explanation_components = self._generate_explanation(
                final_score, threat_category, indicators, component_scores
            )
            computation_trace["steps"].append({
                "step": "generate_explanation",
                "explanation_length": len(explanation),
                "components_count": len(explanation_components)
            })
            
            processing_time = time.time() - start_time
            
            return DeterministicThreatResult(
                final_score=final_score,
                threat_category=threat_category,
                confidence_level=confidence_level,
                confidence_score=confidence_score,
                explanation=explanation,
                components=explanation_components,
                indicators=indicators,
                algorithm_version=self.VERSION,
                input_hash=input_hash,
                computation_trace=computation_trace,
                analysis_timestamp=start_time,
                processing_time=processing_time,
                source_data=email_data
            )
            
        except Exception as e:
            self.logger.error(f"Deterministic threat analysis failed: {e}")
            processing_time = time.time() - start_time
            
            # Return error result with diagnostic information
            return DeterministicThreatResult(
                final_score=0.0,
                threat_category=ThreatCategory.LEGITIMATE,
                confidence_level=ConfidenceLevel.VERY_LOW,
                confidence_score=0.0,
                explanation=f"Analysis failed: {str(e)}",
                components=[],
                indicators=[],
                algorithm_version=self.VERSION,
                input_hash="error",
                computation_trace={"error": str(e), "timestamp": start_time},
                analysis_timestamp=start_time,
                processing_time=processing_time,
                source_data=email_data
            )
    
    def _create_input_hash(
        self,
        email_data: Dict[str, Any],
        analysis_components: Dict[str, Dict[str, Any]]
    ) -> str:
        """Create deterministic hash of input data for reproducibility."""
        
        # Create normalized input representation
        normalized_input = {
            "email_data": self._normalize_dict(email_data),
            "analysis_components": self._normalize_dict(analysis_components),
            "algorithm_version": self.VERSION,
            "component_weights": self.component_weights
        }
        
        # Create deterministic hash
        input_json = json.dumps(normalized_input, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(input_json.encode()).hexdigest()[:16]
    
    def _normalize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize dictionary for consistent hashing."""
        if not isinstance(data, dict):
            return data
        
        normalized = {}
        for key, value in data.items():
            if isinstance(value, dict):
                normalized[key] = self._normalize_dict(value)
            elif isinstance(value, list):
                # Sort lists of primitives, normalize lists of dicts
                try:
                    if all(isinstance(item, (str, int, float)) for item in value):
                        normalized[key] = sorted(value)
                    else:
                        normalized[key] = [self._normalize_dict(item) if isinstance(item, dict) else item for item in value]
                except TypeError:
                    normalized[key] = value
            elif isinstance(value, float):
                # Round floats to avoid precision issues
                normalized[key] = round(value, 6)
            else:
                normalized[key] = value
        
        return normalized
    
    def _extract_threat_indicators(
        self,
        analysis_components: Dict[str, Dict[str, Any]]
    ) -> List[ThreatIndicator]:
        """Extract structured threat indicators from analysis components."""
        
        indicators = []
        timestamp = time.time()
        
        for component_name, component_data in analysis_components.items():
            try:
                # Extract indicators from URL analysis
                if component_name == "url_analysis":
                    indicators.extend(self._extract_url_indicators(component_data, timestamp))
                
                # Extract indicators from content analysis
                elif component_name == "content_analysis":
                    indicators.extend(self._extract_content_indicators(component_data, timestamp))
                
                # Extract indicators from sender analysis
                elif component_name == "sender_analysis":
                    indicators.extend(self._extract_sender_indicators(component_data, timestamp))
                
                # Extract indicators from attachment analysis
                elif component_name == "attachment_analysis":
                    indicators.extend(self._extract_attachment_indicators(component_data, timestamp))
                
            except Exception as e:
                self.logger.warning(f"Failed to extract indicators from {component_name}: {e}")
        
        return indicators
    
    def _extract_url_indicators(
        self,
        url_data: Dict[str, Any],
        timestamp: float
    ) -> List[ThreatIndicator]:
        """Extract threat indicators from URL analysis."""
        
        indicators = []
        
        # Malicious URLs
        malicious_urls = url_data.get("malicious_urls", [])
        if malicious_urls:
            indicators.append(ThreatIndicator(
                name="malicious_urls",
                category="url",
                value=min(len(malicious_urls) * 0.3, 1.0),  # Scale by count
                weight=self.indicator_definitions["malicious_urls"]["weight"],
                confidence=0.9,
                evidence=[f"Malicious URL detected: {url}" for url in malicious_urls[:3]],
                source="url_analysis",
                timestamp=timestamp
            ))
        
        # Suspicious URLs
        suspicious_urls = url_data.get("suspicious_urls", [])
        if suspicious_urls:
            indicators.append(ThreatIndicator(
                name="suspicious_urls",
                category="url",
                value=min(len(suspicious_urls) * 0.2, 1.0),
                weight=self.indicator_definitions["suspicious_urls"]["weight"],
                confidence=0.7,
                evidence=[f"Suspicious URL detected: {url}" for url in suspicious_urls[:3]],
                source="url_analysis",
                timestamp=timestamp
            ))
        
        # Typosquatting detection
        if url_data.get("typosquatting_detected", False):
            indicators.append(ThreatIndicator(
                name="typosquatting",
                category="url",
                value=0.8,
                weight=self.indicator_definitions["typosquatting"]["weight"],
                confidence=0.8,
                evidence=["Typosquatting domain detected"],
                source="url_analysis",
                timestamp=timestamp
            ))
        
        return indicators
    
    def _extract_content_indicators(
        self,
        content_data: Dict[str, Any],
        timestamp: float
    ) -> List[ThreatIndicator]:
        """Extract threat indicators from content analysis."""
        
        indicators = []
        
        # Phishing keywords
        phishing_score = content_data.get("phishing_indicators", 0.0)
        if phishing_score > 0.3:
            indicators.append(ThreatIndicator(
                name="phishing_keywords",
                category="content",
                value=phishing_score,
                weight=self.indicator_definitions["phishing_keywords"]["weight"],
                confidence=0.8,
                evidence=content_data.get("phishing_evidence", ["Phishing language detected"]),
                source="content_analysis",
                timestamp=timestamp
            ))
        
        # Urgency language
        urgency_score = content_data.get("urgency_score", 0.0)
        if urgency_score > 0.4:
            indicators.append(ThreatIndicator(
                name="urgency_language",
                category="content",
                value=urgency_score,
                weight=self.indicator_definitions["urgency_language"]["weight"],
                confidence=0.7,
                evidence=content_data.get("urgency_keywords", ["Urgent language detected"]),
                source="content_analysis",
                timestamp=timestamp
            ))
        
        # Credential harvesting
        if content_data.get("credential_harvesting", False):
            indicators.append(ThreatIndicator(
                name="credential_harvesting",
                category="content",
                value=0.9,
                weight=self.indicator_definitions["credential_harvesting"]["weight"],
                confidence=0.9,
                evidence=["Credential harvesting patterns detected"],
                source="content_analysis",
                timestamp=timestamp
            ))
        
        return indicators
    
    def _extract_sender_indicators(
        self,
        sender_data: Dict[str, Any],
        timestamp: float
    ) -> List[ThreatIndicator]:
        """Extract threat indicators from sender analysis."""
        
        indicators = []
        
        # Sender spoofing
        if sender_data.get("spoofing_detected", False):
            indicators.append(ThreatIndicator(
                name="sender_spoofing",
                category="sender",
                value=0.8,
                weight=self.indicator_definitions["sender_spoofing"]["weight"],
                confidence=0.8,
                evidence=["Sender spoofing detected"],
                source="sender_analysis",
                timestamp=timestamp
            ))
        
        return indicators
    
    def _extract_attachment_indicators(
        self,
        attachment_data: Dict[str, Any],
        timestamp: float
    ) -> List[ThreatIndicator]:
        """Extract threat indicators from attachment analysis."""
        
        indicators = []
        
        # Suspicious attachments
        suspicious_attachments = attachment_data.get("suspicious_files", [])
        if suspicious_attachments:
            indicators.append(ThreatIndicator(
                name="suspicious_attachments",
                category="attachment",
                value=min(len(suspicious_attachments) * 0.4, 1.0),
                weight=self.indicator_definitions["suspicious_attachments"]["weight"],
                confidence=0.7,
                evidence=[f"Suspicious attachment: {att}" for att in suspicious_attachments[:3]],
                source="attachment_analysis",
                timestamp=timestamp
            ))
        
        return indicators
    
    def _calculate_component_scores(
        self,
        indicators: List[ThreatIndicator],
        analysis_components: Dict[str, Dict[str, Any]]
    ) -> Dict[str, float]:
        """Calculate standardized scores for each analysis component."""
        
        component_scores = {}
        
        # Group indicators by component
        component_indicators = {
            "url_analysis": [ind for ind in indicators if ind.category == "url"],
            "content_analysis": [ind for ind in indicators if ind.category == "content"],
            "sender_analysis": [ind for ind in indicators if ind.category == "sender"],
            "attachment_analysis": [ind for ind in indicators if ind.category == "attachment"],
            "context_analysis": []  # Placeholder for future context analysis
        }
        
        # Calculate score for each component
        for component_name, component_inds in component_indicators.items():
            if not component_inds:
                component_scores[component_name] = 0.0
                continue
            
            # Calculate weighted average of indicators
            total_weighted_score = 0.0
            total_weight = 0.0
            
            for indicator in component_inds:
                weighted_score = indicator.value * indicator.weight * indicator.confidence
                total_weighted_score += weighted_score
                total_weight += indicator.weight * indicator.confidence
            
            if total_weight > 0:
                component_scores[component_name] = min(total_weighted_score / total_weight, 1.0)
            else:
                component_scores[component_name] = 0.0
        
        return component_scores
    
    def _aggregate_final_score(self, component_scores: Dict[str, float]) -> float:
        """Aggregate component scores into final threat score."""
        
        final_score = 0.0
        
        for component_name, score in component_scores.items():
            weight = self.component_weights.get(component_name, 0.0)
            final_score += score * weight
        
        # Apply non-linear transformation for better discrimination
        # This helps separate borderline cases more clearly
        if final_score > 0.5:
            final_score = 0.5 + (final_score - 0.5) * 1.2
        
        return min(final_score, 1.0)
    
    def _determine_threat_category(
        self,
        final_score: float,
        indicators: List[ThreatIndicator]
    ) -> ThreatCategory:
        """Determine threat category based on score and indicators."""
        
        # Check for specific high-confidence indicators
        high_conf_indicators = [ind for ind in indicators if ind.confidence > 0.8]
        
        # Override based on critical indicators
        for indicator in high_conf_indicators:
            if indicator.name == "malicious_urls" and indicator.value > 0.8:
                return ThreatCategory.PHISHING
            elif indicator.name == "credential_harvesting":
                return ThreatCategory.PHISHING
            elif indicator.name == "suspicious_attachments" and indicator.value > 0.7:
                return ThreatCategory.MALWARE
        
        # Default threshold-based categorization
        for category, threshold in sorted(self.threat_thresholds.items(), 
                                        key=lambda x: x[1], reverse=True):
            if final_score >= threshold:
                return category
        
        return ThreatCategory.LEGITIMATE
    
    def _get_threshold_for_category(self, category: ThreatCategory) -> float:
        """Get threshold value for a threat category."""
        return self.threat_thresholds.get(category, 0.0)
    
    def _calculate_confidence(
        self,
        indicators: List[ThreatIndicator],
        component_scores: Dict[str, float],
        analysis_components: Dict[str, Dict[str, Any]]
    ) -> Tuple[float, ConfidenceLevel]:
        """Calculate confidence in the threat assessment."""
        
        if not indicators:
            return 0.1, ConfidenceLevel.VERY_LOW
        
        # Factors affecting confidence
        indicator_confidence = statistics.mean([ind.confidence for ind in indicators])
        indicator_count = min(len(indicators) / 5.0, 1.0)  # More indicators = higher confidence
        component_consistency = self._calculate_component_consistency(component_scores)
        data_quality = self._assess_data_quality(analysis_components)
        
        # Weighted confidence calculation
        confidence_score = (
            indicator_confidence * 0.4 +
            indicator_count * 0.2 +
            component_consistency * 0.2 +
            data_quality * 0.2
        )
        
        # Determine confidence level
        confidence_level = ConfidenceLevel.VERY_LOW
        for (min_conf, max_conf), level in self.confidence_levels.items():
            if min_conf <= confidence_score <= max_conf:
                confidence_level = level
                break
        
        return confidence_score, confidence_level
    
    def _calculate_component_consistency(self, component_scores: Dict[str, float]) -> float:
        """Calculate consistency between component scores."""
        scores = [score for score in component_scores.values() if score > 0]
        
        if len(scores) < 2:
            return 0.5
        
        # Calculate coefficient of variation (lower = more consistent)
        mean_score = statistics.mean(scores)
        if mean_score == 0:
            return 0.5
        
        std_dev = statistics.stdev(scores)
        cv = std_dev / mean_score
        
        # Convert to consistency score (higher = more consistent)
        consistency = max(0.0, 1.0 - cv)
        return consistency
    
    def _assess_data_quality(self, analysis_components: Dict[str, Dict[str, Any]]) -> float:
        """Assess quality of input data for analysis."""
        
        quality_factors = []
        
        # Check completeness
        expected_components = ["url_analysis", "content_analysis", "sender_analysis"]
        completeness = len([comp for comp in expected_components if comp in analysis_components]) / len(expected_components)
        quality_factors.append(completeness)
        
        # Check data richness
        for component_name, component_data in analysis_components.items():
            if isinstance(component_data, dict) and len(component_data) > 3:
                quality_factors.append(1.0)
            else:
                quality_factors.append(0.5)
        
        return statistics.mean(quality_factors) if quality_factors else 0.3
    
    def _generate_explanation(
        self,
        final_score: float,
        threat_category: ThreatCategory,
        indicators: List[ThreatIndicator],
        component_scores: Dict[str, float]
    ) -> Tuple[str, List[ExplanationComponent]]:
        """Generate human-readable explanation of the threat assessment."""
        
        # Generate explanation components
        explanation_components = []
        
        for component_name, score in component_scores.items():
            if score > 0:
                weight = self.component_weights.get(component_name, 0.0)
                contribution = score * weight
                
                # Generate component reasoning
                component_indicators = [ind for ind in indicators 
                                     if self._get_indicator_component(ind) == component_name]
                
                reasoning = self._generate_component_reasoning(component_name, score, component_indicators)
                evidence = []
                for ind in component_indicators:
                    evidence.extend(ind.evidence)
                
                explanation_components.append(ExplanationComponent(
                    component=component_name,
                    score=score,
                    weight=weight,
                    contribution=contribution,
                    reasoning=reasoning,
                    evidence=evidence[:5]  # Limit evidence items
                ))
        
        # Generate overall explanation
        explanation = self._generate_overall_explanation(
            final_score, threat_category, explanation_components
        )
        
        return explanation, explanation_components
    
    def _get_indicator_component(self, indicator: ThreatIndicator) -> str:
        """Map indicator category to component name."""
        category_mapping = {
            "url": "url_analysis",
            "content": "content_analysis",
            "sender": "sender_analysis",
            "attachment": "attachment_analysis"
        }
        return category_mapping.get(indicator.category, "context_analysis")
    
    def _generate_component_reasoning(
        self,
        component_name: str,
        score: float,
        indicators: List[ThreatIndicator]
    ) -> str:
        """Generate reasoning for a component score."""
        
        if not indicators:
            return f"{component_name.replace('_', ' ').title()} shows no significant threat indicators."
        
        if score > 0.8:
            severity = "critical threat indicators"
        elif score > 0.6:
            severity = "significant threat indicators"
        elif score > 0.4:
            severity = "moderate threat indicators"
        else:
            severity = "minor threat indicators"
        
        indicator_names = [ind.name.replace('_', ' ') for ind in indicators]
        
        return (f"{component_name.replace('_', ' ').title()} detected {severity} "
                f"including: {', '.join(indicator_names[:3])}")
    
    def _generate_overall_explanation(
        self,
        final_score: float,
        threat_category: ThreatCategory,
        components: List[ExplanationComponent]
    ) -> str:
        """Generate overall threat explanation."""
        
        # Threat level description
        if final_score >= 0.8:
            threat_level = "HIGH THREAT"
        elif final_score >= 0.6:
            threat_level = "MODERATE THREAT"
        elif final_score >= 0.3:
            threat_level = "LOW THREAT"
        else:
            threat_level = "MINIMAL THREAT"
        
        # Primary contributors
        top_contributors = sorted(components, key=lambda x: x.contribution, reverse=True)[:2]
        
        explanation = f"**{threat_level}** (Score: {final_score:.2f}) - "
        explanation += f"Classified as {threat_category.value.upper()}. "
        
        if top_contributors:
            explanation += "Primary concerns: "
            explanations = [f"{comp.component.replace('_', ' ').title()} "
                          f"(score: {comp.score:.2f})" for comp in top_contributors]
            explanation += ", ".join(explanations) + ". "
        
        # Add key evidence
        all_evidence = []
        for comp in components:
            all_evidence.extend(comp.evidence)
        
        if all_evidence:
            explanation += f"Key evidence: {'; '.join(all_evidence[:3])}."
        
        return explanation


# Factory function for easy instantiation
def create_deterministic_threat_aggregator() -> DeterministicThreatAggregator:
    """Create a new deterministic threat aggregator instance."""
    return DeterministicThreatAggregator()


# Global instance for shared use
deterministic_aggregator = create_deterministic_threat_aggregator()