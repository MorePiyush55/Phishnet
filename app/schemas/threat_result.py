"""
Canonical threat result schema and models for the ThreatAggregator system.

Provides standardized data structures for combining ML scores, LLM verdicts, 
threat intelligence feeds, and redirect analysis into defensible threat assessments.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from datetime import datetime
import json


class ThreatLevel(str, Enum):
    """Standardized threat levels for consistent classification."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ComponentType(str, Enum):
    """Types of analysis components that contribute to threat assessment."""
    ML_SCORE = "ml_score"
    LLM_VERDICT = "llm_verdict"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    REDIRECT_ANALYSIS = "redirect_analysis"
    CLOAKING_DETECTION = "cloaking_detection"
    CONTENT_ANALYSIS = "content_analysis"
    REPUTATION_CHECK = "reputation_check"


class EvidenceType(str, Enum):
    """Types of evidence that support threat assessments."""
    SCREENSHOT = "screenshot"
    REDIRECT_CHAIN = "redirect_chain"
    NETWORK_LOG = "network_log"
    REPUTATION_DATA = "reputation_data"
    ML_FEATURES = "ml_features"
    LLM_REASONING = "llm_reasoning"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"


@dataclass
class ComponentScore:
    """Individual component contribution to threat assessment."""
    component_type: ComponentType
    score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    weight: float  # Applied weight in aggregation
    raw_data: Dict[str, Any]
    explanation: str
    evidence_urls: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=lambda: datetime.utcnow().timestamp())
    
    def __post_init__(self):
        """Validate score ranges."""
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"Score must be 0.0-1.0, got {self.score}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be 0.0-1.0, got {self.confidence}")
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError(f"Weight must be 0.0-1.0, got {self.weight}")


@dataclass
class Evidence:
    """Evidence supporting threat assessment decisions."""
    evidence_type: EvidenceType
    url: str
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    component_source: Optional[ComponentType] = None
    timestamp: float = field(default_factory=lambda: datetime.utcnow().timestamp())


@dataclass
class ThreatExplanation:
    """Human-readable explanation of threat assessment."""
    primary_reasons: List[str]  # Top 3-5 reasons for the verdict
    supporting_evidence: List[Evidence]
    component_breakdown: str  # Summary of how components contributed
    confidence_reasoning: str  # Why this confidence level
    recommendations: List[str]  # Suggested actions
    
    def get_top_reasons(self, limit: int = 3) -> List[str]:
        """Get the top N reasons for display."""
        return self.primary_reasons[:limit]


@dataclass
class RuleOverride:
    """Rule-based override that can supersede aggregated scores."""
    rule_name: str
    condition: str  # Human-readable condition
    triggered: bool
    original_score: float
    override_level: ThreatLevel
    explanation: str
    priority: int = 0  # Higher priority rules take precedence


@dataclass
class AggregationConfig:
    """Configuration for threat aggregation weights and thresholds."""
    component_weights: Dict[ComponentType, float]
    threat_thresholds: Dict[ThreatLevel, float]  # Min scores for each level
    confidence_boost_threshold: float = 0.8  # When to boost confidence
    rule_overrides_enabled: bool = True
    minimum_components: int = 2  # Minimum components needed for assessment
    
    def __post_init__(self):
        """Validate configuration."""
        # Ensure weights sum to 1.0 (within tolerance)
        total_weight = sum(self.component_weights.values())
        if not 0.95 <= total_weight <= 1.05:
            raise ValueError(f"Component weights must sum to ~1.0, got {total_weight}")
        
        # Validate threshold ordering
        thresholds = [
            self.threat_thresholds[ThreatLevel.SAFE],
            self.threat_thresholds[ThreatLevel.SUSPICIOUS], 
            self.threat_thresholds[ThreatLevel.MALICIOUS]
        ]
        if not all(thresholds[i] <= thresholds[i+1] for i in range(len(thresholds)-1)):
            raise ValueError("Threat thresholds must be in ascending order")


@dataclass
class ThreatResult:
    """
    Canonical threat assessment result combining all analysis components.
    
    This is the primary output of the ThreatAggregator system and provides
    a comprehensive, defensible, and explainable threat assessment.
    """
    # Core Assessment
    target: str  # URL, email, file, etc.
    target_type: str  # "url", "email", "file", etc.
    
    # Threat Assessment
    score: float  # 0.0 to 1.0 (aggregated final score)
    level: ThreatLevel  # Categorical threat level
    confidence: float  # 0.0 to 1.0 (confidence in assessment)
    
    # Component Analysis
    components: Dict[ComponentType, ComponentScore]
    
    # Explainability
    explanation: ThreatExplanation
    
    # Metadata
    analysis_id: str  # Unique identifier for this analysis
    timestamp: float = field(default_factory=lambda: datetime.utcnow().timestamp())
    processing_time_ms: int = 0
    
    # Configuration Used
    config: Optional[AggregationConfig] = None
    
    # Rule Overrides Applied
    rule_overrides: List[RuleOverride] = field(default_factory=list)
    
    # Quality Metrics
    component_count: int = field(init=False)
    component_agreement: float = field(init=False)  # How much components agree
    coverage_score: float = field(init=False)  # How comprehensive the analysis was
    
    def __post_init__(self):
        """Calculate derived fields."""
        self.component_count = len(self.components)
        self.component_agreement = self._calculate_component_agreement()
        self.coverage_score = self._calculate_coverage_score()
        
        # Validate core fields
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"Score must be 0.0-1.0, got {self.score}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be 0.0-1.0, got {self.confidence}")
    
    def _calculate_component_agreement(self) -> float:
        """Calculate how much the component scores agree with each other."""
        if len(self.components) < 2:
            return 1.0
        
        scores = [comp.score for comp in self.components.values()]
        mean_score = sum(scores) / len(scores)
        
        # Calculate variance
        variance = sum((score - mean_score) ** 2 for score in scores) / len(scores)
        
        # Convert variance to agreement (lower variance = higher agreement)
        # Max variance is 0.25 (when scores are 0.0 and 1.0), so normalize
        agreement = max(0.0, 1.0 - (variance / 0.25))
        return agreement
    
    def _calculate_coverage_score(self) -> float:
        """Calculate how comprehensive the analysis coverage was."""
        # Define ideal component set for comprehensive analysis
        ideal_components = {
            ComponentType.ML_SCORE,
            ComponentType.LLM_VERDICT,
            ComponentType.VIRUSTOTAL,
            ComponentType.REDIRECT_ANALYSIS
        }
        
        actual_components = set(self.components.keys())
        coverage = len(actual_components.intersection(ideal_components)) / len(ideal_components)
        return coverage
    
    def get_primary_evidence(self, limit: int = 5) -> List[Evidence]:
        """Get the most important evidence for this assessment."""
        all_evidence = self.explanation.supporting_evidence
        
        # Sort by relevance (evidence from higher-scoring components first)
        def evidence_score(evidence: Evidence) -> float:
            if evidence.component_source and evidence.component_source in self.components:
                return self.components[evidence.component_source].score
            return 0.0
        
        sorted_evidence = sorted(all_evidence, key=evidence_score, reverse=True)
        return sorted_evidence[:limit]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "target": self.target,
            "target_type": self.target_type,
            "score": self.score,
            "level": self.level.value,
            "confidence": self.confidence,
            "components": {
                comp_type.value: {
                    "score": comp.score,
                    "confidence": comp.confidence,
                    "weight": comp.weight,
                    "explanation": comp.explanation,
                    "evidence_urls": comp.evidence_urls,
                    "timestamp": comp.timestamp
                }
                for comp_type, comp in self.components.items()
            },
            "explanation": {
                "primary_reasons": self.explanation.primary_reasons,
                "component_breakdown": self.explanation.component_breakdown,
                "confidence_reasoning": self.explanation.confidence_reasoning,
                "recommendations": self.explanation.recommendations,
                "supporting_evidence": [
                    {
                        "type": ev.evidence_type.value,
                        "url": ev.url,
                        "description": ev.description,
                        "metadata": ev.metadata,
                        "component_source": ev.component_source.value if ev.component_source else None,
                        "timestamp": ev.timestamp
                    }
                    for ev in self.explanation.supporting_evidence
                ]
            },
            "analysis_id": self.analysis_id,
            "timestamp": self.timestamp,
            "processing_time_ms": self.processing_time_ms,
            "rule_overrides": [
                {
                    "rule_name": rule.rule_name,
                    "condition": rule.condition,
                    "triggered": rule.triggered,
                    "original_score": rule.original_score,
                    "override_level": rule.override_level.value,
                    "explanation": rule.explanation,
                    "priority": rule.priority
                }
                for rule in self.rule_overrides
            ],
            "quality_metrics": {
                "component_count": self.component_count,
                "component_agreement": self.component_agreement,
                "coverage_score": self.coverage_score
            }
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatResult':
        """Create ThreatResult from dictionary."""
        # Reconstruct components
        components = {}
        for comp_type_str, comp_data in data.get("components", {}).items():
            comp_type = ComponentType(comp_type_str)
            components[comp_type] = ComponentScore(
                component_type=comp_type,
                score=comp_data["score"],
                confidence=comp_data["confidence"],
                weight=comp_data["weight"],
                explanation=comp_data["explanation"],
                evidence_urls=comp_data.get("evidence_urls", []),
                timestamp=comp_data.get("timestamp", datetime.utcnow().timestamp()),
                raw_data=comp_data.get("raw_data", {})
            )
        
        # Reconstruct evidence
        evidence_list = []
        for ev_data in data.get("explanation", {}).get("supporting_evidence", []):
            evidence = Evidence(
                evidence_type=EvidenceType(ev_data["type"]),
                url=ev_data["url"],
                description=ev_data["description"],
                metadata=ev_data.get("metadata", {}),
                component_source=ComponentType(ev_data["component_source"]) if ev_data.get("component_source") else None,
                timestamp=ev_data.get("timestamp", datetime.utcnow().timestamp())
            )
            evidence_list.append(evidence)
        
        # Reconstruct explanation
        explanation = ThreatExplanation(
            primary_reasons=data.get("explanation", {}).get("primary_reasons", []),
            supporting_evidence=evidence_list,
            component_breakdown=data.get("explanation", {}).get("component_breakdown", ""),
            confidence_reasoning=data.get("explanation", {}).get("confidence_reasoning", ""),
            recommendations=data.get("explanation", {}).get("recommendations", [])
        )
        
        # Reconstruct rule overrides
        rule_overrides = []
        for rule_data in data.get("rule_overrides", []):
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
        
        return cls(
            target=data["target"],
            target_type=data["target_type"],
            score=data["score"],
            level=ThreatLevel(data["level"]),
            confidence=data["confidence"],
            components=components,
            explanation=explanation,
            analysis_id=data["analysis_id"],
            timestamp=data.get("timestamp", datetime.utcnow().timestamp()),
            processing_time_ms=data.get("processing_time_ms", 0),
            rule_overrides=rule_overrides
        )


# Predefined configurations for different use cases
DEFAULT_CONFIG = AggregationConfig(
    component_weights={
        ComponentType.ML_SCORE: 0.40,
        ComponentType.LLM_VERDICT: 0.30,
        ComponentType.VIRUSTOTAL: 0.15,
        ComponentType.ABUSEIPDB: 0.10,
        ComponentType.REDIRECT_ANALYSIS: 0.05
    },
    threat_thresholds={
        ThreatLevel.SAFE: 0.0,
        ThreatLevel.SUSPICIOUS: 0.4,
        ThreatLevel.MALICIOUS: 0.7
    },
    confidence_boost_threshold=0.8,
    rule_overrides_enabled=True,
    minimum_components=2
)

CONSERVATIVE_CONFIG = AggregationConfig(
    component_weights={
        ComponentType.ML_SCORE: 0.35,
        ComponentType.LLM_VERDICT: 0.25,
        ComponentType.VIRUSTOTAL: 0.25,
        ComponentType.ABUSEIPDB: 0.15
    },
    threat_thresholds={
        ThreatLevel.SAFE: 0.0,
        ThreatLevel.SUSPICIOUS: 0.3,
        ThreatLevel.MALICIOUS: 0.6
    },
    confidence_boost_threshold=0.9,
    rule_overrides_enabled=True,
    minimum_components=3
)

AGGRESSIVE_CONFIG = AggregationConfig(
    component_weights={
        ComponentType.ML_SCORE: 0.50,
        ComponentType.LLM_VERDICT: 0.30,
        ComponentType.VIRUSTOTAL: 0.20
    },
    threat_thresholds={
        ThreatLevel.SAFE: 0.0,
        ThreatLevel.SUSPICIOUS: 0.5,
        ThreatLevel.MALICIOUS: 0.8
    },
    confidence_boost_threshold=0.7,
    rule_overrides_enabled=True,
    minimum_components=2
)
