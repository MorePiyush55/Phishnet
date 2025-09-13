"""
Threat Aggregator service that combines multiple analysis results.
Provides unified threat scoring and human-readable explanations.
"""

import time
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import statistics
import json

from app.config.logging import get_logger
from app.services.interfaces import AnalysisResult, AnalysisType
from app.services.virustotal import VirusTotalClient
from app.services.abuseipdb import AbuseIPDBClient
from app.services.gemini import GeminiClient
from app.services.link_redirect_analyzer import LinkRedirectAnalyzer

logger = get_logger(__name__)


class ThreatLevel(Enum):
    """Threat level classifications."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AggregatedThreatResult:
    """Unified threat analysis result."""
    threat_score: float  # 0.0 to 1.0
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    verdict: str
    explanation: str
    indicators: List[str]
    recommendations: List[str]
    component_results: Dict[str, Dict[str, Any]]
    metadata: Dict[str, Any]
    timestamp: float


class ThreatAggregator:
    """
    Aggregates multiple threat analysis results into unified scoring.
    Combines ML scores, LLM verdicts, VT/Abuse signals, and redirect analysis.
    """
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.ThreatAggregator")
        
        # Service weights for scoring (must sum to 1.0)
        self.service_weights = {
            'virustotal': 0.25,
            'abuseipdb': 0.20,
            'gemini': 0.30,
            'link_redirect_analyzer': 0.25
        }
        
        # Confidence thresholds
        self.confidence_thresholds = {
            'minimum_services': 2,  # Minimum services for reliable result
            'high_confidence': 0.8,
            'medium_confidence': 0.6
        }
        
        # Threat level thresholds
        self.threat_thresholds = {
            ThreatLevel.CRITICAL: 0.9,
            ThreatLevel.HIGH: 0.7,
            ThreatLevel.MEDIUM: 0.5,
            ThreatLevel.LOW: 0.3,
            ThreatLevel.SAFE: 0.0
        }
    
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
                    'explanation': result.explanation,
                    'recommendations': result.recommendations,
                    'component_results': result.component_results,
                    'metadata': result.metadata
                },
                'service': 'threat_aggregator',
                'timestamp': result.timestamp,
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


# Factory function
def create_threat_aggregator() -> ThreatAggregator:
    """Factory function to create ThreatAggregator."""
    return ThreatAggregator()
