"""
Enhanced scoring service integrating deterministic threat aggregator.
Provides production-ready threat scoring with explainable AI output.
"""

import asyncio
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

from app.config.logging import get_logger
from app.services.deterministic_threat_aggregator import (
    DeterministicThreatAggregator,
    DeterministicThreatResult,
    ThreatCategory,
    ConfidenceLevel,
    deterministic_aggregator
)

logger = get_logger(__name__)


@dataclass
class EnhancedThreatScore:
    """Enhanced threat score with deterministic analysis."""
    # Core scoring
    final_score: float  # 0.0 to 1.0
    threat_level: str   # "low", "medium", "high", "critical"
    threat_category: str  # "legitimate", "phishing", "malware", etc.
    confidence_score: float  # 0.0 to 1.0
    confidence_level: str   # "very_low", "low", "medium", "high", "very_high"
    
    # Explainability
    explanation: str
    key_indicators: List[str]
    component_breakdown: Dict[str, float]
    evidence: List[str]
    
    # Reproducibility
    algorithm_version: str
    input_hash: str
    deterministic: bool
    
    # Performance metrics
    processing_time: float
    timestamp: float
    
    # Legacy compatibility
    risk_score: float  # Same as final_score for backward compatibility


class EnhancedScoringService:
    """
    Enhanced scoring service with deterministic threat aggregation.
    Provides consistent, explainable threat scoring for production use.
    """
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.EnhancedScoringService")
        self.aggregator = deterministic_aggregator
        
        # Performance tracking
        self.score_history = []
        self.performance_metrics = {
            "total_analyses": 0,
            "avg_processing_time": 0.0,
            "accuracy_samples": []
        }
        
        # Threat level mapping
        self.threat_level_mapping = {
            ThreatCategory.LEGITIMATE: "low",
            ThreatCategory.SUSPICIOUS: "medium",
            ThreatCategory.SPAM: "medium",
            ThreatCategory.SCAM: "high",
            ThreatCategory.PHISHING: "high",
            ThreatCategory.MALWARE: "critical"
        }
    
    async def calculate_enhanced_threat_score(
        self,
        email_data: Dict[str, Any],
        analysis_components: Dict[str, Dict[str, Any]]
    ) -> EnhancedThreatScore:
        """
        Calculate enhanced threat score using deterministic aggregation.
        
        Args:
            email_data: Email metadata and content
            analysis_components: Results from various analyzers
            
        Returns:
            Enhanced threat score with full explainability
        """
        start_time = time.time()
        
        try:
            # Use deterministic threat aggregator
            deterministic_result = await self.aggregator.analyze_threat_deterministic(
                email_data, analysis_components
            )
            
            # Convert to enhanced score format
            enhanced_score = self._convert_to_enhanced_score(deterministic_result, start_time)
            
            # Update performance metrics
            self._update_performance_metrics(enhanced_score)
            
            # Store for analysis
            self.score_history.append(enhanced_score)
            
            return enhanced_score
            
        except Exception as e:
            self.logger.error(f"Enhanced threat scoring failed: {e}")
            
            # Return safe fallback score
            processing_time = time.time() - start_time
            return self._create_fallback_score(email_data, processing_time, str(e))
    
    def _convert_to_enhanced_score(
        self,
        deterministic_result: DeterministicThreatResult,
        start_time: float
    ) -> EnhancedThreatScore:
        """Convert deterministic result to enhanced score format."""
        
        # Extract key information
        threat_level = self.threat_level_mapping.get(
            deterministic_result.threat_category, "medium"
        )
        
        # Get key indicators
        key_indicators = [
            ind.name.replace('_', ' ').title() 
            for ind in deterministic_result.indicators[:5]
        ]
        
        # Create component breakdown
        component_breakdown = {
            comp.component.replace('_', ' ').title(): comp.score
            for comp in deterministic_result.components
        }
        
        # Extract key evidence
        evidence = []
        for comp in deterministic_result.components:
            evidence.extend(comp.evidence[:2])  # Limit evidence per component
        evidence = evidence[:10]  # Limit total evidence
        
        return EnhancedThreatScore(
            final_score=deterministic_result.final_score,
            threat_level=threat_level,
            threat_category=deterministic_result.threat_category.value,
            confidence_score=deterministic_result.confidence_score,
            confidence_level=deterministic_result.confidence_level.value,
            explanation=deterministic_result.explanation,
            key_indicators=key_indicators,
            component_breakdown=component_breakdown,
            evidence=evidence,
            algorithm_version=deterministic_result.algorithm_version,
            input_hash=deterministic_result.input_hash,
            deterministic=True,
            processing_time=deterministic_result.processing_time,
            timestamp=deterministic_result.analysis_timestamp,
            risk_score=deterministic_result.final_score  # Legacy compatibility
        )
    
    def _create_fallback_score(
        self,
        email_data: Dict[str, Any],
        processing_time: float,
        error_message: str
    ) -> EnhancedThreatScore:
        """Create fallback score when analysis fails."""
        
        return EnhancedThreatScore(
            final_score=0.5,  # Neutral score for safety
            threat_level="medium",
            threat_category="unknown",
            confidence_score=0.1,
            confidence_level="very_low",
            explanation=f"Analysis failed: {error_message}. Defaulting to medium threat level for safety.",
            key_indicators=["analysis_failure"],
            component_breakdown={"error": 0.5},
            evidence=[f"Error: {error_message}"],
            algorithm_version="fallback",
            input_hash="error",
            deterministic=False,
            processing_time=processing_time,
            timestamp=time.time(),
            risk_score=0.5
        )
    
    def _update_performance_metrics(self, score: EnhancedThreatScore):
        """Update performance tracking metrics."""
        
        self.performance_metrics["total_analyses"] += 1
        
        # Update average processing time
        total_time = (self.performance_metrics["avg_processing_time"] * 
                     (self.performance_metrics["total_analyses"] - 1) + 
                     score.processing_time)
        self.performance_metrics["avg_processing_time"] = total_time / self.performance_metrics["total_analyses"]
    
    async def batch_calculate_scores(
        self,
        email_batch: List[Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]]
    ) -> List[EnhancedThreatScore]:
        """
        Calculate threat scores for a batch of emails efficiently.
        
        Args:
            email_batch: List of (email_data, analysis_components) tuples
            
        Returns:
            List of enhanced threat scores
        """
        
        self.logger.info(f"Processing batch of {len(email_batch)} emails")
        
        # Process batch concurrently
        tasks = [
            self.calculate_enhanced_threat_score(email_data, analysis_components)
            for email_data, analysis_components in email_batch
        ]
        
        scores = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle any exceptions
        valid_scores = []
        for i, score in enumerate(scores):
            if isinstance(score, Exception):
                self.logger.error(f"Batch scoring failed for email {i}: {score}")
                # Create fallback score
                email_data, _ = email_batch[i]
                fallback_score = self._create_fallback_score(
                    email_data, 0.0, f"Batch processing error: {score}"
                )
                valid_scores.append(fallback_score)
            else:
                valid_scores.append(score)
        
        return valid_scores
    
    def get_scoring_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scoring statistics."""
        
        if not self.score_history:
            return {"message": "No scoring history available"}
        
        # Calculate statistics
        scores = [score.final_score for score in self.score_history]
        confidence_scores = [score.confidence_score for score in self.score_history]
        processing_times = [score.processing_time for score in self.score_history]
        
        # Threat level distribution
        threat_levels = [score.threat_level for score in self.score_history]
        threat_level_dist = {level: threat_levels.count(level) for level in set(threat_levels)}
        
        # Category distribution
        categories = [score.threat_category for score in self.score_history]
        category_dist = {cat: categories.count(cat) for cat in set(categories)}
        
        return {
            "total_analyses": len(self.score_history),
            "score_statistics": {
                "mean": sum(scores) / len(scores),
                "min": min(scores),
                "max": max(scores),
                "std": self._calculate_std_dev(scores)
            },
            "confidence_statistics": {
                "mean": sum(confidence_scores) / len(confidence_scores),
                "min": min(confidence_scores),
                "max": max(confidence_scores)
            },
            "performance_statistics": {
                "avg_processing_time": sum(processing_times) / len(processing_times),
                "min_processing_time": min(processing_times),
                "max_processing_time": max(processing_times),
                "throughput_per_second": 1.0 / (sum(processing_times) / len(processing_times))
            },
            "threat_level_distribution": threat_level_dist,
            "category_distribution": category_dist,
            "deterministic_analyses": sum(1 for score in self.score_history if score.deterministic),
            "algorithm_version": self.aggregator.VERSION
        }
    
    def _calculate_std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation."""
        if len(values) < 2:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5
    
    async def validate_scoring_consistency(
        self,
        test_email: Dict[str, Any],
        test_analysis: Dict[str, Dict[str, Any]],
        num_iterations: int = 10
    ) -> Dict[str, Any]:
        """
        Validate scoring consistency for the same input.
        
        Args:
            test_email: Test email data
            test_analysis: Test analysis components
            num_iterations: Number of scoring iterations
            
        Returns:
            Consistency validation results
        """
        
        self.logger.info(f"Validating scoring consistency with {num_iterations} iterations")
        
        scores = []
        hashes = []
        processing_times = []
        
        for i in range(num_iterations):
            result = await self.calculate_enhanced_threat_score(test_email, test_analysis)
            scores.append(result.final_score)
            hashes.append(result.input_hash)
            processing_times.append(result.processing_time)
        
        # Analyze consistency
        unique_scores = set(scores)
        unique_hashes = set(hashes)
        
        avg_processing_time = sum(processing_times) / len(processing_times)
        processing_time_variance = self._calculate_std_dev(processing_times)
        
        return {
            "consistency_check": {
                "identical_scores": len(unique_scores) == 1,
                "unique_scores": list(unique_scores),
                "identical_hashes": len(unique_hashes) == 1,
                "iterations": num_iterations
            },
            "performance_check": {
                "avg_processing_time": avg_processing_time,
                "processing_time_variance": processing_time_variance,
                "performance_consistent": processing_time_variance < avg_processing_time * 0.5
            },
            "deterministic": all(result.deterministic for result in [scores[0]]),
            "algorithm_version": self.aggregator.VERSION
        }
    
    def export_threat_score_report(self, score: EnhancedThreatScore) -> Dict[str, Any]:
        """Export comprehensive threat score report."""
        
        return {
            "summary": {
                "final_score": score.final_score,
                "threat_level": score.threat_level,
                "threat_category": score.threat_category,
                "confidence": f"{score.confidence_score:.2f} ({score.confidence_level})"
            },
            "analysis": {
                "explanation": score.explanation,
                "key_indicators": score.key_indicators,
                "evidence": score.evidence
            },
            "component_breakdown": score.component_breakdown,
            "metadata": {
                "algorithm_version": score.algorithm_version,
                "input_hash": score.input_hash,
                "deterministic": score.deterministic,
                "processing_time": f"{score.processing_time:.4f}s",
                "timestamp": datetime.fromtimestamp(score.timestamp, timezone.utc).isoformat()
            },
            "recommendations": self._generate_recommendations(score)
        }
    
    def _generate_recommendations(self, score: EnhancedThreatScore) -> List[str]:
        """Generate actionable recommendations based on threat score."""
        
        recommendations = []
        
        if score.final_score >= 0.8:
            recommendations.extend([
                "🚨 IMMEDIATE ACTION: Block this email and quarantine",
                "🔍 Investigate sender for potential account compromise",
                "📋 Report to security team for threat intelligence update"
            ])
        elif score.final_score >= 0.6:
            recommendations.extend([
                "⚠️ HIGH RISK: Review email carefully before taking any action",
                "🔗 Do not click any links or download attachments",
                "👤 Verify sender identity through alternative communication"
            ])
        elif score.final_score >= 0.3:
            recommendations.extend([
                "⚡ MODERATE RISK: Exercise caution with this email",
                "🔍 Verify any unexpected requests or information"
            ])
        else:
            recommendations.append("✅ LOW RISK: Email appears legitimate")
        
        # Add specific recommendations based on indicators
        if "malicious_urls" in score.key_indicators:
            recommendations.append("🔗 Contains malicious URLs - do not click any links")
        
        if "credential_harvesting" in score.key_indicators:
            recommendations.append("🔑 Potential credential theft attempt - verify through official channels")
        
        if "sender_spoofing" in score.key_indicators:
            recommendations.append("👤 Sender may be spoofed - verify sender identity")
        
        return recommendations


# Global enhanced scoring service instance
enhanced_scoring_service = EnhancedScoringService()


# Convenience functions for easy integration
async def calculate_enhanced_score(
    email_data: Dict[str, Any],
    analysis_components: Dict[str, Dict[str, Any]]
) -> EnhancedThreatScore:
    """Convenience function for calculating enhanced threat scores."""
    return await enhanced_scoring_service.calculate_enhanced_threat_score(
        email_data, analysis_components
    )


async def batch_score_emails(
    email_batch: List[Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]]
) -> List[EnhancedThreatScore]:
    """Convenience function for batch scoring."""
    return await enhanced_scoring_service.batch_calculate_scores(email_batch)


def get_scoring_statistics() -> Dict[str, Any]:
    """Get current scoring statistics."""
    return enhanced_scoring_service.get_scoring_statistics()