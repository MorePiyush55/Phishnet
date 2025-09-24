"""
Enhanced Threat Aggregation Service with Persistence

Integrates the deterministic ThreatAggregator with database persistence
for audit trails, historical analysis, and reproducibility verification.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import structlog

from app.services.threat_aggregator import (
    ThreatAggregator,
    ThreatAggregatorConfig,
    ComponentScore,
    ComponentType,
    ThresholdProfile,
    AggregatedThreatResult,
    balanced_aggregator,
    strict_aggregator,
    lenient_aggregator
)
from app.repositories.threat_aggregation_repository import (
    ThreatAggregationRepository,
    ThreatAnalysisSession
)
from app.db.session import get_db

logger = structlog.get_logger(__name__)


class ThreatAggregationService:
    """
    Enhanced threat aggregation service with persistence and audit capabilities.
    
    Provides:
    - Deterministic threat scoring with explanations
    - Persistent storage of analysis results
    - Historical analysis and trend tracking
    - Reproducibility verification
    - Performance monitoring
    """
    
    def __init__(self, db_session=None):
        self.db_session = db_session or next(get_db())
        self.repository = ThreatAggregationRepository(self.db_session)
        
        # Available aggregators by profile
        self.aggregators = {
            ThresholdProfile.STRICT: strict_aggregator,
            ThresholdProfile.BALANCED: balanced_aggregator,
            ThresholdProfile.LENIENT: lenient_aggregator
        }
        
        logger.info("ThreatAggregationService initialized")
    
    async def analyze_and_persist(self,
                                target_identifier: str,
                                target_type: str,
                                component_scores: List[ComponentScore],
                                threshold_profile: ThresholdProfile = ThresholdProfile.BALANCED,
                                save_to_db: bool = True) -> Dict[str, Any]:
        """
        Perform threat aggregation and optionally persist results.
        
        Args:
            target_identifier: Unique identifier for the target
            target_type: Type of target (email, url, file, etc.)
            component_scores: List of component analysis results
            threshold_profile: Risk tolerance profile to use
            save_to_db: Whether to persist results to database
            
        Returns:
            Dictionary with analysis results and metadata
        """
        
        start_time = datetime.now(timezone.utc)
        
        try:
            # Get appropriate aggregator for profile
            aggregator = self.aggregators[threshold_profile]
            
            # Check for existing analysis with same deterministic hash
            if save_to_db:
                existing_session = await self._check_existing_analysis(
                    component_scores, target_identifier, threshold_profile
                )
                if existing_session:
                    logger.info("Found existing analysis with identical parameters",
                              deterministic_hash=existing_session.deterministic_hash,
                              target_identifier=target_identifier)
                    
                    return self._format_response(existing_session, from_cache=True)
            
            # Perform aggregation
            result = aggregator.aggregate_threat_scores(component_scores, target_identifier)
            
            # Persist to database if requested
            session = None
            if save_to_db:
                session = self.repository.save_threat_analysis(
                    target_identifier, target_type, result
                )
                logger.info("Threat analysis saved to database",
                          session_id=str(session.id),
                          deterministic_hash=result.deterministic_hash,
                          threat_score=result.threat_score)
            
            # Format response
            response = self._format_analysis_response(result, session)
            
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.info("Threat aggregation completed",
                       target_identifier=target_identifier,
                       threat_score=result.threat_score,
                       threat_level=result.threat_level.value,
                       processing_time=processing_time)
            
            return response
            
        except Exception as e:
            logger.error("Threat aggregation failed",
                        target_identifier=target_identifier,
                        error=str(e))
            raise
    
    async def get_threat_history(self,
                               target_identifier: Optional[str] = None,
                               target_hash: Optional[str] = None,
                               days: int = 30) -> List[Dict[str, Any]]:
        """
        Get threat analysis history for a target.
        
        Args:
            target_identifier: Target identifier to search for
            target_hash: Target hash to search for
            days: Number of days to look back
            
        Returns:
            List of historical threat analyses
        """
        
        if target_identifier:
            sessions = self.repository.get_analyses_for_target(target_identifier)
        elif target_hash:
            sessions = self.repository.get_threat_score_history(target_hash, days)
            return sessions  # Already formatted
        else:
            raise ValueError("Either target_identifier or target_hash must be provided")
        
        return [self._format_session_summary(session) for session in sessions]
    
    async def verify_deterministic_consistency(self,
                                             target_hash: str) -> Dict[str, Any]:
        """
        Verify that analyses of the same target produce consistent results.
        
        Args:
            target_hash: Hash of the target to verify
            
        Returns:
            Consistency verification results
        """
        
        return self.repository.verify_deterministic_consistency(target_hash)
    
    async def get_component_performance(self,
                                      component_type: Optional[str] = None,
                                      days: int = 7) -> Dict[str, Any]:
        """
        Get performance statistics for threat analysis components.
        
        Args:
            component_type: Specific component to analyze (optional)
            days: Number of days to analyze
            
        Returns:
            Component performance statistics
        """
        
        if component_type:
            return self.repository.get_component_performance_stats(component_type, days)
        else:
            # Get stats for all component types
            all_stats = {}
            for comp_type in ComponentType:
                stats = self.repository.get_component_performance_stats(comp_type.value, days)
                all_stats[comp_type.value] = stats
            
            return {
                "period_days": days,
                "component_stats": all_stats,
                "summary": self._calculate_overall_performance(all_stats)
            }
    
    async def get_top_threat_signals(self,
                                   days: int = 7,
                                   limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most frequent threat signals across all analyses.
        
        Args:
            days: Number of days to analyze
            limit: Maximum number of signals to return
            
        Returns:
            List of top threat signals with statistics
        """
        
        return self.repository.get_top_threat_signals(days, limit)
    
    async def get_analysis_by_hash(self,
                                 deterministic_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve analysis by deterministic hash.
        
        Args:
            deterministic_hash: Deterministic hash to search for
            
        Returns:
            Analysis details if found, None otherwise
        """
        
        session = self.repository.get_analysis_by_deterministic_hash(deterministic_hash)
        if session:
            return self._format_response(session)
        return None
    
    async def _check_existing_analysis(self,
                                     component_scores: List[ComponentScore],
                                     target_identifier: str,
                                     threshold_profile: ThresholdProfile) -> Optional[ThreatAnalysisSession]:
        """Check if identical analysis already exists."""
        
        # Calculate what the deterministic hash would be
        aggregator = self.aggregators[threshold_profile]
        temp_hash = aggregator._calculate_deterministic_hash(component_scores, target_identifier)
        
        # Look for existing analysis with same hash
        return self.repository.get_analysis_by_deterministic_hash(temp_hash)
    
    def _format_analysis_response(self,
                                result: AggregatedThreatResult,
                                session: Optional[ThreatAnalysisSession] = None) -> Dict[str, Any]:
        """Format aggregation result for API response."""
        
        response = {
            # Core results
            "threat_score": result.threat_score,
            "threat_level": result.threat_level.value,
            "recommended_action": result.recommended_action.value,
            "deterministic_hash": result.deterministic_hash,
            
            # Explanation
            "explanation": {
                "reasoning": result.explanation.reasoning,
                "confidence_band": {
                    "lower_bound": result.explanation.confidence_band.lower_bound,
                    "upper_bound": result.explanation.confidence_band.upper_bound,
                    "confidence_level": result.explanation.confidence_band.confidence_level
                },
                "top_signals": [
                    {
                        "name": signal.signal_name,
                        "description": signal.description,
                        "component": signal.component_type.value,
                        "contribution": signal.contribution,
                        "evidence": signal.evidence
                    }
                    for signal in result.explanation.top_signals
                ],
                "component_breakdown": result.explanation.component_breakdown,
                "certainty_factors": result.explanation.certainty_factors,
                "risk_factors": result.explanation.risk_factors
            },
            
            # Component details
            "components": [
                {
                    "type": cs.component_type.value,
                    "score": cs.score,
                    "confidence": cs.confidence,
                    "signals": cs.signals,
                    "processing_time": cs.processing_time
                }
                for cs in result.component_scores
            ],
            
            # Metadata
            "metadata": {
                "threshold_profile": result.threshold_profile.value,
                "processing_time": result.processing_time,
                "timestamp": result.timestamp.isoformat(),
                "version": result.version,
                "aggregation_metadata": result.aggregation_metadata
            },
            
            # Legacy compatibility
            "confidence": result.confidence,
            "verdict": result.verdict,
            "indicators": result.indicators,
            "recommendations": result.recommendations
        }
        
        # Add database info if persisted
        if session:
            response["persistence"] = {
                "session_id": str(session.id),
                "saved_at": session.created_at.isoformat(),
                "target_hash": session.target_hash
            }
        
        return response
    
    def _format_response(self,
                       session: ThreatAnalysisSession,
                       from_cache: bool = False) -> Dict[str, Any]:
        """Format database session for response."""
        
        response = {
            "threat_score": session.final_threat_score,
            "threat_level": session.threat_level,
            "recommended_action": session.recommended_action,
            "deterministic_hash": session.deterministic_hash,
            
            "explanation": {
                "reasoning": session.reasoning_summary,
                "confidence_band": {
                    "lower_bound": session.confidence_lower_bound,
                    "upper_bound": session.confidence_upper_bound,
                    "confidence_level": session.confidence_level
                },
                "top_signals": [
                    {
                        "name": signal.signal_name,
                        "description": signal.signal_description,
                        "component": signal.component_type,
                        "contribution": signal.contribution_value,
                        "evidence": signal.evidence,
                        "rank": signal.rank_order
                    }
                    for signal in sorted(session.explanation_signals, key=lambda x: x.rank_order)
                ],
                "component_breakdown": {
                    comp.component_type: comp.score_contribution
                    for comp in session.component_results
                }
            },
            
            "components": [
                {
                    "type": comp.component_type,
                    "score": comp.threat_score,
                    "confidence": comp.confidence_score,
                    "signals": comp.signals,
                    "processing_time": comp.processing_time
                }
                for comp in session.component_results
            ],
            
            "metadata": {
                "threshold_profile": session.threshold_profile,
                "processing_time": session.total_processing_time,
                "timestamp": session.session_completed.isoformat() if session.session_completed else session.session_started.isoformat(),
                "version": session.aggregator_version,
                "from_cache": from_cache
            },
            
            "persistence": {
                "session_id": str(session.id),
                "saved_at": session.created_at.isoformat(),
                "target_hash": session.target_hash
            }
        }
        
        return response
    
    def _format_session_summary(self, session: ThreatAnalysisSession) -> Dict[str, Any]:
        """Format session for summary listing."""
        
        return {
            "session_id": str(session.id),
            "target_identifier": session.target_identifier,
            "target_type": session.target_type,
            "threat_score": session.final_threat_score,
            "threat_level": session.threat_level,
            "recommended_action": session.recommended_action,
            "confidence_level": session.confidence_level,
            "threshold_profile": session.threshold_profile,
            "deterministic_hash": session.deterministic_hash,
            "analysis_time": session.session_completed.isoformat() if session.session_completed else session.session_started.isoformat(),
            "processing_time": session.total_processing_time
        }
    
    def _calculate_overall_performance(self, component_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall performance metrics from component stats."""
        
        active_components = [stats for stats in component_stats.values() if stats["total_analyses"] > 0]
        
        if not active_components:
            return {
                "total_components": len(component_stats),
                "active_components": 0,
                "overall_avg_processing_time": 0,
                "overall_avg_confidence": 0
            }
        
        total_analyses = sum(stats["total_analyses"] for stats in active_components)
        weighted_processing_time = sum(
            stats["avg_processing_time"] * stats["total_analyses"] for stats in active_components
        )
        weighted_confidence = sum(
            stats["avg_confidence"] * stats["total_analyses"] for stats in active_components
        )
        
        return {
            "total_components": len(component_stats),
            "active_components": len(active_components),
            "total_analyses": total_analyses,
            "overall_avg_processing_time": weighted_processing_time / total_analyses if total_analyses > 0 else 0,
            "overall_avg_confidence": weighted_confidence / total_analyses if total_analyses > 0 else 0,
            "fastest_component": min(active_components, key=lambda x: x["avg_processing_time"])["component_type"],
            "most_confident_component": max(active_components, key=lambda x: x["avg_confidence"])["component_type"]
        }


# Factory function
def create_threat_aggregation_service(db_session=None) -> ThreatAggregationService:
    """Create ThreatAggregationService instance."""
    return ThreatAggregationService(db_session)