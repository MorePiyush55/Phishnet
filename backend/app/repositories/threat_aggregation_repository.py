"""
Database models and repository for threat aggregation persistence.

Stores component outputs, aggregated results, explanations, and audit trails
for historical analysis and deterministic verification.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, JSON, Index, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.dialects.postgresql import UUID
import uuid
import json

from app.db.base_class import Base


class ThreatAnalysisSession(Base):
    """Represents a complete threat analysis session with multiple components."""
    
    __tablename__ = "threat_analysis_sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_identifier = Column(String(500), nullable=False, index=True)
    target_type = Column(String(50), nullable=False)  # email, url, file, etc.
    target_hash = Column(String(64), nullable=False, index=True)  # SHA256 of target content
    
    # Session metadata
    session_started = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    session_completed = Column(DateTime(timezone=True), nullable=True)
    total_processing_time = Column(Float, nullable=True)  # Total seconds
    
    # Analysis configuration
    threshold_profile = Column(String(20), nullable=False)  # strict, balanced, lenient
    aggregator_version = Column(String(20), nullable=False, default="2.0")
    component_weights = Column(JSON, nullable=False)  # Weights used for aggregation
    
    # Final results
    final_threat_score = Column(Float, nullable=True)
    threat_level = Column(String(20), nullable=True)
    recommended_action = Column(String(20), nullable=True)
    deterministic_hash = Column(String(32), nullable=True, index=True)
    
    # Confidence and explanation summary
    confidence_level = Column(Float, nullable=True)
    confidence_lower_bound = Column(Float, nullable=True)
    confidence_upper_bound = Column(Float, nullable=True)
    reasoning_summary = Column(Text, nullable=True)
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    component_results = relationship("ComponentAnalysisResult", back_populates="session", cascade="all, delete-orphan")
    explanation_signals = relationship("ExplanationSignal", back_populates="session", cascade="all, delete-orphan")
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_threat_sessions_target_hash', 'target_hash'),
        Index('idx_threat_sessions_deterministic_hash', 'deterministic_hash'),
        Index('idx_threat_sessions_created_at', 'created_at'),
        Index('idx_threat_sessions_threat_score', 'final_threat_score'),
    )


class ComponentAnalysisResult(Base):
    """Stores individual component analysis results."""
    
    __tablename__ = "component_analysis_results"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True), ForeignKey('threat_analysis_sessions.id'), nullable=False)
    
    # Component identification
    component_type = Column(String(50), nullable=False, index=True)  # gemini_llm, virus_total, etc.
    component_version = Column(String(20), nullable=False, default="1.0")
    
    # Analysis results
    threat_score = Column(Float, nullable=False)
    confidence_score = Column(Float, nullable=False)
    processing_time = Column(Float, nullable=False)  # Seconds
    
    # Signals and metadata
    signals = Column(JSON, nullable=False)  # List of detected signals
    raw_metadata = Column(JSON, nullable=True)  # Full component metadata
    
    # Contribution to final score
    weight_used = Column(Float, nullable=False)
    score_contribution = Column(Float, nullable=False)
    
    # Timing
    analysis_started = Column(DateTime(timezone=True), nullable=False)
    analysis_completed = Column(DateTime(timezone=True), nullable=False)
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    session = relationship("ThreatAnalysisSession", back_populates="component_results")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_component_results_session_id', 'session_id'),
        Index('idx_component_results_component_type', 'component_type'),
        Index('idx_component_results_threat_score', 'threat_score'),
    )


class ExplanationSignal(Base):
    """Stores top contributing signals for explanation."""
    
    __tablename__ = "explanation_signals"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True), ForeignKey('threat_analysis_sessions.id'), nullable=False)
    
    # Signal details
    signal_name = Column(String(200), nullable=False, index=True)
    signal_description = Column(Text, nullable=False)
    component_type = Column(String(50), nullable=False, index=True)
    
    # Contribution metrics
    signal_weight = Column(Float, nullable=False)
    signal_score = Column(Float, nullable=False)
    contribution_value = Column(Float, nullable=False)
    rank_order = Column(Integer, nullable=False)  # 1-5 for top signals
    
    # Supporting evidence
    evidence = Column(JSON, nullable=False)  # List of evidence strings
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    session = relationship("ThreatAnalysisSession", back_populates="explanation_signals")
    
    # Indexes for queries
    __table_args__ = (
        Index('idx_explanation_signals_session_id', 'session_id'),
        Index('idx_explanation_signals_signal_name', 'signal_name'),
        Index('idx_explanation_signals_rank', 'rank_order'),
    )


class ThreatAggregationRepository:
    """Repository for threat aggregation persistence operations."""
    
    def __init__(self, db_session):
        self.db = db_session
    
    def save_threat_analysis(self, 
                           target_identifier: str,
                           target_type: str,
                           result: 'AggregatedThreatResult') -> ThreatAnalysisSession:
        """
        Save complete threat analysis session to database.
        
        Args:
            target_identifier: Unique identifier for the analyzed target
            target_type: Type of target (email, url, file, etc.)
            result: AggregatedThreatResult from threat aggregator
            
        Returns:
            Saved ThreatAnalysisSession with assigned ID
        """
        
        # Create main session record
        session = ThreatAnalysisSession(
            target_identifier=target_identifier,
            target_type=target_type,
            target_hash=result.aggregation_metadata.get("target_hash", "unknown"),
            session_started=result.timestamp,
            session_completed=result.timestamp,
            total_processing_time=result.processing_time,
            threshold_profile=result.threshold_profile.value,
            aggregator_version=result.version,
            component_weights=result.aggregation_metadata.get("component_weights", {}),
            final_threat_score=result.threat_score,
            threat_level=result.threat_level.value,
            recommended_action=result.recommended_action.value,
            deterministic_hash=result.deterministic_hash,
            confidence_level=result.explanation.confidence_band.confidence_level,
            confidence_lower_bound=result.explanation.confidence_band.lower_bound,
            confidence_upper_bound=result.explanation.confidence_band.upper_bound,
            reasoning_summary=result.explanation.reasoning
        )
        
        self.db.add(session)
        self.db.flush()  # Get session ID
        
        # Save component results
        for component_score in result.component_scores:
            component_result = ComponentAnalysisResult(
                session_id=session.id,
                component_type=component_score.component_type.value,
                component_version=component_score.version,
                threat_score=component_score.score,
                confidence_score=component_score.confidence,
                processing_time=component_score.processing_time,
                signals=component_score.signals,
                raw_metadata=component_score.metadata,
                weight_used=result.aggregation_metadata.get("component_weights", {}).get(
                    component_score.component_type.value, 0.0
                ),
                score_contribution=result.explanation.component_breakdown.get(
                    component_score.component_type.value, 0.0
                ),
                analysis_started=component_score.timestamp,
                analysis_completed=component_score.timestamp
            )
            self.db.add(component_result)
        
        # Save explanation signals
        for i, signal in enumerate(result.explanation.top_signals):
            explanation_signal = ExplanationSignal(
                session_id=session.id,
                signal_name=signal.signal_name,
                signal_description=signal.description,
                component_type=signal.component_type.value,
                signal_weight=signal.weight,
                signal_score=signal.score,
                contribution_value=signal.contribution,
                rank_order=i + 1,
                evidence=signal.evidence
            )
            self.db.add(explanation_signal)
        
        self.db.commit()
        return session
    
    def get_analysis_by_deterministic_hash(self, 
                                         deterministic_hash: str) -> Optional[ThreatAnalysisSession]:
        """
        Retrieve analysis by deterministic hash for reproducibility verification.
        
        Args:
            deterministic_hash: Deterministic hash of the analysis
            
        Returns:
            ThreatAnalysisSession if found, None otherwise
        """
        return self.db.query(ThreatAnalysisSession).filter(
            ThreatAnalysisSession.deterministic_hash == deterministic_hash
        ).first()
    
    def get_analyses_for_target(self, 
                              target_identifier: str,
                              limit: int = 10) -> List[ThreatAnalysisSession]:
        """
        Get recent analyses for a specific target.
        
        Args:
            target_identifier: Target identifier to search for
            limit: Maximum number of results to return
            
        Returns:
            List of ThreatAnalysisSession ordered by creation time (newest first)
        """
        return self.db.query(ThreatAnalysisSession).filter(
            ThreatAnalysisSession.target_identifier == target_identifier
        ).order_by(ThreatAnalysisSession.created_at.desc()).limit(limit).all()
    
    def get_threat_score_history(self, 
                               target_hash: str,
                               days: int = 30) -> List[Dict[str, Any]]:
        """
        Get threat score history for a target over time.
        
        Args:
            target_hash: Hash of the target content
            days: Number of days to look back
            
        Returns:
            List of threat score records with timestamps
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        sessions = self.db.query(ThreatAnalysisSession).filter(
            ThreatAnalysisSession.target_hash == target_hash,
            ThreatAnalysisSession.created_at >= cutoff_date
        ).order_by(ThreatAnalysisSession.created_at).all()
        
        return [
            {
                "timestamp": session.created_at.isoformat(),
                "threat_score": session.final_threat_score,
                "threat_level": session.threat_level,
                "deterministic_hash": session.deterministic_hash,
                "threshold_profile": session.threshold_profile
            }
            for session in sessions
        ]
    
    def get_component_performance_stats(self, 
                                      component_type: str,
                                      days: int = 7) -> Dict[str, Any]:
        """
        Get performance statistics for a specific component.
        
        Args:
            component_type: Type of component to analyze
            days: Number of days to analyze
            
        Returns:
            Dictionary with performance statistics
        """
        from sqlalchemy import func
        from datetime import timedelta
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        stats = self.db.query(
            func.count(ComponentAnalysisResult.id).label('total_analyses'),
            func.avg(ComponentAnalysisResult.threat_score).label('avg_threat_score'),
            func.avg(ComponentAnalysisResult.confidence_score).label('avg_confidence'),
            func.avg(ComponentAnalysisResult.processing_time).label('avg_processing_time'),
            func.max(ComponentAnalysisResult.processing_time).label('max_processing_time'),
            func.min(ComponentAnalysisResult.processing_time).label('min_processing_time')
        ).filter(
            ComponentAnalysisResult.component_type == component_type,
            ComponentAnalysisResult.created_at >= cutoff_date
        ).first()
        
        return {
            "component_type": component_type,
            "period_days": days,
            "total_analyses": stats.total_analyses or 0,
            "avg_threat_score": float(stats.avg_threat_score or 0),
            "avg_confidence": float(stats.avg_confidence or 0),
            "avg_processing_time": float(stats.avg_processing_time or 0),
            "max_processing_time": float(stats.max_processing_time or 0),
            "min_processing_time": float(stats.min_processing_time or 0)
        }
    
    def get_top_threat_signals(self, 
                             days: int = 7,
                             limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most frequent threat signals across all analyses.
        
        Args:
            days: Number of days to analyze
            limit: Maximum number of signals to return
            
        Returns:
            List of threat signals with frequency and impact data
        """
        from sqlalchemy import func
        from datetime import timedelta
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        signal_stats = self.db.query(
            ExplanationSignal.signal_name,
            func.count(ExplanationSignal.id).label('frequency'),
            func.avg(ExplanationSignal.contribution_value).label('avg_contribution'),
            func.max(ExplanationSignal.contribution_value).label('max_contribution')
        ).filter(
            ExplanationSignal.created_at >= cutoff_date
        ).group_by(
            ExplanationSignal.signal_name
        ).order_by(
            func.count(ExplanationSignal.id).desc()
        ).limit(limit).all()
        
        return [
            {
                "signal_name": stat.signal_name,
                "frequency": stat.frequency,
                "avg_contribution": float(stat.avg_contribution),
                "max_contribution": float(stat.max_contribution)
            }
            for stat in signal_stats
        ]
    
    def verify_deterministic_consistency(self, 
                                       target_hash: str) -> Dict[str, Any]:
        """
        Verify that analyses of the same target produce consistent results.
        
        Args:
            target_hash: Hash of the target to verify
            
        Returns:
            Dictionary with consistency verification results
        """
        sessions = self.db.query(ThreatAnalysisSession).filter(
            ThreatAnalysisSession.target_hash == target_hash
        ).all()
        
        if len(sessions) < 2:
            return {
                "target_hash": target_hash,
                "total_analyses": len(sessions),
                "consistency_check": "insufficient_data",
                "identical_results": None
            }
        
        # Group by deterministic hash and threshold profile
        result_groups = {}
        for session in sessions:
            key = (session.deterministic_hash, session.threshold_profile)
            if key not in result_groups:
                result_groups[key] = []
            result_groups[key].append(session)
        
        # Check consistency within each group
        consistent_groups = 0
        total_groups = len(result_groups)
        
        for (det_hash, profile), group_sessions in result_groups.items():
            # All sessions in group should have identical scores
            scores = [s.final_threat_score for s in group_sessions]
            if len(set(scores)) == 1:  # All scores identical
                consistent_groups += 1
        
        return {
            "target_hash": target_hash,
            "total_analyses": len(sessions),
            "unique_result_groups": total_groups,
            "consistent_groups": consistent_groups,
            "consistency_rate": consistent_groups / total_groups if total_groups > 0 else 0,
            "is_fully_consistent": consistent_groups == total_groups
        }


# Migration script for creating tables
def create_threat_aggregation_tables(engine):
    """Create threat aggregation tables in the database."""
    Base.metadata.create_all(bind=engine, tables=[
        ThreatAnalysisSession.__table__,
        ComponentAnalysisResult.__table__,
        ExplanationSignal.__table__
    ])