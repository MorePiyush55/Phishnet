"""
API endpoints for deterministic threat aggregation - Priority 5
Provides explainable AI threat scoring with reproducible results.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from app.config.logging import get_logger
from app.services.enhanced_scoring_service import (
    enhanced_scoring_service,
    calculate_enhanced_score,
    batch_score_emails,
    get_scoring_statistics
)
from app.services.deterministic_threat_aggregator import (
    deterministic_aggregator,
    ThreatCategory,
    ConfidenceLevel
)

logger = get_logger(__name__)

# Create router for deterministic threat analysis
deterministic_router = APIRouter(prefix="/api/v2/threat-analysis", tags=["Deterministic Threat Analysis"])


# Request/Response Models
class EmailAnalysisRequest(BaseModel):
    """Request model for email threat analysis."""
    email_data: Dict[str, Any] = Field(..., description="Email metadata and content")
    analysis_components: Dict[str, Dict[str, Any]] = Field(..., description="Analysis results from various components")
    include_trace: bool = Field(False, description="Include computation trace in response")


class ThreatScoreResponse(BaseModel):
    """Response model for threat score analysis."""
    final_score: float = Field(..., description="Final threat score (0.0 to 1.0)")
    threat_level: str = Field(..., description="Threat level (low, medium, high, critical)")
    threat_category: str = Field(..., description="Threat category")
    confidence_score: float = Field(..., description="Confidence in assessment (0.0 to 1.0)")
    confidence_level: str = Field(..., description="Confidence level")
    explanation: str = Field(..., description="Human-readable explanation")
    key_indicators: List[str] = Field(..., description="Key threat indicators detected")
    component_breakdown: Dict[str, float] = Field(..., description="Score breakdown by component")
    evidence: List[str] = Field(..., description="Supporting evidence")
    metadata: Dict[str, Any] = Field(..., description="Analysis metadata")
    recommendations: List[str] = Field(..., description="Actionable recommendations")


class BatchAnalysisRequest(BaseModel):
    """Request model for batch email analysis."""
    emails: List[EmailAnalysisRequest] = Field(..., description="List of emails to analyze")
    include_statistics: bool = Field(True, description="Include batch statistics in response")


class ConsistencyTestRequest(BaseModel):
    """Request model for scoring consistency testing."""
    email_data: Dict[str, Any] = Field(..., description="Test email data")
    analysis_components: Dict[str, Dict[str, Any]] = Field(..., description="Test analysis components")
    iterations: int = Field(10, description="Number of test iterations", ge=1, le=50)


# API Endpoints

@deterministic_router.post("/analyze", response_model=ThreatScoreResponse)
async def analyze_threat_deterministic(request: EmailAnalysisRequest):
    """
    Perform deterministic threat analysis with explainable AI output.
    
    Returns consistent, reproducible threat scores with detailed explanations.
    """
    try:
        logger.info("Processing deterministic threat analysis request")
        
        # Calculate enhanced threat score
        enhanced_score = await calculate_enhanced_score(
            request.email_data, 
            request.analysis_components
        )
        
        # Generate comprehensive report
        report = enhanced_scoring_service.export_threat_score_report(enhanced_score)
        
        # Add computation trace if requested
        if request.include_trace:
            # Get original deterministic result for trace
            deterministic_result = await deterministic_aggregator.analyze_threat_deterministic(
                request.email_data, request.analysis_components
            )
            report["metadata"]["computation_trace"] = deterministic_result.computation_trace
        
        return ThreatScoreResponse(
            final_score=enhanced_score.final_score,
            threat_level=enhanced_score.threat_level,
            threat_category=enhanced_score.threat_category,
            confidence_score=enhanced_score.confidence_score,
            confidence_level=enhanced_score.confidence_level,
            explanation=enhanced_score.explanation,
            key_indicators=enhanced_score.key_indicators,
            component_breakdown=enhanced_score.component_breakdown,
            evidence=enhanced_score.evidence,
            metadata=report["metadata"],
            recommendations=report["recommendations"]
        )
        
    except Exception as e:
        logger.error(f"Deterministic threat analysis failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Threat analysis failed: {str(e)}"
        )


@deterministic_router.post("/batch-analyze")
async def batch_analyze_threats(request: BatchAnalysisRequest):
    """
    Perform batch threat analysis for multiple emails efficiently.
    
    Processes multiple emails concurrently and returns comprehensive results.
    """
    try:
        logger.info(f"Processing batch threat analysis for {len(request.emails)} emails")
        
        # Prepare batch data
        email_batch = [
            (email.email_data, email.analysis_components) 
            for email in request.emails
        ]
        
        # Process batch
        scores = await batch_score_emails(email_batch)
        
        # Generate individual reports
        results = []
        for i, score in enumerate(scores):
            report = enhanced_scoring_service.export_threat_score_report(score)
            
            result = {
                "email_index": i,
                "final_score": score.final_score,
                "threat_level": score.threat_level,
                "threat_category": score.threat_category,
                "confidence_score": score.confidence_score,
                "explanation": score.explanation,
                "key_indicators": score.key_indicators,
                "recommendations": report["recommendations"][:3]  # Limit for batch response
            }
            results.append(result)
        
        response = {"results": results}
        
        # Add batch statistics if requested
        if request.include_statistics:
            batch_scores = [score.final_score for score in scores]
            threat_levels = [score.threat_level for score in scores]
            
            response["batch_statistics"] = {
                "total_emails": len(scores),
                "avg_score": sum(batch_scores) / len(batch_scores),
                "high_threat_count": len([s for s in batch_scores if s >= 0.7]),
                "medium_threat_count": len([s for s in batch_scores if 0.3 <= s < 0.7]),
                "low_threat_count": len([s for s in batch_scores if s < 0.3]),
                "threat_level_distribution": {
                    level: threat_levels.count(level) for level in set(threat_levels)
                },
                "processing_summary": {
                    "total_processing_time": sum(score.processing_time for score in scores),
                    "avg_processing_time": sum(score.processing_time for score in scores) / len(scores),
                    "deterministic_analyses": sum(1 for score in scores if score.deterministic)
                }
            }
        
        return response
        
    except Exception as e:
        logger.error(f"Batch threat analysis failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Batch analysis failed: {str(e)}"
        )


@deterministic_router.get("/statistics")
async def get_threat_analysis_statistics():
    """
    Get comprehensive threat analysis statistics and performance metrics.
    
    Returns scoring statistics, performance metrics, and system health.
    """
    try:
        # Get scoring statistics
        stats = get_scoring_statistics()
        
        # Add system information
        system_info = {
            "algorithm_version": deterministic_aggregator.VERSION,
            "service_status": "operational",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return {
            "statistics": stats,
            "system_info": system_info
        }
        
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve statistics: {str(e)}"
        )


@deterministic_router.post("/test-consistency")
async def test_scoring_consistency(request: ConsistencyTestRequest):
    """
    Test scoring consistency and reproducibility.
    
    Runs multiple analyses on the same input to verify deterministic behavior.
    """
    try:
        logger.info(f"Testing scoring consistency with {request.iterations} iterations")
        
        # Run consistency validation
        consistency_results = await enhanced_scoring_service.validate_scoring_consistency(
            request.email_data,
            request.analysis_components,
            request.iterations
        )
        
        return {
            "consistency_test": consistency_results,
            "test_parameters": {
                "iterations": request.iterations,
                "email_subject": request.email_data.get("subject", "Unknown"),
                "analysis_components": list(request.analysis_components.keys())
            },
            "verdict": {
                "reproducible": consistency_results["consistency_check"]["identical_scores"],
                "performance_stable": consistency_results["performance_check"]["performance_consistent"],
                "deterministic": consistency_results["deterministic"]
            }
        }
        
    except Exception as e:
        logger.error(f"Consistency test failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Consistency test failed: {str(e)}"
        )


@deterministic_router.get("/health")
async def threat_analysis_health_check():
    """
    Health check for deterministic threat analysis service.
    
    Verifies service functionality and readiness.
    """
    try:
        # Test basic functionality
        test_email = {"subject": "Health Check", "content": "Test content"}
        test_analysis = {
            "url_analysis": {"risk_score": 0.1},
            "content_analysis": {"risk_score": 0.1}
        }
        
        # Perform test analysis
        start_time = datetime.utcnow()
        test_result = await calculate_enhanced_score(test_email, test_analysis)
        end_time = datetime.utcnow()
        
        response_time = (end_time - start_time).total_seconds()
        
        return {
            "status": "healthy",
            "service": "Deterministic Threat Analysis",
            "version": deterministic_aggregator.VERSION,
            "response_time": f"{response_time:.4f}s",
            "test_results": {
                "basic_analysis": "passed",
                "deterministic": test_result.deterministic,
                "score_valid": 0 <= test_result.final_score <= 1
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": "Deterministic Threat Analysis",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )


@deterministic_router.get("/algorithm-info")
async def get_algorithm_information():
    """
    Get detailed information about the threat analysis algorithm.
    
    Returns algorithm specifications, weights, and thresholds.
    """
    try:
        algorithm_info = {
            "algorithm": {
                "name": "Deterministic Threat Aggregator",
                "version": deterministic_aggregator.VERSION,
                "type": "Explainable AI with Deterministic Scoring"
            },
            "component_weights": deterministic_aggregator.component_weights,
            "threat_thresholds": {
                category.value: threshold 
                for category, threshold in deterministic_aggregator.threat_thresholds.items()
            },
            "confidence_levels": {
                f"{min_val}-{max_val}": level.value
                for (min_val, max_val), level in deterministic_aggregator.confidence_levels.items()
            },
            "indicator_definitions": deterministic_aggregator.indicator_definitions,
            "features": [
                "Reproducible results for identical inputs",
                "Transparent scoring with detailed explanations", 
                "Standardized threat categorization",
                "Confidence quantification",
                "Full audit trail of scoring decisions",
                "Component-wise score breakdown",
                "Evidence-based reasoning"
            ],
            "supported_analysis_types": [
                "URL Analysis",
                "Content Analysis", 
                "Sender Analysis",
                "Attachment Analysis",
                "Context Analysis"
            ]
        }
        
        return algorithm_info
        
    except Exception as e:
        logger.error(f"Failed to get algorithm info: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve algorithm information: {str(e)}"
        )


# Background task for performance monitoring
async def monitor_scoring_performance():
    """Background task to monitor scoring performance."""
    try:
        stats = get_scoring_statistics()
        if stats.get("total_analyses", 0) > 0:
            avg_time = stats.get("performance_statistics", {}).get("avg_processing_time", 0)
            if avg_time > 1.0:  # Alert if processing takes more than 1 second
                logger.warning(f"Slow scoring performance detected: {avg_time:.3f}s average")
    except Exception as e:
        logger.error(f"Performance monitoring failed: {e}")


@deterministic_router.post("/analyze-with-monitoring")
async def analyze_with_performance_monitoring(
    request: EmailAnalysisRequest, 
    background_tasks: BackgroundTasks
):
    """
    Perform threat analysis with background performance monitoring.
    
    Same as regular analysis but includes performance monitoring.
    """
    # Schedule performance monitoring
    background_tasks.add_task(monitor_scoring_performance)
    
    # Perform regular analysis
    return await analyze_threat_deterministic(request)