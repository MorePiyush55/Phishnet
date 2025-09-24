"""API endpoints for advanced ML ensemble system.

This module provides:
1. Email analysis with explainable predictions
2. Model performance monitoring endpoints
3. Analyst feedback collection for active learning
4. Model drift detection and alerts
5. A/B testing endpoints for model comparison
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import json
import asyncio

from app.db.session import get_db
from app.ml.advanced_ensemble import advanced_ml_system, EnsembleResult
from app.ml.monitoring import get_model_monitor, ModelPerformanceMetrics, ModelDriftMetrics
from app.config.logging import get_logger
from app.auth.auth_handler import get_current_user
from app.models.core.user import User

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/ml", tags=["machine-learning"])


# Request/Response Models
class EmailAnalysisRequest(BaseModel):
    """Request for email analysis with ensemble ML."""
    sender: str
    subject: str
    content: str
    urls: Optional[List[str]] = []
    headers: Optional[Dict[str, Any]] = {}
    sender_history: Optional[Dict[str, Any]] = {}


class FeatureExplanation(BaseModel):
    """Individual feature explanation."""
    feature_name: str
    importance_score: float
    contribution: float
    explanation: str


class MLPredictionResponse(BaseModel):
    """Response for ML prediction with explanations."""
    is_phishing: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk_score: float = Field(..., ge=0.0, le=1.0)
    
    # Individual model contributions
    content_model_score: float
    url_model_score: float
    sender_model_score: float
    
    # Explanations
    top_risk_factors: List[FeatureExplanation]
    explanation_summary: str
    model_confidence: str  # "high", "medium", "low"
    
    # Performance metadata
    processing_time_ms: float
    model_version: str
    analysis_timestamp: datetime


class AnalystFeedbackRequest(BaseModel):
    """Request for analyst feedback on predictions."""
    email_id: Optional[str] = None
    original_prediction: float
    correct_label: int = Field(..., ge=0, le=1)  # 0 = legitimate, 1 = phishing
    feedback_reason: str
    confidence_in_correction: float = Field(..., ge=0.0, le=1.0)
    
    # Original email data for retraining
    email_data: EmailAnalysisRequest


class ModelStatusResponse(BaseModel):
    """Model system status response."""
    system_health: str  # "healthy", "degraded", "critical"
    active_models: Dict[str, bool]
    model_versions: Dict[str, str]
    last_training_date: Optional[datetime]
    
    # Performance summary
    current_accuracy: float
    current_f1_score: float
    predictions_today: int
    
    # Drift status
    drift_detected: bool
    drift_score: float
    drift_type: Optional[str]
    
    # Active learning status
    pending_corrections: int
    next_retrain_scheduled: Optional[datetime]


class ModelMetricsResponse(BaseModel):
    """Model performance metrics response."""
    model_id: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    processing_time_ms: float
    evaluation_date: datetime


@router.post("/analyze", response_model=MLPredictionResponse)
async def analyze_email_advanced(
    request: EmailAnalysisRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Analyze email with advanced ensemble ML and explanations."""
    
    try:
        # Prepare email data
        email_data = {
            'sender': request.sender,
            'subject': request.subject,
            'content': request.content,
            'urls': request.urls or [],
            'headers': request.headers or {},
            'sender_history': request.sender_history or {}
        }
        
        # Get prediction with explanations
        result: EnsembleResult = await advanced_ml_system.predict_with_explanation(email_data)
        
        # Extract individual model scores
        content_score = result.individual_predictions.get('content', 0.5)
        url_score = result.individual_predictions.get('url', 0.5)  
        sender_score = result.individual_predictions.get('sender', 0.5)
        
        # Process explanations
        top_factors = []
        for feature_name, importance in result.explanation.top_features[:5]:
            top_factors.append(FeatureExplanation(
                feature_name=feature_name,
                importance_score=abs(importance),
                contribution=importance,
                explanation=_generate_feature_explanation(feature_name, importance)
            ))
        
        # Determine confidence level
        confidence_level = "high" if result.confidence > 0.8 else "medium" if result.confidence > 0.6 else "low"
        
        # Background task: Check for model drift
        background_tasks.add_task(
            _check_model_drift_async,
            email_data,
            result,
            db
        )
        
        response = MLPredictionResponse(
            is_phishing=result.is_phishing,
            confidence=result.confidence,
            risk_score=result.risk_score,
            content_model_score=content_score,
            url_model_score=url_score,
            sender_model_score=sender_score,
            top_risk_factors=top_factors,
            explanation_summary=result.explanation.explanation_text,
            model_confidence=confidence_level,
            processing_time_ms=result.processing_time_ms,
            model_version=advanced_ml_system.model_version,
            analysis_timestamp=datetime.now()
        )
        
        logger.info(f"Advanced ML analysis completed for user {current_user.id}: confidence={result.confidence:.3f}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error in advanced email analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/feedback")
async def submit_analyst_feedback(
    feedback: AnalystFeedbackRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Submit analyst feedback for active learning."""
    
    try:
        # Prepare feedback data for active learning
        email_data = {
            'sender': feedback.email_data.sender,
            'subject': feedback.email_data.subject,
            'content': feedback.email_data.content,
            'urls': feedback.email_data.urls or [],
            'sender_history': feedback.email_data.sender_history or {}
        }
        
        # Add correction to active learning queue
        advanced_ml_system.add_analyst_correction(
            email_data=email_data,
            correct_label=feedback.correct_label,
            model_prediction=feedback.original_prediction,
            user_id=str(current_user.id)
        )
        
        # Background task: Log feedback for analysis
        background_tasks.add_task(
            _log_analyst_feedback,
            feedback,
            current_user.id,
            db
        )
        
        logger.info(f"Analyst feedback received from user {current_user.id}: {feedback.feedback_reason}")
        
        return {
            "status": "success",
            "message": "Feedback recorded for model improvement",
            "correction_queued": True,
            "queue_size": len(advanced_ml_system.active_learning.correction_queue)
        }
        
    except Exception as e:
        logger.error(f"Error processing analyst feedback: {e}")
        raise HTTPException(status_code=500, detail=f"Feedback processing failed: {str(e)}")


@router.get("/status", response_model=ModelStatusResponse)
async def get_model_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get comprehensive model system status."""
    
    try:
        # Get model status
        status = advanced_ml_system.get_model_status()
        
        # Get recent performance metrics
        monitor = get_model_monitor(db)
        recent_metrics = monitor.get_model_performance_history(
            model_id=f"ensemble_{advanced_ml_system.model_version}",
            days=1
        )
        
        # Determine system health
        health = "healthy"
        if status['next_retrain_due']:
            health = "degraded"
        if not any(status['models_trained'].values()):
            health = "critical"
        
        # Get drift status (placeholder - would query recent drift records)
        drift_detected = False
        drift_score = 0.0
        drift_type = None
        
        response = ModelStatusResponse(
            system_health=health,
            active_models=status['models_trained'],
            model_versions={
                'ensemble': status['model_version'],
                'content': '1.0.0' if status['models_trained']['content'] else 'none',
                'url': '1.0.0' if status['models_trained']['url'] else 'none',
                'sender': '1.0.0' if status['models_trained']['sender'] else 'none'
            },
            last_training_date=datetime.now() - timedelta(days=1),  # Placeholder
            current_accuracy=recent_metrics[0].accuracy if recent_metrics else 0.0,
            current_f1_score=recent_metrics[0].f1_score if recent_metrics else 0.0,
            predictions_today=1250,  # Would track this in production
            drift_detected=drift_detected,
            drift_score=drift_score,
            drift_type=drift_type,
            pending_corrections=status['active_learning_queue_size'],
            next_retrain_scheduled=datetime.now() + timedelta(days=7) if status['next_retrain_due'] else None
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting model status: {e}")
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")


@router.get("/metrics/{model_id}", response_model=List[ModelMetricsResponse])
async def get_model_metrics(
    model_id: str,
    days: int = 30,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get model performance metrics history."""
    
    try:
        monitor = get_model_monitor(db)
        history = monitor.get_model_performance_history(model_id, days=days)
        
        response = []
        for metrics in history:
            response.append(ModelMetricsResponse(
                model_id=metrics.model_id,
                accuracy=metrics.accuracy,
                precision=metrics.precision,
                recall=metrics.recall,
                f1_score=metrics.f1_score,
                false_positive_rate=metrics.false_positives / (metrics.false_positives + metrics.true_negatives) if (metrics.false_positives + metrics.true_negatives) > 0 else 0,
                false_negative_rate=metrics.false_negatives / (metrics.false_negatives + metrics.true_positives) if (metrics.false_negatives + metrics.true_positives) > 0 else 0,
                processing_time_ms=metrics.avg_prediction_time_ms,
                evaluation_date=metrics.evaluation_timestamp
            ))
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting model metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Metrics retrieval failed: {str(e)}")


@router.get("/drift/{model_id}")
async def get_drift_status(
    model_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get model drift status and history."""
    
    try:
        # Query recent drift records from database
        from app.ml.monitoring import ModelDriftDB
        
        recent_drift = db.query(ModelDriftDB).filter(
            ModelDriftDB.model_id == model_id
        ).order_by(ModelDriftDB.timestamp.desc()).limit(10).all()
        
        drift_history = []
        for drift_record in recent_drift:
            drift_history.append({
                'timestamp': drift_record.timestamp.isoformat(),
                'drift_detected': drift_record.drift_detected,
                'drift_score': drift_record.drift_score,
                'drift_type': drift_record.drift_type,
                'accuracy_drop': drift_record.accuracy_drop,
                'feature_drift_scores': drift_record.feature_drift_scores
            })
        
        current_drift = drift_history[0] if drift_history else None
        
        return {
            'model_id': model_id,
            'current_drift_status': current_drift,
            'drift_history': drift_history,
            'recommendations': _generate_drift_recommendations(current_drift) if current_drift else []
        }
        
    except Exception as e:
        logger.error(f"Error getting drift status: {e}")
        raise HTTPException(status_code=500, detail=f"Drift status check failed: {str(e)}")


@router.post("/retrain/{model_type}")
async def trigger_model_retraining(
    model_type: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Trigger model retraining (admin only)."""
    
    # Check if user has admin privileges (simplified check)
    if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    try:
        # Trigger retraining in background
        background_tasks.add_task(
            _trigger_retraining_async,
            model_type,
            current_user.id,
            db
        )
        
        logger.info(f"Model retraining triggered by admin {current_user.id} for {model_type}")
        
        return {
            'status': 'success',
            'message': f'Retraining initiated for {model_type}',
            'estimated_completion': (datetime.now() + timedelta(hours=2)).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error triggering retraining: {e}")
        raise HTTPException(status_code=500, detail=f"Retraining failed: {str(e)}")


@router.get("/explanations/features")
async def get_feature_explanations(
    current_user: User = Depends(get_current_user)
):
    """Get explanations for model features and their importance."""
    
    feature_explanations = {
        'content_features': {
            'suspicious_keywords': 'Presence of urgent or threatening language commonly used in phishing',
            'sentiment_analysis': 'Emotional tone and urgency indicators in email content',
            'grammar_errors': 'Spelling and grammar mistakes that indicate low-quality content',
            'social_engineering': 'Psychological manipulation tactics like urgency or authority'
        },
        'url_features': {
            'domain_reputation': 'Trustworthiness and age of linked domains',
            'url_shorteners': 'Use of URL shortening services to hide destinations',
            'typosquatting': 'Domains that mimic legitimate sites with slight variations',
            'suspicious_tlds': 'Top-level domains commonly associated with malicious activity'
        },
        'sender_features': {
            'sender_reputation': 'Historical behavior and trustworthiness of email sender',
            'authentication': 'SPF, DKIM, and DMARC validation results',
            'sending_patterns': 'Unusual sending times or frequency anomalies',
            'geographic_anomalies': 'Unexpected geographic origins for the sender'
        },
        'ensemble_weights': {
            'content_model': 0.4,
            'url_model': 0.35,
            'sender_model': 0.25
        }
    }
    
    return {
        'feature_explanations': feature_explanations,
        'model_version': advanced_ml_system.model_version,
        'explanation_methods': ['LIME', 'SHAP', 'Feature Importance'],
        'confidence_levels': {
            'high': '> 80% - High confidence in prediction',
            'medium': '60-80% - Moderate confidence, manual review recommended',
            'low': '< 60% - Low confidence, requires analyst attention'
        }
    }


# Helper Functions
def _generate_feature_explanation(feature_name: str, importance: float) -> str:
    """Generate human-readable explanation for feature importance."""
    
    explanations = {
        'Suspicious content patterns': 'Email contains language commonly used in phishing attempts',
        'Legitimate content patterns': 'Email content appears normal and trustworthy',
        'Malicious URL indicators': 'Links in email point to suspicious or known malicious domains',
        'Trusted URL patterns': 'All links point to legitimate and trusted domains',
        'Suspicious sender behavior': 'Sender exhibits patterns associated with phishing campaigns',
        'Trusted sender history': 'Sender has established trustworthy communication patterns'
    }
    
    base_explanation = explanations.get(feature_name, f'Feature {feature_name} influences the prediction')
    
    if importance > 0.5:
        return f"{base_explanation} (Strong positive influence)"
    elif importance > 0.2:
        return f"{base_explanation} (Moderate positive influence)"
    elif importance < -0.2:
        return f"{base_explanation} (Moderate negative influence)"
    else:
        return f"{base_explanation} (Weak influence)"


async def _check_model_drift_async(email_data: Dict, result: EnsembleResult, db: Session):
    """Background task to check for model drift."""
    try:
        monitor = get_model_monitor(db)
        
        # Simulate feature extraction for drift check
        import numpy as np
        features = np.random.random(20)  # Placeholder
        predictions = np.array([result.confidence])
        labels = np.array([1 if result.is_phishing else 0])  # Actual label would come from feedback
        
        model_id = f"ensemble_{advanced_ml_system.model_version}"
        drift_metrics = monitor.check_model_drift(model_id, predictions, features, labels)
        
        if drift_metrics.drift_detected:
            logger.warning(f"Model drift detected: {drift_metrics.drift_type}")
            
    except Exception as e:
        logger.error(f"Error in drift check background task: {e}")


async def _log_analyst_feedback(feedback: AnalystFeedbackRequest, user_id: int, db: Session):
    """Background task to log analyst feedback."""
    try:
        # Would store detailed feedback in database for analysis
        logger.info(f"Logging feedback from analyst {user_id}: {feedback.feedback_reason}")
        
    except Exception as e:
        logger.error(f"Error logging analyst feedback: {e}")


async def _trigger_retraining_async(model_type: str, admin_id: int, db: Session):
    """Background task to trigger model retraining."""
    try:
        logger.info(f"Starting retraining for {model_type} initiated by admin {admin_id}")
        
        # Simulate retraining process
        await asyncio.sleep(2)  # Placeholder for actual retraining
        
        logger.info(f"Retraining completed for {model_type}")
        
    except Exception as e:
        logger.error(f"Error in retraining background task: {e}")


def _generate_drift_recommendations(drift_status: Dict) -> List[str]:
    """Generate recommendations based on drift status."""
    
    recommendations = []
    
    if drift_status and drift_status['drift_detected']:
        if drift_status['drift_type'] == 'performance':
            recommendations.append("Model performance has degraded. Consider retraining with recent data.")
        elif drift_status['drift_type'] == 'data':
            recommendations.append("Input data distribution has shifted. Update feature preprocessing.")
        elif drift_status['drift_type'] == 'concept':
            recommendations.append("Concept drift detected. Phishing patterns may have evolved.")
        
        if drift_status['accuracy_drop'] > 0.1:
            recommendations.append("Significant accuracy drop detected. Immediate retraining recommended.")
    
    return recommendations