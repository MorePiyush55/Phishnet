"""Email processing service for phishing detection with performance optimization."""

import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import asyncio

from sqlalchemy.orm import Session
from sqlalchemy import and_, func

# Optional ML imports - graceful degradation if not available
try:
    from app.ml.feature_extraction import FeatureExtractor
    from app.ml.classical_models import ModelManager
    ML_AVAILABLE = True
except ImportError as e:
    print(f"ML dependencies not available: {e}")
    FeatureExtractor = None
    ModelManager = None
    ML_AVAILABLE = False

from app.models.core.email import Email
from app.models.analysis.detection import Detection
from app.schemas.email import EmailRequest, DetectionResult
from app.config.logging import get_logger
from app.config.settings import settings
from app.core.redis_client import get_cache_manager
from app.core.metrics import performance_metrics

logger = get_logger(__name__)


class EmailProcessor:
    """Email processing service for phishing detection with Redis caching and performance optimization."""
    
    def __init__(self):
        """Initialize email processor."""
        # Initialize ML components if available
        if ML_AVAILABLE:
            try:
                self.feature_extractor = FeatureExtractor()
                self.model_manager = ModelManager()
                logger.info("ML components initialized successfully in email_processor")
            except Exception as e:
                logger.error(f"Failed to initialize ML components in email_processor: {e}")
                self.feature_extractor = None
                self.model_manager = None
        else:
            logger.warning("ML dependencies not available - email_processor will use basic analysis")
            self.feature_extractor = None
            self.model_manager = None
            
        self.cache_manager = get_cache_manager()
        self.is_initialized = False
        
        # Performance tracking
        self.processed_count = 0
        self.cache_hits = 0
        self.cache_misses = 0
    
    async def initialize(self):
        """Initialize the processor and load models."""
        try:
            # Load pre-trained models
            self.model_manager.load_models(settings.MODEL_PATH)
            self.is_initialized = True
            logger.info("Email processor initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize email processor: {e}")
            # For development, we'll continue without pre-trained models
            self.is_initialized = True
    
    async def analyze_email(
        self, 
        email_request: EmailRequest, 
        user_id: int,
        db: Session
    ) -> DetectionResult:
        """Analyze email for phishing detection with caching and performance optimization."""
        start_time = time.time()
        
        try:
            # Create content hash for caching
            content_hash = hashlib.sha256(
                f"{email_request.content}{email_request.sender}{email_request.subject}".encode('utf-8')
            ).hexdigest()
            
            # Check cache first
            cache_key = f"email_analysis:{content_hash}"
            cached_result = await self.cache_manager.get(cache_key)
            
            if cached_result:
                self.cache_hits += 1
                logger.info("Cache hit for email analysis", cache_key=cache_key)
                
                # Update metrics
                performance_metrics.emails_processed.inc()
                performance_metrics.cache_hits.inc()
                
                return DetectionResult(**cached_result)
            
            self.cache_misses += 1
            performance_metrics.cache_misses.inc()
            
            # Extract features
            features = self.feature_extractor.extract_features(
                email_request.content,
                email_request.subject or "",
                email_request.sender or ""
            )
            
            # Check if we've seen similar patterns (batch processing optimization)
            similar_analysis = await self._check_similar_patterns(features, db)
            if similar_analysis:
                prediction, confidence = similar_analysis
                logger.info("Using similar pattern analysis")
            else:
                # Convert to feature vector
                feature_vector = self.feature_extractor.get_feature_vector(features)
                
                # Make prediction with ensemble model
                prediction, confidence = await self._ensemble_prediction(feature_vector, features)
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Determine risk level
            risk_level = self._determine_risk_level(confidence)
            
            # Batch database operations for performance
            email, detection = await self._save_analysis_batch(
                email_request, user_id, content_hash, features, 
                prediction, confidence, risk_level, processing_time_ms, db
            )
            
            result = DetectionResult(
                detection_id=detection.id,
                is_phishing=detection.is_phishing,
                confidence_score=detection.confidence_score,
                risk_level=detection.risk_level,
                model_version=detection.model_version,
                model_type=detection.model_type,
                features=detection.features,
                risk_factors=detection.risk_factors,
                processing_time_ms=detection.processing_time_ms,
                created_at=detection.created_at
            )
            
            # Cache the result (TTL: 1 hour for email analysis)
            await self.cache_manager.set(cache_key, result.dict(), ttl=3600)
            
            # Update performance metrics
            self.processed_count += 1
            performance_metrics.emails_processed.inc()
            performance_metrics.processing_time.observe(processing_time_ms / 1000)
            
            logger.info(
                f"Email analysis completed",
                user_id=user_id,
                email_id=email.id,
                is_phishing=prediction,
                confidence=confidence,
                processing_time_ms=processing_time_ms,
                cache_hit_ratio=self.cache_hits / (self.cache_hits + self.cache_misses)
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Email analysis failed: {e}")
            performance_metrics.analysis_errors.inc()
            raise
    
    async def _ensemble_prediction(self, feature_vector: List[float], features: Dict[str, Any]) -> Tuple[int, float]:
        """Enhanced ensemble prediction combining multiple models with adaptive weighting."""
        
        # Get cached model weights or use defaults
        weights_key = "ensemble_weights"
        cached_weights = await self.cache_manager.get(weights_key)
        
        if cached_weights:
            weights = cached_weights
        else:
            # Default weights - will be adapted based on historical accuracy
            weights = {
                "ml_model": 0.4,
                "rule_based": 0.3,
                "llm_analysis": 0.3
            }
        
        predictions = {}
        confidences = {}
        
        # ML Model prediction
        if self.is_initialized and self.model_manager.current_model:
            ml_pred, ml_conf = self.model_manager.predict(feature_vector)
            predictions["ml_model"] = ml_pred
            confidences["ml_model"] = ml_conf
        else:
            predictions["ml_model"] = 0
            confidences["ml_model"] = 0.5
        
        # Rule-based prediction
        rule_pred, rule_conf = self._rule_based_detection(features)
        predictions["rule_based"] = rule_pred
        confidences["rule_based"] = rule_conf
        
        # LLM-based analysis (simplified for now - would integrate with OpenAI/Anthropic)
        llm_pred, llm_conf = await self._llm_analysis(features)
        predictions["llm_analysis"] = llm_pred
        confidences["llm_analysis"] = llm_conf
        
        # Weighted ensemble
        final_confidence = sum(weights[model] * confidences[model] for model in weights.keys())
        final_prediction = 1 if final_confidence > 0.5 else 0
        
        # Update model weights based on recent performance (adaptive learning)
        asyncio.create_task(self._update_model_weights(weights, predictions, confidences))
        
        return final_prediction, final_confidence
    
    async def _llm_analysis(self, features: Dict[str, Any]) -> Tuple[int, float]:
        """LLM-based phishing analysis (simplified implementation)."""
        
        # Check cache for similar content analysis
        content_key = f"llm_analysis:{features.get('content_hash', 'unknown')}"
        cached_llm = await self.cache_manager.get(content_key)
        
        if cached_llm:
            return cached_llm["prediction"], cached_llm["confidence"]
        
        # Simplified LLM analysis based on features
        # In production, this would use OpenAI API or similar
        score = 0.0
        
        if features.get('urgent_language_count', 0) > 2:
            score += 0.3
        if features.get('suspicious_links', 0) > 0:
            score += 0.4
        if features.get('grammar_errors', 0) > 3:
            score += 0.2
        if features.get('sender_spoofing_indicators', 0) > 0:
            score += 0.3
        
        prediction = 1 if score > 0.5 else 0
        confidence = min(score, 1.0)
        
        # Cache LLM analysis (TTL: 24 hours)
        await self.cache_manager.set(content_key, {
            "prediction": prediction,
            "confidence": confidence
        }, ttl=86400)
        
        return prediction, confidence
    
    async def _check_similar_patterns(self, features: Dict[str, Any], db: Session) -> Optional[Tuple[int, float]]:
        """Check for similar email patterns to optimize processing."""
        from datetime import timedelta
        
        # Create pattern signature
        pattern_key = self._create_pattern_signature(features)
        cache_key = f"pattern_analysis:{pattern_key}"
        
        cached_pattern = await self.cache_manager.get(cache_key)
        if cached_pattern:
            return cached_pattern["prediction"], cached_pattern["confidence"]
        
        # Query recent similar detections (optimized with indexes)
        similar_detections = db.query(Detection).filter(
            and_(
                Detection.created_at >= datetime.utcnow() - timedelta(days=7),
                func.json_extract(Detection.features, '$.sender_domain') == features.get('sender_domain'),
                func.json_extract(Detection.features, '$.url_count') == features.get('url_count')
            )
        ).limit(10).all()
        
        if len(similar_detections) >= 3:
            # Use average of similar detections
            avg_prediction = sum(d.is_phishing for d in similar_detections) / len(similar_detections)
            avg_confidence = sum(d.confidence_score for d in similar_detections) / len(similar_detections)
            
            prediction = 1 if avg_prediction > 0.5 else 0
            
            # Cache pattern analysis (TTL: 1 hour)
            await self.cache_manager.set(cache_key, {
                "prediction": prediction,
                "confidence": avg_confidence
            }, ttl=3600)
            
            return prediction, avg_confidence
        
        return None
    
    def _create_pattern_signature(self, features: Dict[str, Any]) -> str:
        """Create a signature for email patterns."""
        signature_data = {
            "sender_domain": features.get('sender_domain', ''),
            "url_count": features.get('url_count', 0),
            "attachment_count": features.get('attachment_count', 0),
            "urgent_language": bool(features.get('urgent_language_count', 0) > 0)
        }
        return hashlib.md5(str(signature_data).encode()).hexdigest()
    
    async def _save_analysis_batch(
        self, email_request: EmailRequest, user_id: int, content_hash: str,
        features: Dict[str, Any], prediction: int, confidence: float,
        risk_level: str, processing_time_ms: int, db: Session
    ) -> Tuple[Email, Detection]:
        """Batch save email and detection for performance."""
        
        # Create email record
        email = Email(
            user_id=user_id,
            subject=email_request.subject,
            sender=email_request.sender or "unknown",
            recipients=",".join(email_request.recipients or []),
            content_hash=content_hash,
            content=email_request.content,
            content_type=email_request.content_type,
            size_bytes=len(email_request.content.encode('utf-8'))
        )
        
        # Create detection record
        detection = Detection(
            user_id=user_id,
            email_id=None,  # Will be set after email is saved
            is_phishing=bool(prediction),
            confidence_score=confidence,
            risk_level=risk_level,
            model_version="2.0.0",
            model_type="ensemble_optimized",
            features=features,
            risk_factors=self._identify_risk_factors(features),
            processing_time_ms=processing_time_ms
        )
        
        # Batch save with single commit
        db.add(email)
        db.flush()  # Get email.id without committing
        detection.email_id = email.id
        db.add(detection)
        db.commit()
        
        # Refresh to get final state
        db.refresh(email)
        db.refresh(detection)
        
        return email, detection
    
    async def _update_model_weights(self, current_weights: Dict[str, float], 
                                  predictions: Dict[str, int], confidences: Dict[str, float]):
        """Update ensemble model weights based on performance (simplified adaptive learning)."""
        
        # This would typically analyze recent accuracy metrics
        # For now, we'll use a simple approach
        
        # Get recent performance metrics from cache
        perf_key = "model_performance_24h"
        recent_performance = await self.cache_manager.get(perf_key)
        
        if not recent_performance:
            recent_performance = {
                "ml_model": {"accuracy": 0.85, "samples": 100},
                "rule_based": {"accuracy": 0.75, "samples": 100},
                "llm_analysis": {"accuracy": 0.90, "samples": 100}
            }
        
        # Adjust weights based on performance
        total_accuracy = sum(perf["accuracy"] for perf in recent_performance.values())
        
        updated_weights = {}
        for model in current_weights.keys():
            if model in recent_performance:
                updated_weights[model] = recent_performance[model]["accuracy"] / total_accuracy
            else:
                updated_weights[model] = current_weights[model]
        
        # Cache updated weights (TTL: 1 hour)
        await self.cache_manager.set("ensemble_weights", updated_weights, ttl=3600)
        
        logger.info(f"Updated ensemble weights", weights=updated_weights)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics."""
        total_requests = self.cache_hits + self.cache_misses
        cache_hit_ratio = self.cache_hits / total_requests if total_requests > 0 else 0
        
        return {
            "processed_count": self.processed_count,
            "cache_hit_ratio": cache_hit_ratio,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "total_requests": total_requests
        }
    
    def _rule_based_detection(self, features: Dict[str, Any]) -> Tuple[int, float]:
        """Rule-based phishing detection as fallback."""
        score = 0.0
        
        # Suspicious keywords
        if features.get('suspicious_keyword_count', 0) > 0:
            score += 0.3
        
        # URL-based features
        if features.get('shortened_url_count', 0) > 0:
            score += 0.2
        if features.get('redirect_url_count', 0) > 0:
            score += 0.2
        
        # Content features
        if features.get('has_javascript', False):
            score += 0.1
        if features.get('has_forms', False):
            score += 0.1
        
        # Sender features
        if not features.get('valid_sender_format', True):
            score += 0.2
        
        # Normalize score
        confidence = min(score, 1.0)
        prediction = 1 if confidence > 0.5 else 0
        
        return prediction, confidence
    
    def _determine_risk_level(self, confidence: float) -> str:
        """Determine risk level based on confidence score."""
        if confidence >= 0.8:
            return "CRITICAL"
        elif confidence >= 0.6:
            return "HIGH"
        elif confidence >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _identify_risk_factors(self, features: Dict[str, Any]) -> List[str]:
        """Identify specific risk factors from features."""
        risk_factors = []
        
        if features.get('suspicious_keyword_count', 0) > 0:
            risk_factors.append("Suspicious keywords detected")
        
        if features.get('shortened_url_count', 0) > 0:
            risk_factors.append("Shortened URLs present")
        
        if features.get('redirect_url_count', 0) > 0:
            risk_factors.append("Redirect URLs detected")
        
        if features.get('has_javascript', False):
            risk_factors.append("JavaScript code present")
        
        if features.get('has_forms', False):
            risk_factors.append("HTML forms detected")
        
        if not features.get('valid_sender_format', True):
            risk_factors.append("Invalid sender email format")
        
        if features.get('uppercase_ratio', 0) > 0.3:
            risk_factors.append("Excessive use of uppercase letters")
        
        if features.get('external_link_count', 0) > 5:
            risk_factors.append("Multiple external links")
        
        return risk_factors
    
    async def get_detection_history(
        self, 
        user_id: int, 
        db: Session,
        limit: int = 50,
        offset: int = 0
    ) -> List[DetectionResult]:
        """Get user's detection history."""
        detections = db.query(Detection).filter(
            Detection.user_id == user_id
        ).order_by(
            Detection.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        return [
            DetectionResult(
                detection_id=d.id,
                is_phishing=d.is_phishing,
                confidence_score=d.confidence_score,
                risk_level=d.risk_level,
                model_version=d.model_version,
                model_type=d.model_type,
                features=d.features,
                risk_factors=d.risk_factors,
                processing_time_ms=d.processing_time_ms,
                created_at=d.created_at
            )
            for d in detections
        ]
    
    async def get_detection_stats(self, user_id: int, db: Session) -> Dict[str, Any]:
        """Get detection statistics for user."""
        total_detections = db.query(Detection).filter(
            Detection.user_id == user_id
        ).count()
        
        phishing_detections = db.query(Detection).filter(
            Detection.user_id == user_id,
            Detection.is_phishing == True
        ).count()
        
        legitimate_detections = total_detections - phishing_detections
        
        # Calculate average confidence
        avg_confidence = db.query(Detection.confidence_score).filter(
            Detection.user_id == user_id
        ).scalar()
        
        return {
            "total_detections": total_detections,
            "phishing_detections": phishing_detections,
            "legitimate_detections": legitimate_detections,
            "detection_rate": phishing_detections / total_detections if total_detections > 0 else 0,
            "average_confidence": float(avg_confidence) if avg_confidence else 0.0
        }


# Global email processor instance
email_processor = EmailProcessor()

