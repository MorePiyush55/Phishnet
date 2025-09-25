"""Email processing service for phishing detection."""

import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

from app.ml.feature_extraction import FeatureExtractor
from app.ml.classical_models import ModelManager
from app.models.core.email import Email
from app.models.analysis.detection import Detection
from app.schemas.email import EmailRequest, DetectionResult
from app.config.logging import get_logger
from app.config.settings import settings
from src.common.interfaces import IEmailProcessor, EmailContent, ProcessingStatus, BaseProcessor

logger = get_logger(__name__)


class EmailProcessor(BaseProcessor, IEmailProcessor):
    """Email processing service for phishing detection."""
    
    def __init__(self):
        """Initialize email processor."""
        super().__init__()  # Initialize BaseProcessor
        self.feature_extractor = FeatureExtractor()
        self.model_manager = ModelManager()
        self.is_initialized = False
        self._processing_status = {}  # Track email processing status
    
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
        user_id: int
    ) -> DetectionResult:
        """Analyze email for phishing detection."""
        start_time = time.time()
        
        try:
            # Extract features
            features = self.feature_extractor.extract_features(
                email_request.content,
                email_request.subject or "",
                email_request.sender or ""
            )
            
            # Convert to feature vector
            feature_vector = self.feature_extractor.get_feature_vector(features)
            
            # Make prediction
            if self.is_initialized and self.model_manager.current_model:
                prediction, confidence = self.model_manager.predict(feature_vector)
            else:
                # Fallback to rule-based detection
                prediction, confidence = self._rule_based_detection(features)
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Determine risk level
            risk_level = self._determine_risk_level(confidence)
            
            # Create content hash
            content_hash = hashlib.sha256(
                email_request.content.encode('utf-8')
            ).hexdigest()
            
            # Save email to database
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
            email = await email.save()
            
            # Save detection result
            detection = Detection(
                user_id=user_id,
                email_id=str(email.id),
                is_phishing=bool(prediction),
                confidence_score=confidence,
                risk_level=risk_level,
                model_version="1.0.0",
                model_type="ensemble" if self.is_initialized else "rule_based",
                features=features,
                risk_factors=self._identify_risk_factors(features),
                processing_time_ms=processing_time_ms
            )
            detection = await detection.save()
            
            logger.info(
                f"Email analysis completed",
                user_id=user_id,
                email_id=email.id,
                is_phishing=prediction,
                confidence=confidence,
                processing_time_ms=processing_time_ms
            )
            
            return DetectionResult(
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
            
        except Exception as e:
            logger.error(f"Email analysis failed: {e}")
            raise
    
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
        limit: int = 50,
        offset: int = 0
    ) -> List[DetectionResult]:
        """Get user's detection history."""
        detections = await Detection.find(
            Detection.user_id == user_id
        ).sort(-Detection.created_at).skip(offset).limit(limit).to_list()
        
        return [
            DetectionResult(
                detection_id=str(d.id),
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
    
    async def get_detection_stats(self, user_id: int) -> Dict[str, Any]:
        """Get detection statistics for user."""
        total_detections = await Detection.find(
            Detection.user_id == user_id
        ).count()
        
        phishing_detections = await Detection.find(
            Detection.user_id == user_id,
            Detection.is_phishing == True
        ).count()
        
        legitimate_detections = total_detections - phishing_detections
        
        # Calculate average confidence
        detections = await Detection.find(
            Detection.user_id == user_id
        ).to_list()
        
        avg_confidence = sum(d.confidence_score for d in detections) / len(detections) if detections else 0.0
        
        return {
            "total_detections": total_detections,
            "phishing_detections": phishing_detections,
            "legitimate_detections": legitimate_detections,
            "detection_rate": phishing_detections / total_detections if total_detections > 0 else 0,
            "average_confidence": avg_confidence
        }

    # Interface methods implementation
    
    async def process_email(self, email_content: EmailContent) -> Dict[str, Any]:
        """Process a single email and return analysis results."""
        try:
            email_key = hash(email_content.subject + email_content.sender)
            self._processing_status[email_key] = ProcessingStatus.IN_PROGRESS
            
            # Use feature extraction for interface compliance
            features = self.feature_extractor.extract_features(
                email_content.body_text,
                email_content.subject,
                email_content.sender
            )
            
            # Return simplified result
            result = {
                'features': features.__dict__ if hasattr(features, '__dict__') else features,
                'sender': email_content.sender,
                'subject': email_content.subject,
                'processed': True
            }
            
            self._processing_status[email_key] = ProcessingStatus.COMPLETED
            self._increment_stat("processed")
            return result
            
        except Exception as e:
            self._processing_status[hash(email_content.subject + email_content.sender)] = ProcessingStatus.FAILED
            self._increment_stat("errors")
            logger.error(f"Error processing email: {str(e)}")
            raise
    
    async def batch_process(self, emails: List[EmailContent]) -> List[Dict[str, Any]]:
        """Process multiple emails in batch."""
        results = []
        for email in emails:
            try:
                result = await self.process_email(email)
                results.append(result)
            except Exception as e:
                results.append({"error": str(e), "email": email.subject})
        return results
    
    def get_processing_status(self, email_id: int) -> ProcessingStatus:
        """Get the current processing status of an email."""
        return self._processing_status.get(email_id, ProcessingStatus.PENDING)
    
    async def extract_features(self, email_content: EmailContent) -> Dict[str, Any]:
        """Extract features from email for analysis."""
        if not self.is_initialized:
            await self.initialize()
        
        # Use the existing feature extractor
        return self.feature_extractor.extract_features(
            subject=email_content.subject,
            sender=email_content.sender, 
            body=email_content.body_text,
            html_content=email_content.body_html
        )


# Global email processor instance
email_processor = EmailProcessor()

