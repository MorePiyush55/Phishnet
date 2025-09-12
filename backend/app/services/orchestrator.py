"""Email processing orchestrator - single source of truth pipeline."""

import asyncio
from datetime import datetime
from typing import Dict, Any, Optional
import json

from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.email import Email, EmailStatus
from app.models.detection import Detection
from src.common.constants import ThreatLevel
from app.services.sanitizer import content_sanitizer
from app.services.analyzers.ai import ai_analyzer
from app.services.analyzers.url_chain import url_analyzer
from app.services.analyzers.intel import intel_service
from app.services.response import response_service
from app.services.ws import websocket_manager
from app.config.logging import get_logger

logger = get_logger(__name__)


class EmailOrchestrator:
    """Orchestrates the complete email analysis pipeline."""
    
    def __init__(self):
        """Initialize orchestrator."""
        self.processing_queue = asyncio.Queue()
        self.is_running = False
    
    async def start(self):
        """Start the orchestrator background task."""
        if self.is_running:
            return
        
        self.is_running = True
        asyncio.create_task(self._process_queue())
        logger.info("Email orchestrator started")
    
    async def stop(self):
        """Stop the orchestrator."""
        self.is_running = False
        logger.info("Email orchestrator stopped")
    
    async def process_email(self, email_id: int):
        """Add email to processing queue."""
        await self.processing_queue.put(email_id)
        logger.debug(f"Email {email_id} added to processing queue")
    
    async def _process_queue(self):
        """Process emails from the queue."""
        while self.is_running:
            try:
                # Get next email ID with timeout
                email_id = await asyncio.wait_for(
                    self.processing_queue.get(), 
                    timeout=1.0
                )
                
                # Process the email
                await self._process_single_email(email_id)
                
            except asyncio.TimeoutError:
                # No emails to process, continue
                continue
            except Exception as e:
                logger.error(f"Error in processing queue: {e}")
                await asyncio.sleep(1)
    
    async def _process_single_email(self, email_id: int):
        """Process a single email through the complete pipeline."""
        with next(get_db()) as db:
            try:
                # Get email record
                email = db.query(Email).filter(Email.id == email_id).first()
                if not email:
                    logger.error(f"Email {email_id} not found")
                    return
                
                logger.info(f"Processing email {email_id} from {email.sender}")
                
                # Update status to processing
                email.status = EmailStatus.PROCESSING
                db.commit()
                
                # Step 1: Content Sanitization
                await self._sanitize_content(email, db)
                
                # Step 2: URL Analysis
                url_analysis = await self._analyze_urls(email)
                
                # Step 3: AI Analysis
                ai_analysis = await self._ai_analysis(email)
                
                # Step 4: Threat Intelligence
                intel_analysis = await self._intel_analysis(email)
                
                # Step 5: Combine Analysis Results
                final_detection = await self._combine_analysis_results(
                    email, url_analysis, ai_analysis, intel_analysis, db
                )
                
                # Step 6: Response Actions
                await self._execute_response_actions(email, final_detection, db)
                
                # Step 7: Real-time Notifications
                await self._send_notifications(email, final_detection)
                
                # Update final status
                email.status = EmailStatus.ANALYZED
                email.analyzed_at = datetime.utcnow()
                email.score = final_detection.confidence_score
                db.commit()
                
                logger.info(
                    f"Email {email_id} processing complete. "
                    f"Phishing: {final_detection.is_phishing}, "
                    f"Score: {final_detection.confidence_score:.3f}"
                )
                
            except Exception as e:
                logger.error(f"Failed to process email {email_id}: {e}")
                
                # Update status to error
                email.status = EmailStatus.ERROR
                db.commit()
    
    async def _sanitize_content(self, email: Email, db: Session):
        """Step 1: Sanitize email content."""
        try:
            if email.raw_html:
                # Sanitize HTML content
                email.sanitized_html = content_sanitizer.sanitize_html(email.raw_html)
            
            # Sanitize text content
            if email.raw_text:
                email.raw_text = content_sanitizer.sanitize_text(email.raw_text)
            
            db.commit()
            logger.debug(f"Content sanitized for email {email.id}")
            
        except Exception as e:
            logger.error(f"Content sanitization failed for email {email.id}: {e}")
            raise
    
    async def _analyze_urls(self, email: Email) -> Dict[str, Any]:
        """Step 2: Analyze URLs in email content."""
        try:
            content = email.raw_text or email.raw_html or ""
            
            # Extract URLs
            urls = content_sanitizer.extract_urls(content)
            
            if not urls:
                return {"urls": [], "risk_score": 0.0, "threats": []}
            
            # Analyze each URL
            url_results = []
            total_risk = 0.0
            threats = []
            
            for url_info in urls[:10]:  # Limit to 10 URLs to avoid quota issues
                try:
                    analysis = await url_analyzer.analyze_url(url_info['url'])
                    url_results.append(analysis)
                    total_risk += analysis.get('risk_score', 0.0)
                    
                    if analysis.get('is_malicious'):
                        threats.append(analysis)
                        
                except Exception as e:
                    logger.error(f"URL analysis failed for {url_info['url']}: {e}")
            
            avg_risk = total_risk / len(url_results) if url_results else 0.0
            
            return {
                "urls": url_results,
                "risk_score": avg_risk,
                "threats": threats,
                "total_urls": len(urls)
            }
            
        except Exception as e:
            logger.error(f"URL analysis failed for email {email.id}: {e}")
            return {"urls": [], "risk_score": 0.0, "threats": []}
    
    async def _ai_analysis(self, email: Email) -> Dict[str, Any]:
        """Step 3: AI-based phishing analysis."""
        try:
            # Prepare content for AI analysis
            content = email.raw_text or email.raw_html or ""
            
            # Analyze with AI
            analysis = await ai_analyzer.analyze_email_content(
                subject=email.subject or "",
                content=content,
                sender=email.sender,
                headers=json.loads(email.raw_headers or "{}")
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed for email {email.id}: {e}")
            return {
                "phishing_probability": 0.0,
                "confidence": 0.0,
                "indicators": [],
                "explanation": "AI analysis failed"
            }
    
    async def _intel_analysis(self, email: Email) -> Dict[str, Any]:
        """Step 4: Threat intelligence analysis."""
        try:
            # Extract sender domain
            sender_domain = email.sender.split('@')[-1] if '@' in email.sender else ""
            
            # Get intel on sender domain
            domain_intel = await intel_service.check_domain(sender_domain)
            
            # Get intel on URLs (if any)
            content = email.raw_text or email.raw_html or ""
            urls = content_sanitizer.extract_urls(content)
            
            url_intel = []
            for url_info in urls[:5]:  # Limit to avoid quota
                try:
                    intel = await intel_service.check_url(url_info['url'])
                    url_intel.append(intel)
                except Exception as e:
                    logger.error(f"Intel check failed for URL {url_info['url']}: {e}")
            
            return {
                "domain_intel": domain_intel,
                "url_intel": url_intel,
                "risk_indicators": self._extract_intel_indicators(domain_intel, url_intel)
            }
            
        except Exception as e:
            logger.error(f"Threat intel analysis failed for email {email.id}: {e}")
            return {
                "domain_intel": {},
                "url_intel": [],
                "risk_indicators": []
            }
    
    def _extract_intel_indicators(self, domain_intel: Dict, url_intel: List[Dict]) -> List[str]:
        """Extract risk indicators from threat intelligence."""
        indicators = []
        
        # Check domain reputation
        if domain_intel.get('is_malicious'):
            indicators.append("Sender domain flagged as malicious")
        
        if domain_intel.get('reputation_score', 0) < 30:
            indicators.append("Sender domain has poor reputation")
        
        # Check URL reputation
        for url_info in url_intel:
            if url_info.get('is_malicious'):
                indicators.append(f"Malicious URL detected: {url_info.get('url', '')}")
        
        return indicators
    
    async def _combine_analysis_results(
        self, 
        email: Email, 
        url_analysis: Dict[str, Any],
        ai_analysis: Dict[str, Any], 
        intel_analysis: Dict[str, Any],
        db: Session
    ) -> Detection:
        """Step 5: Combine all analysis results into final detection."""
        try:
            # Calculate combined confidence score
            url_score = url_analysis.get('risk_score', 0.0)
            ai_score = ai_analysis.get('phishing_probability', 0.0)
            
            # Weight the scores
            combined_score = (
                url_score * 0.3 +  # URL analysis weight
                ai_score * 0.6 +   # AI analysis weight (highest)
                (1.0 if intel_analysis.get('risk_indicators') else 0.0) * 0.1  # Intel weight
            )
            
            # Determine if phishing
            is_phishing = combined_score > 0.7
            
            # Determine threat level
            if combined_score >= 0.9:
                threat_level = ThreatLevel.CRITICAL
            elif combined_score >= 0.7:
                threat_level = ThreatLevel.HIGH
            elif combined_score >= 0.4:
                threat_level = ThreatLevel.MEDIUM
            elif combined_score >= 0.2:
                threat_level = ThreatLevel.LOW
            else:
                threat_level = ThreatLevel.SAFE
            
            # Combine indicators
            all_indicators = []
            all_indicators.extend(ai_analysis.get('indicators', []))
            all_indicators.extend(intel_analysis.get('risk_indicators', []))
            
            if url_analysis.get('threats'):
                all_indicators.append(f"Malicious URLs detected: {len(url_analysis['threats'])}")
            
            # Create detection record
            detection = Detection(
                email_id=email.id,
                user_id=email.user_id,
                is_phishing=is_phishing,
                confidence_score=combined_score,
                threat_level=threat_level,
                indicators=json.dumps(all_indicators),
                model_version="orchestrator_v1.0",
                analysis_metadata=json.dumps({
                    "url_analysis": url_analysis,
                    "ai_analysis": ai_analysis,
                    "intel_analysis": intel_analysis
                })
            )
            
            db.add(detection)
            db.commit()
            db.refresh(detection)
            
            return detection
            
        except Exception as e:
            logger.error(f"Failed to combine analysis results: {e}")
            raise
    
    async def _execute_response_actions(self, email: Email, detection: Detection, db: Session):
        """Step 6: Execute response actions based on detection."""
        try:
            if detection.is_phishing:
                # Execute automated response
                await response_service.handle_phishing_detection(email, detection)
                
                # Update email status
                if detection.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    email.status = EmailStatus.QUARANTINED
                
                logger.warning(
                    f"Phishing email detected and quarantined: {email.id}",
                    extra={
                        "email_id": email.id,
                        "sender": email.sender,
                        "confidence": detection.confidence_score,
                        "threat_level": detection.threat_level.value
                    }
                )
            else:
                email.status = EmailStatus.SAFE
            
            db.commit()
            
        except Exception as e:
            logger.error(f"Response action execution failed: {e}")
    
    async def _send_notifications(self, email: Email, detection: Detection):
        """Step 7: Send real-time notifications."""
        try:
            if detection.is_phishing:
                # Send WebSocket notification
                await websocket_manager.send_phishing_alert(
                    email.user_id,
                    {
                        "email_id": email.id,
                        "sender": email.sender,
                        "subject": email.subject,
                        "confidence_score": detection.confidence_score,
                        "threat_level": detection.threat_level.value,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                )
            
        except Exception as e:
            logger.error(f"Notification sending failed: {e}")


# Global orchestrator instance
email_orchestrator = EmailOrchestrator()
