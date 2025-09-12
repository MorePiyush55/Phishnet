"""Enhanced email analysis orchestrator integrating all analysis services."""

import asyncio
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import json

from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.config.logging import get_logger
from app.core.database import SessionLocal
from app.models.core.email import Email, EmailStatus
from app.models.analysis.detection import Detection
from app.models.analysis.link_analysis import LinkAnalysis, EmailAIResults, EmailIndicators
from app.services.sanitizer import ContentSanitizer
from app.services.link_analyzer import analyze_email_links
from app.services.ai_analyzer import analyze_email_with_ai
from app.services.threat_intel import analyze_email_threat_intel
from app.schemas.analysis import EmailAnalysisSummary

logger = get_logger(__name__)


class EnhancedEmailOrchestrator:
    """Enhanced orchestrator for comprehensive email analysis."""
    
    def __init__(self):
        self.sanitizer = ContentSanitizer()
        
        # Analysis weights for final score calculation
        self.analysis_weights = {
            'content_sanitization': 0.2,
            'link_analysis': 0.3,
            'ai_analysis': 0.3,
            'threat_intelligence': 0.2
        }
        
        # Risk thresholds
        self.risk_thresholds = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'critical': 0.9
        }
    
    async def process_email_comprehensive(self, email_id: int) -> EmailAnalysisSummary:
        """Perform comprehensive analysis of an email."""
        start_time = time.time()
        
        db = SessionLocal()
        try:
            # Get email from database
            email = db.query(Email).filter(Email.id == email_id).first()
            if not email:
                raise ValueError(f"Email {email_id} not found")
            
            # Update status to processing
            email.status = EmailStatus.PROCESSING
            db.commit()
            
            logger.info(f"Starting comprehensive analysis for email {email_id}")
            
            # Step 1: Content sanitization and URL extraction
            sanitization_results = await self._perform_content_sanitization(email, db)
            
            # Step 2: Link redirection analysis (parallel)
            link_analysis_task = self._perform_link_analysis(email, sanitization_results.get('urls', []))
            
            # Step 3: AI content analysis (parallel)
            ai_analysis_task = self._perform_ai_analysis(email, sanitization_results)
            
            # Step 4: Threat intelligence analysis (parallel)
            threat_intel_task = self._perform_threat_intelligence_analysis(email, sanitization_results)
            
            # Wait for all parallel analyses to complete
            link_results, ai_results, threat_results = await asyncio.gather(
                link_analysis_task,
                ai_analysis_task,
                threat_intel_task,
                return_exceptions=True
            )
            
            # Handle any exceptions
            if isinstance(link_results, Exception):
                logger.error(f"Link analysis failed: {link_results}")
                link_results = []
            
            if isinstance(ai_results, Exception):
                logger.error(f"AI analysis failed: {ai_results}")
                ai_results = None
            
            if isinstance(threat_results, Exception):
                logger.error(f"Threat intel analysis failed: {threat_results}")
                threat_results = []
            
            # Step 5: Combine all results and calculate final score
            analysis_summary = await self._combine_analysis_results(
                email, sanitization_results, link_results, ai_results, threat_results, db
            )
            
            # Step 6: Update email status and final score
            email.score = analysis_summary.overall_risk_score
            email.status = EmailStatus.ANALYZED if analysis_summary.overall_risk_score < 0.7 else EmailStatus.QUARANTINED
            email.analyzed_at = datetime.utcnow()
            
            # Create detection record
            detection = Detection(
                email_id=email_id,
                model_name="enhanced_orchestrator",
                confidence=analysis_summary.overall_risk_score,
                is_phishing=analysis_summary.overall_risk_score > 0.6,
                details={
                    'analysis_summary': analysis_summary.dict(),
                    'risk_factors': analysis_summary.risk_factors,
                    'recommendations': analysis_summary.recommendations
                }
            )
            db.add(detection)
            db.commit()
            
            analysis_summary.analysis_duration = time.time() - start_time
            analysis_summary.analysis_status = "completed"
            
            logger.info(f"Comprehensive analysis completed for email {email_id} in {analysis_summary.analysis_duration:.2f}s")
            
            return analysis_summary
            
        except Exception as e:
            logger.error(f"Email analysis failed for email {email_id}: {str(e)}")
            
            # Update email status to error
            if 'email' in locals():
                email.status = EmailStatus.ERROR
                db.commit()
            
            # Return error summary
            return EmailAnalysisSummary(
                email_id=email_id,
                overall_risk_score=0.5,  # Neutral score for errors
                risk_level="unknown",
                analysis_status="failed",
                risk_factors=[f"Analysis failed: {str(e)}"],
                recommendations=["Manual review required due to analysis failure"],
                analysis_duration=time.time() - start_time
            )
        
        finally:
            db.close()
    
    async def _perform_content_sanitization(self, email: Email, db: Session) -> Dict[str, Any]:
        """Perform content sanitization and extract metadata."""
        try:
            # Sanitize HTML content
            if email.raw_html:
                sanitized_html = self.sanitizer.sanitize_html(email.raw_html)
                email.sanitized_html = sanitized_html
            
            # Extract URLs from content
            content_to_analyze = f"{email.raw_html or ''} {email.raw_text or ''}"
            urls = self.sanitizer.extract_urls(content_to_analyze)
            
            # Extract domains
            domains = []
            for url in urls:
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(url).netloc.lower()
                    if domain:
                        domains.append(domain)
                except:
                    continue
            
            # Security analysis
            security_issues = []
            if email.raw_html:
                if '<script' in email.raw_html.lower():
                    security_issues.append("Contains JavaScript")
                if 'javascript:' in email.raw_html.lower():
                    security_issues.append("Contains JavaScript URLs")
                if any(event in email.raw_html.lower() for event in ['onclick', 'onload', 'onerror']):
                    security_issues.append("Contains event handlers")
            
            db.commit()
            
            return {
                'urls': urls,
                'domains': list(set(domains)),
                'security_issues': security_issues,
                'sanitized_successfully': email.sanitized_html is not None
            }
            
        except Exception as e:
            logger.error(f"Content sanitization failed: {str(e)}")
            return {
                'urls': [],
                'domains': [],
                'security_issues': [f"Sanitization failed: {str(e)}"],
                'sanitized_successfully': False
            }
    
    async def _perform_link_analysis(self, email: Email, urls: List[str]) -> List[LinkAnalysis]:
        """Perform link redirection analysis."""
        try:
            if not urls:
                return []
            
            # Limit to first 10 URLs to avoid excessive processing
            limited_urls = urls[:10]
            
            # Analyze each URL
            results = await analyze_email_links(email.id, limited_urls)
            
            logger.info(f"Analyzed {len(results)} links for email {email.id}")
            return results
            
        except Exception as e:
            logger.error(f"Link analysis failed for email {email.id}: {str(e)}")
            return []
    
    async def _perform_ai_analysis(self, email: Email, sanitization_results: Dict[str, Any]) -> Optional[EmailAIResults]:
        """Perform AI content analysis."""
        try:
            # Prepare content for AI analysis
            content_text = email.raw_text or ""
            if not content_text and email.sanitized_html:
                # Extract text from HTML if no plain text available
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(email.sanitized_html, 'html.parser')
                content_text = soup.get_text()
            
            if len(content_text.strip()) < 10:
                logger.warning(f"Email {email.id} has insufficient content for AI analysis")
                return None
            
            # Perform AI analysis
            result = await analyze_email_with_ai(
                email_id=email.id,
                subject=email.subject or "",
                sender=email.sender,
                content_text=content_text,
                content_html=email.sanitized_html,
                link_domains=sanitization_results.get('domains', [])
            )
            
            logger.info(f"AI analysis completed for email {email.id}")
            return result
            
        except Exception as e:
            logger.error(f"AI analysis failed for email {email.id}: {str(e)}")
            return None
    
    async def _perform_threat_intelligence_analysis(self, email: Email, sanitization_results: Dict[str, Any]) -> List[EmailIndicators]:
        """Perform threat intelligence analysis."""
        try:
            # Combine all content for indicator extraction
            content = f"{email.raw_html or ''} {email.raw_text or ''}"
            headers = email.raw_headers or ""
            
            # Analyze threat intelligence
            results = await analyze_email_threat_intel(
                email_id=email.id,
                content=content,
                headers=headers
            )
            
            logger.info(f"Threat intelligence analysis completed for email {email.id}")
            return results
            
        except Exception as e:
            logger.error(f"Threat intelligence analysis failed for email {email.id}: {str(e)}")
            return []
    
    async def _combine_analysis_results(self, email: Email, sanitization_results: Dict[str, Any],
                                      link_results: List[LinkAnalysis], ai_results: Optional[EmailAIResults],
                                      threat_results: List[EmailIndicators], db: Session) -> EmailAnalysisSummary:
        """Combine all analysis results into a comprehensive summary."""
        
        # Calculate component scores
        sanitization_score = self._calculate_sanitization_score(sanitization_results)
        link_score = self._calculate_link_score(link_results)
        ai_score = ai_results.ai_score if ai_results else 0.5  # Neutral score if no AI analysis
        threat_score = self._calculate_threat_score(threat_results)
        
        # Calculate weighted overall score
        overall_score = (
            sanitization_score * self.analysis_weights['content_sanitization'] +
            link_score * self.analysis_weights['link_analysis'] +
            ai_score * self.analysis_weights['ai_analysis'] +
            threat_score * self.analysis_weights['threat_intelligence']
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)
        
        # Collect risk factors and recommendations
        risk_factors = []
        recommendations = []
        
        # Add sanitization risks
        if sanitization_results.get('security_issues'):
            risk_factors.extend(sanitization_results['security_issues'])
            recommendations.append("Content contains potentially dangerous elements")
        
        # Add link analysis risks
        high_risk_links = [link for link in link_results if link.risk_score > 0.7]
        if high_risk_links:
            risk_factors.append(f"Contains {len(high_risk_links)} high-risk links")
            recommendations.append("Review suspicious links before clicking")
        
        # Add AI analysis insights
        if ai_results and ai_results.ai_score > 0.6:
            risk_factors.append(f"AI detected phishing indicators: {ai_results.summary}")
            recommendations.append("High probability of phishing - exercise caution")
        
        # Add threat intelligence risks
        malicious_indicators = [indicator for indicator in threat_results if indicator.reputation_score > 0.7]
        if malicious_indicators:
            risk_factors.append(f"Contains {len(malicious_indicators)} known malicious indicators")
            recommendations.append("Contains known threats - avoid interaction")
        
        # Count statistics
        total_links = len(link_results)
        suspicious_links = len([link for link in link_results if link.risk_score > 0.5])
        malicious_indicator_count = len(malicious_indicators)
        
        # Create summary
        summary = EmailAnalysisSummary(
            email_id=email.id,
            overall_risk_score=overall_score,
            risk_level=risk_level,
            analysis_status="completed",
            ai_analysis=ai_results,
            total_links=total_links,
            suspicious_links=suspicious_links,
            malicious_indicators=malicious_indicator_count,
            risk_factors=risk_factors,
            recommendations=recommendations
        )
        
        # Add link and threat intel results to summary (convert to response models)
        try:
            from app.schemas.analysis import LinkAnalysisResponse, EmailIndicatorsResponse
            
            summary.link_analysis = [
                LinkAnalysisResponse.from_orm(link) for link in link_results
            ]
            summary.threat_intel = [
                EmailIndicatorsResponse.from_orm(indicator) for indicator in threat_results
            ]
        except Exception as e:
            logger.warning(f"Failed to convert analysis results to response models: {str(e)}")
        
        return summary
    
    def _calculate_sanitization_score(self, results: Dict[str, Any]) -> float:
        """Calculate risk score from sanitization results."""
        score = 0.0
        
        security_issues = results.get('security_issues', [])
        for issue in security_issues:
            if 'JavaScript' in issue:
                score += 0.4
            elif 'event handlers' in issue:
                score += 0.3
            else:
                score += 0.1
        
        return min(score, 1.0)
    
    def _calculate_link_score(self, link_results: List[LinkAnalysis]) -> float:
        """Calculate average risk score from link analysis."""
        if not link_results:
            return 0.0
        
        total_score = sum(link.risk_score for link in link_results)
        avg_score = total_score / len(link_results)
        
        # Boost score if multiple high-risk links
        high_risk_count = len([link for link in link_results if link.risk_score > 0.7])
        if high_risk_count > 1:
            avg_score = min(avg_score + (high_risk_count * 0.1), 1.0)
        
        return avg_score
    
    def _calculate_threat_score(self, threat_results: List[EmailIndicators]) -> float:
        """Calculate risk score from threat intelligence."""
        if not threat_results:
            return 0.0
        
        # Find highest reputation score
        max_score = max(indicator.reputation_score or 0.0 for indicator in threat_results)
        
        # Count malicious indicators
        malicious_count = len([
            indicator for indicator in threat_results 
            if (indicator.reputation_score or 0.0) > 0.7
        ])
        
        # Boost score based on number of malicious indicators
        if malicious_count > 0:
            max_score = min(max_score + (malicious_count * 0.1), 1.0)
        
        return max_score
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from overall score."""
        if score >= self.risk_thresholds['critical']:
            return 'critical'
        elif score >= self.risk_thresholds['high']:
            return 'high'
        elif score >= self.risk_thresholds['medium']:
            return 'medium'
        else:
            return 'low'


# Singleton instance
orchestrator = EnhancedEmailOrchestrator()


async def process_email_comprehensive(email_id: int) -> EmailAnalysisSummary:
    """Process email with comprehensive analysis."""
    return await orchestrator.process_email_comprehensive(email_id)
