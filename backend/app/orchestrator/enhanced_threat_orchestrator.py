"""
Enhanced threat analysis orchestrator using unified service adapters.
Coordinates multiple security services with the new analyzer factory architecture.
"""

import asyncio
import time
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import json

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.redis_client import redis_client
from app.services.interfaces import AnalysisResult, AnalysisType, ServiceStatus
from app.services.analyzer_factory import (
    get_analyzer_factory, initialize_global_factory, analyze_with_best_available
)
from app.services.redirect_analyzer import LinkRedirectAnalyzer, create_redirect_analyzer
from app.services.redirect_interfaces import RedirectAnalysisResult
from app.repositories.redirect_repository import RedirectAnalysisRepository

logger = get_logger(__name__)


@dataclass
class ThreatAnalysisRequest:
    """Request for enhanced threat analysis using service adapters."""
    scan_request_id: str
    gmail_message_id: str
    user_id: str
    
    # Email metadata (privacy-safe)
    sender_domain: str
    sender_ip: Optional[str]
    subject_hash: str  # SHA-256 hash instead of plain text
    
    # Analysis targets
    urls_to_analyze: List[str]
    ip_addresses: List[str]
    email_content: str  # For LLM analysis
    attachments: List[Dict[str, Any]] = None  # File hashes for analysis
    
    # Configuration
    priority: str = "normal"  # low, normal, high, urgent
    analysis_depth: str = "standard"  # quick, standard, deep
    user_preferences: Dict[str, Any] = None


@dataclass
class EnhancedThreatResult:
    """Enhanced threat analysis result with comprehensive security assessment."""
    
    # Request context
    scan_request_id: str
    gmail_message_id: str = ""
    user_id: str = ""
    
    # Overall threat assessment  
    threat_level: str = "low"  # low, medium, high, critical
    threat_score: float = 0.0  # Weighted aggregate 0.0-1.0
    confidence: float = 0.0   # Based on service consensus
    
    # Service-specific results
    service_results: Dict[str, AnalysisResult] = None
    redirect_analysis_results: Dict[str, RedirectAnalysisResult] = None  # URL -> redirect analysis
    
    # Component scores  
    url_analysis_score: float = 0.0
    ip_reputation_score: float = 0.0
    content_analysis_score: float = 0.0
    redirect_analysis_score: float = 0.0  # New component score
    
    # Actionable findings
    malicious_urls: List[str] = None
    suspicious_ips: List[str] = None
    phishing_indicators: List[str] = None
    redirect_findings: List[str] = None  # Redirect-specific findings
    
    # Service health tracking
    services_used: List[str] = None
    services_failed: List[str] = None
    
    # AI-generated insights
    explanation: str = ""
    recommendations: List[str] = None
    confidence_reasoning: str = ""
    
    # Analysis metadata
    analysis_start_time: float = 0.0
    analysis_duration_seconds: float = 0.0
    
    def __post_init__(self):
        """Initialize default values for mutable fields."""
        if self.service_results is None:
            self.service_results = {}
        if self.redirect_analysis_results is None:
            self.redirect_analysis_results = {}
        if self.malicious_urls is None:
            self.malicious_urls = []
        if self.suspicious_ips is None:
            self.suspicious_ips = []
        if self.phishing_indicators is None:
            self.phishing_indicators = []
        if self.redirect_findings is None:
            self.redirect_findings = []
        if self.services_used is None:
            self.services_used = []
        if self.services_failed is None:
            self.services_failed = []
        if self.recommendations is None:
            self.recommendations = []
    """Enhanced threat analysis result using service adapters."""
    scan_request_id: str
    
    # Overall assessment
    threat_level: str  # low, medium, high, critical
    threat_score: float  # 0.0 to 1.0 (weighted aggregate)
    confidence: float  # 0.0 to 1.0
    
    # Service-specific results
    service_results: Dict[str, AnalysisResult]
    
    # Component scores for detailed analysis
    url_analysis_score: float
    ip_reputation_score: float
    content_analysis_score: float
    
    # Aggregated findings
    malicious_urls: List[str]
    suspicious_ips: List[str]
    phishing_indicators: List[str]
    
    # Service availability and health
    services_used: List[str]
    services_failed: List[str]
    
    # Metadata
    analysis_start_time: float
    analysis_duration_seconds: float
    
    # AI-generated insights
    explanation: str
    recommendations: List[str]
    confidence_reasoning: str


class EnhancedThreatOrchestrator:
    """
    Enhanced threat analysis orchestrator using service adapter architecture.
    Provides comprehensive threat assessment with unified service integration.
    """
    
    def __init__(self, db_session=None):
        """Initialize the enhanced orchestrator."""
        self.factory = None
        self.redirect_analyzer = None
        self.redirect_repository = None
        self.db_session = db_session
        self.initialized = False
        
        # Scoring weights for different analysis types
        self.scoring_weights = {
            'url_analysis': 0.25,       # URLs are important for phishing
            'ip_reputation': 0.20,      # IP reputation is important
            'content_analysis': 0.30,   # Content analysis via LLM is key
            'redirect_analysis': 0.25,  # Redirect analysis for phishing chains
        }
        
        # Threat level thresholds
        self.threat_thresholds = {
            'low': 0.2,
            'medium': 0.5,
            'high': 0.75,
            'critical': 0.9
        }
    
    async def initialize(self):
        """Initialize the orchestrator with service factory."""
        if self.initialized:
            return
        
        try:
            await initialize_global_factory()
            self.factory = get_analyzer_factory()
            
            # Initialize redirect analyzer
            self.redirect_analyzer = await create_redirect_analyzer(
                reputation_factory=self.factory,
                browser_type="chromium",
                screenshot_dir="/app/screenshots"
            )
            
            # Initialize redirect repository if database session available
            if self.db_session:
                self.redirect_repository = RedirectAnalysisRepository(self.db_session)
            
            self.initialized = True
            logger.info("Enhanced threat orchestrator initialized with redirect analysis")
            
            # Log available services
            analyzers = self.factory.get_analyzers()
            available_services = [name for name, analyzer in analyzers.items() if analyzer.is_available]
            logger.info(f"Available analysis services: {available_services}")
            
        except Exception as e:
            logger.error(f"Failed to initialize threat orchestrator: {e}")
            raise
    
    async def analyze_threat(self, request: ThreatAnalysisRequest) -> EnhancedThreatResult:
        """
        Perform comprehensive threat analysis using service adapters.
        
        Args:
            request: Threat analysis request with email metadata and content
            
        Returns:
            EnhancedThreatResult with aggregated analysis from all services
        """
        if not self.initialized:
            await self.initialize()
        
        start_time = time.time()
        logger.info(f"Starting enhanced threat analysis for scan {request.scan_request_id}")
        
        try:
            # Execute parallel analysis across all relevant services
            service_results, redirect_results = await self._execute_parallel_analysis(request)
            
            # Aggregate results into final threat assessment
            threat_result = await self._aggregate_threat_assessment(
                request, service_results, redirect_results, start_time
            )
            
            # Cache result for future reference
            await self._cache_result(threat_result)
            
            duration = time.time() - start_time
            logger.info(
                f"Enhanced threat analysis complete for {request.scan_request_id}: "
                f"score {threat_result.threat_score:.3f}, "
                f"level {threat_result.threat_level}, "
                f"duration {duration:.2f}s"
            )
            
            return threat_result
            
        except Exception as e:
            logger.error(f"Enhanced threat analysis failed for {request.scan_request_id}: {e}")
            
            # Return error result with safe defaults
            return EnhancedThreatResult(
                scan_request_id=request.scan_request_id,
                threat_level="low",
                threat_score=0.0,
                confidence=0.0,
                service_results={},
                redirect_analysis_results={},
                url_analysis_score=0.0,
                ip_reputation_score=0.0,
                content_analysis_score=0.0,
                redirect_analysis_score=0.0,
                malicious_urls=[],
                suspicious_ips=[],
                phishing_indicators=["Analysis failed"],
                redirect_findings=[],
                services_used=[],
                services_failed=["orchestrator"],
                analysis_start_time=start_time,
                analysis_duration_seconds=time.time() - start_time,
                explanation=f"Threat analysis failed: {str(e)}",
                recommendations=["Manual review recommended due to analysis failure"],
                confidence_reasoning="Analysis failed, defaulting to safe values"
            )
    
    async def _execute_parallel_analysis(self, request: ThreatAnalysisRequest) -> Tuple[Dict[str, AnalysisResult], Dict[str, RedirectAnalysisResult]]:
        """Execute parallel analysis across all relevant services including redirect analysis."""
        service_results = {}
        redirect_results = {}
        
        # Prepare analysis tasks
        analysis_tasks = []
        redirect_tasks = []
        
        # URL Analysis (VirusTotal)
        if request.urls_to_analyze:
            for url in request.urls_to_analyze[:10]:  # Limit to 10 URLs
                analysis_tasks.append(
                    self._safe_analyze(url, AnalysisType.URL_SCAN, f"url_{hashlib.md5(url.encode()).hexdigest()[:8]}")
                )
                
                # Also add redirect analysis for each URL
                if self.redirect_analyzer:
                    redirect_tasks.append(
                        self._safe_redirect_analyze(url, f"redirect_{hashlib.md5(url.encode()).hexdigest()[:8]}")
                    )
        
        # IP Reputation Analysis (AbuseIPDB, VirusTotal)
        if request.ip_addresses:
            for ip in request.ip_addresses[:5]:  # Limit to 5 IPs
                analysis_tasks.append(
                    self._safe_analyze(ip, AnalysisType.IP_REPUTATION, f"ip_{hashlib.md5(ip.encode()).hexdigest()[:8]}")
                )
        
        # Content Analysis (Gemini LLM)
        if request.email_content and len(request.email_content.strip()) > 10:
            analysis_tasks.append(
                self._safe_analyze(request.email_content, AnalysisType.TEXT_ANALYSIS, "content")
            )
        
        # File Hash Analysis (VirusTotal) - if attachments present
        if request.attachments:
            for attachment in request.attachments[:5]:  # Limit to 5 files
                if 'hash' in attachment:
                    analysis_tasks.append(
                        self._safe_analyze(attachment['hash'], AnalysisType.FILE_HASH, f"file_{attachment.get('name', 'unknown')}")
                    )
        
        # Execute all analysis tasks in parallel
        all_tasks = analysis_tasks + redirect_tasks
        
        if all_tasks:
            logger.info(f"Executing {len(analysis_tasks)} service tasks and {len(redirect_tasks)} redirect tasks")
            task_results = await asyncio.gather(*all_tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(task_results):
                if isinstance(result, Exception):
                    logger.error(f"Analysis task {i} failed: {result}")
                elif isinstance(result, tuple) and len(result) == 2:
                    task_id, analysis_result = result
                    if analysis_result:
                        if task_id.startswith("redirect_"):
                            redirect_results[task_id] = analysis_result
                        else:
                            service_results[task_id] = analysis_result
        
        return service_results, redirect_results
    
    async def _safe_analyze(self, target: str, analysis_type: AnalysisType, task_id: str) -> Tuple[str, Optional[AnalysisResult]]:
        """Safely execute analysis with error handling."""
        try:
            # Get available analyzers for this analysis type
            analyzers = self.factory.get_analyzers_for_type(analysis_type)
            
            if not analyzers:
                logger.warning(f"No analyzers available for {analysis_type.value}")
                return task_id, None
            
            # Use the first available analyzer (could be enhanced to use multiple)
            analyzer = analyzers[0]
            
            # Execute analysis
            result = await analyzer.analyze(target, analysis_type)
            return task_id, result
            
        except Exception as e:
            logger.error(f"Analysis failed for {task_id}: {e}")
            return task_id, None
    
    async def _safe_redirect_analyze(self, url: str, task_id: str) -> Tuple[str, Optional[RedirectAnalysisResult]]:
        """Safely execute redirect analysis with error handling."""
        try:
            if not self.redirect_analyzer:
                logger.warning("Redirect analyzer not available")
                return task_id, None
            
            # Execute redirect analysis
            result = await self.redirect_analyzer.analyze_redirects(
                url=url,
                max_hops=10,
                timeout_seconds=30,
                include_browser_analysis=True,
                include_cloaking_detection=True,
                include_reputation_checks=True
            )
            
            # Store result in database if repository available
            if self.redirect_repository and result:
                try:
                    analysis_id = await self.redirect_repository.save_redirect_analysis(result)
                    logger.info(f"Saved redirect analysis {analysis_id} for URL: {url}")
                except Exception as e:
                    logger.error(f"Failed to save redirect analysis: {e}")
            
            return task_id, result
            
        except Exception as e:
            logger.error(f"Redirect analysis failed for {task_id}: {e}")
            return task_id, None
    
    async def _aggregate_threat_assessment(
        self, 
        request: ThreatAnalysisRequest, 
        service_results: Dict[str, AnalysisResult],
        redirect_results: Dict[str, RedirectAnalysisResult],
        start_time: float
    ) -> EnhancedThreatResult:
        """Aggregate individual service results into comprehensive threat assessment."""
        
        # Separate results by analysis type
        url_results = []
        ip_results = []
        content_results = []
        
        services_used = []
        services_failed = []
        
        for task_id, result in service_results.items():
            if result:
                services_used.append(result.service_name)
                
                if result.analysis_type == AnalysisType.URL_SCAN:
                    url_results.append(result)
                elif result.analysis_type == AnalysisType.IP_REPUTATION:
                    ip_results.append(result)
                elif result.analysis_type == AnalysisType.TEXT_ANALYSIS:
                    content_results.append(result)
                
                # Track any service errors
                if result.error:
                    services_failed.append(result.service_name)
        
        # Calculate component scores
        url_analysis_score = self._calculate_component_score(url_results)
        ip_reputation_score = self._calculate_component_score(ip_results)
        content_analysis_score = self._calculate_component_score(content_results)
        
        # Calculate redirect analysis score
        redirect_analysis_score = self._calculate_redirect_component_score(redirect_results)
        
        # Add redirect analyzer to services used if we have redirect results
        if redirect_results:
            services_used.append("redirect_analyzer")
        
        # Calculate weighted overall threat score
        threat_score = (
            url_analysis_score * self.scoring_weights['url_analysis'] +
            ip_reputation_score * self.scoring_weights['ip_reputation'] +
            content_analysis_score * self.scoring_weights['content_analysis'] +
            redirect_analysis_score * self.scoring_weights['redirect_analysis']
        )
        
        # Determine threat level
        threat_level = self._determine_threat_level(threat_score)
        
        # Calculate confidence based on service availability and consensus
        confidence = self._calculate_confidence(service_results, services_used)
        
        # Extract findings
        malicious_urls = self._extract_malicious_urls(url_results)
        suspicious_ips = self._extract_suspicious_ips(ip_results)
        phishing_indicators = self._extract_phishing_indicators(service_results.values())
        redirect_findings = self._extract_redirect_findings(redirect_results)
        
        # Generate explanations and recommendations
        explanation = self._generate_explanation(service_results, redirect_results, threat_score, threat_level)
        recommendations = self._generate_recommendations(threat_level, service_results, redirect_results)
        confidence_reasoning = self._generate_confidence_reasoning(services_used, services_failed, confidence)
        
        return EnhancedThreatResult(
            scan_request_id=request.scan_request_id,
            threat_level=threat_level,
            threat_score=threat_score,
            confidence=confidence,
            service_results=service_results,
            redirect_analysis_results=redirect_results,
            url_analysis_score=url_analysis_score,
            ip_reputation_score=ip_reputation_score,
            content_analysis_score=content_analysis_score,
            redirect_analysis_score=redirect_analysis_score,
            malicious_urls=malicious_urls,
            suspicious_ips=suspicious_ips,
            phishing_indicators=phishing_indicators,
            redirect_findings=redirect_findings,
            services_used=list(set(services_used)),
            services_failed=list(set(services_failed)),
            analysis_start_time=start_time,
            analysis_duration_seconds=time.time() - start_time,
            explanation=explanation,
            recommendations=recommendations,
            confidence_reasoning=confidence_reasoning
        )
    
    def _calculate_component_score(self, results: List[AnalysisResult]) -> float:
        """Calculate weighted component score from multiple results."""
        if not results:
            return 0.0
        
        # Weight by confidence and take maximum (most conservative approach)
        weighted_scores = []
        for result in results:
            if not result.error:
                weighted_score = result.threat_score * result.confidence
                weighted_scores.append(weighted_score)
        
        if not weighted_scores:
            return 0.0
        
        # Use maximum weighted score (most conservative)
        return min(max(weighted_scores), 1.0)
    
    def _determine_threat_level(self, threat_score: float) -> str:
        """Determine threat level based on score."""
        if threat_score >= self.threat_thresholds['critical']:
            return "critical"
        elif threat_score >= self.threat_thresholds['high']:
            return "high"
        elif threat_score >= self.threat_thresholds['medium']:
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence(self, service_results: Dict[str, AnalysisResult], services_used: List[str]) -> float:
        """Calculate overall confidence based on service consensus and availability."""
        
        if not service_results:
            return 0.0
        
        # Base confidence starts with service availability
        total_services = len(self.factory.get_analyzers())
        available_services = len(services_used)
        availability_confidence = available_services / max(total_services, 1)
        
        # Confidence based on individual service confidence
        service_confidences = []
        for result in service_results.values():
            if result and not result.error:
                service_confidences.append(result.confidence)
        
        if service_confidences:
            avg_service_confidence = sum(service_confidences) / len(service_confidences)
        else:
            avg_service_confidence = 0.5
        
        # Combined confidence
        combined_confidence = (availability_confidence * 0.3 + avg_service_confidence * 0.7)
        
        return min(combined_confidence, 1.0)
    
    def _extract_malicious_urls(self, url_results: List[AnalysisResult]) -> List[str]:
        """Extract URLs identified as malicious."""
        malicious_urls = []
        
        for result in url_results:
            if result.threat_score >= 0.7 and not result.error:  # High confidence malicious
                malicious_urls.append(result.target)
        
        return malicious_urls
    
    def _extract_suspicious_ips(self, ip_results: List[AnalysisResult]) -> List[str]:
        """Extract IP addresses identified as suspicious."""
        suspicious_ips = []
        
        for result in ip_results:
            if result.threat_score >= 0.5 and not result.error:  # Medium+ confidence suspicious
                suspicious_ips.append(result.target)
        
        return suspicious_ips
    
    def _extract_phishing_indicators(self, all_results: List[AnalysisResult]) -> List[str]:
        """Extract phishing indicators from all analysis results."""
        indicators = []
        
        for result in all_results:
            if result and result.indicators and not result.error:
                indicators.extend(result.indicators[:3])  # Top 3 from each service
        
        # Deduplicate and limit
        return list(set(indicators))[:10]
    
    def _generate_explanation(self, service_results: Dict[str, AnalysisResult], threat_score: float, threat_level: str) -> str:
        """Generate human-readable explanation of analysis results."""
        
        if not service_results:
            return "No analysis services were available to assess this email."
        
        explanation_parts = [
            f"Comprehensive analysis indicates {threat_level} threat level with score {threat_score:.2f}/1.0."
        ]
        
        # Add service-specific insights
        for task_id, result in service_results.items():
            if result and not result.error and result.explanation:
                service_name = result.service_name.title()
                explanation_parts.append(f"{service_name}: {result.explanation}")
        
        return " ".join(explanation_parts)
    
    def _generate_recommendations(self, threat_level: str, service_results: Dict[str, AnalysisResult]) -> List[str]:
        """Generate actionable recommendations based on threat level and findings."""
        
        recommendations = []
        
        if threat_level == "critical":
            recommendations.extend([
                "IMMEDIATE ACTION: Quarantine this email immediately",
                "Block sender domain and report to security team",
                "Scan systems for potential compromise",
                "Alert user about potential phishing attempt"
            ])
        elif threat_level == "high":
            recommendations.extend([
                "Quarantine email and flag for manual review",
                "Warning notification to user",
                "Consider blocking sender domain"
            ])
        elif threat_level == "medium":
            recommendations.extend([
                "Flag email for user attention",
                "Add warning labels to suspicious elements",
                "Monitor user interaction"
            ])
        else:
            recommendations.append("Email appears safe, allow normal delivery")
        
        # Add specific recommendations based on findings
        for result in service_results.values():
            if result and result.threat_score > 0.5:
                if result.analysis_type == AnalysisType.URL_SCAN:
                    recommendations.append("Block suspicious URLs found in email")
                elif result.analysis_type == AnalysisType.IP_REPUTATION:
                    recommendations.append("Monitor communications from suspicious IP addresses")
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def _generate_confidence_reasoning(self, services_used: List[str], services_failed: List[str], confidence: float) -> str:
        """Generate reasoning for confidence score."""
        
        reasoning_parts = []
        
        if services_used:
            reasoning_parts.append(f"Analysis completed by {len(services_used)} services: {', '.join(services_used)}")
        
        if services_failed:
            reasoning_parts.append(f"Some services failed: {', '.join(services_failed)}")
        
        if confidence >= 0.8:
            reasoning_parts.append("High confidence due to service consensus")
        elif confidence >= 0.6:
            reasoning_parts.append("Moderate confidence with some service limitations")
        else:
            reasoning_parts.append("Lower confidence due to limited service availability")
        
        return ". ".join(reasoning_parts) + "."
    
    def _extract_suspicious_redirects(self, redirect_results: List[RedirectAnalysisResult]) -> List[str]:
        """Extract URLs identified as suspicious in redirect analysis."""
        suspicious_urls = []
        
        for result in redirect_results:
            if result.threat_score >= 0.5:  # Medium+ threat score
                suspicious_urls.append(result.target_url)
                
                # Add suspicious hops from redirect chain
                for hop in result.redirect_chain:
                    if hop.reputation_score and hop.reputation_score >= 0.5:
                        suspicious_urls.append(hop.url)
        
        return list(set(suspicious_urls))  # Deduplicate
    
    def _extract_redirect_indicators(self, redirect_results: List[RedirectAnalysisResult]) -> List[str]:
        """Extract threat indicators from redirect analysis results."""
        indicators = []
        
        for result in redirect_results:
            if result.cloaking_detected:
                for detection in result.cloaking_detected:
                    indicators.append(f"Cloaking via {detection.method}: {detection.description}")
            
            if result.malicious_content_detected:
                indicators.append("Malicious content detected in redirect chain")
            
            # Add certificate warnings
            for hop in result.redirect_chain:
                if hop.tls_info and not hop.tls_info.is_valid:
                    indicators.append(f"Invalid TLS certificate: {hop.tls_info.subject}")
        
        return indicators[:5]  # Limit to top 5 indicators

    async def _cache_result(self, result: EnhancedThreatResult):
        """Cache analysis result for future reference."""
        try:
            cache_key = f"threat_analysis:{result.scan_request_id}"
            
            # Create cacheable data (exclude large objects)
            cache_data = {
                "scan_request_id": result.scan_request_id,
                "threat_level": result.threat_level,
                "threat_score": result.threat_score,
                "confidence": result.confidence,
                "services_used": result.services_used,
                "cached_at": time.time()
            }
            
            await redis_client.setex(cache_key, 3600, json.dumps(cache_data))  # 1 hour TTL
            
        except Exception as e:
            logger.warning(f"Failed to cache threat analysis result: {e}")
    
    async def get_service_health(self) -> Dict[str, Any]:
        """Get health status of all analysis services."""
        if not self.initialized:
            await self.initialize()
        
        try:
            health_status = await self.factory.get_service_health()
            
            # Convert to simple status format
            service_status = {}
            for service_name, health in health_status.items():
                service_status[service_name] = {
                    "status": health.status.value,
                    "available": health.status == ServiceStatus.AVAILABLE,
                    "last_success": health.last_success,
                    "consecutive_failures": health.consecutive_failures
                }
            
            return {
                "services": service_status,
                "total_services": len(service_status),
                "available_services": sum(1 for s in service_status.values() if s["available"]),
                "health_check_time": time.time()
            }
            
        except Exception as e:
            logger.error(f"Failed to get service health: {e}")
            return {"error": str(e)}


# Global orchestrator instance
_orchestrator_instance: Optional[EnhancedThreatOrchestrator] = None


def get_threat_orchestrator() -> EnhancedThreatOrchestrator:
    """Get or create global threat orchestrator instance."""
    global _orchestrator_instance
    
    if _orchestrator_instance is None:
        _orchestrator_instance = EnhancedThreatOrchestrator()
    
    return _orchestrator_instance


async def analyze_email_threat(request: ThreatAnalysisRequest) -> EnhancedThreatResult:
    """Convenience function for email threat analysis."""
    orchestrator = get_threat_orchestrator()
    return await orchestrator.analyze_threat(request)
