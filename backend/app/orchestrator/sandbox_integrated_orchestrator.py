"""
Sandbox Integration for Enhanced Threat Orchestrator

Integrates the sandbox infrastructure with the existing threat analysis pipeline,
enabling automated URL analysis with proper job queuing and result aggregation.
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import uuid

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.redis_client import redis_client
from app.services.interfaces import AnalysisResult, AnalysisType, ServiceStatus
from app.orchestrator.enhanced_threat_orchestrator import (
    ThreatAnalysisRequest, 
    EnhancedThreatResult,
    EnhancedThreatOrchestrator
)

# Import sandbox components
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'sandbox'))

from job_queue import SandboxJobQueue, SandboxJob, JobPriority, JobStatus
from orchestrator import ThreatOrchestrator as SandboxOrchestrator
from artifact_storage import get_artifact_manager

logger = get_logger(__name__)


@dataclass
class SandboxAnalysisResult:
    """Result from sandbox analysis integrated with threat assessment."""
    job_id: str
    target_url: str
    analysis_time: str
    duration_ms: int
    
    # Analysis findings
    cloaking_detected: bool
    security_findings: List[str]
    threat_score: float = 0.0
    confidence: float = 0.0
    
    # Artifact information
    screenshots: List[Dict[str, Any]] = None
    dom_snapshots: List[Dict[str, Any]] = None
    network_logs: Dict[str, Any] = None
    console_logs: Dict[str, Any] = None
    archive_url: Optional[str] = None
    
    # Analysis details
    bot_user_analysis: Dict[str, Any] = None
    real_user_analysis: Dict[str, Any] = None
    cloaking_evidence: List[str] = None
    
    def __post_init__(self):
        if self.screenshots is None:
            self.screenshots = []
        if self.dom_snapshots is None:
            self.dom_snapshots = []
        if self.network_logs is None:
            self.network_logs = {}
        if self.console_logs is None:
            self.console_logs = {}
        if self.cloaking_evidence is None:
            self.cloaking_evidence = []


class SandboxIntegratedOrchestrator(EnhancedThreatOrchestrator):
    """Enhanced threat orchestrator with sandbox integration."""
    
    def __init__(self):
        super().__init__()
        self.sandbox_orchestrator = None
        self.sandbox_enabled = settings.SANDBOX_ENABLED if hasattr(settings, 'SANDBOX_ENABLED') else True
        self.sandbox_timeout = getattr(settings, 'SANDBOX_TIMEOUT', 300)  # 5 minutes
    
    async def initialize(self):
        """Initialize orchestrator with sandbox integration."""
        await super().initialize()
        
        if self.sandbox_enabled:
            try:
                self.sandbox_orchestrator = SandboxOrchestrator()
                logger.info("Sandbox orchestrator initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize sandbox orchestrator: {e}")
                self.sandbox_enabled = False
    
    async def analyze_threat(self, request: ThreatAnalysisRequest) -> EnhancedThreatResult:
        """
        Enhanced threat analysis with sandbox integration.
        
        Performs standard threat analysis and adds sandbox analysis
        for URLs that require deeper inspection.
        """
        if not self.initialized:
            await self.initialize()
        
        start_time = time.time()
        logger.info(f"Starting sandbox-integrated threat analysis for scan {request.scan_request_id}")
        
        try:
            # Execute standard threat analysis first
            standard_result = await super().analyze_threat(request)
            
            # Determine if sandbox analysis is needed
            urls_for_sandbox = await self._identify_sandbox_candidates(
                request, standard_result
            )
            
            if urls_for_sandbox and self.sandbox_enabled:
                # Perform sandbox analysis
                sandbox_results = await self._execute_sandbox_analysis(
                    urls_for_sandbox, request
                )
                
                # Integrate sandbox results with standard analysis
                enhanced_result = await self._integrate_sandbox_results(
                    standard_result, sandbox_results
                )
                
                logger.info(
                    f"Sandbox analysis completed for {len(urls_for_sandbox)} URLs "
                    f"in scan {request.scan_request_id}"
                )
                
                return enhanced_result
            else:
                logger.info(
                    f"No sandbox analysis needed for scan {request.scan_request_id} "
                    f"(candidates: {len(urls_for_sandbox)}, enabled: {self.sandbox_enabled})"
                )
                return standard_result
                
        except Exception as e:
            logger.error(f"Error in sandbox-integrated analysis: {e}")
            # Fall back to standard analysis if sandbox fails
            return await super().analyze_threat(request)
    
    async def _identify_sandbox_candidates(
        self, 
        request: ThreatAnalysisRequest, 
        standard_result: EnhancedThreatResult
    ) -> List[str]:
        """
        Identify URLs that should undergo sandbox analysis.
        
        Criteria:
        - URLs with suspicious characteristics
        - URLs that failed standard analysis
        - High-priority requests
        - URLs with redirect chains
        """
        candidates = []
        
        # Always analyze URLs marked as suspicious by standard analysis
        candidates.extend(standard_result.malicious_urls)
        
        # Analyze URLs from high-priority requests
        if request.priority in ['high', 'urgent']:
            candidates.extend(request.urls_to_analyze)
        
        # Analyze URLs that had service failures (might need deeper inspection)
        if standard_result.services_failed:
            candidates.extend(request.urls_to_analyze)
        
        # Analyze URLs with redirect findings
        if hasattr(standard_result, 'redirect_findings') and standard_result.redirect_findings:
            # Extract URLs from redirect findings
            for finding in standard_result.redirect_findings:
                if isinstance(finding, dict) and 'final_url' in finding:
                    candidates.append(finding['final_url'])
        
        # Analyze URLs with medium+ threat score but low confidence
        if (standard_result.threat_score >= 0.5 and 
            standard_result.confidence < 0.7):
            candidates.extend(request.urls_to_analyze)
        
        # Remove duplicates and return
        unique_candidates = list(set(candidates))
        
        # Limit to prevent overwhelming the sandbox
        max_sandbox_urls = getattr(settings, 'MAX_SANDBOX_URLS', 5)
        if len(unique_candidates) > max_sandbox_urls:
            # Prioritize based on threat score and other factors
            unique_candidates = unique_candidates[:max_sandbox_urls]
        
        logger.info(
            f"Identified {len(unique_candidates)} URLs for sandbox analysis "
            f"from {len(request.urls_to_analyze)} total URLs"
        )
        
        return unique_candidates
    
    async def _execute_sandbox_analysis(
        self, 
        urls: List[str], 
        request: ThreatAnalysisRequest
    ) -> Dict[str, SandboxAnalysisResult]:
        """Execute sandbox analysis for multiple URLs."""
        if not self.sandbox_orchestrator:
            logger.warning("Sandbox orchestrator not available")
            return {}
        
        sandbox_results = {}
        
        try:
            # Submit URLs for sandbox analysis
            job_ids = []
            url_to_job = {}
            
            for url in urls:
                priority = self._get_sandbox_priority(request.priority)
                metadata = {
                    'scan_request_id': request.scan_request_id,
                    'user_id': request.user_id,
                    'analysis_depth': request.analysis_depth
                }
                
                job_id = await self.sandbox_orchestrator.analyze_url(
                    target_url=url,
                    priority=priority,
                    metadata=metadata
                )
                
                job_ids.append(job_id)
                url_to_job[url] = job_id
                
                logger.info(f"Submitted URL {url} for sandbox analysis: {job_id}")
            
            # Wait for completion with timeout
            completion_stats = await self.sandbox_orchestrator.wait_for_completion(
                job_ids, timeout=self.sandbox_timeout
            )
            
            # Collect results
            for url, job_id in url_to_job.items():
                if job_id in completion_stats['results']:
                    result_data = completion_stats['results'][job_id]
                    
                    if 'error' not in result_data:
                        # Get enhanced summary with artifact URLs
                        summary = await self.sandbox_orchestrator.get_analysis_summary(job_id)
                        
                        sandbox_result = self._create_sandbox_result(
                            job_id, url, result_data, summary
                        )
                        sandbox_results[url] = sandbox_result
                        
                        logger.info(
                            f"Sandbox analysis completed for {url}: "
                            f"threat_score={sandbox_result.threat_score:.3f}, "
                            f"cloaking={sandbox_result.cloaking_detected}"
                        )
                    else:
                        logger.error(
                            f"Sandbox analysis failed for {url}: "
                            f"{result_data.get('error', 'Unknown error')}"
                        )
                else:
                    logger.warning(f"No sandbox result found for {url} (job {job_id})")
            
            return sandbox_results
            
        except Exception as e:
            logger.error(f"Error executing sandbox analysis: {e}")
            return {}
    
    def _get_sandbox_priority(self, request_priority: str) -> JobPriority:
        """Convert request priority to sandbox job priority."""
        priority_map = {
            'urgent': JobPriority.HIGH,
            'high': JobPriority.HIGH,
            'normal': JobPriority.NORMAL,
            'low': JobPriority.LOW
        }
        return priority_map.get(request_priority, JobPriority.NORMAL)
    
    def _create_sandbox_result(
        self, 
        job_id: str, 
        url: str, 
        result_data: Dict[str, Any],
        summary: Optional[Dict[str, Any]]
    ) -> SandboxAnalysisResult:
        """Create SandboxAnalysisResult from raw data."""
        
        # Calculate threat score based on findings
        threat_score = 0.0
        confidence = 0.8  # High confidence in sandbox results
        
        # Cloaking detection increases threat score significantly
        if result_data.get('cloaking_detected', False):
            threat_score += 0.6
        
        # Security findings increase threat score
        security_findings = result_data.get('security_findings', [])
        if security_findings:
            threat_score += min(0.4, len(security_findings) * 0.1)
        
        # Network violations increase threat score
        if result_data.get('security', {}).get('violations'):
            threat_score += 0.3
        
        # Blocked requests indicate potential malicious behavior
        if result_data.get('security', {}).get('blocked_requests'):
            threat_score += 0.2
        
        # Cap threat score at 1.0
        threat_score = min(1.0, threat_score)
        
        return SandboxAnalysisResult(
            job_id=job_id,
            target_url=url,
            analysis_time=result_data.get('analysis_time', ''),
            duration_ms=result_data.get('duration_ms', 0),
            cloaking_detected=result_data.get('cloaking_detected', False),
            security_findings=security_findings,
            threat_score=threat_score,
            confidence=confidence,
            screenshots=summary.get('artifacts', {}).get('screenshot', []) if summary else [],
            dom_snapshots=summary.get('artifacts', {}).get('dom_snapshot', []) if summary else [],
            network_logs=result_data.get('network_logs', {}),
            console_logs=result_data.get('console_logs', {}),
            archive_url=summary.get('archive_url') if summary else None,
            bot_user_analysis=result_data.get('bot_user_analysis', {}),
            real_user_analysis=result_data.get('real_user_analysis', {}),
            cloaking_evidence=result_data.get('cloaking_evidence', [])
        )
    
    async def _integrate_sandbox_results(
        self,
        standard_result: EnhancedThreatResult,
        sandbox_results: Dict[str, SandboxAnalysisResult]
    ) -> EnhancedThreatResult:
        """Integrate sandbox results with standard threat analysis."""
        
        if not sandbox_results:
            return standard_result
        
        # Calculate enhanced threat score
        sandbox_threat_scores = [r.threat_score for r in sandbox_results.values()]
        max_sandbox_score = max(sandbox_threat_scores) if sandbox_threat_scores else 0.0
        avg_sandbox_score = sum(sandbox_threat_scores) / len(sandbox_threat_scores) if sandbox_threat_scores else 0.0
        
        # Combine with standard score (weighted average)
        standard_weight = 0.6
        sandbox_weight = 0.4
        enhanced_score = (
            standard_result.threat_score * standard_weight + 
            max_sandbox_score * sandbox_weight
        )
        
        # Increase confidence if sandbox confirms findings
        enhanced_confidence = standard_result.confidence
        if max_sandbox_score > 0.5 and standard_result.threat_score > 0.5:
            enhanced_confidence = min(1.0, enhanced_confidence + 0.2)
        
        # Update threat level based on enhanced score
        if enhanced_score >= 0.8:
            threat_level = "critical"
        elif enhanced_score >= 0.6:
            threat_level = "high"
        elif enhanced_score >= 0.4:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        # Collect malicious URLs from sandbox analysis
        malicious_urls = list(standard_result.malicious_urls)
        for url, result in sandbox_results.items():
            if result.threat_score >= 0.6 and url not in malicious_urls:
                malicious_urls.append(url)
        
        # Collect phishing indicators from sandbox
        phishing_indicators = list(standard_result.phishing_indicators)
        for result in sandbox_results.values():
            if result.cloaking_detected:
                phishing_indicators.append(f"Cloaking detected: {result.target_url}")
            
            for finding in result.security_findings:
                if finding not in phishing_indicators:
                    phishing_indicators.append(finding)
        
        # Enhanced recommendations
        recommendations = list(standard_result.recommendations)
        
        for url, result in sandbox_results.items():
            if result.cloaking_detected:
                recommendations.append(
                    f"CRITICAL: Cloaking behavior detected on {url}. "
                    "This site presents different content to bots vs. real users."
                )
            
            if result.threat_score >= 0.7:
                recommendations.append(
                    f"HIGH RISK: Sandbox analysis of {url} revealed suspicious behavior. "
                    "Consider blocking this URL."
                )
        
        # Enhanced explanation
        sandbox_explanation = ""
        if sandbox_results:
            cloaking_count = sum(1 for r in sandbox_results.values() if r.cloaking_detected)
            high_threat_count = sum(1 for r in sandbox_results.values() if r.threat_score >= 0.6)
            
            sandbox_explanation = (
                f" Sandbox analysis of {len(sandbox_results)} URLs revealed "
                f"{cloaking_count} instances of cloaking behavior and "
                f"{high_threat_count} high-threat indicators."
            )
        
        enhanced_explanation = standard_result.explanation + sandbox_explanation
        
        # Create enhanced result
        enhanced_result = EnhancedThreatResult(
            scan_request_id=standard_result.scan_request_id,
            threat_level=threat_level,
            threat_score=enhanced_score,
            confidence=enhanced_confidence,
            service_results=standard_result.service_results,
            url_analysis_score=max(standard_result.url_analysis_score, max_sandbox_score),
            ip_reputation_score=standard_result.ip_reputation_score,
            content_analysis_score=standard_result.content_analysis_score,
            malicious_urls=malicious_urls,
            suspicious_ips=standard_result.suspicious_ips,
            phishing_indicators=phishing_indicators,
            services_used=standard_result.services_used + ['sandbox'],
            services_failed=standard_result.services_failed,
            analysis_start_time=standard_result.analysis_start_time,
            analysis_duration_seconds=time.time() - standard_result.analysis_start_time,
            explanation=enhanced_explanation,
            recommendations=recommendations,
            confidence_reasoning=standard_result.confidence_reasoning + 
                               f" Sandbox analysis provided additional verification."
        )
        
        # Add sandbox-specific data as custom attributes
        enhanced_result.sandbox_results = sandbox_results
        enhanced_result.sandbox_analysis_count = len(sandbox_results)
        enhanced_result.cloaking_detected = any(r.cloaking_detected for r in sandbox_results.values())
        
        logger.info(
            f"Enhanced threat analysis complete: "
            f"standard_score={standard_result.threat_score:.3f}, "
            f"enhanced_score={enhanced_score:.3f}, "
            f"sandbox_urls={len(sandbox_results)}"
        )
        
        return enhanced_result


# Global instance for use throughout the application
_sandbox_integrated_orchestrator = None


async def get_sandbox_integrated_orchestrator() -> SandboxIntegratedOrchestrator:
    """Get or create the global sandbox-integrated orchestrator."""
    global _sandbox_integrated_orchestrator
    
    if _sandbox_integrated_orchestrator is None:
        _sandbox_integrated_orchestrator = SandboxIntegratedOrchestrator()
        await _sandbox_integrated_orchestrator.initialize()
    
    return _sandbox_integrated_orchestrator


async def analyze_threat_with_sandbox(request: ThreatAnalysisRequest) -> EnhancedThreatResult:
    """
    Convenience function to perform threat analysis with sandbox integration.
    
    Args:
        request: Threat analysis request
        
    Returns:
        Enhanced threat result with sandbox analysis
    """
    orchestrator = await get_sandbox_integrated_orchestrator()
    return await orchestrator.analyze_threat(request)
