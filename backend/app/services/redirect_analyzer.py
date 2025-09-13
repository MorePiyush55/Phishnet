"""
Link Redirect Analyzer

Main service that integrates HTTP redirect tracing, browser analysis, cloaking detection,
and reputation checking to provide comprehensive redirect chain analysis.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import logging

from .redirect_interfaces import (
    IRedirectAnalyzer, RedirectAnalysisResult, RedirectHop, BrowserAnalysisResult,
    CloakingDetection, COMMON_USER_AGENTS
)
from .http_redirect_tracer import HTTPRedirectTracer, RedirectChainAnalyzer
from .browser_redirect_analyzer import BrowserRedirectAnalyzer, DOMAnalyzer
from .cloaking_detection import CloakingDetectionEngine, BehaviorAnalyzer
from .interfaces import IAnalyzer, AnalysisType, AnalysisResult
from .analyzer_factory import AnalyzerFactory, FactoryConfig, AnalyzerMode


logger = logging.getLogger(__name__)


class LinkRedirectAnalyzer(IRedirectAnalyzer):
    """
    Comprehensive redirect analysis service that traces redirect chains,
    detects cloaking, and analyzes security implications
    """
    
    def __init__(
        self,
        http_tracer: Optional[HTTPRedirectTracer] = None,
        browser_analyzer: Optional[BrowserRedirectAnalyzer] = None,
        cloaking_detector: Optional[CloakingDetectionEngine] = None,
        reputation_factory: Optional[AnalyzerFactory] = None,
        max_concurrent_analysis: int = 3
    ):
        self.http_tracer = http_tracer or HTTPRedirectTracer()
        self.browser_analyzer = browser_analyzer or BrowserRedirectAnalyzer()
        self.cloaking_detector = cloaking_detector or CloakingDetectionEngine()
        self.reputation_factory = reputation_factory
        self.max_concurrent_analysis = max_concurrent_analysis
        
        # Semaphore to limit concurrent analyses
        self.analysis_semaphore = asyncio.Semaphore(max_concurrent_analysis)
    
    async def analyze_redirects(
        self,
        url: str,
        max_hops: int = 10,
        timeout_seconds: int = 30,
        include_browser_analysis: bool = True,
        include_cloaking_detection: bool = True,
        include_reputation_checks: bool = True
    ) -> RedirectAnalysisResult:
        """
        Analyze redirect chain for a given URL
        
        Args:
            url: The URL to analyze
            max_hops: Maximum number of redirects to follow
            timeout_seconds: Timeout for the entire analysis
            include_browser_analysis: Whether to run headless browser analysis
            include_cloaking_detection: Whether to perform cloaking detection
            include_reputation_checks: Whether to check reputation for each hop
            
        Returns:
            Complete redirect analysis result
        """
        async with self.analysis_semaphore:
            start_time = time.time()
            
            result = RedirectAnalysisResult(
                original_url=url,
                final_destination=url,
                analysis_timestamp=start_time
            )
            
            try:
                # Step 1: HTTP redirect tracing
                logger.info(f"Starting HTTP redirect analysis for {url}")
                http_hops = await self.trace_http_redirects(
                    url=url,
                    max_hops=max_hops,
                    timeout_seconds=min(timeout_seconds // 2, 15)
                )
                
                result.redirect_chain = http_hops
                result.total_hops = len(http_hops)
                result.max_hops_reached = len(http_hops) >= max_hops
                
                # Determine final destination
                if http_hops:
                    last_hop = http_hops[-1]
                    if last_hop.location_header and last_hop.status_code in [301, 302, 303, 307, 308]:
                        # Chain was cut off, use location header as final destination
                        result.final_destination = last_hop.location_header
                    else:
                        result.final_destination = last_hop.url
                
                # Step 2: Reputation checking for each hop
                if include_reputation_checks and self.reputation_factory:
                    logger.info("Starting reputation checks for redirect chain")
                    await self._analyze_hop_reputations(result.redirect_chain)
                
                # Step 3: Browser analysis (if requested)
                if include_browser_analysis:
                    logger.info("Starting browser analysis")
                    
                    user_agents_to_test = [
                        COMMON_USER_AGENTS["chrome_user"],
                        COMMON_USER_AGENTS["chrome_bot"]
                    ]
                    
                    browser_results = await self.analyze_with_browser(
                        url=url,
                        user_agents=user_agents_to_test,
                        timeout_seconds=min(timeout_seconds // 2, 20),
                        take_screenshots=True
                    )
                    
                    if len(browser_results) >= 2:
                        result.user_browser_result = browser_results[0]
                        result.bot_browser_result = browser_results[1]
                        
                        # Update final destination from browser analysis
                        if result.user_browser_result.final_url != url:
                            result.final_destination = result.user_browser_result.final_url
                
                # Step 4: Cloaking detection
                if (include_cloaking_detection and 
                    result.user_browser_result and 
                    result.bot_browser_result):
                    
                    logger.info("Starting cloaking detection analysis")
                    result.cloaking_analysis = await self.detect_cloaking(
                        url=url,
                        user_browser_result=result.user_browser_result,
                        bot_browser_result=result.bot_browser_result
                    )
                
                # Step 5: Security analysis
                logger.info("Performing security analysis of redirect chain")
                await self._perform_security_analysis(result)
                
                # Step 6: Generate recommendations
                await self._generate_recommendations(result)
                
            except Exception as e:
                logger.error(f"Error during redirect analysis: {str(e)}")
                result.analysis_errors.append(f"Analysis error: {str(e)}")
                result.partial_analysis = True
            
            finally:
                result.total_execution_time_ms = int((time.time() - start_time) * 1000)
            
            return result
    
    async def trace_http_redirects(
        self,
        url: str,
        max_hops: int = 10,
        timeout_seconds: int = 15
    ) -> List[RedirectHop]:
        """
        Trace HTTP redirects synchronously without browser
        
        Args:
            url: The URL to trace
            max_hops: Maximum redirects to follow
            timeout_seconds: Request timeout
            
        Returns:
            List of redirect hops
        """
        try:
            return await self.http_tracer.trace_redirects(
                url=url,
                max_hops=max_hops,
                timeout_seconds=timeout_seconds
            )
        except Exception as e:
            logger.error(f"HTTP redirect tracing failed: {str(e)}")
            # Return a single hop with error
            return [RedirectHop(
                hop_number=0,
                url=url,
                error=f"HTTP tracing failed: {str(e)}"
            )]
    
    async def analyze_with_browser(
        self,
        url: str,
        user_agents: List[str],
        timeout_seconds: int = 30,
        take_screenshots: bool = True
    ) -> List[BrowserAnalysisResult]:
        """
        Analyze URL with headless browser using different user agents
        
        Args:
            url: The URL to analyze
            user_agents: List of user agents to test
            timeout_seconds: Browser timeout
            take_screenshots: Whether to capture screenshots
            
        Returns:
            List of browser analysis results (one per user agent)
        """
        try:
            return await self.browser_analyzer.analyze_with_browser(
                url=url,
                user_agents=user_agents,
                timeout_seconds=timeout_seconds,
                take_screenshots=take_screenshots
            )
        except Exception as e:
            logger.error(f"Browser analysis failed: {str(e)}")
            # Return error results for each user agent
            return [
                BrowserAnalysisResult(
                    user_agent_used=ua,
                    final_url=url,
                    error=f"Browser analysis failed: {str(e)}"
                )
                for ua in user_agents
            ]
    
    async def detect_cloaking(
        self,
        url: str,
        user_browser_result: BrowserAnalysisResult,
        bot_browser_result: BrowserAnalysisResult
    ) -> CloakingDetection:
        """
        Compare browser results to detect cloaking
        
        Args:
            url: The analyzed URL
            user_browser_result: Result from user-agent browser
            bot_browser_result: Result from bot user-agent browser
            
        Returns:
            Cloaking detection analysis
        """
        try:
            return await self.cloaking_detector.detect_cloaking(
                url=url,
                user_browser_result=user_browser_result,
                bot_browser_result=bot_browser_result
            )
        except Exception as e:
            logger.error(f"Cloaking detection failed: {str(e)}")
            detection = CloakingDetection()
            detection.cloaking_indicators.append(f"Cloaking analysis failed: {str(e)}")
            return detection
    
    async def _analyze_hop_reputations(self, hops: List[RedirectHop]):
        """Analyze reputation for each hop in the redirect chain"""
        if not self.reputation_factory:
            return
        
        # Get available analyzers
        try:
            url_analyzers = self.reputation_factory.get_analyzers_for_type(AnalysisType.URL_SCAN)
            ip_analyzers = self.reputation_factory.get_analyzers_for_type(AnalysisType.IP_REPUTATION)
        except Exception as e:
            logger.error(f"Failed to get reputation analyzers: {str(e)}")
            return
        
        # Analyze each hop
        for hop in hops:
            if hop.error:
                continue
            
            try:
                # URL reputation analysis
                await self._analyze_hop_url_reputation(hop, url_analyzers)
                
                # IP reputation analysis
                if hop.resolved_ip:
                    await self._analyze_hop_ip_reputation(hop, ip_analyzers)
                
            except Exception as e:
                logger.error(f"Reputation analysis failed for hop {hop.hop_number}: {str(e)}")
    
    async def _analyze_hop_url_reputation(
        self,
        hop: RedirectHop,
        url_analyzers: List[IAnalyzer]
    ):
        """Analyze URL reputation for a single hop"""
        max_score = 0.0
        
        # Run reputation checks in parallel
        tasks = []
        for analyzer in url_analyzers:
            if analyzer.is_available:
                task = asyncio.create_task(
                    analyzer.analyze(hop.url, AnalysisType.URL_SCAN)
                )
                tasks.append((analyzer.service_name, task))
        
        # Collect results
        for service_name, task in tasks:
            try:
                result = await asyncio.wait_for(task, timeout=10)
                if result.threat_score is not None:
                    max_score = max(max_score, result.threat_score)
                    
                    if service_name == "virustotal":
                        hop.vt_score = result.threat_score
                    elif service_name == "domain_reputation":
                        hop.domain_reputation = result.threat_score
                        
            except asyncio.TimeoutError:
                logger.warning(f"Timeout during {service_name} analysis for {hop.url}")
            except Exception as e:
                logger.error(f"Error in {service_name} analysis: {str(e)}")
    
    async def _analyze_hop_ip_reputation(
        self,
        hop: RedirectHop,
        ip_analyzers: List[IAnalyzer]
    ):
        """Analyze IP reputation for a single hop"""
        if not hop.resolved_ip:
            return
        
        max_score = 0.0
        
        # Run IP reputation checks in parallel
        tasks = []
        for analyzer in ip_analyzers:
            if analyzer.is_available:
                task = asyncio.create_task(
                    analyzer.analyze(hop.resolved_ip, AnalysisType.IP_REPUTATION)
                )
                tasks.append((analyzer.service_name, task))
        
        # Collect results
        for service_name, task in tasks:
            try:
                result = await asyncio.wait_for(task, timeout=10)
                if result.threat_score is not None:
                    max_score = max(max_score, result.threat_score)
                    
                    if service_name == "abuseipdb":
                        hop.abuse_score = result.threat_score
                        
            except asyncio.TimeoutError:
                logger.warning(f"Timeout during {service_name} IP analysis for {hop.resolved_ip}")
            except Exception as e:
                logger.error(f"Error in {service_name} IP analysis: {str(e)}")
    
    async def _perform_security_analysis(self, result: RedirectAnalysisResult):
        """Perform comprehensive security analysis of the redirect chain"""
        
        # Analyze redirect chain security
        security_analysis = RedirectChainAnalyzer.analyze_security_issues(result.redirect_chain)
        
        result.insecure_hops = security_analysis['insecure_hops']
        result.mixed_content_detected = security_analysis['mixed_content']
        
        # Check TLS validity across the chain
        result.tls_chain_valid = True
        for hop in result.redirect_chain:
            if hop.tls_info and hop.tls_info.validation_status.value not in ["valid", "not_https"]:
                result.tls_chain_valid = False
                break
        
        # Calculate chain reputation score
        result.chain_reputation_score = RedirectChainAnalyzer.calculate_chain_reputation(
            result.redirect_chain
        )
        
        # Identify malicious hops
        result.malicious_hops = []
        result.highest_threat_hop = None
        max_threat_score = 0.0
        
        for hop in result.redirect_chain:
            hop_threat_score = max(
                hop.vt_score or 0.0,
                hop.abuse_score or 0.0,
                hop.domain_reputation or 0.0
            )
            
            if hop_threat_score > 0.3:  # Threshold for suspicious
                result.malicious_hops.append(hop.hop_number)
            
            if hop_threat_score > max_threat_score:
                max_threat_score = hop_threat_score
                result.highest_threat_hop = hop.hop_number
        
        # Determine threat level
        if result.chain_reputation_score > 0.7:
            result.threat_level = "critical"
        elif result.chain_reputation_score > 0.5:
            result.threat_level = "high"
        elif result.chain_reputation_score > 0.3:
            result.threat_level = "medium"
        else:
            result.threat_level = "low"
        
        # Collect risk factors
        if result.cloaking_analysis and result.cloaking_analysis.is_cloaking_detected:
            result.risk_factors.append("Cloaking behavior detected")
        
        if not result.tls_chain_valid:
            result.risk_factors.append("TLS certificate issues in chain")
        
        if result.mixed_content_detected:
            result.risk_factors.append("Mixed HTTP/HTTPS content")
        
        if len(result.malicious_hops) > 0:
            result.risk_factors.append(f"{len(result.malicious_hops)} malicious hops detected")
        
        if result.max_hops_reached:
            result.risk_factors.append("Maximum hop limit reached")
        
        # Analyze browser results for additional risks
        if result.user_browser_result:
            if result.user_browser_result.forms_detected:
                credential_forms = [
                    f for f in result.user_browser_result.forms_detected
                    if 'password' in f.get('input_types', [])
                ]
                if credential_forms:
                    result.risk_factors.append("Credential harvesting forms detected")
            
            if result.user_browser_result.javascript_errors:
                result.risk_factors.append("JavaScript errors detected")
    
    async def _generate_recommendations(self, result: RedirectAnalysisResult):
        """Generate actionable recommendations based on analysis"""
        
        if result.threat_level in ["high", "critical"]:
            result.recommendations.append("BLOCK: High threat level detected")
        
        if result.cloaking_analysis and result.cloaking_analysis.is_cloaking_detected:
            result.recommendations.append("BLOCK: Cloaking behavior indicates malicious intent")
        
        if len(result.malicious_hops) > 0:
            result.recommendations.append(
                f"INVESTIGATE: {len(result.malicious_hops)} hops with poor reputation"
            )
        
        if not result.tls_chain_valid:
            result.recommendations.append("WARNING: TLS certificate issues in redirect chain")
        
        if result.mixed_content_detected:
            result.recommendations.append("WARNING: Mixed HTTP/HTTPS content detected")
        
        if result.max_hops_reached:
            result.recommendations.append("INVESTIGATE: Unusually long redirect chain")
        
        # Browser-based recommendations
        if result.user_browser_result:
            credential_forms = [
                f for f in result.user_browser_result.forms_detected
                if 'password' in f.get('input_types', [])
            ]
            if credential_forms:
                result.recommendations.append("WARNING: Credential harvesting forms detected")
            
            if result.user_browser_result.javascript_errors:
                result.recommendations.append("MONITOR: JavaScript errors may indicate issues")
        
        # Default recommendation if no specific threats
        if not result.recommendations and result.threat_level == "low":
            result.recommendations.append("ALLOW: No significant threats detected")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check the health of the redirect analyzer service
        
        Returns:
            Health status information
        """
        health = {
            "service": "LinkRedirectAnalyzer",
            "status": "healthy",
            "components": {},
            "timestamp": time.time()
        }
        
        try:
            # Check HTTP tracer
            health["components"]["http_tracer"] = {
                "status": "available",
                "type": type(self.http_tracer).__name__
            }
            
            # Check browser analyzer
            health["components"]["browser_analyzer"] = {
                "status": "available",
                "type": type(self.browser_analyzer).__name__
            }
            
            # Check cloaking detector
            health["components"]["cloaking_detector"] = {
                "status": "available",
                "type": type(self.cloaking_detector).__name__
            }
            
            # Check reputation factory
            if self.reputation_factory:
                health["components"]["reputation_factory"] = {
                    "status": "available",
                    "mode": self.reputation_factory.config.mode.value if self.reputation_factory.config else "unknown"
                }
            else:
                health["components"]["reputation_factory"] = {
                    "status": "not_configured"
                }
        
        except Exception as e:
            health["status"] = "degraded"
            health["error"] = str(e)
        
        return health


# Factory function for creating configured redirect analyzer
async def create_redirect_analyzer(
    reputation_factory: Optional[AnalyzerFactory] = None,
    browser_type: str = "chromium",
    screenshot_dir: Optional[str] = None
) -> LinkRedirectAnalyzer:
    """
    Create a configured LinkRedirectAnalyzer instance
    
    Args:
        reputation_factory: Factory for reputation analysis services
        browser_type: Browser type for Playwright ("chromium", "firefox", "webkit")
        screenshot_dir: Directory for storing screenshots
        
    Returns:
        Configured LinkRedirectAnalyzer instance
    """
    
    # Create HTTP tracer
    http_tracer = HTTPRedirectTracer(
        max_concurrent_requests=3,
        default_timeout=15,
        verify_ssl=True
    )
    
    # Create browser analyzer
    browser_analyzer = BrowserRedirectAnalyzer(
        browser_type=browser_type,
        headless=True,
        screenshot_dir=screenshot_dir
    )
    
    # Create cloaking detector
    cloaking_detector = CloakingDetectionEngine()
    
    # Create main analyzer
    analyzer = LinkRedirectAnalyzer(
        http_tracer=http_tracer,
        browser_analyzer=browser_analyzer,
        cloaking_detector=cloaking_detector,
        reputation_factory=reputation_factory
    )
    
    return analyzer
