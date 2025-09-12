"""
Enhanced threat orchestrator that integrates real analyzers with privacy-preserving features.
Replaces mock analyzers with production-ready threat detection services.
"""

import asyncio
import time
import hashlib
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime
import ipaddress

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.redis_client import redis_client
from app.services.analyzer_factory import get_analyzer_factory
from app.services.threat_aggregator import ThreatAggregator, create_threat_aggregator
from app.services.security_sanitizer import get_security_sanitizer
from app.services.url_rewriter import get_url_rewriter
from app.services.audit_service import get_audit_service, log_scan_started, log_scan_completed
from app.services.interfaces import AnalysisType
from app.models.email_scan import ThreatLevel, ScanStatus

logger = get_logger(__name__)


class RealThreatOrchestrator:
    """
    Enhanced threat orchestrator using real analyzers with privacy-preserving features.
    Integrates VirusTotal, AbuseIPDB, Gemini, and comprehensive redirect analysis.
    """
    
    def __init__(self):
        self.analyzer_factory = None
        self.threat_aggregator = create_threat_aggregator()
        self.security_sanitizer = get_security_sanitizer()
        self.url_rewriter = get_url_rewriter()
        self.audit_service = get_audit_service()
        self.sandbox_ips = self._get_sandbox_ip_pool()
        self.initialized = False
        
        # Privacy settings
        self.privacy_config = {
            'redact_user_data': True,
            'use_sandbox_ips': True,
            'anonymize_requests': True,
            'max_content_length': 2000,  # Limit content sent to external APIs
            'allowed_domains_only': False
        }
    
    async def initialize(self):
        """Initialize the orchestrator with real analyzers."""
        try:
            self.analyzer_factory = get_analyzer_factory()
            await self.analyzer_factory.initialize()
            self.initialized = True
            logger.info("RealThreatOrchestrator initialized with real analyzers")
        except Exception as e:
            logger.error(f"Failed to initialize RealThreatOrchestrator: {e}")
            raise
    
    async def analyze_email_comprehensive(
        self, 
        email_data: Dict[str, Any], 
        user_id: Optional[int] = None,
        request_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive email analysis using real threat detection services.
        Includes security sanitization and audit logging.
        
        Args:
            email_data: Email data including headers, content, and links
            user_id: User who initiated the scan
            request_id: Request correlation ID for audit trail
            
        Returns:
            Comprehensive threat analysis result with sanitized content
        """
        if not self.initialized:
            await self.initialize()
        
        start_time = time.time()
        analysis_id = hashlib.md5(str(email_data).encode()).hexdigest()[:16]
        
        # Generate request ID if not provided
        if not request_id:
            request_id = f"scan_{analysis_id}"
        
        logger.info(f"Starting comprehensive analysis {analysis_id}")
        
        # Log scan start for audit trail
        await log_scan_started(
            request_id=request_id,
            user_id=user_id,
            email_id=analysis_id,
            scan_type="comprehensive"
        )
        
        try:
            # SECURITY: Sanitize email content early in pipeline
            sanitized_email = await self._sanitize_email_content_comprehensive(email_data)
            
            # Extract and sanitize data for analysis
            sanitized_data = await self._sanitize_email_data(sanitized_email)
            
            # Run parallel analysis with real services
            analysis_results = await self._run_parallel_analysis(sanitized_data)
            
            # Extract links and analyze separately
            links = self._extract_links(sanitized_email)
            if links:
                link_analysis = await self._analyze_links_comprehensive(links)
                analysis_results['link_analysis'] = link_analysis
            
            # Extract IPs and analyze
            ips = self._extract_ip_addresses(sanitized_email, links)
            if ips:
                ip_analysis = await self._analyze_ips_comprehensive(ips)
                analysis_results['ip_analysis'] = ip_analysis
            
            # Aggregate all results
            aggregated_result = await self.threat_aggregator.aggregate_threat_analysis(
                target=analysis_id,
                analysis_results=analysis_results,
                context={'email_analysis': True, 'analysis_id': analysis_id}
            )
            
            # Format final result with sanitized content for UI display
            final_result = self._format_final_result_with_security(
                aggregated_result, 
                analysis_results, 
                start_time,
                email_content=str(email_data.get('text_content', '') or email_data.get('body', '')),
                user_id=user_id
            )
            
            # Log scan completion for audit trail
            duration_ms = int((time.time() - start_time) * 1000)
            await log_scan_completed(
                request_id=request_id,
                user_id=user_id,
                email_id=analysis_id,
                threat_score=final_result['threat_score'],
                verdict=final_result['verdict'],
                duration_ms=duration_ms,
                services_used=list(analysis_results.keys())
            )
            
            logger.info(f"Analysis {analysis_id} completed: threat_score={final_result['threat_score']}")
            return final_result
            
        except Exception as e:
            logger.error(f"Comprehensive analysis failed for {analysis_id}: {e}")
            
            # Log failed scan for audit trail
            duration_ms = int((time.time() - start_time) * 1000)
            await self.audit_service.log_orchestrator_event(
                action="scan_failed",
                request_id=request_id,
                user_id=user_id,
                email_id=analysis_id,
                description=f"Email scan failed: {str(e)}",
                details={"error": str(e), "error_type": type(e).__name__},
                duration_ms=duration_ms,
                severity="error"
            )
            
            return self._create_error_result(analysis_id, str(e))
    
    async def _sanitize_email_content_comprehensive(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive sanitization of email content for security and safe UI display.
        This is the primary sanitization point before content is stored or displayed.
        """
        try:
            # Use SecuritySanitizer for comprehensive sanitization
            sanitized_email = self.security_sanitizer.sanitize_email_content(email_data)
            
            # Rewrite URLs in content for safe click-through
            if 'html_content' in sanitized_email:
                sanitized_email['html_content'] = self.url_rewriter.rewrite_urls_in_content(
                    sanitized_email['html_content'],
                    context="email",
                    email_id=hashlib.md5(str(email_data).encode()).hexdigest()[:16]
                )
            
            if 'text_content' in sanitized_email:
                sanitized_email['text_content'] = self.url_rewriter.rewrite_urls_in_content(
                    sanitized_email['text_content'],
                    context="email",
                    email_id=hashlib.md5(str(email_data).encode()).hexdigest()[:16]
                )
            
            # Rewrite individual links
            if 'links' in sanitized_email:
                safe_links = []
                for link in sanitized_email['links']:
                    safe_link = self.url_rewriter.rewrite_url(
                        link,
                        context="email",
                        email_id=hashlib.md5(str(email_data).encode()).hexdigest()[:16]
                    )
                    safe_links.append(safe_link)
                sanitized_email['links'] = safe_links
            
            # Log sanitization results if violations found
            sanitization_metadata = sanitized_email.get('_sanitization', {})
            if sanitization_metadata.get('violations_count', 0) > 0:
                await self.audit_service.log_security_event(
                    action="content_sanitized",
                    description=f"Email content sanitized: {sanitization_metadata['violations_count']} violations found",
                    details={
                        "violations": sanitization_metadata.get('violations', []),
                        "email_id": hashlib.md5(str(email_data).encode()).hexdigest()[:16]
                    },
                    is_suspicious=True,
                    security_violation=sanitization_metadata['violations_count'] > 5
                )
            
            return sanitized_email
            
        except Exception as e:
            logger.error(f"Email content sanitization failed: {e}")
            # Fall back to basic sanitization
            return self._basic_email_sanitization_fallback(email_data)
    
    async def _sanitize_email_data(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize email data for external API calls with privacy protection."""
        sanitized = {}
        
        # Extract headers safely
        headers = email_data.get('headers', {})
        safe_headers = {}
        
        # Only include safe headers, redact sensitive information
        safe_header_keys = ['subject', 'from', 'to', 'date', 'message-id']
        for key in safe_header_keys:
            if key in headers:
                value = headers[key]
                if self.privacy_config['redact_user_data']:
                    value = self._redact_sensitive_data(value)
                safe_headers[key] = value
        
        sanitized['headers'] = safe_headers
        
        # Sanitize content
        content = email_data.get('text_content', '') or email_data.get('body', '')
        if content:
            # Limit content length
            if len(content) > self.privacy_config['max_content_length']:
                content = content[:self.privacy_config['max_content_length']] + "...[truncated]"
            
            # Redact sensitive data
            if self.privacy_config['redact_user_data']:
                content = self._redact_sensitive_data(content)
            
            sanitized['content'] = content
        
        # Include links safely
        links = email_data.get('links', [])
        sanitized['links'] = links[:20]  # Limit number of links
        
        return sanitized
    
    def _redact_sensitive_data(self, text: str) -> str:
        """Redact sensitive data from text before sending to external APIs."""
        if not text:
            return text
        
        # Redact email addresses (keep domain for analysis)
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})', r'[USER]@\\1', text)
        
        # Redact phone numbers
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', text)
        
        # Redact credit card numbers
        text = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CARD]', text)
        
        # Redact SSN patterns
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]', text)
        
        # Redact potential passwords/tokens (common patterns)
        text = re.sub(r'\b[A-Za-z0-9+/]{20,}\b', '[TOKEN]', text)
        
        return text
    
    async def _run_parallel_analysis(self, sanitized_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Run parallel analysis with real threat detection services."""
        analyzers = self.analyzer_factory.get_real_analyzers()
        results = {}
        
        # Prepare analysis tasks
        tasks = []
        
        # Text analysis with Gemini (if available)
        if 'gemini' in analyzers and sanitized_data.get('content'):
            task = self._run_gemini_analysis(analyzers['gemini'], sanitized_data['content'])
            tasks.append(('gemini', task))
        
        # VirusTotal analysis for any URLs in headers/content
        if 'virustotal' in analyzers:
            urls = self._extract_urls_from_text(str(sanitized_data))
            if urls:
                task = self._run_virustotal_analysis(analyzers['virustotal'], urls[:5])  # Limit URLs
                tasks.append(('virustotal', task))
        
        # Execute tasks with timeout
        if tasks:
            completed_results = await self._execute_tasks_with_timeout(tasks, timeout=30)
            results.update(completed_results)
        
        return results
    
    async def _run_gemini_analysis(self, gemini_analyzer, content: str) -> Dict[str, Any]:
        """Run Gemini text analysis with error handling."""
        try:
            result = await gemini_analyzer.scan(content)
            return result
        except Exception as e:
            logger.error(f"Gemini analysis failed: {e}")
            return {
                'threat_score': 0.0,
                'verdict': 'error',
                'confidence': 0.0,
                'indicators': [f'gemini_error: {str(e)}'],
                'service': 'gemini'
            }
    
    async def _run_virustotal_analysis(self, vt_analyzer, urls: List[str]) -> Dict[str, Any]:
        """Run VirusTotal analysis for URLs with privacy protection."""
        try:
            # Analyze each URL and aggregate results
            url_results = []
            
            for url in urls:
                try:
                    result = await vt_analyzer.scan(url)
                    url_results.append(result)
                    # Rate limiting
                    await asyncio.sleep(1)
                except Exception as e:
                    logger.warning(f"VirusTotal analysis failed for {url}: {e}")
                    url_results.append({
                        'threat_score': 0.0,
                        'verdict': 'error',
                        'error': str(e)
                    })
            
            # Aggregate URL results
            if url_results:
                avg_score = sum(r.get('threat_score', 0.0) for r in url_results) / len(url_results)
                malicious_count = sum(1 for r in url_results if r.get('verdict') == 'malicious')
                
                return {
                    'threat_score': avg_score,
                    'verdict': 'malicious' if malicious_count > 0 else 'safe',
                    'confidence': 0.8,
                    'indicators': [f'analyzed_{len(url_results)}_urls', f'malicious_urls_{malicious_count}'],
                    'service': 'virustotal',
                    'url_results': url_results
                }
            else:
                return {
                    'threat_score': 0.0,
                    'verdict': 'safe',
                    'confidence': 0.5,
                    'indicators': ['no_urls_analyzed'],
                    'service': 'virustotal'
                }
                
        except Exception as e:
            logger.error(f"VirusTotal analysis failed: {e}")
            return {
                'threat_score': 0.0,
                'verdict': 'error',
                'confidence': 0.0,
                'indicators': [f'virustotal_error: {str(e)}'],
                'service': 'virustotal'
            }
    
    async def _analyze_links_comprehensive(self, links: List[str]) -> Dict[str, Any]:
        """Comprehensive link analysis using redirect analyzer."""
        analyzers = self.analyzer_factory.get_real_analyzers()
        
        if 'link_redirect_analyzer' not in analyzers:
            return {
                'threat_score': 0.0,
                'verdict': 'error',
                'confidence': 0.0,
                'indicators': ['redirect_analyzer_unavailable'],
                'service': 'link_redirect_analyzer'
            }
        
        try:
            redirect_analyzer = analyzers['link_redirect_analyzer']
            link_results = []
            
            # Analyze each link (limit to prevent abuse)
            for link in links[:10]:
                try:
                    result = await redirect_analyzer.scan(link)
                    link_results.append(result)
                    # Delay between analyses
                    await asyncio.sleep(2)
                except Exception as e:
                    logger.warning(f"Link analysis failed for {link}: {e}")
                    link_results.append({
                        'threat_score': 0.0,
                        'verdict': 'error',
                        'error': str(e)
                    })
            
            # Aggregate link analysis results
            if link_results:
                avg_score = sum(r.get('threat_score', 0.0) for r in link_results)
                malicious_count = sum(1 for r in link_results if r.get('verdict') == 'malicious')
                suspicious_count = sum(1 for r in link_results if r.get('verdict') == 'suspicious')
                
                # Collect all indicators
                all_indicators = []
                for result in link_results:
                    all_indicators.extend(result.get('indicators', []))
                
                verdict = 'safe'
                if malicious_count > 0:
                    verdict = 'malicious'
                elif suspicious_count > 0:
                    verdict = 'suspicious'
                
                return {
                    'threat_score': min(avg_score, 1.0),
                    'verdict': verdict,
                    'confidence': 0.9,
                    'indicators': list(set(all_indicators))[:15],  # Unique indicators
                    'service': 'link_redirect_analyzer',
                    'stats': {
                        'total_links': len(link_results),
                        'malicious': malicious_count,
                        'suspicious': suspicious_count
                    },
                    'link_results': link_results
                }
            else:
                return {
                    'threat_score': 0.0,
                    'verdict': 'safe',
                    'confidence': 0.5,
                    'indicators': ['no_links_analyzed'],
                    'service': 'link_redirect_analyzer'
                }
                
        except Exception as e:
            logger.error(f"Link analysis failed: {e}")
            return {
                'threat_score': 0.0,
                'verdict': 'error',
                'confidence': 0.0,
                'indicators': [f'link_analysis_error: {str(e)}'],
                'service': 'link_redirect_analyzer'
            }
    
    async def _analyze_ips_comprehensive(self, ips: List[str]) -> Dict[str, Any]:
        """Comprehensive IP analysis using AbuseIPDB."""
        analyzers = self.analyzer_factory.get_real_analyzers()
        
        if 'abuseipdb' not in analyzers:
            return {
                'threat_score': 0.0,
                'verdict': 'error',
                'confidence': 0.0,
                'indicators': ['abuseipdb_unavailable'],
                'service': 'abuseipdb'
            }
        
        try:
            abuseipdb_analyzer = analyzers['abuseipdb']
            ip_results = []
            
            # Analyze each IP (limit to prevent abuse)
            for ip in ips[:5]:
                try:
                    result = await abuseipdb_analyzer.scan(ip)
                    ip_results.append(result)
                    # Rate limiting
                    await asyncio.sleep(1)
                except Exception as e:
                    logger.warning(f"IP analysis failed for {ip}: {e}")
                    ip_results.append({
                        'threat_score': 0.0,
                        'verdict': 'error',
                        'error': str(e)
                    })
            
            # Aggregate IP analysis results
            if ip_results:
                avg_score = sum(r.get('threat_score', 0.0) for r in ip_results) / len(ip_results)
                malicious_count = sum(1 for r in ip_results if r.get('verdict') == 'malicious')
                
                # Collect all indicators
                all_indicators = []
                for result in ip_results:
                    all_indicators.extend(result.get('indicators', []))
                
                verdict = 'malicious' if malicious_count > 0 else 'safe'
                
                return {
                    'threat_score': avg_score,
                    'verdict': verdict,
                    'confidence': 0.8,
                    'indicators': list(set(all_indicators))[:10],  # Unique indicators
                    'service': 'abuseipdb',
                    'stats': {
                        'total_ips': len(ip_results),
                        'malicious': malicious_count
                    },
                    'ip_results': ip_results
                }
            else:
                return {
                    'threat_score': 0.0,
                    'verdict': 'safe',
                    'confidence': 0.5,
                    'indicators': ['no_ips_analyzed'],
                    'service': 'abuseipdb'
                }
                
        except Exception as e:
            logger.error(f"IP analysis failed: {e}")
            return {
                'threat_score': 0.0,
                'verdict': 'error',
                'confidence': 0.0,
                'indicators': [f'ip_analysis_error: {str(e)}'],
                'service': 'abuseipdb'
            }
    
    async def _execute_tasks_with_timeout(
        self, 
        tasks: List[Tuple[str, asyncio.Task]], 
        timeout: int = 30
    ) -> Dict[str, Dict[str, Any]]:
        """Execute analysis tasks with timeout protection."""
        results = {}
        
        try:
            # Wait for all tasks with timeout
            task_dict = {name: task for name, task in tasks}
            done, pending = await asyncio.wait(
                task_dict.values(),
                timeout=timeout,
                return_when=asyncio.ALL_COMPLETED
            )
            
            # Collect results from completed tasks
            for name, task in task_dict.items():
                if task in done:
                    try:
                        result = await task
                        results[name] = result
                    except Exception as e:
                        logger.error(f"Task {name} failed: {e}")
                        results[name] = {
                            'threat_score': 0.0,
                            'verdict': 'error',
                            'confidence': 0.0,
                            'indicators': [f'{name}_error: {str(e)}'],
                            'service': name
                        }
                else:
                    # Task timed out
                    task.cancel()
                    results[name] = {
                        'threat_score': 0.0,
                        'verdict': 'error',
                        'confidence': 0.0,
                        'indicators': [f'{name}_timeout'],
                        'service': name
                    }
            
        except Exception as e:
            logger.error(f"Task execution failed: {e}")
        
        return results
    
    def _extract_links(self, email_data: Dict[str, Any]) -> List[str]:
        """Extract links from email data."""
        links = []
        
        # Direct links
        if 'links' in email_data:
            links.extend(email_data['links'])
        
        # Extract from content
        content = email_data.get('text_content', '') or email_data.get('body', '')
        if content:
            url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
            found_urls = re.findall(url_pattern, content)
            links.extend(found_urls)
        
        # Extract from headers
        headers = email_data.get('headers', {})
        for header_value in headers.values():
            if isinstance(header_value, str):
                found_urls = re.findall(r'https?://[^\s<>"]+', header_value)
                links.extend(found_urls)
        
        # Clean and deduplicate
        clean_links = []
        for link in links:
            if isinstance(link, str) and len(link) > 10:
                # Basic URL validation
                try:
                    parsed = urlparse(link)
                    if parsed.scheme and parsed.netloc:
                        clean_links.append(link)
                except:
                    pass
        
        return list(set(clean_links))[:20]  # Limit and deduplicate
    
    def _extract_ip_addresses(self, email_data: Dict[str, Any], links: List[str]) -> List[str]:
        """Extract IP addresses from email data and links."""
        ips = set()
        
        # Extract from content
        content = str(email_data)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        found_ips = re.findall(ip_pattern, content)
        
        for ip_str in found_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                # Only include public IPs
                if not ip.is_private and not ip.is_loopback:
                    ips.add(str(ip))
            except ValueError:
                pass
        
        # Extract from link domains that are IPs
        for link in links:
            try:
                parsed = urlparse(link)
                if parsed.netloc:
                    # Check if netloc is an IP
                    hostname = parsed.netloc.split(':')[0]  # Remove port
                    ip = ipaddress.ip_address(hostname)
                    if not ip.is_private and not ip.is_loopback:
                        ips.add(str(ip))
            except ValueError:
                pass
        
        return list(ips)[:10]  # Limit
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text content."""
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        urls = re.findall(url_pattern, text)
        
        clean_urls = []
        for url in urls:
            try:
                if not url.startswith('http'):
                    url = 'http://' + url
                parsed = urlparse(url)
                if parsed.scheme and parsed.netloc:
                    clean_urls.append(url)
            except:
                pass
        
        return clean_urls
    
    def _format_final_result(
        self,
        aggregated_result,
        analysis_results: Dict[str, Dict[str, Any]],
        start_time: float
    ) -> Dict[str, Any]:
        """Format the final analysis result."""
        execution_time = time.time() - start_time
        
        return {
            'threat_score': aggregated_result.threat_score,
            'threat_level': aggregated_result.threat_level.value,
            'confidence': aggregated_result.confidence,
            'verdict': aggregated_result.verdict,
            'explanation': aggregated_result.explanation,
            'indicators': aggregated_result.indicators,
            'recommendations': aggregated_result.recommendations,
            'analysis_results': analysis_results,
            'metadata': {
                'analysis_id': aggregated_result.metadata.get('analysis_id'),
                'execution_time_seconds': round(execution_time, 2),
                'services_used': list(analysis_results.keys()),
                'privacy_protected': True,
                'timestamp': aggregated_result.timestamp
            }
        }
    
    def _format_final_result_with_security(
        self,
        aggregated_result,
        analysis_results: Dict[str, Dict[str, Any]],
        start_time: float,
        email_content: str,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Format final result with comprehensive security sanitization."""
        try:
            # Get base formatted result
            result = self._format_final_result(aggregated_result, analysis_results, start_time)
            
            # Sanitize all text fields
            if self.security_sanitizer:
                # Sanitize main text fields
                result['explanation'] = self.security_sanitizer.sanitize_text(result.get('explanation', ''))
                result['verdict'] = self.security_sanitizer.sanitize_text(result.get('verdict', ''))
                
                # Sanitize indicators list
                if 'indicators' in result and isinstance(result['indicators'], list):
                    result['indicators'] = [
                        self.security_sanitizer.sanitize_text(str(indicator))
                        for indicator in result['indicators']
                    ]
                
                # Sanitize recommendations list
                if 'recommendations' in result and isinstance(result['recommendations'], list):
                    result['recommendations'] = [
                        self.security_sanitizer.sanitize_text(str(rec))
                        for rec in result['recommendations']
                    ]
                
                # Sanitize analysis results
                if 'analysis_results' in result:
                    for service_name, service_result in result['analysis_results'].items():
                        if isinstance(service_result, dict):
                            for key, value in service_result.items():
                                if isinstance(value, str):
                                    service_result[key] = self.security_sanitizer.sanitize_text(value)
                
                # Add sanitized email content for frontend display
                result['email_content_safe'] = self.security_sanitizer.sanitize_html(email_content)
                
                # Rewrite any URLs found in the content for click-through protection
                if self.url_rewriter:
                    result['email_content_safe'] = self.url_rewriter.rewrite_content_urls(
                        result['email_content_safe'],
                        user_id=user_id
                    )
            
            # Log security processing
            if self.audit_service and user_id:
                self.audit_service.log_security_event(
                    user_id=user_id,
                    event_type="content_sanitization",
                    details={
                        'analysis_id': result['metadata'].get('analysis_id'),
                        'content_length': len(email_content),
                        'sanitizer_applied': bool(self.security_sanitizer),
                        'url_rewriter_applied': bool(self.url_rewriter)
                    }
                )
            
            return result
            
        except Exception as e:
            # Fallback to basic sanitization
            logger.error(f"Security formatting failed: {e}")
            return self._basic_sanitization_fallback(aggregated_result, analysis_results, start_time)
    
    def _basic_sanitization_fallback(
        self,
        aggregated_result,
        analysis_results: Dict[str, Dict[str, Any]],
        start_time: float
    ) -> Dict[str, Any]:
        """Basic sanitization fallback when comprehensive security fails."""
        result = self._format_final_result(aggregated_result, analysis_results, start_time)
        
        # Basic text cleaning without external dependencies
        def basic_clean(text: str) -> str:
            if not isinstance(text, str):
                return str(text)
            # Remove potential script tags and basic XSS patterns
            cleaned = text.replace('<script', '&lt;script')
            cleaned = cleaned.replace('javascript:', 'blocked:')
            cleaned = cleaned.replace('onload=', 'data-blocked=')
            cleaned = cleaned.replace('onerror=', 'data-blocked=')
            return cleaned
        
        # Apply basic cleaning to text fields
        if 'explanation' in result:
            result['explanation'] = basic_clean(result['explanation'])
        if 'verdict' in result:
            result['verdict'] = basic_clean(result['verdict'])
        if 'indicators' in result and isinstance(result['indicators'], list):
            result['indicators'] = [basic_clean(str(item)) for item in result['indicators']]
        if 'recommendations' in result and isinstance(result['recommendations'], list):
            result['recommendations'] = [basic_clean(str(item)) for item in result['recommendations']]
        
        # Mark as fallback sanitization
        result['metadata']['security_fallback'] = True
        
        return result
    
    def _create_error_result(self, analysis_id: str, error_message: str) -> Dict[str, Any]:
        """Create error result when analysis fails."""
        return {
            'threat_score': 0.0,
            'threat_level': ThreatLevel.SAFE.value,
            'confidence': 0.0,
            'verdict': 'ERROR',
            'explanation': f'Analysis failed: {error_message}',
            'indicators': [f'analysis_error: {error_message}'],
            'recommendations': ['Retry analysis', 'Check service availability'],
            'analysis_results': {},
            'metadata': {
                'analysis_id': analysis_id,
                'error': error_message,
                'timestamp': time.time()
            }
        }
    
    def _get_sandbox_ip_pool(self) -> List[str]:
        """Get pool of sandbox IP addresses for external API calls."""
        # In production, this would be a pool of dedicated sandbox IPs
        # For now, return empty list (will use default routing)
        return []
    
    async def health_check(self) -> Dict[str, Any]:
        """Check health of all integrated services."""
        if not self.initialized:
            return {'status': 'not_initialized'}
        
        try:
            health_results = await self.analyzer_factory.run_health_checks()
            
            available_count = sum(
                1 for health in health_results.values()
                if health.status.value == 'available'
            )
            
            overall_status = 'healthy' if available_count >= 2 else 'degraded'
            
            return {
                'status': overall_status,
                'available_services': available_count,
                'total_services': len(health_results),
                'service_health': {
                    name: health.status.value 
                    for name, health in health_results.items()
                },
                'timestamp': time.time()
            }
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': time.time()
            }
    
    def _basic_email_sanitization_fallback(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Basic email content sanitization fallback when comprehensive security fails."""
        sanitized = email_data.copy()
        
        def basic_clean(text: str) -> str:
            if not isinstance(text, str):
                return str(text)
            # Remove potential script tags and basic XSS patterns
            cleaned = text.replace('<script', '&lt;script')
            cleaned = cleaned.replace('<Script', '&lt;Script')
            cleaned = cleaned.replace('<SCRIPT', '&lt;SCRIPT')
            cleaned = cleaned.replace('javascript:', 'blocked:')
            cleaned = cleaned.replace('data:text/html', 'blocked:html')
            cleaned = cleaned.replace('onload=', 'data-blocked=')
            cleaned = cleaned.replace('onerror=', 'data-blocked=')
            cleaned = cleaned.replace('onclick=', 'data-blocked=')
            cleaned = cleaned.replace('onmouseover=', 'data-blocked=')
            return cleaned
        
        # Apply basic cleaning to content fields
        if 'html_content' in sanitized:
            sanitized['html_content'] = basic_clean(sanitized['html_content'])
        if 'text_content' in sanitized:
            sanitized['text_content'] = basic_clean(sanitized['text_content'])
        if 'body' in sanitized:
            sanitized['body'] = basic_clean(sanitized['body'])
        
        # Clean headers
        if 'headers' in sanitized:
            for key, value in sanitized['headers'].items():
                if isinstance(value, str):
                    sanitized['headers'][key] = basic_clean(value)
        
        # Clean subject
        if 'subject' in sanitized:
            sanitized['subject'] = basic_clean(sanitized['subject'])
        
        # Clean sender/recipient info
        for field in ['from', 'to', 'sender', 'recipient']:
            if field in sanitized:
                sanitized[field] = basic_clean(str(sanitized[field]))
        
        # Mark as fallback sanitization
        sanitized['_sanitization'] = {
            'method': 'basic_fallback',
            'violations_count': 0,
            'timestamp': time.time()
        }
        
        return sanitized

    async def full_scan(
        self,
        email_data: Dict[str, Any],
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        persist_results: bool = True
    ) -> Dict[str, Any]:
        """
        Complete email scanning with sanitization, analysis, and optional persistence.
        
        This method provides a comprehensive scanning interface that:
        1. Sanitizes all content early in the pipeline
        2. Performs full threat analysis
        3. Optionally persists results to database
        4. Returns sanitized, secure results for UI display
        
        Args:
            email_data: Raw email data to analyze
            user_id: User performing the scan
            request_id: Request correlation ID
            persist_results: Whether to save results to database
            
        Returns:
            Comprehensive analysis results with sanitized content
        """
        start_time = time.time()
        analysis_id = request_id or f"full_scan_{int(start_time)}"
        
        try:
            # 1. SECURITY: Immediate content sanitization
            logger.info(f"Starting full scan {analysis_id} - sanitizing content")
            sanitized_email = await self._sanitize_email_content_comprehensive(email_data)
            
            # 2. Perform comprehensive analysis with sanitized content
            results = await self.analyze_email_comprehensive(
                email_data=sanitized_email,
                user_id=user_id,
                request_id=request_id
            )
            
            # 3. Additional sanitization of results for UI safety
            if 'email_content_safe' not in results:
                # Ensure UI-safe content is available
                original_content = email_data.get('html_content') or email_data.get('text_content', '')
                if self.security_sanitizer:
                    results['email_content_safe'] = self.security_sanitizer.sanitize_html(original_content)
                else:
                    results['email_content_safe'] = self._basic_sanitization_fallback(
                        {'content': original_content}
                    ).get('content', '')
            
            # 4. Database persistence (optional)
            if persist_results:
                await self._persist_scan_results(analysis_id, results, user_id)
            
            # 5. Audit logging for full scan completion
            if self.audit_service:
                duration_ms = int((time.time() - start_time) * 1000)
                await self.audit_service.log_orchestrator_event(
                    action="full_scan_completed",
                    request_id=request_id,
                    user_id=user_id,
                    email_id=analysis_id,
                    description=f"Full email scan completed successfully",
                    details={
                        "threat_score": results.get('threat_score', 0),
                        "verdict": results.get('verdict', 'unknown'),
                        "services_used": results.get('metadata', {}).get('services_used', []),
                        "content_sanitized": True,
                        "persistence_enabled": persist_results
                    },
                    duration_ms=duration_ms,
                    severity="info"
                )
            
            logger.info(f"Full scan {analysis_id} completed successfully")
            return results
            
        except Exception as e:
            logger.error(f"Full scan {analysis_id} failed: {e}")
            
            # Log scan failure
            if self.audit_service:
                duration_ms = int((time.time() - start_time) * 1000)
                await self.audit_service.log_orchestrator_event(
                    action="full_scan_failed",
                    request_id=request_id,
                    user_id=user_id,
                    email_id=analysis_id,
                    description=f"Full email scan failed: {str(e)}",
                    details={"error": str(e), "error_type": type(e).__name__},
                    duration_ms=duration_ms,
                    severity="error"
                )
            
            return self._create_error_result(analysis_id, str(e))
    
    async def _persist_scan_results(
        self,
        analysis_id: str,
        results: Dict[str, Any],
        user_id: Optional[str] = None
    ) -> None:
        """Persist scan results to database with sanitized content."""
        try:
            from app.models.email_scan import EmailScan
            from app.db.session import get_db_session
            
            async with get_db_session() as db:
                # Create email scan record with sanitized content
                email_scan = EmailScan(
                    id=analysis_id,
                    user_id=user_id,
                    threat_score=results.get('threat_score', 0.0),
                    threat_level=results.get('threat_level', 'safe'),
                    verdict=results.get('verdict', 'unknown'),
                    explanation=results.get('explanation', ''),
                    
                    # Store sanitized content for safe UI display
                    email_content_safe=results.get('email_content_safe', ''),
                    
                    # Store analysis results as JSON
                    analysis_results=results.get('analysis_results', {}),
                    indicators=results.get('indicators', []),
                    recommendations=results.get('recommendations', []),
                    
                    # Metadata
                    execution_time_seconds=results.get('metadata', {}).get('execution_time_seconds', 0),
                    services_used=results.get('metadata', {}).get('services_used', []),
                    
                    # Security flags
                    content_sanitized=True,
                    is_quarantined=results.get('threat_score', 0) > 0.8
                )
                
                db.add(email_scan)
                await db.commit()
                
                logger.info(f"Scan results persisted for {analysis_id}")
                
        except Exception as e:
            logger.error(f"Failed to persist scan results for {analysis_id}: {e}")


# Factory function
def create_real_threat_orchestrator() -> RealThreatOrchestrator:
    """Factory function to create RealThreatOrchestrator."""
    return RealThreatOrchestrator()
