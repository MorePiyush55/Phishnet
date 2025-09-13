"""Enhanced threat analysis orchestrator with multiple security components."""

import asyncio
import json
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import traceback
import re
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import aiohttp
import ssl
from concurrent.futures import ThreadPoolExecutor
import time

from app.config.settings import settings
from app.config.logging import get_logger
from app.core.database import get_db
from app.core.redis_client import redis_client
from app.models.email_scan import (
    EmailScanRequest, ThreatResult, AnalysisComponentResult, 
    ScanStatus, ThreatLevel
)
from app.core.metrics import threat_analysis_metrics

logger = get_logger(__name__)


class LinkRedirectAnalyzer:
    """Sandboxed link redirect chain analyzer."""
    
    def __init__(self):
        """Initialize link analyzer with safe session."""
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Security headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; PhishNet-Security-Scanner/1.0)',
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive'
        })
        
        # Timeout settings
        self.timeout = 10
        self.max_redirects = 10
        
    async def analyze_links(self, links: List[str]) -> Dict[str, Any]:
        """Analyze links for suspicious patterns and redirects."""
        try:
            if not links:
                return {"verdict": "safe", "score": 0.0, "findings": []}
            
            findings = []
            suspicious_count = 0
            malicious_count = 0
            total_score = 0.0
            
            for link in links[:20]:  # Limit analysis to first 20 links
                try:
                    link_analysis = await self._analyze_single_link(link)
                    findings.append(link_analysis)
                    
                    if link_analysis["verdict"] == "suspicious":
                        suspicious_count += 1
                    elif link_analysis["verdict"] == "malicious":
                        malicious_count += 1
                    
                    total_score += link_analysis["score"]
                    
                except Exception as e:
                    logger.error(f"Failed to analyze link {link}: {e}")
                    findings.append({
                        "url": link,
                        "verdict": "error",
                        "score": 0.0,
                        "error": str(e)
                    })
            
            # Calculate overall verdict
            avg_score = total_score / len(findings) if findings else 0.0
            
            if malicious_count > 0:
                verdict = "malicious"
            elif suspicious_count >= len(findings) * 0.5:  # 50% or more suspicious
                verdict = "suspicious"
            elif avg_score > 0.6:
                verdict = "suspicious"
            else:
                verdict = "safe"
            
            return {
                "verdict": verdict,
                "score": min(avg_score, 1.0),
                "findings": findings,
                "stats": {
                    "total_links": len(findings),
                    "suspicious": suspicious_count,
                    "malicious": malicious_count,
                    "safe": len(findings) - suspicious_count - malicious_count
                }
            }
            
        except Exception as e:
            logger.error(f"Link analysis failed: {e}")
            return {
                "verdict": "error",
                "score": 0.0,
                "error": str(e),
                "findings": []
            }
    
    async def _analyze_single_link(self, url: str) -> Dict[str, Any]:
        """Analyze a single link safely."""
        start_time = time.time()
        
        try:
            # Static analysis first
            static_analysis = self._static_url_analysis(url)
            
            # Skip dynamic analysis for obviously malicious URLs
            if static_analysis["score"] >= 0.8:
                return {
                    "url": url,
                    "verdict": "malicious",
                    "score": static_analysis["score"],
                    "indicators": static_analysis["indicators"],
                    "redirect_chain": [],
                    "analysis_type": "static_only"
                }
            
            # Dynamic analysis with redirect following
            dynamic_analysis = await self._dynamic_url_analysis(url)
            
            # Combine results
            combined_score = max(static_analysis["score"], dynamic_analysis["score"])
            indicators = static_analysis["indicators"] + dynamic_analysis["indicators"]
            
            verdict = "safe"
            if combined_score >= 0.8:
                verdict = "malicious"
            elif combined_score >= 0.5:
                verdict = "suspicious"
            
            duration = time.time() - start_time
            
            return {
                "url": url,
                "verdict": verdict,
                "score": combined_score,
                "indicators": indicators,
                "redirect_chain": dynamic_analysis.get("redirect_chain", []),
                "final_url": dynamic_analysis.get("final_url", url),
                "analysis_duration": duration,
                "static_score": static_analysis["score"],
                "dynamic_score": dynamic_analysis["score"]
            }
            
        except Exception as e:
            return {
                "url": url,
                "verdict": "error",
                "score": 0.0,
                "error": str(e),
                "analysis_duration": time.time() - start_time
            }
    
    def _static_url_analysis(self, url: str) -> Dict[str, Any]:
        """Perform static analysis on URL patterns."""
        indicators = []
        score = 0.0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            
            # Suspicious domain patterns
            if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain):
                indicators.append("ip_address_domain")
                score += 0.7
            
            if len(domain.split('.')) > 4:
                indicators.append("excessive_subdomains")
                score += 0.3
            
            if re.search(r'[0-9]{5,}', domain):
                indicators.append("long_number_in_domain")
                score += 0.4
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                indicators.append("suspicious_tld")
                score += 0.5
            
            # URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
            if any(shortener in domain for shortener in shorteners):
                indicators.append("url_shortener")
                score += 0.3
            
            # Suspicious path patterns
            if re.search(r'(login|signin|account|verify|update|secure)', path):
                indicators.append("login_keywords_in_path")
                score += 0.4
            
            if len(path) > 100:
                indicators.append("extremely_long_path")
                score += 0.2
            
            # Suspicious query parameters
            if re.search(r'(redirect|url|link|goto|target)', query):
                indicators.append("redirect_parameters")
                score += 0.3
            
            # Homograph attacks (basic detection)
            if re.search(r'[а-я]', domain):  # Cyrillic characters
                indicators.append("potential_homograph")
                score += 0.6
            
            return {
                "score": min(score, 1.0),
                "indicators": indicators
            }
            
        except Exception as e:
            logger.error(f"Static URL analysis error for {url}: {e}")
            return {"score": 0.0, "indicators": ["analysis_error"]}
    
    async def _dynamic_url_analysis(self, url: str) -> Dict[str, Any]:
        """Perform dynamic analysis by following redirects safely."""
        indicators = []
        score = 0.0
        redirect_chain = []
        final_url = url
        
        try:
            # Use asyncio to run requests in thread pool
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=1) as executor:
                response = await loop.run_in_executor(
                    executor,
                    self._safe_head_request,
                    url
                )
            
            if not response:
                return {"score": 0.5, "indicators": ["connection_failed"]}
            
            # Analyze response headers
            headers = response.headers
            
            # Check for suspicious headers
            if 'X-Forwarded-For' in headers:
                indicators.append("proxy_detected")
                score += 0.2
            
            # Check content type
            content_type = headers.get('Content-Type', '').lower()
            if 'application/octet-stream' in content_type:
                indicators.append("binary_download")
                score += 0.7
            
            # Analyze redirect chain
            redirect_chain = self._get_redirect_chain(url)
            final_url = redirect_chain[-1] if redirect_chain else url
            
            if len(redirect_chain) > 3:
                indicators.append("excessive_redirects")
                score += 0.4
            
            # Check if redirect goes through suspicious domains
            for redirect_url in redirect_chain:
                parsed = urlparse(redirect_url)
                if any(suspicious in parsed.netloc for suspicious in ['bit.ly', 'tinyurl', 't.co']):
                    indicators.append("redirect_through_shortener")
                    score += 0.3
                    break
            
            # Check final domain reputation (basic)
            final_domain = urlparse(final_url).netloc
            if final_domain != urlparse(url).netloc:
                indicators.append("domain_change_in_redirect")
                score += 0.3
            
            return {
                "score": min(score, 1.0),
                "indicators": indicators,
                "redirect_chain": redirect_chain,
                "final_url": final_url,
                "response_headers": dict(headers)
            }
            
        except Exception as e:
            logger.error(f"Dynamic URL analysis error for {url}: {e}")
            return {
                "score": 0.3,
                "indicators": ["dynamic_analysis_failed"],
                "error": str(e)
            }
    
    def _safe_head_request(self, url: str) -> Optional[requests.Response]:
        """Make a safe HEAD request to check URL."""
        try:
            response = self.session.head(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=True
            )
            return response
        except Exception as e:
            logger.debug(f"HEAD request failed for {url}: {e}")
            return None
    
    def _get_redirect_chain(self, url: str) -> List[str]:
        """Get the full redirect chain for a URL."""
        chain = []
        current_url = url
        
        try:
            for _ in range(self.max_redirects):
                response = self.session.head(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                chain.append(current_url)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location')
                    if location:
                        current_url = location
                    else:
                        break
                else:
                    break
            
            return chain
            
        except Exception as e:
            logger.debug(f"Redirect chain analysis failed for {url}: {e}")
            return chain


class VirusTotalAdapter:
    """VirusTotal API adapter for threat intelligence."""
    
    def __init__(self):
        """Initialize VirusTotal adapter."""
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limit_delay = 15  # seconds between requests for free tier
    
    async def analyze_urls(self, urls: List[str]) -> Dict[str, Any]:
        """Analyze URLs using VirusTotal API."""
        if not self.api_key or not urls:
            return {"verdict": "safe", "score": 0.0, "findings": []}
        
        findings = []
        malicious_count = 0
        
        try:
            for url in urls[:5]:  # Limit to 5 URLs due to rate limits
                result = await self._check_url(url)
                findings.append(result)
                
                if result.get("verdict") == "malicious":
                    malicious_count += 1
                
                # Rate limiting
                await asyncio.sleep(self.rate_limit_delay)
            
            # Calculate overall verdict
            malicious_ratio = malicious_count / len(findings) if findings else 0
            
            if malicious_ratio >= 0.5:
                verdict = "malicious"
                score = 0.9
            elif malicious_ratio > 0:
                verdict = "suspicious"
                score = 0.6
            else:
                verdict = "safe"
                score = 0.0
            
            return {
                "verdict": verdict,
                "score": score,
                "findings": findings,
                "stats": {
                    "total_checked": len(findings),
                    "malicious": malicious_count
                }
            }
            
        except Exception as e:
            logger.error(f"VirusTotal analysis failed: {e}")
            return {"verdict": "error", "score": 0.0, "error": str(e)}
    
    async def _check_url(self, url: str) -> Dict[str, Any]:
        """Check single URL with VirusTotal."""
        try:
            # First, submit URL for analysis
            url_id = self._get_url_id(url)
            
            async with aiohttp.ClientSession() as session:
                headers = {"x-apikey": self.api_key}
                
                # Get analysis results
                async with session.get(
                    f"{self.base_url}/urls/{url_id}",
                    headers=headers,
                    timeout=30
                ) as response:
                    
                    if response.status != 200:
                        return {"url": url, "verdict": "error", "error": f"API error: {response.status}"}
                    
                    data = await response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    clean = stats.get("harmless", 0)
                    total = sum(stats.values()) or 1
                    
                    malicious_ratio = (malicious + suspicious) / total
                    
                    verdict = "safe"
                    if malicious_ratio >= 0.3:
                        verdict = "malicious"
                    elif malicious_ratio > 0.1:
                        verdict = "suspicious"
                    
                    return {
                        "url": url,
                        "verdict": verdict,
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "clean_count": clean,
                        "total_engines": total,
                        "malicious_ratio": malicious_ratio,
                        "scan_date": attributes.get("last_analysis_date")
                    }
            
        except Exception as e:
            logger.error(f"VirusTotal URL check failed for {url}: {e}")
            return {"url": url, "verdict": "error", "error": str(e)}
    
    def _get_url_id(self, url: str) -> str:
        """Generate VirusTotal URL ID."""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class AbuseIPDBAdapter:
    """AbuseIPDB adapter for IP reputation checking."""
    
    def __init__(self):
        """Initialize AbuseIPDB adapter."""
        self.api_key = settings.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"
    
    async def check_ips(self, ips: List[str]) -> Dict[str, Any]:
        """Check IP addresses for abuse reports."""
        if not self.api_key or not ips:
            return {"verdict": "safe", "score": 0.0, "findings": []}
        
        findings = []
        malicious_count = 0
        
        try:
            for ip in ips[:10]:  # Limit checks
                result = await self._check_ip(ip)
                findings.append(result)
                
                if result.get("verdict") == "malicious":
                    malicious_count += 1
                
                # Rate limiting
                await asyncio.sleep(1)
            
            malicious_ratio = malicious_count / len(findings) if findings else 0
            
            if malicious_ratio >= 0.3:
                verdict = "malicious"
                score = 0.8
            elif malicious_ratio > 0:
                verdict = "suspicious"  
                score = 0.5
            else:
                verdict = "safe"
                score = 0.0
            
            return {
                "verdict": verdict,
                "score": score,
                "findings": findings,
                "stats": {"total_checked": len(findings), "malicious": malicious_count}
            }
            
        except Exception as e:
            logger.error(f"AbuseIPDB analysis failed: {e}")
            return {"verdict": "error", "score": 0.0, "error": str(e)}
    
    async def _check_ip(self, ip: str) -> Dict[str, Any]:
        """Check single IP with AbuseIPDB."""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Key": self.api_key,
                    "Accept": "application/json"
                }
                params = {
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": ""
                }
                
                async with session.get(
                    f"{self.base_url}/check",
                    headers=headers,
                    params=params,
                    timeout=15
                ) as response:
                    
                    if response.status != 200:
                        return {"ip": ip, "verdict": "error", "error": f"API error: {response.status}"}
                    
                    data = await response.json()
                    result_data = data.get("data", {})
                    
                    abuse_confidence = result_data.get("abuseConfidencePercentage", 0)
                    is_whitelisted = result_data.get("isWhitelisted", False)
                    total_reports = result_data.get("totalReports", 0)
                    
                    verdict = "safe"
                    if is_whitelisted:
                        verdict = "safe"
                    elif abuse_confidence >= 75:
                        verdict = "malicious"
                    elif abuse_confidence >= 25 or total_reports > 0:
                        verdict = "suspicious"
                    
                    return {
                        "ip": ip,
                        "verdict": verdict,
                        "abuse_confidence": abuse_confidence,
                        "total_reports": total_reports,
                        "is_whitelisted": is_whitelisted,
                        "country": result_data.get("countryCode"),
                        "isp": result_data.get("isp")
                    }
            
        except Exception as e:
            logger.error(f"AbuseIPDB IP check failed for {ip}: {e}")
            return {"ip": ip, "verdict": "error", "error": str(e)}


class GeminiLLMAnalyzer:
    """Google Gemini LLM analyzer for content analysis."""
    
    def __init__(self):
        """Initialize Gemini analyzer."""
        self.api_key = settings.GEMINI_API_KEY
        self.model = "gemini-1.5-flash"
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"
    
    async def analyze_content(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email content using Gemini LLM."""
        if not self.api_key:
            return {"verdict": "safe", "score": 0.0, "explanation": "LLM analysis disabled"}
        
        try:
            # Prepare safe prompt
            analysis_prompt = self._create_analysis_prompt(email_content)
            
            # Call Gemini API
            result = await self._call_gemini_api(analysis_prompt)
            
            return self._parse_llm_response(result)
            
        except Exception as e:
            logger.error(f"Gemini LLM analysis failed: {e}")
            return {"verdict": "error", "score": 0.0, "error": str(e)}
    
    def _create_analysis_prompt(self, email_content: Dict[str, Any]) -> str:
        """Create safe analysis prompt for LLM."""
        headers = email_content.get("headers", {})
        text_content = email_content.get("text_content", "")[:2000]  # Limit content
        links = email_content.get("links", [])
        
        prompt = f"""Analyze this email for phishing indicators. Respond with JSON only.

Email Headers:
From: {headers.get('From', 'Unknown')[:100]}
Subject: {headers.get('Subject', 'No subject')[:200]}

Text Content (truncated):
{text_content}

Links found: {len(links)}
First few links: {', '.join(links[:3])}

Analyze for:
1. Urgency/pressure tactics
2. Suspicious sender patterns  
3. Credential harvesting attempts
4. Impersonation indicators
5. Social engineering techniques

Respond with JSON:
{{
  "threat_score": 0.0-1.0,
  "verdict": "safe|suspicious|malicious", 
  "confidence": 0.0-1.0,
  "indicators": ["list", "of", "indicators"],
  "explanation": "Brief explanation",
  "impersonation_target": "company/service name if detected"
}}"""
        
        return prompt
    
    async def _call_gemini_api(self, prompt: str) -> Dict[str, Any]:
        """Call Gemini API safely."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/{self.model}:generateContent?key={self.api_key}"
                
                payload = {
                    "contents": [{
                        "parts": [{"text": prompt}]
                    }],
                    "generationConfig": {
                        "temperature": 0.1,
                        "maxOutputTokens": 1000,
                        "topP": 0.8,
                        "topK": 10
                    },
                    "safetySettings": [
                        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"}
                    ]
                }
                
                async with session.post(url, json=payload, timeout=30) as response:
                    if response.status != 200:
                        raise Exception(f"Gemini API error: {response.status}")
                    
                    data = await response.json()
                    return data
                    
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")
            raise
    
    def _parse_llm_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Gemini response safely."""
        try:
            candidates = response.get("candidates", [])
            if not candidates:
                return {"verdict": "error", "score": 0.0, "error": "No response from LLM"}
            
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            if not parts:
                return {"verdict": "error", "score": 0.0, "error": "Empty response from LLM"}
            
            text_response = parts[0].get("text", "")
            
            # Try to parse JSON response
            try:
                # Clean response (remove markdown formatting if present)
                clean_response = text_response.strip()
                if clean_response.startswith("```json"):
                    clean_response = clean_response[7:]
                if clean_response.endswith("```"):
                    clean_response = clean_response[:-3]
                
                result = json.loads(clean_response)
                
                # Validate and sanitize response
                verdict = result.get("verdict", "safe").lower()
                if verdict not in ["safe", "suspicious", "malicious"]:
                    verdict = "safe"
                
                score = float(result.get("threat_score", 0.0))
                score = max(0.0, min(1.0, score))  # Clamp to 0-1
                
                confidence = float(result.get("confidence", 0.5))
                confidence = max(0.0, min(1.0, confidence))
                
                return {
                    "verdict": verdict,
                    "score": score,
                    "confidence": confidence,
                    "indicators": result.get("indicators", [])[:10],  # Limit indicators
                    "explanation": result.get("explanation", "")[:500],  # Limit explanation
                    "impersonation_target": result.get("impersonation_target", "")[:100]
                }
                
            except json.JSONDecodeError:
                # Fallback: simple text analysis
                text_lower = text_response.lower()
                
                score = 0.0
                if "malicious" in text_lower or "phishing" in text_lower:
                    score = 0.8
                    verdict = "malicious"
                elif "suspicious" in text_lower or "warning" in text_lower:
                    score = 0.5
                    verdict = "suspicious"
                else:
                    verdict = "safe"
                
                return {
                    "verdict": verdict,
                    "score": score,
                    "confidence": 0.3,  # Lower confidence for unparsed response
                    "explanation": "LLM response could not be parsed as JSON",
                    "raw_response": text_response[:200]
                }
                
        except Exception as e:
            logger.error(f"LLM response parsing failed: {e}")
            return {"verdict": "error", "score": 0.0, "error": str(e)}


class ThreatOrchestrator:
    """Main threat analysis orchestrator."""
    
    def __init__(self):
        """Initialize threat orchestrator."""
        self.link_analyzer = LinkRedirectAnalyzer()
        self.virustotal = VirusTotalAdapter()
        self.abuseipdb = AbuseIPDBAdapter()
        self.gemini = GeminiLLMAnalyzer()
    
    async def analyze_email(self, scan_request_id: str, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Run comprehensive threat analysis on email."""
        start_time = datetime.utcnow()
        analysis_id = str(uuid.uuid4())
        
        logger.info(f"Starting threat analysis {analysis_id} for scan {scan_request_id}")
        
        try:
            # Extract data for analysis
            links = email_content.get("links", [])
            headers = email_content.get("headers", {})
            
            # Extract IPs from headers and links
            ips = self._extract_ips(headers, links)
            
            # Run all analyses concurrently
            analyses = await asyncio.gather(
                self.link_analyzer.analyze_links(links),
                self.virustotal.analyze_urls(links),
                self.abuseipdb.check_ips(ips),
                self.gemini.analyze_content(email_content),
                return_exceptions=True
            )
            
            link_analysis, vt_analysis, ip_analysis, llm_analysis = analyses
            
            # Handle any exceptions
            components = {
                "link_analysis": link_analysis if not isinstance(link_analysis, Exception) else {"verdict": "error", "score": 0.0, "error": str(link_analysis)},
                "virustotal": vt_analysis if not isinstance(vt_analysis, Exception) else {"verdict": "error", "score": 0.0, "error": str(vt_analysis)},
                "abuseipdb": ip_analysis if not isinstance(ip_analysis, Exception) else {"verdict": "error", "score": 0.0, "error": str(ip_analysis)},
                "gemini_llm": llm_analysis if not isinstance(llm_analysis, Exception) else {"verdict": "error", "score": 0.0, "error": str(llm_analysis)}
            }
            
            # Aggregate results
            aggregated_result = self._aggregate_threat_results(components)
            
            # Calculate analysis duration
            duration = (datetime.utcnow() - start_time).total_seconds()
            aggregated_result["analysis_duration_seconds"] = duration
            aggregated_result["analysis_id"] = analysis_id
            aggregated_result["components"] = components
            
            logger.info(f"Threat analysis {analysis_id} completed in {duration:.2f}s - verdict: {aggregated_result['threat_level']}")
            
            # Update metrics
            threat_analysis_metrics.analyses_completed.inc()
            threat_analysis_metrics.analysis_duration.observe(duration)
            
            return aggregated_result
            
        except Exception as e:
            logger.error(f"Threat analysis {analysis_id} failed: {e}")
            logger.error(traceback.format_exc())
            
            threat_analysis_metrics.analysis_errors.inc()
            
            return {
                "threat_score": 0.0,
                "threat_level": ThreatLevel.SAFE,
                "confidence": 0.0,
                "error": str(e),
                "analysis_id": analysis_id,
                "analysis_duration_seconds": (datetime.utcnow() - start_time).total_seconds()
            }
    
    def _extract_ips(self, headers: Dict[str, Any], links: List[str]) -> List[str]:
        """Extract IP addresses from headers and links."""
        ips = []
        
        # Extract from headers
        for header_value in headers.values():
            if isinstance(header_value, str):
                ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header_value)
                ips.extend(ip_matches)
        
        # Extract from links
        for link in links:
            parsed = urlparse(link)
            if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', parsed.netloc):
                ips.append(parsed.netloc)
        
        return list(set(ips))  # Remove duplicates
    
    def _aggregate_threat_results(self, components: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate results from all threat analysis components."""
        try:
            # Extract scores and verdicts
            scores = []
            verdicts = []
            indicators = []
            explanations = []
            
            for component_name, result in components.items():
                if result.get("verdict") != "error":
                    score = result.get("score", 0.0)
                    verdict = result.get("verdict", "safe")
                    
                    scores.append(score)
                    verdicts.append(verdict)
                    
                    # Collect indicators
                    if "indicators" in result:
                        indicators.extend(result["indicators"])
                    
                    # Collect explanations
                    if "explanation" in result:
                        explanations.append(f"{component_name}: {result['explanation']}")
            
            # Calculate weighted average score
            if scores:
                # Weight different components
                weights = {
                    "gemini_llm": 0.4,      # Highest weight for LLM analysis
                    "link_analysis": 0.3,    # High weight for link analysis
                    "virustotal": 0.2,       # Medium weight for VT
                    "abuseipdb": 0.1         # Lower weight for IP reputation
                }
                
                weighted_score = 0.0
                total_weight = 0.0
                
                for i, (component_name, result) in enumerate(components.items()):
                    if result.get("verdict") != "error" and i < len(scores):
                        weight = weights.get(component_name, 0.1)
                        weighted_score += scores[i] * weight
                        total_weight += weight
                
                final_score = weighted_score / total_weight if total_weight > 0 else 0.0
            else:
                final_score = 0.0
            
            # Determine threat level
            malicious_count = verdicts.count("malicious")
            suspicious_count = verdicts.count("suspicious")
            
            if malicious_count >= 2 or final_score >= 0.8:
                threat_level = ThreatLevel.CRITICAL
            elif malicious_count >= 1 or final_score >= 0.6:
                threat_level = ThreatLevel.HIGH
            elif suspicious_count >= 2 or final_score >= 0.4:
                threat_level = ThreatLevel.MEDIUM
            elif suspicious_count >= 1 or final_score >= 0.2:
                threat_level = ThreatLevel.LOW
            else:
                threat_level = ThreatLevel.SAFE
            
            # Calculate confidence
            error_count = sum(1 for result in components.values() if result.get("verdict") == "error")
            total_components = len(components)
            confidence = max(0.1, 1.0 - (error_count / total_components))
            
            # Generate explanation
            explanation = self._generate_explanation(
                threat_level, 
                final_score, 
                components, 
                indicators
            )
            
            # Generate recommendations
            recommendations = self._generate_recommendations(threat_level, indicators)
            
            return {
                "threat_score": round(final_score, 3),
                "threat_level": threat_level,
                "confidence": round(confidence, 3),
                "phishing_indicators": list(set(indicators))[:20],  # Unique indicators, max 20
                "explanation": explanation,
                "recommendations": recommendations,
                "component_scores": {
                    name: result.get("score", 0.0) 
                    for name, result in components.items()
                },
                "malicious_links": sum(
                    result.get("stats", {}).get("malicious", 0) 
                    for result in components.values()
                ),
                "suspicious_attachments": 0,  # TODO: Add attachment analysis
                "reputation_flags": sum(
                    1 for result in components.values() 
                    if result.get("verdict") == "malicious"
                )
            }
            
        except Exception as e:
            logger.error(f"Result aggregation failed: {e}")
            return {
                "threat_score": 0.5,
                "threat_level": ThreatLevel.MEDIUM,
                "confidence": 0.1,
                "explanation": f"Analysis aggregation failed: {str(e)}",
                "error": str(e)
            }
    
    def _generate_explanation(
        self, 
        threat_level: ThreatLevel, 
        score: float,
        components: Dict[str, Any],
        indicators: List[str]
    ) -> str:
        """Generate human-readable explanation of threat analysis."""
        try:
            if threat_level == ThreatLevel.CRITICAL:
                base = "CRITICAL THREAT: This email shows strong indicators of phishing or malware."
            elif threat_level == ThreatLevel.HIGH:
                base = "HIGH THREAT: This email contains multiple suspicious elements."
            elif threat_level == ThreatLevel.MEDIUM:
                base = "MEDIUM THREAT: This email has some concerning characteristics."
            elif threat_level == ThreatLevel.LOW:
                base = "LOW THREAT: Minor suspicious elements detected."
            else:
                base = "SAFE: No significant threats detected."
            
            details = []
            
            # Add component-specific details
            if components.get("link_analysis", {}).get("verdict") == "malicious":
                details.append("malicious links detected")
            
            if components.get("virustotal", {}).get("verdict") == "malicious":
                details.append("known malicious URLs identified")
            
            if components.get("abuseipdb", {}).get("verdict") == "malicious":
                details.append("IP addresses with abuse reports")
            
            if components.get("gemini_llm", {}).get("verdict") in ["malicious", "suspicious"]:
                llm_explanation = components["gemini_llm"].get("explanation", "")
                if llm_explanation:
                    details.append(f"content analysis: {llm_explanation[:100]}")
            
            # Add top indicators
            if indicators:
                top_indicators = indicators[:3]
                details.append(f"key indicators: {', '.join(top_indicators)}")
            
            if details:
                return f"{base} {'. '.join(details).capitalize()}."
            else:
                return base
                
        except Exception as e:
            logger.error(f"Explanation generation failed: {e}")
            return f"Threat level: {threat_level.value} (score: {score:.2f})"
    
    def _generate_recommendations(self, threat_level: ThreatLevel, indicators: List[str]) -> List[str]:
        """Generate actionable recommendations based on threat analysis."""
        recommendations = []
        
        try:
            if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                recommendations.extend([
                    "Quarantine this email immediately",
                    "Do not click any links or download attachments",
                    "Report to security team",
                    "Block sender if confirmed malicious"
                ])
            
            elif threat_level == ThreatLevel.MEDIUM:
                recommendations.extend([
                    "Exercise caution with this email",
                    "Verify sender through alternative means",
                    "Avoid clicking suspicious links"
                ])
            
            elif threat_level == ThreatLevel.LOW:
                recommendations.extend([
                    "Review email carefully before taking action",
                    "Verify any requests for sensitive information"
                ])
            
            # Add specific recommendations based on indicators
            if any("login" in indicator for indicator in indicators):
                recommendations.append("Never enter credentials via email links")
            
            if any("redirect" in indicator for indicator in indicators):
                recommendations.append("Be cautious of redirect chains")
            
            if any("urgent" in indicator for indicator in indicators):
                recommendations.append("Verify urgent requests through official channels")
            
            return recommendations[:5]  # Limit to 5 recommendations
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}")
            return ["Review email carefully before taking any action"]
