"""Real URL analyzer with threat intelligence integration."""

import re
import httpx
import asyncio
import os
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, unquote
from datetime import datetime
import hashlib
import base64

from app.config.logging import get_logger

logger = get_logger(__name__)

# Dangerous file extensions in URL paths (malware/payload indicators)
DANGEROUS_FILE_EXTENSIONS = {
    '.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.ps1', '.psm1',
    '.sh', '.bash', '.bin', '.elf', '.run',
    '.dll', '.sys', '.drv', '.cpl',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
    '.iso', '.img', '.dmg', '.pkg', '.deb', '.rpm', '.apk',
    '.jar', '.war', '.class',
    '.docm', '.xlsm', '.pptm', '.dotm',
    '.hta', '.inf', '.reg', '.lnk',
}

# Comprehensive suspicious TLDs (commonly abused for phishing/malware)
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq',          # Free TLDs (heavy abuse)
    '.pw', '.cc', '.ws', '.info', '.biz',       # Historically abused
    '.top', '.xyz', '.club', '.work', '.click',  # Cheap bulk-registered
    '.link', '.buzz', '.surf', '.rest', '.icu',   # Newer abused
    '.sbs', '.cfd', '.cyou', '.lol', '.fun',     # Very high abuse rate
    '.store', '.site', '.online', '.live',        # Moderate abuse
    '.su', '.to', '.cm', '.cn',                   # Country codes w/ abuse
    '.monster', '.digital', '.network',
}


class URLAnalyzer:
    """Advanced URL analyzer with threat intelligence and behavioral analysis."""
    
    def __init__(self):
        self.virustotal_api_key = None  # Set from environment
        self.urlvoid_api_key = None     # Set from environment
        self.timeout = 30
        
    async def analyze_urls_in_content(self, content: str) -> Dict[str, Any]:
        """Extract and analyze all URLs from email content."""
        try:
            # Extract URLs from content
            urls = self._extract_urls(content)
            
            if not urls:
                return {
                    "total_urls": 0,
                    "malicious_urls": [],
                    "suspicious_urls": [],
                    "safe_urls": [],
                    "analysis_results": {},
                    "risk_score": 0.0
                }
            
            # Analyze each URL
            analysis_results = {}
            malicious_urls = []
            suspicious_urls = []
            safe_urls = []
            
            for url in urls:
                try:
                    result = await self._analyze_single_url(url)
                    analysis_results[url] = result
                    
                    if result["verdict"] == "malicious":
                        malicious_urls.append(url)
                    elif result["verdict"] == "suspicious":
                        suspicious_urls.append(url)
                    else:
                        safe_urls.append(url)
                        
                except Exception as e:
                    logger.error(f"Failed to analyze URL {url}: {e}")
                    analysis_results[url] = {
                        "verdict": "unknown",
                        "error": str(e),
                        "risk_score": 0.5
                    }
            
            # Calculate overall risk score
            overall_risk = self._calculate_url_risk_score(
                len(malicious_urls), len(suspicious_urls), len(safe_urls)
            )
            
            return {
                "total_urls": len(urls),
                "malicious_urls": malicious_urls,
                "suspicious_urls": suspicious_urls,
                "safe_urls": safe_urls,
                "analysis_results": analysis_results,
                "risk_score": overall_risk
            }
            
        except Exception as e:
            logger.error(f"URL analysis failed: {e}")
            return {
                "total_urls": 0,
                "malicious_urls": [],
                "suspicious_urls": [],
                "safe_urls": [],
                "analysis_results": {},
                "risk_score": 0.0,
                "error": str(e)
            }
    
    def _extract_urls(self, content: str) -> List[str]:
        """Extract URLs from email content using regex."""
        # Enhanced URL regex pattern
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        
        urls = url_pattern.findall(content)
        
        # Clean and validate URLs
        cleaned_urls = []
        for url in urls:
            # Remove trailing punctuation
            url = url.rstrip('.,;!?)')
            
            # Basic validation
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    cleaned_urls.append(url)
            except Exception:
                continue
                
        return list(set(cleaned_urls))  # Remove duplicates
    
    async def _analyze_single_url(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL for threats."""
        try:
            # Parse URL components
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Basic checks
            basic_checks = self._perform_basic_url_checks(url, domain)
            
            # Domain reputation check
            domain_reputation = await self._check_domain_reputation(domain)
            
            # URL redirection analysis
            redirect_analysis = await self._analyze_redirects(url)
            
            # Calculate risk score
            risk_score = self._calculate_single_url_risk(
                basic_checks, domain_reputation, redirect_analysis
            )
            
            # Determine verdict
            if risk_score >= 0.8:
                verdict = "malicious"
            elif risk_score >= 0.5:
                verdict = "suspicious"
            else:
                verdict = "safe"
            
            return {
                "url": url,
                "domain": domain,
                "verdict": verdict,
                "risk_score": risk_score,
                "basic_checks": basic_checks,
                "domain_reputation": domain_reputation,
                "redirect_analysis": redirect_analysis,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Single URL analysis failed for {url}: {e}")
            return {
                "url": url,
                "verdict": "unknown",
                "risk_score": 0.5,
                "error": str(e)
            }
    
    def _perform_basic_url_checks(self, url: str, domain: str) -> Dict[str, Any]:
        """Perform basic URL security checks."""
        checks = {
            "is_shortened": False,
            "has_suspicious_chars": False,
            "is_ip_address": False,
            "has_suspicious_subdomain": False,
            "suspicious_tld": False,
            "typosquatting_indicators": []
        }
        
        # Check for URL shorteners
        shortener_domains = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link',
            'ow.ly', 'buff.ly', 'adf.ly', 'tiny.cc'
        ]
        checks["is_shortened"] = any(shortener in domain for shortener in shortener_domains)
        
        # Check for suspicious characters
        suspicious_chars = ['%', '@', '..', '--']
        checks["has_suspicious_chars"] = any(char in url for char in suspicious_chars)
        
        # Check if domain is IP address (strip port first)
        domain_no_port = domain.split(':')[0]
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        checks["is_ip_address"] = bool(ip_pattern.match(domain_no_port))
        
        # Check for non-standard ports (strong malware indicator)
        if ':' in domain:
            try:
                port = int(domain.split(':')[1])
                if port not in (80, 443, 8080, 8443):
                    checks["has_non_standard_port"] = True
            except (ValueError, IndexError):
                pass
        
        # Check for suspicious subdomains
        suspicious_subdomains = [
            'secure', 'verify', 'update', 'login', 'account',
            'security', 'auth', 'confirm', 'validation'
        ]
        checks["has_suspicious_subdomain"] = any(
            subdomain in domain for subdomain in suspicious_subdomains
        )
        
        # Check for suspicious TLDs (comprehensive list)
        checks["suspicious_tld"] = any(domain_no_port.endswith(tld) for tld in SUSPICIOUS_TLDS)
        
        # Check for dangerous file extensions in URL path
        try:
            parsed = urlparse(f"http://{domain}" if '://' not in domain else domain)
            path = urlparse(f"http://{domain}").path if '://' not in domain else ''
        except Exception:
            path = ''
        # Re-parse the original URL for path
        try:
            full_parsed = urlparse(url)
            path = full_parsed.path.lower()
        except Exception:
            path = ''
        checks["has_dangerous_extension"] = any(path.endswith(ext) for ext in DANGEROUS_FILE_EXTENSIONS)
        
        # Check for malware distribution paths
        malware_paths = ['/bins/', '/bin/', '/payload/', '/exploit/', '/exec/',
                        '/download/', '/dropper/', '/loader/', '/bot/', '/malware/',
                        '/tmp/', '/shell/', '/backdoor/', '/trojan/', '/rat/',
                        '/c2/', '/cnc/', '/gate/', '/panel/']
        checks["has_malware_path"] = any(mp in path for mp in malware_paths)
        
        # Check for malware binary names (IoT botnets like Mirai)
        path_filename = path.split('/')[-1] if '/' in path else ''
        malware_binaries = ['x86_64', 'x86', 'i686', 'i586', 'arm', 'arm5', 'arm6', 'arm7',
                           'aarch64', 'mips', 'mipsel', 'mips64', 'powerpc', 'ppc', 'sparc',
                           'sh4', 'm68k', 'arc', 'xtensa', 'riscv64']
        checks["has_malware_binary_name"] = any(bn == path_filename or path.endswith(f'/{bn}')
                                                 for bn in malware_binaries)
        
        # Check for typosquatting of popular domains
        popular_domains = [
            'google.com', 'microsoft.com', 'amazon.com', 'paypal.com',
            'apple.com', 'facebook.com', 'twitter.com', 'instagram.com'
        ]
        
        for pop_domain in popular_domains:
            similarity = self._calculate_domain_similarity(domain, pop_domain)
            if similarity > 0.7 and domain != pop_domain:
                checks["typosquatting_indicators"].append({
                    "target_domain": pop_domain,
                    "similarity": similarity
                })
        
        return checks
    
    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains (simplified Levenshtein)."""
        # Remove TLD for comparison
        d1 = domain1.split('.')[0] if '.' in domain1 else domain1
        d2 = domain2.split('.')[0] if '.' in domain2 else domain2
        
        # Simple character-based similarity
        common_chars = set(d1) & set(d2)
        total_chars = set(d1) | set(d2)
        
        if not total_chars:
            return 0.0
            
        return len(common_chars) / len(total_chars)
    
    async def _check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation using VirusTotal + heuristics."""
        reputation = {
            "score": 0.0,  # Start clean, accumulate risk
            "sources": {},
            "categories": [],
            "last_seen": None,
            "threat_types": []
        }
        
        domain_no_port = domain.split(':')[0]
        
        # === VirusTotal API check (if key available) ===
        try:
            vt_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
            if vt_api_key:
                vt_result = await self._check_virustotal(domain_no_port, vt_api_key)
                if vt_result:
                    reputation["sources"]["virustotal"] = vt_result
                    positives = vt_result.get("positives", 0)
                    total = vt_result.get("total", 0)
                    if positives > 0:
                        # Scale: 1 detection = 0.4, 3+ = 0.7, 5+ = 0.9
                        vt_score = min(0.9, 0.3 + (positives * 0.15))
                        reputation["score"] = max(reputation["score"], vt_score)
                        reputation["threat_types"].append(f"virustotal_{positives}_detections")
                        reputation["categories"].append("malware" if positives >= 3 else "suspicious")
        except Exception as e:
            logger.warning(f"VirusTotal check failed for {domain_no_port}: {e}")
        
        # === Heuristic reputation checks ===
        # IP-based domains are inherently suspicious
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(domain_no_port):
            reputation["score"] = max(reputation["score"], 0.5)
            reputation["threat_types"].append("ip_based_domain")
        
        # Non-standard port
        if ':' in domain:
            try:
                port = int(domain.split(':')[1])
                if port not in (80, 443, 8080, 8443):
                    reputation["score"] = max(reputation["score"], 0.6)
                    reputation["threat_types"].append("non_standard_port")
            except (ValueError, IndexError):
                pass
        
        # Very new/suspicious TLD
        if any(domain_no_port.endswith(tld) for tld in SUSPICIOUS_TLDS):
            reputation["score"] = max(reputation["score"], 0.4)
            reputation["threat_types"].append("suspicious_tld")
        
        # Random-looking domain (high entropy)
        base_domain = domain_no_port.split('.')[0] if '.' in domain_no_port else domain_no_port
        if len(base_domain) > 15 and re.search(r'\d+', base_domain):
            reputation["score"] = max(reputation["score"], 0.3)
            reputation["threat_types"].append("suspicious_pattern")
        
        return reputation
    
    async def _check_virustotal(self, domain: str, api_key: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal URL report API for a domain."""
        try:
            url_to_check = f"http://{domain}" if not domain.startswith('http') else domain
            async with httpx.AsyncClient(timeout=15) as client:
                # Try URL report endpoint
                response = await client.get(
                    "https://www.virustotal.com/vtapi/v2/url/report",
                    params={
                        "apikey": api_key,
                        "resource": url_to_check
                    }
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("response_code") == 1:  # Result found
                        return {
                            "positives": data.get("positives", 0),
                            "total": data.get("total", 0),
                            "scan_date": data.get("scan_date"),
                            "permalink": data.get("permalink")
                        }
                elif response.status_code == 204:
                    logger.warning("VirusTotal rate limit hit")
        except Exception as e:
            logger.warning(f"VirusTotal API error: {e}")
        return None
    
    async def _analyze_redirects(self, url: str) -> Dict[str, Any]:
        """Analyze URL redirect chains."""
        redirect_info = {
            "redirect_count": 0,
            "final_url": url,
            "redirect_chain": [url],
            "suspicious_redirects": False,
            "risk_factors": []
        }
        
        try:
            async with httpx.AsyncClient(
                timeout=10,
                follow_redirects=False
            ) as client:
                current_url = url
                max_redirects = 10
                
                for i in range(max_redirects):
                    try:
                        response = await client.head(current_url)
                        
                        if response.status_code in [301, 302, 303, 307, 308]:
                            next_url = response.headers.get('location')
                            if next_url:
                                redirect_info["redirect_chain"].append(next_url)
                                redirect_info["redirect_count"] += 1
                                current_url = next_url
                            else:
                                break
                        else:
                            break
                            
                    except Exception as e:
                        logger.warning(f"Redirect analysis failed at step {i}: {e}")
                        break
                
                redirect_info["final_url"] = current_url
                
                # Analyze redirect chain for suspicious patterns
                if redirect_info["redirect_count"] > 3:
                    redirect_info["suspicious_redirects"] = True
                    redirect_info["risk_factors"].append("excessive_redirects")
                
                # Check for domain changes in redirect chain
                domains = [urlparse(u).netloc for u in redirect_info["redirect_chain"]]
                unique_domains = set(domains)
                
                if len(unique_domains) > 2:
                    redirect_info["suspicious_redirects"] = True
                    redirect_info["risk_factors"].append("multiple_domain_redirects")
                    
        except Exception as e:
            logger.error(f"Redirect analysis failed for {url}: {e}")
            redirect_info["error"] = str(e)
        
        return redirect_info
    
    def _calculate_single_url_risk(
        self, 
        basic_checks: Dict[str, Any],
        domain_reputation: Dict[str, Any],
        redirect_analysis: Dict[str, Any]
    ) -> float:
        """Calculate risk score for a single URL."""
        risk_score = 0.0
        
        # Basic checks scoring
        if basic_checks.get("is_shortened"):
            risk_score += 0.3
        if basic_checks.get("has_suspicious_chars"):
            risk_score += 0.3
        if basic_checks.get("is_ip_address"):
            risk_score += 0.5  # IP-based URLs are very suspicious
        if basic_checks.get("has_non_standard_port"):
            risk_score += 0.4  # Non-standard port = strong malware signal
        if basic_checks.get("has_suspicious_subdomain"):
            risk_score += 0.3
        if basic_checks.get("suspicious_tld"):
            risk_score += 0.35
        if basic_checks.get("has_dangerous_extension"):
            risk_score += 0.5  # Direct payload download
        if basic_checks.get("has_malware_path"):
            risk_score += 0.5  # Malware distribution path (e.g., /bins/)
        if basic_checks.get("has_malware_binary_name"):
            risk_score += 0.45  # Architecture-specific binary (e.g., x86_64)
        if basic_checks.get("typosquatting_indicators"):
            risk_score += 0.5
        
        # Compound risk: IP + non-standard port + dangerous extension = almost certain malware
        ip_and_port = basic_checks.get("is_ip_address") and basic_checks.get("has_non_standard_port")
        if ip_and_port:
            risk_score += 0.3  # Extra boost for IP:port combo
        if ip_and_port and basic_checks.get("has_dangerous_extension"):
            risk_score = max(risk_score, 0.95)  # Near-certain malware
        
        # Malware path + binary name = definite malware distribution
        if basic_checks.get("has_malware_path") and basic_checks.get("has_malware_binary_name"):
            risk_score = max(risk_score, 0.95)
        if basic_checks.get("has_malware_path") or basic_checks.get("has_malware_binary_name"):
            if basic_checks.get("is_ip_address") or basic_checks.get("has_non_standard_port"):
                risk_score = max(risk_score, 0.90)
        
        # Domain reputation scoring (now includes VirusTotal)
        rep_score = domain_reputation.get("score", 0.0)
        if rep_score > 0.7:
            risk_score += 0.5
        elif rep_score > 0.4:
            risk_score += 0.3
        elif rep_score > 0.2:
            risk_score += 0.15
        
        # Redirect analysis scoring
        if redirect_analysis.get("suspicious_redirects"):
            risk_score += 0.3
        
        return min(risk_score, 1.0)
    
    def _calculate_url_risk_score(
        self, 
        malicious_count: int, 
        suspicious_count: int, 
        safe_count: int
    ) -> float:
        """Calculate overall URL risk score."""
        total_urls = malicious_count + suspicious_count + safe_count
        
        if total_urls == 0:
            return 0.0
        
        # Weight malicious URLs more heavily
        risk_score = (
            (malicious_count * 1.0) + 
            (suspicious_count * 0.5) + 
            (safe_count * 0.0)
        ) / total_urls
        
        return risk_score


# Global instance
url_analyzer = URLAnalyzer()