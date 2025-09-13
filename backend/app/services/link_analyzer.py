"""Link redirection analysis service using Playwright."""

import asyncio
import json
import time
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
import re

import httpx
import tldextract
from playwright.async_api import async_playwright, Browser, Page, TimeoutError as PlaywrightTimeoutError

from app.config.logging import get_logger
from app.models.analysis.link_analysis import LinkAnalysis
from app.core.database import SessionLocal

logger = get_logger(__name__)


class LinkRedirectionAnalyzer:
    """Analyzes URL redirections and detects phishing indicators."""
    
    def __init__(self):
        self.browser: Optional[Browser] = None
        self.http_client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=False,  # We want to track redirects manually
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        # Suspicious TLD patterns
        self.suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'freenom', 'bit', 'link', 'click',
            'download', 'zip', 'rar', 'exe', 'scr', 'app'
        }
        
        # Known legitimate domains (simplified)
        self.trusted_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
            'youtube.com', 'wikipedia.org', 'stackoverflow.com'
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-extensions',
                '--disable-plugins',
                '--disable-images',  # Faster loading
                '--disable-javascript',  # We'll enable selectively
            ]
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.browser:
            await self.browser.close()
        await self.http_client.aclose()
    
    async def analyze_url(self, email_id: int, url: str) -> LinkAnalysis:
        """Analyze a URL for redirection and phishing indicators."""
        start_time = time.time()
        
        analysis = LinkAnalysis(
            email_id=email_id,
            original_url=url,
            original_domain=self._extract_domain(url),
            status="analyzing"
        )
        
        try:
            # Step 1: Follow HTTP redirects
            redirect_chain = await self._follow_http_redirects(url)
            
            # Step 2: Check for JavaScript/Meta redirects
            js_redirects = await self._check_javascript_redirects(
                redirect_chain[-1]['url'] if redirect_chain else url
            )
            
            # Combine all redirects
            full_chain = redirect_chain + js_redirects
            
            # Step 3: Analyze the chain
            analysis_results = await self._analyze_redirect_chain(url, full_chain)
            
            # Update analysis object
            analysis.final_url = analysis_results['final_url']
            analysis.final_domain = self._extract_domain(analysis_results['final_url'])
            analysis.redirect_chain = full_chain
            analysis.analysis_details = analysis_results
            analysis.redirect_count = len(full_chain)
            analysis.has_javascript_redirect = "yes" if js_redirects else "no"
            analysis.has_meta_redirect = analysis_results.get('has_meta_redirect', 'unknown')
            analysis.has_timed_redirect = analysis_results.get('has_timed_redirect', 'unknown')
            
            # Calculate risk score and reasons
            risk_data = self._calculate_risk_score(url, analysis_results, full_chain)
            analysis.risk_score = risk_data['score']
            analysis.risk_reasons = risk_data['reasons']
            
            # Domain analysis
            analysis.domain_mismatch = self._check_domain_mismatch(
                analysis.original_domain, analysis.final_domain
            )
            analysis.has_punycode = self._check_punycode(analysis_results['final_url'])
            analysis.is_lookalike = self._check_lookalike_domain(analysis.final_domain)
            
            analysis.status = "completed"
            analysis.analysis_duration = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Link analysis failed for {url}: {str(e)}")
            analysis.status = "failed"
            analysis.error_message = str(e)
            analysis.analysis_duration = time.time() - start_time
        
        return analysis
    
    async def _follow_http_redirects(self, url: str, max_redirects: int = 10) -> List[Dict[str, Any]]:
        """Follow HTTP redirects and build chain."""
        chain = []
        current_url = url
        redirect_count = 0
        
        while redirect_count < max_redirects:
            try:
                response = await self.http_client.get(current_url)
                
                chain.append({
                    'step': redirect_count + 1,
                    'url': current_url,
                    'status_code': response.status_code,
                    'method': 'http',
                    'headers': dict(response.headers),
                    'is_redirect': 300 <= response.status_code < 400
                })
                
                if 300 <= response.status_code < 400:
                    location = response.headers.get('location')
                    if location:
                        # Handle relative URLs
                        next_url = urljoin(current_url, location)
                        current_url = next_url
                        redirect_count += 1
                    else:
                        break
                else:
                    break
                    
            except Exception as e:
                logger.warning(f"HTTP redirect failed for {current_url}: {str(e)}")
                chain.append({
                    'step': redirect_count + 1,
                    'url': current_url,
                    'error': str(e),
                    'method': 'http'
                })
                break
        
        return chain
    
    async def _check_javascript_redirects(self, url: str) -> List[Dict[str, Any]]:
        """Check for JavaScript and meta refresh redirects."""
        if not self.browser:
            return []
        
        redirects = []
        
        try:
            page = await self.browser.new_page()
            
            # Intercept navigation to detect redirects
            navigation_history = []
            
            async def handle_response(response):
                navigation_history.append({
                    'url': response.url,
                    'status': response.status,
                    'timestamp': time.time()
                })
            
            page.on('response', handle_response)
            
            # Navigate with JavaScript enabled
            await page.goto(url, wait_until='networkidle', timeout=15000)
            
            # Check for meta refresh
            meta_refresh = await page.evaluate("""
                () => {
                    const metaTags = document.querySelectorAll('meta[http-equiv="refresh"]');
                    return Array.from(metaTags).map(tag => ({
                        content: tag.getAttribute('content'),
                        url: tag.getAttribute('content')?.split('url=')[1]
                    }));
                }
            """)
            
            # Check for timed redirects (wait a bit)
            initial_url = page.url
            await asyncio.sleep(3)  # Wait for potential timed redirects
            final_url = page.url
            
            # Build redirect chain
            if len(navigation_history) > 1:
                for i, nav in enumerate(navigation_history[1:], 1):
                    redirects.append({
                        'step': i,
                        'url': nav['url'],
                        'status_code': nav['status'],
                        'method': 'javascript',
                        'timestamp': nav['timestamp']
                    })
            
            # Add meta refresh info
            if meta_refresh:
                for meta in meta_refresh:
                    redirects.append({
                        'method': 'meta_refresh',
                        'content': meta['content'],
                        'target_url': meta.get('url', 'unknown')
                    })
            
            # Check if final URL is different (timed redirect)
            if initial_url != final_url:
                redirects.append({
                    'method': 'timed_redirect',
                    'from_url': initial_url,
                    'to_url': final_url,
                    'detected': True
                })
            
            await page.close()
            
        except PlaywrightTimeoutError:
            logger.warning(f"Timeout while checking JS redirects for {url}")
        except Exception as e:
            logger.error(f"Error checking JS redirects for {url}: {str(e)}")
        
        return redirects
    
    async def _analyze_redirect_chain(self, original_url: str, chain: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the complete redirect chain."""
        if not chain:
            return {
                'final_url': original_url,
                'has_meta_redirect': 'no',
                'has_timed_redirect': 'no',
                'chain_length': 0,
                'suspicious_patterns': []
            }
        
        final_url = original_url
        has_meta = False
        has_timed = False
        suspicious_patterns = []
        
        for step in chain:
            if step.get('method') == 'meta_refresh':
                has_meta = True
            elif step.get('method') == 'timed_redirect':
                has_timed = True
                final_url = step.get('to_url', final_url)
            elif step.get('url'):
                final_url = step['url']
            
            # Check for suspicious patterns
            if step.get('url'):
                if self._is_suspicious_url(step['url']):
                    suspicious_patterns.append({
                        'step': step.get('step', 'unknown'),
                        'url': step['url'],
                        'reason': 'suspicious_domain_or_path'
                    })
        
        return {
            'final_url': final_url,
            'has_meta_redirect': 'yes' if has_meta else 'no',
            'has_timed_redirect': 'yes' if has_timed else 'no',
            'chain_length': len(chain),
            'suspicious_patterns': suspicious_patterns
        }
    
    def _calculate_risk_score(self, original_url: str, analysis: Dict[str, Any], chain: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate risk score based on analysis results."""
        score = 0.0
        reasons = []
        
        # Long redirect chain (suspicious)
        if analysis['chain_length'] > 3:
            score += 0.3
            reasons.append(f"Long redirect chain ({analysis['chain_length']} steps)")
        
        # JavaScript/meta redirects (more suspicious)
        if analysis['has_meta_redirect'] == 'yes':
            score += 0.2
            reasons.append("Uses meta refresh redirect")
        
        if analysis['has_timed_redirect'] == 'yes':
            score += 0.3
            reasons.append("Uses timed JavaScript redirect")
        
        # Domain analysis
        original_domain = self._extract_domain(original_url)
        final_domain = self._extract_domain(analysis['final_url'])
        
        if original_domain != final_domain:
            score += 0.2
            reasons.append(f"Domain change: {original_domain} → {final_domain}")
        
        # Suspicious domains in chain
        for pattern in analysis.get('suspicious_patterns', []):
            score += 0.1
            reasons.append(f"Suspicious URL in chain: {pattern['url']}")
        
        # Check final domain reputation
        if self._is_suspicious_domain(final_domain):
            score += 0.4
            reasons.append(f"Suspicious final domain: {final_domain}")
        
        # Punycode (IDN attacks)
        if 'xn--' in analysis['final_url']:
            score += 0.3
            reasons.append("Contains punycode (possible IDN attack)")
        
        # Too many subdomains
        subdomain_count = final_domain.count('.') - 1
        if subdomain_count > 3:
            score += 0.2
            reasons.append(f"Too many subdomains ({subdomain_count})")
        
        return {
            'score': min(score, 1.0),  # Cap at 1.0
            'reasons': reasons
        }
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return "unknown"
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL has suspicious characteristics."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Check for suspicious TLDs
            extracted = tldextract.extract(url)
            if extracted.suffix in self.suspicious_tlds:
                return True
            
            # Check for suspicious keywords in path
            suspicious_keywords = [
                'download', 'click', 'redirect', 'goto', 'link',
                'secure', 'verify', 'account', 'update', 'confirm'
            ]
            
            for keyword in suspicious_keywords:
                if keyword in path:
                    return True
            
            # Check for IP addresses instead of domains
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.search(ip_pattern, domain):
                return True
            
            return False
            
        except:
            return True  # If we can't parse it, consider it suspicious
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious."""
        if not domain or domain == "unknown":
            return True
        
        # Check against trusted domains
        extracted = tldextract.extract(f"http://{domain}")
        main_domain = f"{extracted.domain}.{extracted.suffix}"
        
        if main_domain in self.trusted_domains:
            return False
        
        # Check for suspicious characteristics
        if extracted.suffix in self.suspicious_tlds:
            return True
        
        # Check for common typosquatting patterns
        for trusted in self.trusted_domains:
            if self._is_typosquatting(main_domain, trusted):
                return True
        
        return False
    
    def _is_typosquatting(self, domain: str, trusted_domain: str) -> bool:
        """Basic typosquatting detection."""
        # Simple edit distance check
        if len(domain) == len(trusted_domain):
            differences = sum(c1 != c2 for c1, c2 in zip(domain, trusted_domain))
            if differences == 1:  # One character different
                return True
        
        # Character substitution (common in phishing)
        substitutions = {
            'o': '0', 'i': '1', 'l': '1', 'e': '3',
            'a': '@', 's': '$', 'g': '9'
        }
        
        for char, sub in substitutions.items():
            if trusted_domain.replace(char, sub) == domain:
                return True
        
        return False
    
    def _check_domain_mismatch(self, original: Optional[str], final: Optional[str]) -> str:
        """Check if domains match."""
        if not original or not final:
            return "unknown"
        return "yes" if original != final else "no"
    
    def _check_punycode(self, url: str) -> str:
        """Check if URL contains punycode."""
        return "yes" if 'xn--' in url else "no"
    
    def _check_lookalike_domain(self, domain: Optional[str]) -> str:
        """Check if domain looks like a known brand."""
        if not domain:
            return "unknown"
        
        # This is a simplified check - in production, use a comprehensive database
        lookalike_patterns = {
            'goog1e', 'facebbok', 'paypaI', 'microsooft', 'amazom',
            'linkedln', 'github', 'twiter', 'instgram'
        }
        
        for pattern in lookalike_patterns:
            if pattern in domain.lower():
                return "yes"
        
        return "no"


async def analyze_email_links(email_id: int, urls: List[str]) -> List[LinkAnalysis]:
    """Analyze all URLs in an email."""
    results = []
    
    async with LinkRedirectionAnalyzer() as analyzer:
        for url in urls:
            try:
                analysis = await analyzer.analyze_url(email_id, url)
                
                # Save to database
                db = SessionLocal()
                try:
                    db.add(analysis)
                    db.commit()
                    db.refresh(analysis)
                    results.append(analysis)
                finally:
                    db.close()
                    
            except Exception as e:
                logger.error(f"Failed to analyze URL {url}: {str(e)}")
    
    return results
