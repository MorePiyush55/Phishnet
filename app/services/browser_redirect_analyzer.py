"""
Browser Redirect Analyzer

Headless browser analysis using Playwright to detect JavaScript-driven redirects,
capture screenshots, and analyze dynamic behavior for cloaking detection.
"""

import asyncio
import hashlib
import json
import os
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import tempfile
import uuid

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, TimeoutError as PlaywrightTimeoutError

from .redirect_interfaces import (
    BrowserAnalysisResult, RedirectHop, RedirectType,
    COMMON_USER_AGENTS
)
from .http_redirect_tracer import JavaScriptRedirectDetector, MetaRefreshDetector


class BrowserRedirectAnalyzer:
    """Analyzes redirects using headless browser with Playwright"""
    
    def __init__(
        self,
        browser_type: str = "chromium",
        headless: bool = True,
        screenshot_dir: Optional[str] = None,
        max_execution_time: int = 30
    ):
        self.browser_type = browser_type
        self.headless = headless
        self.screenshot_dir = screenshot_dir or tempfile.gettempdir()
        self.max_execution_time = max_execution_time
        
        # Ensure screenshot directory exists
        os.makedirs(self.screenshot_dir, exist_ok=True)
    
    async def analyze_with_browser(
        self,
        url: str,
        user_agents: List[str],
        timeout_seconds: int = 30,
        take_screenshots: bool = True,
        capture_network: bool = True
    ) -> List[BrowserAnalysisResult]:
        """
        Analyze URL with headless browser using different user agents
        
        Args:
            url: The URL to analyze
            user_agents: List of user agents to test
            timeout_seconds: Browser timeout
            take_screenshots: Whether to capture screenshots
            capture_network: Whether to capture network requests
            
        Returns:
            List of browser analysis results (one per user agent)
        """
        results = []
        
        async with async_playwright() as playwright:
            # Launch browser
            browser = await self._launch_browser(playwright)
            
            try:
                for user_agent in user_agents:
                    result = await self._analyze_single_user_agent(
                        browser=browser,
                        url=url,
                        user_agent=user_agent,
                        timeout_seconds=timeout_seconds,
                        take_screenshots=take_screenshots,
                        capture_network=capture_network
                    )
                    results.append(result)
            
            finally:
                await browser.close()
        
        return results
    
    async def _launch_browser(self, playwright) -> Browser:
        """Launch browser with security settings"""
        browser_args = [
            '--no-sandbox',
            '--disable-dev-shm-usage',
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding',
            '--disable-features=TranslateUI',
            '--disable-ipc-flooding-protection',
            '--disable-web-security',  # For some redirects that might be blocked
            '--disable-features=VizDisplayCompositor',
        ]
        
        if self.browser_type == "chromium":
            browser = await playwright.chromium.launch(
                headless=self.headless,
                args=browser_args
            )
        elif self.browser_type == "firefox":
            browser = await playwright.firefox.launch(
                headless=self.headless,
                args=['--no-sandbox'] if not self.headless else []
            )
        else:
            browser = await playwright.webkit.launch(
                headless=self.headless
            )
        
        return browser
    
    async def _analyze_single_user_agent(
        self,
        browser: Browser,
        url: str,
        user_agent: str,
        timeout_seconds: int,
        take_screenshots: bool,
        capture_network: bool
    ) -> BrowserAnalysisResult:
        """Analyze URL with a single user agent"""
        start_time = time.time()
        
        result = BrowserAnalysisResult(
            user_agent_used=user_agent,
            final_url=url
        )
        
        # Create browser context with user agent
        context = await browser.new_context(
            user_agent=user_agent,
            viewport={'width': 1280, 'height': 720},
            ignore_https_errors=True,  # For testing purposes
            java_script_enabled=True
        )
        
        # Create page and set up monitoring
        page = await context.new_page()
        
        # Network request tracking
        network_requests = []
        if capture_network:
            page.on("request", lambda request: network_requests.append({
                'url': request.url,
                'method': request.method,
                'headers': dict(request.headers),
                'timestamp': time.time()
            }))
        
        # Console log tracking
        console_logs = []
        page.on("console", lambda msg: console_logs.append(f"{msg.type}: {msg.text}"))
        
        # JavaScript error tracking
        js_errors = []
        page.on("pageerror", lambda error: js_errors.append(str(error)))
        
        try:
            # Navigate to the URL with timeout
            await page.goto(
                url,
                wait_until="networkidle",
                timeout=timeout_seconds * 1000
            )
            
            # Wait for any JavaScript redirects
            await asyncio.sleep(2)
            
            # Capture final state
            result.final_url = page.url
            result.page_title = await page.title()
            
            # Capture DOM content hash
            dom_content = await page.content()
            result.dom_content_hash = hashlib.sha256(dom_content.encode()).hexdigest()
            
            # Detect JavaScript redirects in the content
            js_redirects = JavaScriptRedirectDetector.extract_js_redirects(dom_content)
            if js_redirects:
                result.console_logs.extend([f"JS redirect detected: {r[0]} -> {r[1]}" for r in js_redirects])
            
            # Detect meta refresh redirects
            meta_refresh = MetaRefreshDetector.extract_meta_refresh(dom_content)
            if meta_refresh:
                delay, refresh_url = meta_refresh
                result.console_logs.append(f"Meta refresh detected: {delay}s -> {refresh_url}")
            
            # Capture loaded scripts
            script_elements = await page.query_selector_all('script[src]')
            for script in script_elements:
                src = await script.get_attribute('src')
                if src:
                    result.loaded_scripts.append(src)
            
            # Detect forms (for credential harvesting detection)
            form_elements = await page.query_selector_all('form')
            for form in form_elements:
                action = await form.get_attribute('action') or ""
                method = await form.get_attribute('method') or "get"
                
                # Find input fields
                inputs = await form.query_selector_all('input')
                input_types = []
                for input_elem in inputs:
                    input_type = await input_elem.get_attribute('type') or "text"
                    input_types.append(input_type)
                
                result.forms_detected.append({
                    'action': action,
                    'method': method.lower(),
                    'input_types': input_types
                })
            
            # Take screenshot if requested
            if take_screenshots:
                screenshot_filename = f"screenshot_{uuid.uuid4().hex}_{int(time.time())}.png"
                screenshot_path = os.path.join(self.screenshot_dir, screenshot_filename)
                await page.screenshot(path=screenshot_path, full_page=True)
                result.screenshot_path = screenshot_path
            
            # Store collected data
            result.console_logs = console_logs
            result.network_requests = network_requests
            result.javascript_errors = js_errors
            
        except PlaywrightTimeoutError:
            result.error = f"Browser timeout after {timeout_seconds} seconds"
        except Exception as e:
            result.error = f"Browser analysis error: {str(e)}"
        
        finally:
            # Calculate execution time
            result.execution_time_ms = int((time.time() - start_time) * 1000)
            
            # Clean up
            await context.close()
        
        return result
    
    async def trace_dynamic_redirects(
        self,
        url: str,
        user_agent: str = None,
        timeout_seconds: int = 30
    ) -> List[RedirectHop]:
        """
        Trace redirects that happen through JavaScript or meta refresh
        
        Args:
            url: The URL to analyze
            user_agent: User agent to use (default: Chrome user)
            timeout_seconds: Maximum time to wait
            
        Returns:
            List of redirect hops detected through browser analysis
        """
        if not user_agent:
            user_agent = COMMON_USER_AGENTS["chrome_user"]
        
        hops = []
        
        async with async_playwright() as playwright:
            browser = await self._launch_browser(playwright)
            
            try:
                context = await browser.new_context(
                    user_agent=user_agent,
                    ignore_https_errors=True
                )
                page = await context.new_page()
                
                # Track navigation events
                navigation_history = []
                
                async def on_response(response):
                    navigation_history.append({
                        'url': response.url,
                        'status': response.status,
                        'headers': dict(response.headers),
                        'timestamp': time.time()
                    })
                
                page.on("response", on_response)
                
                # Navigate to initial URL
                await page.goto(url, timeout=timeout_seconds * 1000)
                
                # Wait for potential redirects
                await asyncio.sleep(3)
                
                # Build redirect hops from navigation history
                for i, nav in enumerate(navigation_history):
                    if nav['status'] in [301, 302, 303, 307, 308] or i > 0:
                        hop = RedirectHop(
                            hop_number=i,
                            url=nav['url'],
                            status_code=nav['status'],
                            response_headers=nav['headers'],
                            timestamp=nav['timestamp']
                        )
                        
                        # Determine redirect type
                        if nav['status'] in [301, 302, 303, 307, 308]:
                            hop.redirect_type = self._status_to_redirect_type(nav['status'])
                        elif i > 0:
                            # Likely JavaScript redirect
                            hop.redirect_type = RedirectType.JAVASCRIPT
                        
                        hops.append(hop)
                
                # Check for meta refresh or JavaScript redirects in final page
                final_content = await page.content()
                
                # Meta refresh detection
                meta_refresh = MetaRefreshDetector.extract_meta_refresh(final_content)
                if meta_refresh:
                    delay, refresh_url = meta_refresh
                    if refresh_url:
                        hop = RedirectHop(
                            hop_number=len(hops),
                            url=refresh_url,
                            redirect_type=RedirectType.META_REFRESH,
                            timestamp=time.time()
                        )
                        hops.append(hop)
                
                # JavaScript redirect detection
                js_redirects = JavaScriptRedirectDetector.extract_js_redirects(final_content)
                for js_type, js_url in js_redirects:
                    hop = RedirectHop(
                        hop_number=len(hops),
                        url=js_url,
                        redirect_type=RedirectType.JAVASCRIPT,
                        timestamp=time.time()
                    )
                    hop.dom_changes = [f"JavaScript redirect: {js_type}"]
                    hops.append(hop)
            
            finally:
                await browser.close()
        
        return hops
    
    def _status_to_redirect_type(self, status_code: int) -> RedirectType:
        """Convert HTTP status code to redirect type"""
        status_map = {
            301: RedirectType.HTTP_301,
            302: RedirectType.HTTP_302,
            303: RedirectType.HTTP_303,
            307: RedirectType.HTTP_307,
            308: RedirectType.HTTP_308
        }
        return status_map.get(status_code, RedirectType.HTTP_302)


class DOMAnalyzer:
    """Analyzes DOM content for security indicators"""
    
    @staticmethod
    async def analyze_page_security(page: Page) -> Dict[str, Any]:
        """
        Analyze page for security indicators
        
        Args:
            page: Playwright page object
            
        Returns:
            Dictionary with security analysis
        """
        analysis = {
            'suspicious_forms': [],
            'external_resources': [],
            'suspicious_scripts': [],
            'credential_harvesting_risk': False,
            'social_engineering_indicators': []
        }
        
        try:
            # Analyze forms for credential harvesting
            forms = await page.query_selector_all('form')
            for form in forms:
                form_analysis = await DOMAnalyzer._analyze_form(form)
                if form_analysis['suspicious']:
                    analysis['suspicious_forms'].append(form_analysis)
                    analysis['credential_harvesting_risk'] = True
            
            # Analyze external resources
            scripts = await page.query_selector_all('script[src]')
            for script in scripts:
                src = await script.get_attribute('src')
                if src and not src.startswith('/') and 'http' in src:
                    analysis['external_resources'].append(src)
            
            # Look for suspicious script content
            inline_scripts = await page.query_selector_all('script:not([src])')
            for script in inline_scripts:
                content = await script.inner_text()
                if DOMAnalyzer._is_suspicious_script(content):
                    analysis['suspicious_scripts'].append(content[:200])  # First 200 chars
            
            # Look for social engineering indicators
            page_text = await page.inner_text('body')
            social_indicators = DOMAnalyzer._detect_social_engineering(page_text)
            analysis['social_engineering_indicators'] = social_indicators
        
        except Exception as e:
            analysis['analysis_error'] = str(e)
        
        return analysis
    
    @staticmethod
    async def _analyze_form(form) -> Dict[str, Any]:
        """Analyze a form for suspicious characteristics"""
        analysis = {
            'suspicious': False,
            'action': '',
            'method': 'get',
            'input_types': [],
            'suspicious_reasons': []
        }
        
        try:
            # Get form attributes
            action = await form.get_attribute('action') or ""
            method = await form.get_attribute('method') or "get"
            
            analysis['action'] = action
            analysis['method'] = method.lower()
            
            # Analyze input fields
            inputs = await form.query_selector_all('input')
            for input_elem in inputs:
                input_type = await input_elem.get_attribute('type') or "text"
                analysis['input_types'].append(input_type)
            
            # Check for suspicious patterns
            if 'password' in analysis['input_types']:
                analysis['suspicious'] = True
                analysis['suspicious_reasons'].append('Password field detected')
            
            if 'email' in analysis['input_types']:
                analysis['suspicious_reasons'].append('Email field detected')
            
            # Check if form submits to external domain
            if action and action.startswith('http') and '://' in action:
                analysis['suspicious'] = True
                analysis['suspicious_reasons'].append('External form submission')
            
            # Check for hidden fields (could be tracking)
            hidden_inputs = [t for t in analysis['input_types'] if t == 'hidden']
            if len(hidden_inputs) > 2:
                analysis['suspicious_reasons'].append(f'{len(hidden_inputs)} hidden fields')
        
        except Exception:
            pass
        
        return analysis
    
    @staticmethod
    def _is_suspicious_script(script_content: str) -> bool:
        """Check if script content contains suspicious patterns"""
        suspicious_patterns = [
            'window.location.replace',
            'document.location.href',
            'eval(',
            'unescape(',
            'fromCharCode',
            'innerHTML',
            'document.write',
            'crypto-',  # Crypto-related scripts
            'wallet',
            'seed phrase',
            'private key'
        ]
        
        content_lower = script_content.lower()
        return any(pattern.lower() in content_lower for pattern in suspicious_patterns)
    
    @staticmethod
    def _detect_social_engineering(page_text: str) -> List[str]:
        """Detect social engineering indicators in page text"""
        indicators = []
        text_lower = page_text.lower()
        
        # Common phishing phrases
        phishing_phrases = [
            'urgent action required',
            'account will be suspended',
            'verify your account',
            'click here immediately',
            'limited time offer',
            'act now',
            'congratulations! you have won',
            'your account has been compromised',
            'security alert',
            'update your payment information',
            'confirm your identity',
            'suspended account',
            'unusual activity detected'
        ]
        
        for phrase in phishing_phrases:
            if phrase in text_lower:
                indicators.append(f"Phishing phrase: '{phrase}'")
        
        # Check for cryptocurrency/financial scams
        crypto_terms = ['bitcoin', 'ethereum', 'crypto', 'wallet', 'investment opportunity']
        crypto_count = sum(1 for term in crypto_terms if term in text_lower)
        if crypto_count >= 2:
            indicators.append('Potential cryptocurrency scam indicators')
        
        # Check for urgency indicators
        urgency_terms = ['urgent', 'immediate', 'expires today', 'limited time', 'act now']
        urgency_count = sum(1 for term in urgency_terms if term in text_lower)
        if urgency_count >= 2:
            indicators.append('High urgency language detected')
        
        return indicators
