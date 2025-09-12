"""
Cloaking Detection Engine

Compares responses between different user agents to detect cloaking behavior,
content fingerprinting, and bot detection mechanisms.
"""

import hashlib
import re
import time
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, urljoin
from difflib import SequenceMatcher
import json

from .redirect_interfaces import (
    BrowserAnalysisResult, CloakingDetection, CloakingMethod,
    CLOAKING_THRESHOLDS
)


class CloakingDetectionEngine:
    """Detects cloaking by comparing responses from different user agents"""
    
    def __init__(self):
        self.similarity_threshold = CLOAKING_THRESHOLDS["content_similarity_min"]
        self.size_difference_threshold = CLOAKING_THRESHOLDS["size_difference_max"]
        self.dom_difference_threshold = CLOAKING_THRESHOLDS["dom_difference_max"]
        self.confidence_threshold = CLOAKING_THRESHOLDS["confidence_threshold"]
    
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
        detection = CloakingDetection()
        
        # Check if both analyses were successful
        if user_browser_result.error or bot_browser_result.error:
            detection.cloaking_indicators.append("Cannot compare due to analysis errors")
            return detection
        
        # Analyze different aspects for cloaking
        await self._analyze_content_similarity(
            user_browser_result, bot_browser_result, detection
        )
        
        await self._analyze_redirect_behavior(
            user_browser_result, bot_browser_result, detection
        )
        
        await self._analyze_dom_differences(
            user_browser_result, bot_browser_result, detection
        )
        
        await self._analyze_network_behavior(
            user_browser_result, bot_browser_result, detection
        )
        
        await self._analyze_form_differences(
            user_browser_result, bot_browser_result, detection
        )
        
        # Calculate final confidence and determination
        detection.confidence = self._calculate_confidence(detection)
        detection.is_cloaking_detected = (
            detection.confidence >= self.confidence_threshold and
            len(detection.cloaking_indicators) > 0
        )
        
        return detection
    
    async def _analyze_content_similarity(
        self,
        user_result: BrowserAnalysisResult,
        bot_result: BrowserAnalysisResult,
        detection: CloakingDetection
    ):
        """Analyze content similarity between user and bot responses"""
        
        # Store response sizes
        user_size = len(user_result.dom_content_hash or "")
        bot_size = len(bot_result.dom_content_hash or "")
        
        detection.user_agent_response_size = user_size
        detection.bot_response_size = bot_size
        
        # Calculate size difference ratio
        if user_size > 0 and bot_size > 0:
            size_ratio = abs(user_size - bot_size) / max(user_size, bot_size)
            if size_ratio > self.size_difference_threshold:
                detection.cloaking_indicators.append(
                    f"Significant size difference: {size_ratio:.2%}"
                )
                detection.methods_used.append(CloakingMethod.CONTENT_FINGERPRINTING)
        
        # Compare DOM content hashes
        if user_result.dom_content_hash and bot_result.dom_content_hash:
            if user_result.dom_content_hash != bot_result.dom_content_hash:
                detection.cloaking_indicators.append("Different DOM content hashes")
                detection.methods_used.append(CloakingMethod.DOM_COMPARISON)
        
        # Compare page titles
        user_title = user_result.page_title or ""
        bot_title = bot_result.page_title or ""
        
        if user_title != bot_title:
            title_similarity = SequenceMatcher(None, user_title, bot_title).ratio()
            if title_similarity < 0.8:
                detection.title_differences = [
                    f"User: {user_title[:100]}",
                    f"Bot: {bot_title[:100]}"
                ]
                detection.cloaking_indicators.append("Different page titles")
                detection.methods_used.append(CloakingMethod.USER_AGENT_SWITCHING)
    
    async def _analyze_redirect_behavior(
        self,
        user_result: BrowserAnalysisResult,
        bot_result: BrowserAnalysisResult,
        detection: CloakingDetection
    ):
        """Analyze differences in redirect behavior"""
        
        user_final = user_result.final_url
        bot_final = bot_result.final_url
        
        detection.final_url_user = user_final
        detection.final_url_bot = bot_final
        
        # Check if final URLs are different
        if user_final != bot_final:
            detection.cloaking_indicators.append(
                f"Different final URLs: User({self._clean_url_for_display(user_final)}) vs "
                f"Bot({self._clean_url_for_display(bot_final)})"
            )
            detection.methods_used.append(CloakingMethod.USER_AGENT_SWITCHING)
            
            # Check if bot is redirected to a different domain
            user_domain = urlparse(user_final).netloc
            bot_domain = urlparse(bot_final).netloc
            
            if user_domain != bot_domain:
                detection.cloaking_indicators.append(
                    f"Bot redirected to different domain: {bot_domain}"
                )
    
    async def _analyze_dom_differences(
        self,
        user_result: BrowserAnalysisResult,
        bot_result: BrowserAnalysisResult,
        detection: CloakingDetection
    ):
        """Analyze DOM structure differences"""
        
        # Compare loaded scripts
        user_scripts = set(user_result.loaded_scripts)
        bot_scripts = set(bot_result.loaded_scripts)
        
        script_differences = user_scripts.symmetric_difference(bot_scripts)
        if script_differences:
            detection.script_differences = list(script_differences)[:10]  # Limit to 10
            detection.cloaking_indicators.append(
                f"{len(script_differences)} different scripts loaded"
            )
            detection.methods_used.append(CloakingMethod.DOM_COMPARISON)
        
        # Compare console logs for differences
        user_logs = set(user_result.console_logs)
        bot_logs = set(bot_result.console_logs)
        
        log_differences = user_logs.symmetric_difference(bot_logs)
        if len(log_differences) > 5:  # Threshold for significant differences
            detection.cloaking_indicators.append(
                f"Different console behavior: {len(log_differences)} unique log entries"
            )
            detection.methods_used.append(CloakingMethod.DOM_COMPARISON)
        
        # Compare JavaScript errors
        user_errors = set(user_result.javascript_errors)
        bot_errors = set(bot_result.javascript_errors)
        
        if user_errors != bot_errors:
            detection.cloaking_indicators.append("Different JavaScript errors")
            detection.methods_used.append(CloakingMethod.DOM_COMPARISON)
    
    async def _analyze_network_behavior(
        self,
        user_result: BrowserAnalysisResult,
        bot_result: BrowserAnalysisResult,
        detection: CloakingDetection
    ):
        """Analyze network request differences"""
        
        # Extract URLs from network requests
        user_urls = {req['url'] for req in user_result.network_requests}
        bot_urls = {req['url'] for req in bot_result.network_requests}
        
        # Check for different resources being loaded
        url_differences = user_urls.symmetric_difference(bot_urls)
        if len(url_differences) > 3:  # Threshold for significant differences
            detection.cloaking_indicators.append(
                f"Different network requests: {len(url_differences)} unique URLs"
            )
            detection.methods_used.append(CloakingMethod.CONTENT_FINGERPRINTING)
        
        # Check for tracking/analytics differences
        tracking_domains = {
            'google-analytics.com', 'googletagmanager.com', 'facebook.com',
            'doubleclick.net', 'googlesyndication.com', 'amazon-adsystem.com'
        }
        
        user_tracking = self._extract_tracking_requests(user_result.network_requests, tracking_domains)
        bot_tracking = self._extract_tracking_requests(bot_result.network_requests, tracking_domains)
        
        if user_tracking != bot_tracking:
            detection.cloaking_indicators.append("Different tracking behavior")
            detection.methods_used.append(CloakingMethod.USER_AGENT_SWITCHING)
    
    async def _analyze_form_differences(
        self,
        user_result: BrowserAnalysisResult,
        bot_result: BrowserAnalysisResult,
        detection: CloakingDetection
    ):
        """Analyze differences in form presentation"""
        
        user_forms = user_result.forms_detected
        bot_forms = bot_result.forms_detected
        
        # Compare number of forms
        if len(user_forms) != len(bot_forms):
            detection.cloaking_indicators.append(
                f"Different number of forms: User({len(user_forms)}) vs Bot({len(bot_forms)})"
            )
            detection.methods_used.append(CloakingMethod.DOM_COMPARISON)
        
        # Compare form actions and input types
        user_form_sigs = {self._form_signature(form) for form in user_forms}
        bot_form_sigs = {self._form_signature(form) for form in bot_forms}
        
        if user_form_sigs != bot_form_sigs:
            detection.cloaking_indicators.append("Different form structures")
            detection.methods_used.append(CloakingMethod.DOM_COMPARISON)
    
    def _extract_tracking_requests(
        self,
        network_requests: List[Dict],
        tracking_domains: Set[str]
    ) -> Set[str]:
        """Extract tracking-related requests"""
        tracking_requests = set()
        
        for request in network_requests:
            url = request.get('url', '')
            parsed = urlparse(url)
            
            for domain in tracking_domains:
                if domain in parsed.netloc:
                    tracking_requests.add(parsed.netloc)
                    break
        
        return tracking_requests
    
    def _form_signature(self, form: Dict) -> str:
        """Create a signature for a form based on its structure"""
        action = form.get('action', '')
        method = form.get('method', 'get')
        input_types = sorted(form.get('input_types', []))
        
        return f"{method}:{action}:{','.join(input_types)}"
    
    def _clean_url_for_display(self, url: str) -> str:
        """Clean URL for safe display in logs"""
        if len(url) > 100:
            return url[:97] + "..."
        return url
    
    def _calculate_confidence(self, detection: CloakingDetection) -> float:
        """Calculate confidence score for cloaking detection"""
        confidence = 0.0
        
        # Base confidence from number of indicators
        indicator_count = len(detection.cloaking_indicators)
        confidence += min(indicator_count * 0.15, 0.6)  # Max 0.6 from indicators
        
        # Bonus for specific methods
        method_bonuses = {
            CloakingMethod.USER_AGENT_SWITCHING: 0.3,
            CloakingMethod.DOM_COMPARISON: 0.2,
            CloakingMethod.CONTENT_FINGERPRINTING: 0.25
        }
        
        for method in detection.methods_used:
            confidence += method_bonuses.get(method, 0.1)
        
        # Penalty if too few indicators
        if indicator_count < 2:
            confidence *= 0.5
        
        # Bonus for multiple detection methods
        if len(detection.methods_used) >= 2:
            confidence += 0.1
        
        # Cap at 1.0
        return min(confidence, 1.0)


class ContentFingerprintAnalyzer:
    """Analyzes content for fingerprinting and behavioral differences"""
    
    @staticmethod
    def analyze_content_fingerprints(
        user_content: str,
        bot_content: str
    ) -> Dict[str, any]:
        """
        Analyze content fingerprints between user and bot responses
        
        Returns:
            Dictionary with fingerprint analysis results
        """
        analysis = {
            'content_similarity': 0.0,
            'structural_similarity': 0.0,
            'unique_elements_user': [],
            'unique_elements_bot': [],
            'suspicious_patterns': []
        }
        
        # Overall content similarity
        similarity = SequenceMatcher(None, user_content, bot_content).ratio()
        analysis['content_similarity'] = similarity
        
        # Extract and compare structural elements
        user_structure = ContentFingerprintAnalyzer._extract_html_structure(user_content)
        bot_structure = ContentFingerprintAnalyzer._extract_html_structure(bot_content)
        
        # Calculate structural similarity
        structural_sim = SequenceMatcher(
            None,
            json.dumps(user_structure, sort_keys=True),
            json.dumps(bot_structure, sort_keys=True)
        ).ratio()
        analysis['structural_similarity'] = structural_sim
        
        # Find unique elements
        user_elements = set(user_structure.get('elements', []))
        bot_elements = set(bot_structure.get('elements', []))
        
        analysis['unique_elements_user'] = list(user_elements - bot_elements)[:10]
        analysis['unique_elements_bot'] = list(bot_elements - user_elements)[:10]
        
        # Check for suspicious patterns
        suspicious_patterns = ContentFingerprintAnalyzer._detect_suspicious_patterns(
            user_content, bot_content
        )
        analysis['suspicious_patterns'] = suspicious_patterns
        
        return analysis
    
    @staticmethod
    def _extract_html_structure(html_content: str) -> Dict[str, any]:
        """Extract structural elements from HTML content"""
        structure = {
            'elements': [],
            'scripts': [],
            'forms': [],
            'links': []
        }
        
        # Simple regex-based extraction (would be better with proper HTML parser)
        # Extract element tags
        tag_pattern = r'<(\w+)(?:\s[^>]*)?>'
        tags = re.findall(tag_pattern, html_content.lower())
        structure['elements'] = list(set(tags))
        
        # Extract script sources
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
        scripts = re.findall(script_pattern, html_content, re.IGNORECASE)
        structure['scripts'] = scripts
        
        # Extract form actions
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\']'
        forms = re.findall(form_pattern, html_content, re.IGNORECASE)
        structure['forms'] = forms
        
        # Extract links
        link_pattern = r'<a[^>]*href=["\']([^"\']+)["\']'
        links = re.findall(link_pattern, html_content, re.IGNORECASE)
        structure['links'] = links[:20]  # Limit to prevent huge lists
        
        return structure
    
    @staticmethod
    def _detect_suspicious_patterns(user_content: str, bot_content: str) -> List[str]:
        """Detect suspicious patterns that might indicate cloaking"""
        patterns = []
        
        # Check for bot detection scripts
        bot_detection_keywords = [
            'navigator.webdriver',
            'webdriver',
            'HeadlessChrome',
            'PhantomJS',
            'selenium',
            'automated',
            'bot detection'
        ]
        
        for keyword in bot_detection_keywords:
            if keyword.lower() in user_content.lower() or keyword.lower() in bot_content.lower():
                patterns.append(f"Bot detection keyword: {keyword}")
        
        # Check for user agent detection
        if 'navigator.userAgent' in user_content or 'navigator.userAgent' in bot_content:
            patterns.append("User agent detection script found")
        
        # Check for conditional content loading
        conditional_patterns = [
            'if.*userAgent',
            'if.*bot',
            'if.*crawler',
            'conditional.*load'
        ]
        
        for pattern in conditional_patterns:
            if re.search(pattern, user_content, re.IGNORECASE) or re.search(pattern, bot_content, re.IGNORECASE):
                patterns.append(f"Conditional loading pattern: {pattern}")
        
        return patterns


class BehaviorAnalyzer:
    """Analyzes behavioral differences between user agents"""
    
    @staticmethod
    def analyze_timing_differences(
        user_result: BrowserAnalysisResult,
        bot_result: BrowserAnalysisResult
    ) -> Dict[str, any]:
        """Analyze timing differences that might indicate cloaking"""
        analysis = {
            'execution_time_difference': 0,
            'relative_difference': 0.0,
            'suspicious_timing': False,
            'timing_indicators': []
        }
        
        user_time = user_result.execution_time_ms
        bot_time = bot_result.execution_time_ms
        
        if user_time > 0 and bot_time > 0:
            time_diff = abs(user_time - bot_time)
            relative_diff = time_diff / max(user_time, bot_time)
            
            analysis['execution_time_difference'] = time_diff
            analysis['relative_difference'] = relative_diff
            
            # Suspicious if one takes significantly longer than the other
            if relative_diff > 0.5:  # 50% difference threshold
                analysis['suspicious_timing'] = True
                analysis['timing_indicators'].append(
                    f"Significant timing difference: {relative_diff:.1%}"
                )
            
            # Very suspicious if bot is much faster (might be getting different content)
            if bot_time < user_time * 0.3:  # Bot is less than 30% of user time
                analysis['suspicious_timing'] = True
                analysis['timing_indicators'].append(
                    "Bot execution significantly faster than user"
                )
        
        return analysis
