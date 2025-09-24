"""
Google Gemini API adapter for content analysis and threat intelligence.

This module provides integration with Google's Gemini API for email content analysis,
phishing detection, and social engineering identification.
"""

import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
import aiohttp
import asyncio

from .base import (
    ThreatIntelligenceAdapter, APIResponse, ThreatIntelligence, APIStatus,
    ThreatLevel, ResourceType, AdapterError, QuotaExceededError, 
    RateLimitError, TimeoutError, UnauthorizedError
)


class GeminiClient(ThreatIntelligenceAdapter):
    """Google Gemini API client for content analysis."""
    
    def __init__(self, api_key: str, model: str = "gemini-1.5-flash", requests_per_minute: int = 15):
        super().__init__(
            api_key=api_key,
            base_url="https://generativelanguage.googleapis.com/v1beta",
            name="gemini"
        )
        self.model = model
        self.requests_per_minute = requests_per_minute
        self.last_request_time = 0
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Configure quota - Gemini has generous free tier
        self.quota.requests_limit = requests_per_minute * 1440  # Per day
        
        # Threat detection prompts
        self.system_prompt = """You are a cybersecurity expert analyzing email content for threats. 
Analyze the provided email content and respond with a JSON object containing:

{
  "threat_level": "safe|low|medium|high|critical",
  "confidence": 0.0-1.0,
  "detected_threats": ["list", "of", "specific", "threats"],
  "categories": ["phishing", "malware", "spam", "social_engineering", etc.],
  "reasoning": "Brief explanation of the analysis",
  "indicators": {
    "urgency_tactics": 0.0-1.0,
    "credential_harvesting": 0.0-1.0,
    "social_engineering": 0.0-1.0,
    "suspicious_links": 0.0-1.0,
    "impersonation": 0.0-1.0,
    "financial_fraud": 0.0-1.0
  },
  "risk_factors": ["specific", "risk", "factors"],
  "language_analysis": {
    "sentiment": "positive|negative|neutral",
    "formality": "formal|informal|mixed",
    "authenticity": 0.0-1.0
  }
}

Analyze for: phishing attempts, malware indicators, social engineering tactics, 
credential harvesting, financial fraud, domain spoofing, urgency manipulation, 
impersonation attempts, suspicious links, and other email-based threats."""
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=60, connect=15)  # Longer timeout for AI
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'PhishNet-ThreatIntel/1.0'
            }
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers
            )
        return self.session
    
    async def _rate_limit(self) -> None:
        """Enforce rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        min_interval = 60.0 / self.requests_per_minute
        
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            self.logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            await asyncio.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    async def _make_request(self, prompt: str) -> Dict[str, Any]:
        """Make request to Gemini API."""
        if not self.check_quota():
            raise QuotaExceededError(
                f"Gemini quota exceeded. Requests made: {self.quota.requests_made}/{self.quota.requests_limit}"
            )
        
        await self._rate_limit()
        
        session = await self._get_session()
        url = f"{self.base_url}/models/{self.model}:generateContent"
        
        # Prepare request payload
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{self.system_prompt}\n\nEmail content to analyze:\n{prompt}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.1,  # Low temperature for consistent analysis
                "maxOutputTokens": 2048,
                "responseMimeType": "application/json"
            },
            "safetySettings": [
                {
                    "category": "HARM_CATEGORY_HARASSMENT",
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_HATE_SPEECH", 
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_NONE"
                },
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_NONE"
                }
            ]
        }
        
        start_time = time.time()
        
        try:
            params = {"key": self.api_key}
            async with session.post(url, json=payload, params=params) as response:
                response_time = time.time() - start_time
                
                if response.status == 200:
                    self.consume_quota()
                    data = await response.json()
                    self.logger.debug(f"Gemini API success")
                    return data
                elif response.status == 401:
                    raise UnauthorizedError("Invalid Gemini API key")
                elif response.status == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    raise RateLimitError(
                        f"Gemini rate limit exceeded",
                        retry_after=retry_after
                    )
                elif response.status == 400:
                    error_data = await response.json()
                    error_msg = error_data.get('error', {}).get('message', 'Bad request')
                    raise AdapterError(f"Gemini API validation error: {error_msg}", APIStatus.ERROR)
                else:
                    error_text = await response.text()
                    raise AdapterError(
                        f"Gemini API error {response.status}: {error_text}",
                        APIStatus.ERROR
                    )
                    
        except asyncio.TimeoutError:
            raise TimeoutError("Gemini API request timed out")
        except aiohttp.ClientError as e:
            raise AdapterError(f"Gemini API connection error: {str(e)}", APIStatus.ERROR)
    
    async def analyze_content(self, content: str) -> APIResponse:
        """Analyze email content using Gemini."""
        try:
            if not content.strip():
                return APIResponse(
                    success=False,
                    status=APIStatus.ERROR,
                    error_message="Empty content provided for analysis"
                )
            
            # Truncate very long content to avoid token limits
            max_content_length = 10000  # Approximate token limit consideration
            if len(content) > max_content_length:
                content = content[:max_content_length] + "... [truncated]"
            
            raw_response = await self._make_request(content)
            threat_intel = self.normalize_response(raw_response, content, ResourceType.EMAIL_ADDRESS)
            
            return APIResponse(
                success=True,
                status=APIStatus.SUCCESS,
                data=threat_intel,
                raw_response=raw_response,
                quota_remaining=self.quota.requests_remaining
            )
            
        except AdapterError as e:
            return APIResponse(
                success=False,
                status=e.status,
                error_message=str(e),
                retry_after=e.retry_after
            )
        except Exception as e:
            self.logger.error(f"Unexpected error analyzing content: {str(e)}")
            return APIResponse(
                success=False,
                status=APIStatus.ERROR,
                error_message=f"Unexpected error: {str(e)}"
            )
    
    async def analyze_url(self, url: str) -> APIResponse:
        """Analyze URL by examining its components."""
        prompt = f"Analyze this URL for threats and suspicious characteristics: {url}"
        return await self.analyze_content(prompt)
    
    async def analyze_domain(self, domain: str) -> APIResponse:
        """Analyze domain for threat indicators."""
        prompt = f"Analyze this domain for threat indicators, spoofing, and suspicious characteristics: {domain}"
        return await self.analyze_content(prompt)
    
    async def analyze_ip(self, ip_address: str) -> APIResponse:
        """IP analysis not optimized for Gemini."""
        return APIResponse(
            success=False,
            status=APIStatus.ERROR,
            error_message="Gemini is not optimized for IP address analysis. Use specialized IP threat intelligence services."
        )
    
    async def analyze_file_hash(self, file_hash: str) -> APIResponse:
        """File hash analysis not supported by Gemini."""
        return APIResponse(
            success=False,
            status=APIStatus.ERROR,
            error_message="Gemini does not support file hash analysis. Use malware analysis services."
        )
    
    def normalize_response(self, raw_response: Dict[str, Any], 
                          resource: str, resource_type: ResourceType) -> ThreatIntelligence:
        """Normalize Gemini response to standard format."""
        try:
            # Extract content from Gemini response
            candidates = raw_response.get("candidates", [])
            if not candidates:
                raise ValueError("No analysis results in response")
            
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            if not parts:
                raise ValueError("No content parts in response")
            
            # Parse the JSON response from Gemini
            analysis_text = parts[0].get("text", "")
            try:
                analysis = json.loads(analysis_text)
            except json.JSONDecodeError:
                # Try to extract JSON from the text if it's wrapped
                import re
                json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
                if json_match:
                    analysis = json.loads(json_match.group())
                else:
                    raise ValueError("Could not parse JSON from Gemini response")
            
            # Extract threat level
            threat_level_str = analysis.get("threat_level", "unknown").lower()
            threat_level_map = {
                "safe": ThreatLevel.SAFE,
                "low": ThreatLevel.LOW,
                "medium": ThreatLevel.MEDIUM,
                "high": ThreatLevel.HIGH,
                "critical": ThreatLevel.CRITICAL
            }
            threat_level = threat_level_map.get(threat_level_str, ThreatLevel.UNKNOWN)
            
            # Extract confidence
            confidence = float(analysis.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))  # Clamp to valid range
            
            # Extract detected threats and categories
            detected_threats = analysis.get("detected_threats", [])
            categories = analysis.get("categories", [])
            
            # Extract risk factors
            risk_factors = analysis.get("risk_factors", [])
            
            # Calculate reputation score based on threat level and confidence
            level_scores = {
                ThreatLevel.SAFE: 1.0,
                ThreatLevel.LOW: 0.8,
                ThreatLevel.MEDIUM: 0.5,
                ThreatLevel.HIGH: 0.2,
                ThreatLevel.CRITICAL: 0.0,
                ThreatLevel.UNKNOWN: 0.5
            }
            base_score = level_scores[threat_level]
            reputation_score = base_score * confidence + (1 - confidence) * 0.5
            
            # Extract additional metadata
            indicators = analysis.get("indicators", {})
            language_analysis = analysis.get("language_analysis", {})
            reasoning = analysis.get("reasoning", "")
            
            return ThreatIntelligence(
                resource=resource[:100],  # Truncate long content for storage
                resource_type=resource_type,
                threat_level=threat_level,
                confidence=confidence,
                source="gemini",
                detected_threats=detected_threats[:10],  # Limit to top 10
                categories=categories,
                reputation_score=reputation_score,
                first_seen=None,
                last_seen=datetime.utcnow(),
                metadata={
                    "reasoning": reasoning,
                    "indicators": indicators,
                    "language_analysis": language_analysis,
                    "risk_factors": risk_factors,
                    "model": self.model,
                    "content_length": len(resource)
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error normalizing Gemini response: {str(e)}")
            # Return fallback based on simple heuristics
            content_lower = resource.lower()
            
            # Simple keyword-based fallback detection
            suspicious_keywords = [
                'urgent', 'suspend', 'verify', 'click here', 'act now',
                'limited time', 'expires', 'account locked', 'security alert'
            ]
            
            detected_count = sum(1 for keyword in suspicious_keywords if keyword in content_lower)
            
            if detected_count >= 3:
                threat_level = ThreatLevel.HIGH
                confidence = 0.6
            elif detected_count >= 1:
                threat_level = ThreatLevel.MEDIUM
                confidence = 0.5
            else:
                threat_level = ThreatLevel.LOW
                confidence = 0.4
            
            return ThreatIntelligence(
                resource=resource[:100],
                resource_type=resource_type,
                threat_level=threat_level,
                confidence=confidence,
                source="gemini",
                detected_threats=[f"keyword_match_{i}" for i in range(detected_count)],
                categories=["fallback_analysis"],
                metadata={
                    "error": f"Normalization failed: {str(e)}",
                    "fallback_method": "keyword_detection",
                    "suspicious_keywords_found": detected_count
                }
            )
    
    async def close(self):
        """Close HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


# Example usage and testing
async def test_gemini_client():
    """Test Gemini client with sample content."""
    import os
    
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("❌ GEMINI_API_KEY environment variable not set")
        return
    
    async with GeminiClient(api_key) as client:
        # Test phishing email content
        phishing_content = """
        From: security@paypal-verification.com
        Subject: URGENT: Account Suspension Notice
        
        Dear Customer,
        
        Your PayPal account has been temporarily suspended due to unusual activity.
        You must verify your account immediately to avoid permanent closure.
        
        Click here to verify: https://paypal-secure-verification.net/login
        
        This is urgent - you have 24 hours to complete verification.
        
        PayPal Security Team
        """
        
        print("Testing phishing content analysis...")
        result = await client.analyze_content(phishing_content)
        print(f"Result: {result.success}")
        if result.data:
            print(f"  Threat Level: {result.data.threat_level}")
            print(f"  Confidence: {result.data.confidence}")
            print(f"  Detected Threats: {result.data.detected_threats}")
            print(f"  Categories: {result.data.categories}")
        
        # Test legitimate content
        legitimate_content = """
        From: noreply@github.com
        Subject: Your pull request was merged
        
        Hi there,
        
        Your pull request #123 "Fix authentication bug" was successfully merged
        into the main branch of your repository.
        
        View the changes: https://github.com/user/repo/pull/123
        
        Thanks for contributing!
        GitHub Team
        """
        
        print("\nTesting legitimate content analysis...")
        result2 = await client.analyze_content(legitimate_content)
        print(f"Result: {result2.success}")
        if result2.data:
            print(f"  Threat Level: {result2.data.threat_level}")
            print(f"  Confidence: {result2.data.confidence}")
        
        # Test quota status
        print(f"\nQuota status: {client.get_quota_status()}")


if __name__ == "__main__":
    asyncio.run(test_gemini_client())