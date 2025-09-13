"""
Google Gemini AI client with unified interface for text analysis.
Provides advanced content analysis for phishing detection and threat assessment.
"""

import asyncio
import hashlib
import time
import json
from typing import Dict, Any, Optional, List

import aiohttp
from app.config.settings import settings
from app.config.logging import get_logger
from app.core.redis_client import get_redis_connection
from app.services.interfaces import (
    IAnalyzer, AnalysisResult, AnalysisType, ServiceHealth, ServiceStatus,
    GeminiResult, ServiceUnavailableError, InvalidTargetError, 
    AnalysisError, RateLimitError
)

logger = get_logger(__name__)


class GeminiClient(IAnalyzer):
    """
    Google Gemini AI client implementing IAnalyzer interface.
    Provides advanced text analysis for phishing and threat detection.
    """
    
    BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
    MODEL_NAME = "gemini-pro"  # or "gemini-1.5-pro" for latest
    
    # Rate limits for Gemini API (free tier)
    REQUESTS_PER_MINUTE = 60
    TOKENS_PER_MINUTE = 32000
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("gemini")
        self.api_key = api_key or settings.GEMINI_API_KEY
        self._rate_limiter = asyncio.Semaphore(10)  # Concurrent requests
        self._last_request_time = 0.0
        
        if not self.api_key:
            logger.warning("Gemini API key not configured")
            self._health.status = ServiceStatus.UNAVAILABLE
    
    async def analyze(self, target: str, analysis_type: AnalysisType) -> AnalysisResult:
        """
        Analyze text content using Gemini AI.
        
        Args:
            target: Text content to analyze (email content, subject, etc.)
            analysis_type: Must be TEXT_ANALYSIS
            
        Returns:
            Normalized AnalysisResult with LLM assessment and reasoning
        """
        if not self.is_available:
            raise ServiceUnavailableError(f"Gemini service unavailable: {self._health.status}")
        
        if analysis_type != AnalysisType.TEXT_ANALYSIS:
            raise InvalidTargetError(f"Gemini only supports text analysis")
        
        start_time = time.time()
        
        try:
            # Check cache first
            cache_key = f"gemini:{hashlib.md5(target.encode()).hexdigest()[:16]}"
            cached_result = await self._get_cached_result(cache_key)
            if cached_result:
                logger.debug(f"Gemini cache hit for text analysis")
                return cached_result
            
            # Validate text content
            self._validate_text_content(target)
            
            # Perform analysis with rate limiting
            raw_response = await self._make_api_request(target)
            
            # Parse response into normalized result
            gemini_result = self._parse_response(raw_response)
            analysis_result = self._create_analysis_result(
                target, analysis_type, gemini_result, raw_response, start_time
            )
            
            # Cache successful results
            await self._cache_result(cache_key, analysis_result, ttl=1800)  # 30 minutes
            
            # Update health status
            self._update_health_success()
            
            logger.info(f"Gemini analysis complete: score {analysis_result.threat_score}")
            return analysis_result
            
        except RateLimitError as e:
            self._update_rate_limit(e.reset_time or time.time() + 60)
            raise ServiceUnavailableError("Gemini rate limit exceeded")
            
        except Exception as e:
            self._update_health_failure()
            execution_time = int((time.time() - start_time) * 1000)
            
            # Return error result instead of raising exception
            return AnalysisResult(
                service_name=self.service_name,
                analysis_type=analysis_type,
                target=target[:100] + "..." if len(target) > 100 else target,  # Truncate for logging
                threat_score=0.0,  # Conservative default
                confidence=0.0,
                raw_response={"error": str(e)},
                timestamp=start_time,
                execution_time_ms=execution_time,
                error=f"Gemini analysis failed: {str(e)}"
            )
    
    async def _make_api_request(self, text_content: str) -> Dict[str, Any]:
        """Make rate-limited API request to Gemini."""
        
        await self._rate_limiter.acquire()
        try:
            # Enforce rate limiting
            now = time.time()
            time_since_last = now - self._last_request_time
            min_interval = 60.0 / self.REQUESTS_PER_MINUTE
            
            if time_since_last < min_interval:
                await asyncio.sleep(min_interval - time_since_last)
            
            self._last_request_time = time.time()
            
            # Build analysis prompt
            prompt = self._build_analysis_prompt(text_content)
            
            # Prepare request
            url = f"{self.BASE_URL}/models/{self.MODEL_NAME}:generateContent"
            headers = {
                'Content-Type': 'application/json'
            }
            params = {
                'key': self.api_key
            }
            
            payload = {
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }],
                "generationConfig": {
                    "temperature": 0.1,  # Low temperature for consistent analysis
                    "topK": 1,
                    "topP": 0.8,
                    "maxOutputTokens": 1000,
                    "candidateCount": 1
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
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    params=params,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    
                    if response.status == 429:
                        raise RateLimitError(time.time() + 60)
                    elif response.status == 400:
                        error_data = await response.json()
                        raise AnalysisError(f"Gemini API error: {error_data}")
                    elif response.status != 200:
                        raise AnalysisError(f"Gemini API error: {response.status}")
                    
                    return await response.json()
                    
        finally:
            self._rate_limiter.release()
    
    def _build_analysis_prompt(self, text_content: str) -> str:
        """Build analysis prompt for Gemini AI."""
        
        # Truncate very long content to stay within token limits
        max_chars = 8000  # Approximate token limit consideration
        if len(text_content) > max_chars:
            text_content = text_content[:max_chars] + "...[truncated]"
        
        prompt = f"""
You are an expert cybersecurity analyst specializing in phishing detection. Analyze the following email content for signs of phishing, scams, or malicious intent.

EMAIL CONTENT TO ANALYZE:
---
{text_content}
---

Please provide your analysis in the following JSON format:

{{
    "threat_score": <float between 0.0 and 1.0, where 1.0 is definitely malicious>,
    "confidence": <float between 0.0 and 1.0 indicating your confidence in the assessment>,
    "verdict": "<one of: 'benign', 'suspicious', 'phishing', 'scam', 'malicious'>",
    "explanation": "<detailed explanation of your assessment>",
    "indicators": [
        "<specific phishing indicators found>",
        "<social engineering techniques detected>",
        "<suspicious elements identified>"
    ],
    "techniques": [
        "<phishing techniques used (e.g., urgency, authority, fear)>",
        "<technical indicators (suspicious links, attachments, etc.)>"
    ],
    "confidence_reasoning": "<explanation of why you have this level of confidence>"
}}

Focus on these key phishing indicators:
- Urgent language or deadline pressure
- Requests for sensitive information (passwords, SSNs, financial data)
- Suspicious sender addresses or domains
- Grammar/spelling errors typical of phishing
- Generic greetings or impersonation attempts
- Threats or consequences for not responding
- Suspicious links or attachments
- Social engineering tactics (authority, fear, curiosity)
- Inconsistencies in branding or formatting

Provide only the JSON response, no additional text.
"""
        
        return prompt
    
    def _validate_text_content(self, text_content: str):
        """Validate text content for analysis."""
        if not text_content or not text_content.strip():
            raise InvalidTargetError("Empty text content provided")
        
        if len(text_content) < 10:
            raise InvalidTargetError("Text content too short for meaningful analysis")
        
        # Check for extremely long content that might exceed API limits
        if len(text_content) > 50000:  # Conservative limit
            logger.warning(f"Large text content ({len(text_content)} chars) will be truncated")
    
    def _parse_response(self, response: Dict[str, Any]) -> GeminiResult:
        """Parse Gemini API response into structured result."""
        
        try:
            candidates = response.get('candidates', [])
            if not candidates:
                raise AnalysisError("No response candidates from Gemini")
            
            content = candidates[0].get('content', {})
            parts = content.get('parts', [])
            if not parts:
                raise AnalysisError("No content parts in Gemini response")
            
            response_text = parts[0].get('text', '')
            if not response_text:
                raise AnalysisError("Empty response from Gemini")
            
            # Parse JSON response
            try:
                analysis_data = json.loads(response_text)
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Gemini JSON response: {e}")
                # Fallback: extract key information with regex if JSON parsing fails
                return self._fallback_parse(response_text)
            
            # Extract structured data
            llm_score = float(analysis_data.get('threat_score', 0.0))
            confidence = float(analysis_data.get('confidence', 0.5))
            verdict = analysis_data.get('verdict', 'unknown')
            explanation = analysis_data.get('explanation', 'Analysis completed')
            indicators = analysis_data.get('indicators', [])
            techniques = analysis_data.get('techniques', [])
            confidence_reasoning = analysis_data.get('confidence_reasoning', '')
            
            # Validate scores
            llm_score = max(0.0, min(1.0, llm_score))
            confidence = max(0.0, min(1.0, confidence))
            
            return GeminiResult(
                llm_score=llm_score,
                verdict=verdict,
                explanation_snippets=indicators[:5],  # Top 5 indicators
                confidence_reasoning=confidence_reasoning,
                detected_techniques=techniques
            )
            
        except Exception as e:
            logger.error(f"Error parsing Gemini response: {e}")
            # Return conservative default
            return GeminiResult(
                llm_score=0.0,
                verdict="unknown",
                explanation_snippets=["Error parsing AI analysis"],
                confidence_reasoning=f"Analysis failed: {str(e)}"
            )
    
    def _fallback_parse(self, response_text: str) -> GeminiResult:
        """Fallback parsing when JSON parsing fails."""
        
        # Simple keyword-based threat detection as fallback
        phishing_keywords = [
            'phishing', 'scam', 'malicious', 'suspicious', 'fraud',
            'urgent', 'verify', 'account suspended', 'click here',
            'personal information', 'password', 'social security'
        ]
        
        text_lower = response_text.lower()
        detected_keywords = [kw for kw in phishing_keywords if kw in text_lower]
        
        # Basic scoring based on detected keywords
        threat_score = min(len(detected_keywords) / 10.0, 1.0)
        
        return GeminiResult(
            llm_score=threat_score,
            verdict="suspicious" if threat_score > 0.3 else "unknown",
            explanation_snippets=detected_keywords[:5],
            confidence_reasoning="Fallback analysis due to parsing error"
        )
    
    def _create_analysis_result(
        self,
        target: str,
        analysis_type: AnalysisType,
        gemini_result: GeminiResult,
        raw_response: Dict[str, Any],
        start_time: float
    ) -> AnalysisResult:
        """Create normalized AnalysisResult from Gemini data."""
        
        # Use Gemini's threat score directly
        threat_score = gemini_result.llm_score
        
        # Calculate confidence (Gemini provides this, but we can adjust)
        confidence = 0.8  # LLMs generally have good confidence for text analysis
        
        if gemini_result.confidence_reasoning:
            # If Gemini provided reasoning, trust its confidence more
            confidence = 0.9
        
        # Generate explanation
        explanation = self._generate_explanation(gemini_result)
        
        # Prepare indicators
        indicators = []
        indicators.extend(gemini_result.explanation_snippets[:3])
        if gemini_result.detected_techniques:
            indicators.extend(gemini_result.detected_techniques[:2])
        
        return AnalysisResult(
            service_name=self.service_name,
            analysis_type=analysis_type,
            target=target[:100] + "..." if len(target) > 100 else target,
            threat_score=threat_score,
            confidence=confidence,
            raw_response=raw_response,
            timestamp=start_time,
            execution_time_ms=int((time.time() - start_time) * 1000),
            verdict=gemini_result.verdict,
            explanation=explanation,
            indicators=indicators[:5]  # Limit to top 5
        )
    
    def _generate_explanation(self, gemini_result: GeminiResult) -> str:
        """Generate human-readable explanation from Gemini results."""
        
        if gemini_result.llm_score == 0.0:
            return "AI analysis found no significant phishing indicators"
        
        explanation = f"AI analysis detected {gemini_result.verdict} content"
        
        if gemini_result.explanation_snippets:
            indicators_text = ", ".join(gemini_result.explanation_snippets[:3])
            explanation += f" with indicators: {indicators_text}"
        
        if gemini_result.detected_techniques:
            techniques_text = ", ".join(gemini_result.detected_techniques[:2])
            explanation += f". Techniques detected: {techniques_text}"
        
        return explanation
    
    async def _get_cached_result(self, cache_key: str) -> Optional[AnalysisResult]:
        """Retrieve cached analysis result."""
        try:
            redis = get_redis_connection()
            cached_data = await redis.get(cache_key)
            if cached_data:
                # In a real implementation, you'd deserialize the AnalysisResult
                pass
        except Exception as e:
            logger.warning(f"Cache retrieval failed: {e}")
        
        return None
    
    async def _cache_result(self, cache_key: str, result: AnalysisResult, ttl: int = 1800):
        """Cache analysis result for future use."""
        try:
            # In a real implementation, you'd serialize the AnalysisResult
            redis = get_redis_connection()
            await redis.setex(cache_key, ttl, f"cached:{result.threat_score}")
        except Exception as e:
            logger.warning(f"Cache storage failed: {e}")
    
    async def health_check(self) -> ServiceHealth:
        """Check Gemini API health."""
        if not self.api_key:
            self._health.status = ServiceStatus.UNAVAILABLE
            return self._health
        
        try:
            # Simple test with minimal content
            test_text = "This is a test message for health check."
            
            url = f"{self.BASE_URL}/models/{self.MODEL_NAME}:generateContent"
            headers = {'Content-Type': 'application/json'}
            params = {'key': self.api_key}
            
            payload = {
                "contents": [{
                    "parts": [{"text": f"Analyze this text: {test_text}"}]
                }],
                "generationConfig": {
                    "maxOutputTokens": 100
                }
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    params=params,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    if response.status == 200:
                        self._update_health_success()
                    elif response.status == 429:
                        self._update_rate_limit(time.time() + 60)
                    else:
                        self._update_health_failure()
                        
        except Exception as e:
            logger.warning(f"Gemini health check failed: {e}")
            self._update_health_failure()
        
        return self._health

    async def scan(self, resource: str) -> Dict[str, Any]:
        """
        Unified scan method for AI-powered text analysis.
        
        Args:
            resource: Text content to analyze (email body, subject, etc.)
            
        Returns:
            Dict with normalized schema: {
                'threat_score': float,
                'verdict': str,
                'confidence': float,
                'indicators': List[str],
                'raw_data': Dict
            }
        """
        try:
            # Perform analysis
            result = await self.analyze(resource, AnalysisType.TEXT_ANALYSIS)
            
            # Extract LLM assessment from raw response
            raw_data = result.raw_response
            llm_assessment = raw_data.get('llm_assessment', {})
            
            # Generate indicators from LLM analysis
            indicators = []
            if llm_assessment.get('urgency_detected', False):
                indicators.append('urgency_pressure_tactics')
            if llm_assessment.get('credential_harvesting', False):
                indicators.append('credential_harvesting_attempt')
            if llm_assessment.get('impersonation_detected', False):
                indicators.append('brand_impersonation')
            if llm_assessment.get('social_engineering', False):
                indicators.append('social_engineering_tactics')
            if llm_assessment.get('suspicious_links', False):
                indicators.append('suspicious_link_patterns')
            
            # Add reasoning-based indicators
            reasoning = llm_assessment.get('reasoning', '').lower()
            if 'typo' in reasoning or 'misspell' in reasoning:
                indicators.append('suspicious_spelling_grammar')
            if 'urgent' in reasoning or 'immediate' in reasoning:
                indicators.append('time_pressure_tactics')
            if 'verify' in reasoning and 'account' in reasoning:
                indicators.append('account_verification_scam')
            
            # Determine verdict based on threat score and confidence
            threat_score = result.threat_score
            confidence = result.confidence
            
            if threat_score >= 0.8 and confidence >= 0.7:
                verdict = 'malicious'
            elif threat_score >= 0.5 and confidence >= 0.6:
                verdict = 'suspicious'
            elif threat_score >= 0.3:
                verdict = 'suspicious'
            else:
                verdict = 'safe'
            
            return {
                'threat_score': threat_score,
                'verdict': verdict,
                'confidence': confidence,
                'indicators': indicators,
                'raw_data': raw_data,
                'service': self.service_name,
                'timestamp': result.timestamp,
                'analysis_type': 'text_analysis',
                'explanation': result.explanation,
                'impersonation_target': llm_assessment.get('impersonation_target'),
                'content_categories': llm_assessment.get('content_categories', [])
            }
            
        except Exception as e:
            logger.error(f"Gemini scan failed for content: {e}")
            return {
                'threat_score': 0.0,
                'verdict': 'error',
                'confidence': 0.0,
                'indicators': [f'scan_error: {str(e)}'],
                'raw_data': {'error': str(e)},
                'service': self.service_name,
                'timestamp': time.time(),
                'analysis_type': 'text_analysis'
            }


# Factory function for dependency injection
def create_gemini_client(api_key: Optional[str] = None) -> GeminiClient:
    """Factory function to create Gemini client."""
    return GeminiClient(api_key=api_key)
