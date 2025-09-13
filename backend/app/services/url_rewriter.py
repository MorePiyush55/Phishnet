"""
URL Rewriter and Click-Through Service for safe link handling.

This service provides secure URL rewriting, click tracking, and access control
for links in emails and other user content to prevent malicious link clicks.
"""

import urllib.parse
import hashlib
import hmac
import base64
import time
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from fastapi import HTTPException, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session

from app.services.audit_service import get_audit_service
from app.services.security_sanitizer import get_security_sanitizer
from app.core.redis_client import get_redis_connection
from app.config.logging import get_logger
from app.config.settings import settings

logger = get_logger(__name__)


class ClickPolicy(Enum):
    """Click-through policy enforcement levels."""
    ALLOW = "allow"          # Allow click without warning
    WARN = "warn"            # Show warning page before redirect
    BLOCK = "block"          # Block click entirely
    QUARANTINE = "quarantine" # Block due to quarantine status


@dataclass
class ClickThroughResult:
    """Result of click-through processing."""
    allowed: bool
    policy: ClickPolicy
    final_url: Optional[str]
    warning_message: Optional[str]
    blocked_reason: Optional[str]
    requires_confirmation: bool
    metadata: Dict[str, Any]


@dataclass
class LinkAnalysis:
    """Analysis result for a link."""
    original_url: str
    final_url: str
    is_safe: bool
    threat_score: float
    reputation_score: float
    categories: List[str]
    warnings: List[str]
    blocked_reasons: List[str]


class URLRewriterService:
    """
    Service for rewriting URLs to go through safe click-through endpoint.
    
    Features:
    - Secure URL encoding with HMAC verification
    - Click tracking and logging
    - Role-based access policies
    - Quarantine enforcement
    - Malicious link detection
    - User confirmation flows
    """
    
    def __init__(self):
        """Initialize URL rewriter service."""
        self.audit_service = get_audit_service()
        self.sanitizer = get_security_sanitizer()
        
        # Secret key for HMAC signing (should be from config)
        self.secret_key = getattr(settings, "URL_REWRITER_SECRET", "default-secret-key").encode()
        
        # Known safe domains that don't need rewriting
        self.safe_domains = {
            "github.com", "google.com", "microsoft.com", "stackoverflow.com",
            "wikipedia.org", "mozilla.org", "python.org", "fastapi.tiangolo.com"
        }
        
        # Known malicious/suspicious TLDs
        self.suspicious_tlds = {
            ".tk", ".ml", ".ga", ".cf", ".bit", ".onion"
        }
        
        logger.info("URLRewriterService initialized")
    
    def rewrite_url(
        self,
        original_url: str,
        context: str = "email",
        user_id: Optional[int] = None,
        email_id: Optional[str] = None,
        require_confirmation: bool = False
    ) -> str:
        """
        Rewrite URL to go through click-through endpoint.
        
        Args:
            original_url: Original URL to rewrite
            context: Context where URL appears (email, comment, etc.)
            user_id: User who will click the link
            email_id: Email containing the link
            require_confirmation: Whether to require user confirmation
            
        Returns:
            Rewritten URL that goes through click-through endpoint
        """
        # Sanitize the URL first
        safe_url = self.sanitizer.sanitize_url(original_url)
        if not safe_url:
            logger.warning(f"URL sanitization failed for: {original_url[:100]}")
            return "#blocked-unsafe-url"
        
        # Check if URL needs rewriting
        if not self._needs_rewriting(safe_url):
            return safe_url
        
        try:
            # Create URL parameters
            params = {
                "url": safe_url,
                "context": context,
                "timestamp": str(int(time.time()))
            }
            
            if user_id:
                params["user_id"] = str(user_id)
            if email_id:
                params["email_id"] = email_id
            if require_confirmation:
                params["confirm"] = "1"
            
            # Create HMAC signature
            signature = self._create_signature(params)
            params["signature"] = signature
            
            # Build click-through URL
            click_through_url = f"/api/click-through?" + urllib.parse.urlencode(params)
            
            logger.debug(f"Rewrote URL: {original_url[:50]} -> {click_through_url[:50]}")
            return click_through_url
            
        except Exception as e:
            logger.error(f"URL rewriting failed for {original_url[:100]}: {e}")
            return "#url-rewrite-error"
    
    def rewrite_urls_in_content(
        self,
        content: str,
        context: str = "email",
        user_id: Optional[int] = None,
        email_id: Optional[str] = None
    ) -> str:
        """
        Rewrite all URLs in HTML/text content.
        
        Args:
            content: HTML or text content containing URLs
            context: Content context
            user_id: User who will see the content
            email_id: Email ID if content is from email
            
        Returns:
            Content with URLs rewritten to click-through endpoints
        """
        import re
        
        # Pattern to match URLs in href attributes
        href_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
        
        def rewrite_href(match):
            original_url = match.group(1)
            rewritten_url = self.rewrite_url(
                original_url, context, user_id, email_id
            )
            return f'href="{rewritten_url}"'
        
        # Rewrite href attributes
        content = re.sub(href_pattern, rewrite_href, content, flags=re.IGNORECASE)
        
        # Pattern to match standalone URLs in text
        url_pattern = r'https?://[^\s<>"\']+[^\s<>"\'.,)]'
        
        def rewrite_standalone_url(match):
            original_url = match.group(0)
            return self.rewrite_url(original_url, context, user_id, email_id)
        
        # Rewrite standalone URLs (not in HTML attributes)
        # Only if not already in an HTML attribute
        if "href=" not in content.lower():
            content = re.sub(url_pattern, rewrite_standalone_url, content)
        
        return content
    
    async def handle_click_through(
        self,
        request: Request,
        url: str,
        signature: str,
        context: str = "unknown",
        user_id: Optional[str] = None,
        email_id: Optional[str] = None,
        confirm: Optional[str] = None,
        timestamp: Optional[str] = None
    ) -> Union[RedirectResponse, JSONResponse]:
        """
        Handle click-through request with security checks and logging.
        
        Args:
            request: FastAPI request object
            url: Target URL to redirect to
            signature: HMAC signature for verification
            context: Click context
            user_id: User performing click
            email_id: Email containing link
            confirm: User confirmation flag
            timestamp: Click timestamp
            
        Returns:
            Redirect response or warning page
        """
        try:
            # Verify signature
            params = {
                "url": url,
                "context": context,
                "timestamp": timestamp or str(int(time.time()))
            }
            if user_id:
                params["user_id"] = user_id
            if email_id:
                params["email_id"] = email_id
            if confirm:
                params["confirm"] = confirm
            
            if not self._verify_signature(params, signature):
                await self._log_security_violation(
                    "invalid_click_signature",
                    request,
                    {"url": url[:100], "provided_signature": signature[:20]}
                )
                raise HTTPException(status_code=400, detail="Invalid click signature")
            
            # Check timestamp validity (prevent replay attacks)
            if timestamp:
                click_time = int(timestamp)
                if abs(time.time() - click_time) > 3600:  # 1 hour validity
                    raise HTTPException(status_code=400, detail="Click link expired")
            
            # Extract user information
            user_id_int = int(user_id) if user_id and user_id.isdigit() else None
            user_ip = self._get_client_ip(request)
            user_agent = request.headers.get("user-agent", "")
            
            # Analyze the target URL
            link_analysis = await self._analyze_link(url)
            
            # Determine click policy
            click_result = await self._determine_click_policy(
                link_analysis, user_id_int, email_id, context
            )
            
            # Log the click attempt
            await self._log_click_attempt(
                url, user_id_int, email_id, context, user_ip, user_agent,
                click_result, request.state.request_id if hasattr(request.state, 'request_id') else None
            )
            
            # Handle based on policy
            if click_result.policy == ClickPolicy.BLOCK or click_result.policy == ClickPolicy.QUARANTINE:
                return JSONResponse(
                    status_code=403,
                    content={
                        "blocked": True,
                        "reason": click_result.blocked_reason,
                        "policy": click_result.policy.value,
                        "safe_alternatives": await self._get_safe_alternatives(url)
                    }
                )
            
            elif click_result.policy == ClickPolicy.WARN and not confirm:
                # Show warning page
                return JSONResponse(
                    status_code=200,
                    content={
                        "requires_confirmation": True,
                        "warning_message": click_result.warning_message,
                        "target_url": url,
                        "link_analysis": {
                            "threat_score": link_analysis.threat_score,
                            "reputation_score": link_analysis.reputation_score,
                            "warnings": link_analysis.warnings,
                            "categories": link_analysis.categories
                        },
                        "confirmation_url": self._create_confirmation_url(request, params)
                    }
                )
            
            else:
                # Allow the click - redirect to target
                await self._log_successful_click(
                    url, user_id_int, email_id, user_ip,
                    request.state.request_id if hasattr(request.state, 'request_id') else None
                )
                
                return RedirectResponse(
                    url=click_result.final_url or url,
                    status_code=302
                )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Click-through handling failed: {e}")
            await self._log_security_violation(
                "click_through_error",
                request,
                {"url": url[:100], "error": str(e)}
            )
            raise HTTPException(status_code=500, detail="Click processing failed")
    
    async def _analyze_link(self, url: str) -> LinkAnalysis:
        """
        Analyze link for safety and reputation.
        
        Args:
            url: URL to analyze
            
        Returns:
            LinkAnalysis with safety assessment
        """
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            warnings = []
            blocked_reasons = []
            categories = []
            threat_score = 0.0
            reputation_score = 1.0  # Default to good reputation
            
            # Check domain reputation
            if domain in self.safe_domains:
                reputation_score = 1.0
                categories.append("trusted")
            
            # Check for suspicious TLD
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    threat_score += 0.3
                    warnings.append(f"Suspicious TLD: {tld}")
                    categories.append("suspicious_tld")
            
            # Check for suspicious patterns
            if any(pattern in url.lower() for pattern in ["bit.ly", "tinyurl", "t.co"]):
                threat_score += 0.1
                warnings.append("Shortened URL - destination unknown")
                categories.append("url_shortener")
            
            # Check for suspicious keywords
            suspicious_keywords = ["verify", "urgent", "suspended", "click-here", "winner"]
            for keyword in suspicious_keywords:
                if keyword in url.lower():
                    threat_score += 0.1
                    warnings.append(f"Suspicious keyword: {keyword}")
            
            # Check for homograph attacks
            if self._detect_homograph_attack(domain):
                threat_score += 0.5
                warnings.append("Potential homograph attack")
                categories.append("homograph")
            
            # Check for excessive subdomain nesting
            if domain.count(".") > 3:
                threat_score += 0.2
                warnings.append("Excessive subdomain nesting")
            
            # Determine if URL is safe
            is_safe = threat_score < 0.3 and len(blocked_reasons) == 0
            
            # Adjust reputation based on threat score
            reputation_score = max(0.0, 1.0 - threat_score)
            
            return LinkAnalysis(
                original_url=url,
                final_url=url,  # Could be different after redirect analysis
                is_safe=is_safe,
                threat_score=min(1.0, threat_score),
                reputation_score=reputation_score,
                categories=categories,
                warnings=warnings,
                blocked_reasons=blocked_reasons
            )
            
        except Exception as e:
            logger.error(f"Link analysis failed for {url}: {e}")
            # Fail-safe: treat as suspicious
            return LinkAnalysis(
                original_url=url,
                final_url=url,
                is_safe=False,
                threat_score=0.8,
                reputation_score=0.2,
                categories=["analysis_failed"],
                warnings=["Link analysis failed"],
                blocked_reasons=[f"Analysis error: {str(e)}"]
            )
    
    async def _determine_click_policy(
        self,
        link_analysis: LinkAnalysis,
        user_id: Optional[int],
        email_id: Optional[str],
        context: str
    ) -> ClickThroughResult:
        """
        Determine click policy based on link analysis and user context.
        
        Args:
            link_analysis: Link analysis results
            user_id: User attempting click
            email_id: Email containing link
            context: Click context
            
        Returns:
            Click policy decision
        """
        try:
            # Check if email is quarantined
            if email_id and await self._is_email_quarantined(email_id):
                return ClickThroughResult(
                    allowed=False,
                    policy=ClickPolicy.QUARANTINE,
                    final_url=None,
                    warning_message=None,
                    blocked_reason="Email is quarantined - links are blocked for security",
                    requires_confirmation=False,
                    metadata={"email_id": email_id, "quarantine_status": True}
                )
            
            # Block if threat score is very high
            if link_analysis.threat_score >= 0.8:
                return ClickThroughResult(
                    allowed=False,
                    policy=ClickPolicy.BLOCK,
                    final_url=None,
                    warning_message=None,
                    blocked_reason=f"High threat score: {link_analysis.threat_score:.2f}",
                    requires_confirmation=False,
                    metadata={"threat_score": link_analysis.threat_score}
                )
            
            # Warn if threat score is moderate
            elif link_analysis.threat_score >= 0.3:
                return ClickThroughResult(
                    allowed=True,
                    policy=ClickPolicy.WARN,
                    final_url=link_analysis.final_url,
                    warning_message=f"This link may be suspicious (threat score: {link_analysis.threat_score:.2f}). "
                                   f"Warnings: {', '.join(link_analysis.warnings[:3])}",
                    blocked_reason=None,
                    requires_confirmation=True,
                    metadata={"threat_score": link_analysis.threat_score, "warnings": link_analysis.warnings}
                )
            
            # Allow safe links
            else:
                return ClickThroughResult(
                    allowed=True,
                    policy=ClickPolicy.ALLOW,
                    final_url=link_analysis.final_url,
                    warning_message=None,
                    blocked_reason=None,
                    requires_confirmation=False,
                    metadata={"threat_score": link_analysis.threat_score}
                )
                
        except Exception as e:
            logger.error(f"Policy determination failed: {e}")
            # Fail-safe: require confirmation
            return ClickThroughResult(
                allowed=True,
                policy=ClickPolicy.WARN,
                final_url=link_analysis.final_url,
                warning_message="Unable to verify link safety - proceed with caution",
                blocked_reason=None,
                requires_confirmation=True,
                metadata={"error": str(e)}
            )
    
    def _needs_rewriting(self, url: str) -> bool:
        """Check if URL needs to be rewritten."""
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            # Don't rewrite internal URLs
            if domain in ["localhost", "127.0.0.1"] or domain.startswith("192.168."):
                return False
            
            # Don't rewrite already rewritten URLs
            if "/api/click-through" in url:
                return False
            
            # Don't rewrite some safe domains (optional)
            if domain in self.safe_domains:
                return False
            
            return True
            
        except Exception:
            return True  # Rewrite if we can't parse
    
    def _create_signature(self, params: Dict[str, str]) -> str:
        """Create HMAC signature for URL parameters."""
        # Sort parameters for consistent signing
        sorted_params = sorted(params.items())
        param_string = "&".join([f"{k}={v}" for k, v in sorted_params])
        
        signature = hmac.new(
            self.secret_key,
            param_string.encode(),
            hashlib.sha256
        ).digest()
        
        return base64.urlsafe_b64encode(signature).decode()
    
    def _verify_signature(self, params: Dict[str, str], provided_signature: str) -> bool:
        """Verify HMAC signature for URL parameters."""
        try:
            expected_signature = self._create_signature(params)
            return hmac.compare_digest(expected_signature, provided_signature)
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def _create_confirmation_url(self, request: Request, params: Dict[str, str]) -> str:
        """Create confirmation URL for warned clicks."""
        confirmation_params = params.copy()
        confirmation_params["confirm"] = "1"
        signature = self._create_signature(confirmation_params)
        confirmation_params["signature"] = signature
        
        return f"/api/click-through?" + urllib.parse.urlencode(confirmation_params)
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address."""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _detect_homograph_attack(self, domain: str) -> bool:
        """Detect potential homograph attacks in domain names."""
        # Simple check for mixed scripts (more sophisticated detection possible)
        ascii_chars = sum(1 for c in domain if ord(c) < 128)
        total_chars = len(domain)
        
        if total_chars > 0:
            ascii_ratio = ascii_chars / total_chars
            # If less than 80% ASCII, might be homograph attack
            return ascii_ratio < 0.8
        
        return False
    
    async def _is_email_quarantined(self, email_id: str) -> bool:
        """Check if email is quarantined."""
        try:
            # Check Redis cache first
            redis = get_redis_connection()
            cache_key = f"email_quarantine:{email_id}"
            quarantine_status = await redis.get(cache_key)
            
            if quarantine_status is not None:
                return quarantine_status == "1"
            
            # TODO: Check database for quarantine status
            # For now, assume not quarantined
            await redis.setex(cache_key, 300, "0")  # Cache for 5 minutes
            return False
            
        except Exception as e:
            logger.error(f"Quarantine check failed for email {email_id}: {e}")
            return False  # Fail open
    
    async def _get_safe_alternatives(self, blocked_url: str) -> List[str]:
        """Get safe alternative URLs for blocked content."""
        try:
            parsed = urllib.parse.urlparse(blocked_url)
            domain = parsed.netloc.lower()
            
            alternatives = []
            
            # Suggest official sites for common services
            if "paypal" in domain:
                alternatives.append("https://www.paypal.com")
            elif "microsoft" in domain or "outlook" in domain:
                alternatives.append("https://www.microsoft.com")
            elif "google" in domain:
                alternatives.append("https://www.google.com")
            elif "amazon" in domain:
                alternatives.append("https://www.amazon.com")
            
            # Add general safety resources
            alternatives.extend([
                "https://support.google.com/websearch/answer/186669",  # Safe browsing help
                "https://www.consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams"
            ])
            
            return alternatives[:3]  # Return top 3
            
        except Exception:
            return ["https://www.consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams"]
    
    async def _log_click_attempt(
        self,
        url: str,
        user_id: Optional[int],
        email_id: Optional[str],
        context: str,
        user_ip: str,
        user_agent: str,
        click_result: ClickThroughResult,
        request_id: Optional[str]
    ):
        """Log click attempt for audit trail."""
        await self.audit_service.log_user_action(
            action="click_attempt",
            user_id=user_id or 0,
            description=f"User attempted to click link: {url[:100]}",
            details={
                "target_url": url,
                "email_id": email_id,
                "context": context,
                "policy": click_result.policy.value,
                "allowed": click_result.allowed,
                "blocked_reason": click_result.blocked_reason,
                "threat_score": click_result.metadata.get("threat_score"),
                "warnings": click_result.metadata.get("warnings", [])[:3]
            },
            resource_type="link",
            resource_id=hashlib.md5(url.encode()).hexdigest()[:16],
            request_id=request_id,
            user_ip=user_ip,
            user_agent=user_agent,
            severity="warning" if not click_result.allowed else "info"
        )
    
    async def _log_successful_click(
        self,
        url: str,
        user_id: Optional[int],
        email_id: Optional[str],
        user_ip: str,
        request_id: Optional[str]
    ):
        """Log successful click for audit trail."""
        await self.audit_service.log_user_action(
            action="click_success",
            user_id=user_id or 0,
            description=f"User successfully clicked link: {url[:100]}",
            details={
                "target_url": url,
                "email_id": email_id,
                "redirect_completed": True
            },
            resource_type="link",
            resource_id=hashlib.md5(url.encode()).hexdigest()[:16],
            request_id=request_id,
            user_ip=user_ip
        )
    
    async def _log_security_violation(
        self,
        violation_type: str,
        request: Request,
        details: Dict[str, Any]
    ):
        """Log security violation."""
        user_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        
        await self.audit_service.log_security_event(
            action=violation_type,
            description=f"Security violation in click-through: {violation_type}",
            user_ip=user_ip,
            user_agent=user_agent,
            details=details,
            is_suspicious=True,
            security_violation=True
        )


# Singleton instance for global use
_url_rewriter_instance: Optional[URLRewriterService] = None


def get_url_rewriter() -> URLRewriterService:
    """Get the global URLRewriterService instance."""
    global _url_rewriter_instance
    
    if _url_rewriter_instance is None:
        _url_rewriter_instance = URLRewriterService()
    
    return _url_rewriter_instance


# Convenience functions
def rewrite_email_urls(
    email_content: str,
    user_id: Optional[int] = None,
    email_id: Optional[str] = None
) -> str:
    """Rewrite all URLs in email content for safe click-through."""
    rewriter = get_url_rewriter()
    return rewriter.rewrite_urls_in_content(
        email_content, "email", user_id, email_id
    )


def create_safe_link(
    url: str,
    context: str = "general",
    user_id: Optional[int] = None,
    require_confirmation: bool = False
) -> str:
    """Create a safe click-through link for a URL."""
    rewriter = get_url_rewriter()
    return rewriter.rewrite_url(url, context, user_id, require_confirmation=require_confirmation)
