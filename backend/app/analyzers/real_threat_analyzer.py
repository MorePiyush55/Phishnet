"""Real threat scoring engine to replace mock analysis."""

from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import asyncio

from app.config.logging import get_logger
from app.analyzers.url_analyzer import url_analyzer
from app.analyzers.content_analyzer import content_analyzer

logger = get_logger(__name__)


class RealThreatAnalyzer:
    """Real threat analysis engine replacing all mock implementations."""
    
    def __init__(self):
        self.url_analyzer = url_analyzer
        self.content_analyzer = content_analyzer
        
    async def analyze_email_threat(
        self,
        subject: str,
        sender: str, 
        body: str,
        headers: Optional[Dict[str, str]] = None,
        snippet: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive email threat analysis replacing mock implementations.
        
        Returns real threat analysis with deterministic scoring.
        """
        try:
            logger.info(f"Starting real threat analysis for email: {subject[:50]}")
            
            # Combine body and snippet for analysis
            content = f"{body or ''} {snippet or ''}".strip()
            if not content:
                content = snippet or ""
            
            # Run analyses in parallel for performance
            content_task = asyncio.create_task(
                self._analyze_content(subject, content, headers)
            )
            url_task = asyncio.create_task(
                self._analyze_urls(content)
            )
            sender_task = asyncio.create_task(
                self._analyze_sender(sender, headers)
            )
            
            # Wait for all analyses
            content_analysis, url_analysis, sender_analysis = await asyncio.gather(
                content_task, url_task, sender_task
            )
            
            # Calculate final threat score
            threat_score = self._calculate_final_threat_score(
                content_analysis, url_analysis, sender_analysis
            )
            
            # Determine risk level
            risk_level = self._determine_risk_level(threat_score)
            
            # Extract indicators
            indicators = self._extract_all_indicators(
                content_analysis, url_analysis, sender_analysis
            )
            
            # Generate summary
            summary = self._generate_threat_summary(threat_score, risk_level, indicators)
            
            result = {
                "risk_score": int(threat_score * 100),  # Convert to 0-100 scale
                "risk_level": risk_level,
                "indicators": indicators,
                "summary": summary,
                "detailed_analysis": {
                    "content_analysis": content_analysis,
                    "url_analysis": url_analysis,
                    "sender_analysis": sender_analysis
                },
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "analyzer_version": "real_v1.0"
            }
            
            logger.info(f"Real threat analysis completed: {risk_level} risk ({threat_score:.2f})")
            return result
            
        except Exception as e:
            logger.error(f"Real threat analysis failed: {e}")
            # Return safe fallback instead of mock
            return {
                "risk_score": 50,
                "risk_level": "UNKNOWN",
                "indicators": ["analysis_error"],
                "summary": "Threat analysis failed - manual review recommended",
                "error": str(e),
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "analyzer_version": "real_v1.0"
            }
    
    async def _analyze_content(
        self, 
        subject: str, 
        content: str, 
        headers: Optional[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Analyze email content for phishing indicators."""
        try:
            return self.content_analyzer.analyze_email_content(subject, content, headers)
        except Exception as e:
            logger.error(f"Content analysis failed: {e}")
            return {
                "risk_score": 0.5,
                "indicators": ["content_analysis_error"],
                "summary": "Content analysis failed"
            }
    
    async def _analyze_urls(self, content: str) -> Dict[str, Any]:
        """Analyze URLs in email content."""
        try:
            return await self.url_analyzer.analyze_urls_in_content(content)
        except Exception as e:
            logger.error(f"URL analysis failed: {e}")
            return {
                "total_urls": 0,
                "malicious_urls": [],
                "suspicious_urls": [],
                "risk_score": 0.0,
                "error": str(e)
            }
    
    async def _analyze_sender(
        self, 
        sender: str, 
        headers: Optional[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Analyze sender reputation and authenticity."""
        try:
            sender_analysis = {
                "sender_email": sender,
                "domain": self._extract_domain(sender),
                "reputation_score": 0.5,
                "spoofing_indicators": [],
                "domain_age_suspicious": False,
                "risk_score": 0.0
            }
            
            # Basic sender domain analysis
            domain = sender_analysis["domain"]
            
            # Check for suspicious domains
            suspicious_patterns = [
                "suspicious", "fake", "phishing", "scam", "evil",
                "malicious", "temp", "throw", "guerrilla"
            ]
            
            if any(pattern in domain.lower() for pattern in suspicious_patterns):
                sender_analysis["spoofing_indicators"].append("suspicious_domain_name")
                sender_analysis["risk_score"] += 0.6
            
            # Check for typosquatting of major services
            major_services = [
                "gmail.com", "outlook.com", "yahoo.com", "hotmail.com",
                "paypal.com", "amazon.com", "microsoft.com", "apple.com",
                "google.com", "facebook.com", "twitter.com"
            ]
            
            for service in major_services:
                if self._is_typosquatting(domain, service):
                    sender_analysis["spoofing_indicators"].append(f"typosquatting_{service}")
                    sender_analysis["risk_score"] += 0.7
                    break
            
            # Check for suspicious TLDs
            suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".top", ".click"]
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                sender_analysis["spoofing_indicators"].append("suspicious_tld")
                sender_analysis["risk_score"] += 0.3
            
            # Analyze headers if available
            if headers:
                header_analysis = self._analyze_sender_headers(headers, sender)
                sender_analysis.update(header_analysis)
            
            sender_analysis["risk_score"] = min(sender_analysis["risk_score"], 1.0)
            
            return sender_analysis
            
        except Exception as e:
            logger.error(f"Sender analysis failed: {e}")
            return {
                "sender_email": sender,
                "risk_score": 0.5,
                "error": str(e)
            }
    
    def _extract_domain(self, email: str) -> str:
        """Extract domain from email address."""
        try:
            return email.split("@")[-1].lower() if "@" in email else email.lower()
        except:
            return email.lower()
    
    def _is_typosquatting(self, domain: str, target: str) -> bool:
        """Check if domain is typosquatting a target domain."""
        if domain == target:
            return False
        
        # Remove TLD for comparison
        domain_base = domain.split(".")[0] if "." in domain else domain
        target_base = target.split(".")[0] if "." in target else target
        
        # Check for character substitution
        if len(domain_base) == len(target_base):
            differences = sum(c1 != c2 for c1, c2 in zip(domain_base, target_base))
            if differences == 1:  # Single character difference
                return True
        
        # Check for character insertion/deletion
        if abs(len(domain_base) - len(target_base)) == 1:
            longer = domain_base if len(domain_base) > len(target_base) else target_base
            shorter = target_base if len(domain_base) > len(target_base) else domain_base
            
            for i in range(len(longer)):
                if longer[:i] + longer[i+1:] == shorter:
                    return True
        
        return False
    
    def _analyze_sender_headers(self, headers: Dict[str, str], sender: str) -> Dict[str, Any]:
        """Analyze sender-related headers for spoofing."""
        header_analysis = {
            "authentication_results": {},
            "spoofing_score": 0.0
        }
        
        # Check SPF
        spf_result = headers.get("Received-SPF", "").lower()
        if "fail" in spf_result:
            header_analysis["authentication_results"]["spf"] = "fail"
            header_analysis["spoofing_score"] += 0.4
        elif "pass" in spf_result:
            header_analysis["authentication_results"]["spf"] = "pass"
        
        # Check DKIM
        auth_results = headers.get("Authentication-Results", "").lower()
        if "dkim=fail" in auth_results:
            header_analysis["authentication_results"]["dkim"] = "fail"
            header_analysis["spoofing_score"] += 0.4
        elif "dkim=pass" in auth_results:
            header_analysis["authentication_results"]["dkim"] = "pass"
        
        # Check DMARC
        if "dmarc=fail" in auth_results:
            header_analysis["authentication_results"]["dmarc"] = "fail"
            header_analysis["spoofing_score"] += 0.5
        elif "dmarc=pass" in auth_results:
            header_analysis["authentication_results"]["dmarc"] = "pass"
        
        # Check Reply-To vs From mismatch
        reply_to = headers.get("Reply-To", "").lower()
        if reply_to and reply_to != sender.lower():
            header_analysis["spoofing_score"] += 0.3
        
        return header_analysis
    
    def _calculate_final_threat_score(
        self,
        content_analysis: Dict[str, Any],
        url_analysis: Dict[str, Any],
        sender_analysis: Dict[str, Any]
    ) -> float:
        """Calculate final threat score from all analyses."""
        
        # Weight different analysis components
        weights = {
            "content": 0.4,
            "urls": 0.35,
            "sender": 0.25
        }
        
        # Extract risk scores
        content_score = content_analysis.get("risk_score", 0.0)
        url_score = url_analysis.get("risk_score", 0.0)
        sender_score = sender_analysis.get("risk_score", 0.0)
        
        # Calculate weighted average
        final_score = (
            content_score * weights["content"] +
            url_score * weights["urls"] +
            sender_score * weights["sender"]
        )
        
        # Apply boosters for high-confidence indicators
        boosters = 0.0
        
        # Boost if multiple malicious URLs
        malicious_urls = len(url_analysis.get("malicious_urls", []))
        if malicious_urls >= 2:
            boosters += 0.2
        elif malicious_urls >= 1:
            boosters += 0.1
        
        # Boost if credential requests detected
        if content_analysis.get("detailed_analysis", {}).get("credential_analysis", {}).get("requests_credentials"):
            boosters += 0.15
        
        # Boost if sender spoofing detected
        spoofing_indicators = sender_analysis.get("spoofing_indicators", [])
        if spoofing_indicators:
            boosters += 0.1 * len(spoofing_indicators)
        
        final_score += boosters
        
        return min(final_score, 1.0)
    
    def _determine_risk_level(self, threat_score: float) -> str:
        """Determine risk level from threat score."""
        if threat_score >= 0.8:
            return "HIGH"
        elif threat_score >= 0.6:
            return "MEDIUM"
        elif threat_score >= 0.3:
            return "LOW"
        else:
            return "SAFE"
    
    def _extract_all_indicators(
        self,
        content_analysis: Dict[str, Any],
        url_analysis: Dict[str, Any],
        sender_analysis: Dict[str, Any]
    ) -> List[str]:
        """Extract all threat indicators from analyses."""
        indicators = []
        
        # Content indicators
        content_indicators = content_analysis.get("indicators", [])
        indicators.extend(content_indicators)
        
        # URL indicators
        malicious_urls = url_analysis.get("malicious_urls", [])
        suspicious_urls = url_analysis.get("suspicious_urls", [])
        
        if malicious_urls:
            indicators.append(f"{len(malicious_urls)} malicious URL(s) detected")
        if suspicious_urls:
            indicators.append(f"{len(suspicious_urls)} suspicious URL(s) detected")
        
        # Sender indicators
        spoofing_indicators = sender_analysis.get("spoofing_indicators", [])
        for indicator in spoofing_indicators:
            if indicator.startswith("typosquatting_"):
                service = indicator.replace("typosquatting_", "")
                indicators.append(f"Domain typosquatting {service}")
            elif indicator == "suspicious_domain_name":
                indicators.append("Suspicious sender domain")
            elif indicator == "suspicious_tld":
                indicators.append("Suspicious top-level domain")
        
        # Authentication failures
        auth_results = sender_analysis.get("authentication_results", {})
        failed_auth = [k for k, v in auth_results.items() if v == "fail"]
        if failed_auth:
            indicators.append(f"Authentication failures: {', '.join(failed_auth).upper()}")
        
        return indicators[:10]  # Limit to top 10 indicators
    
    def _generate_threat_summary(
        self, 
        threat_score: float, 
        risk_level: str, 
        indicators: List[str]
    ) -> str:
        """Generate human-readable threat summary."""
        
        if risk_level == "HIGH":
            base_summary = "High risk phishing attempt detected"
        elif risk_level == "MEDIUM":
            base_summary = "Medium risk suspicious email detected"
        elif risk_level == "LOW":
            base_summary = "Low risk email with minor concerns"
        else:
            base_summary = "Email appears safe"
        
        if indicators and risk_level != "SAFE":
            # Add top indicators to summary
            top_indicators = indicators[:2]
            indicator_text = "; ".join(top_indicators).lower()
            base_summary += f". Key concerns: {indicator_text}."
        
        return base_summary


# Global instance
real_threat_analyzer = RealThreatAnalyzer()