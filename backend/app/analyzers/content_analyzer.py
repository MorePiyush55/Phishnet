"""Real content analyzer for phishing detection."""

import re
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import string
from collections import Counter

from app.config.logging import get_logger

logger = get_logger(__name__)


class ContentAnalyzer:
    """Advanced content analyzer for detecting phishing patterns in email text."""
    
    def __init__(self):
        self.phishing_keywords = self._load_phishing_keywords()
        self.legitimate_keywords = self._load_legitimate_keywords()
        self.urgency_patterns = self._load_urgency_patterns()
        self.credential_patterns = self._load_credential_patterns()
        
    def analyze_email_content(
        self, 
        subject: str, 
        body: str, 
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Comprehensive content analysis for phishing detection."""
        try:
            # Normalize content
            subject_norm = self._normalize_text(subject)
            body_norm = self._normalize_text(body)
            
            # Perform various analyses
            keyword_analysis = self._analyze_keywords(subject_norm, body_norm)
            urgency_analysis = self._analyze_urgency_indicators(subject_norm, body_norm)
            credential_analysis = self._analyze_credential_requests(subject_norm, body_norm)
            linguistic_analysis = self._analyze_linguistic_patterns(subject_norm, body_norm)
            header_analysis = self._analyze_headers(headers) if headers else {}
            
            # Calculate content risk score
            risk_score = self._calculate_content_risk(
                keyword_analysis, urgency_analysis, credential_analysis, 
                linguistic_analysis, header_analysis
            )
            
            # Generate summary
            indicators = self._extract_indicators(
                keyword_analysis, urgency_analysis, credential_analysis, linguistic_analysis
            )
            
            summary = self._generate_content_summary(risk_score, indicators)
            
            return {
                "risk_score": risk_score,
                "indicators": indicators,
                "summary": summary,
                "detailed_analysis": {
                    "keyword_analysis": keyword_analysis,
                    "urgency_analysis": urgency_analysis,
                    "credential_analysis": credential_analysis,
                    "linguistic_analysis": linguistic_analysis,
                    "header_analysis": header_analysis
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Content analysis failed: {e}")
            return {
                "risk_score": 0.5,
                "indicators": ["analysis_error"],
                "summary": "Content analysis failed",
                "error": str(e)
            }
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text for analysis."""
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove HTML tags (basic)
        text = re.sub(r'<[^>]+>', ' ', text)
        
        return text.strip()
    
    def _analyze_keywords(self, subject: str, body: str) -> Dict[str, Any]:
        """Analyze presence of phishing and legitimate keywords."""
        content = f"{subject} {body}"
        
        phishing_matches = []
        legitimate_matches = []
        
        # Check phishing keywords
        for category, keywords in self.phishing_keywords.items():
            for keyword in keywords:
                if keyword in content:
                    phishing_matches.append({
                        "keyword": keyword,
                        "category": category,
                        "location": "subject" if keyword in subject else "body"
                    })
        
        # Check legitimate keywords
        for category, keywords in self.legitimate_keywords.items():
            for keyword in keywords:
                if keyword in content:
                    legitimate_matches.append({
                        "keyword": keyword,
                        "category": category,
                        "location": "subject" if keyword in subject else "body"
                    })
        
        return {
            "phishing_keywords": phishing_matches,
            "legitimate_keywords": legitimate_matches,
            "phishing_score": min(len(phishing_matches) * 0.1, 1.0),
            "legitimacy_score": min(len(legitimate_matches) * 0.1, 1.0)
        }
    
    def _analyze_urgency_indicators(self, subject: str, body: str) -> Dict[str, Any]:
        """Analyze urgency and pressure tactics."""
        content = f"{subject} {body}"
        urgency_matches = []
        
        for pattern in self.urgency_patterns:
            matches = re.findall(pattern["pattern"], content, re.IGNORECASE)
            for match in matches:
                urgency_matches.append({
                    "pattern": pattern["name"],
                    "match": match,
                    "severity": pattern["severity"],
                    "location": "subject" if re.search(pattern["pattern"], subject, re.IGNORECASE) else "body"
                })
        
        # Calculate urgency score
        urgency_score = sum(m["severity"] for m in urgency_matches) / 10.0
        urgency_score = min(urgency_score, 1.0)
        
        return {
            "urgency_indicators": urgency_matches,
            "urgency_score": urgency_score,
            "has_time_pressure": any(m["severity"] >= 0.8 for m in urgency_matches)
        }
    
    def _analyze_credential_requests(self, subject: str, body: str) -> Dict[str, Any]:
        """Analyze requests for credentials or sensitive information."""
        content = f"{subject} {body}"
        credential_requests = []
        
        for pattern in self.credential_patterns:
            matches = re.findall(pattern["pattern"], content, re.IGNORECASE)
            for match in matches:
                credential_requests.append({
                    "type": pattern["type"],
                    "pattern": pattern["name"],
                    "match": match,
                    "risk_level": pattern["risk_level"]
                })
        
        # Calculate credential request score
        cred_score = sum(r["risk_level"] for r in credential_requests) / 10.0
        cred_score = min(cred_score, 1.0)
        
        return {
            "credential_requests": credential_requests,
            "credential_score": cred_score,
            "requests_credentials": len(credential_requests) > 0
        }
    
    def _analyze_linguistic_patterns(self, subject: str, body: str) -> Dict[str, Any]:
        """Analyze linguistic patterns that indicate phishing."""
        content = f"{subject} {body}"
        
        patterns = {
            "spelling_errors": self._count_spelling_errors(content),
            "grammar_issues": self._detect_grammar_issues(content),
            "suspicious_formatting": self._detect_suspicious_formatting(content),
            "character_encoding_issues": self._detect_encoding_issues(content),
            "excessive_punctuation": self._detect_excessive_punctuation(content)
        }
        
        # Calculate linguistic risk score
        linguistic_score = 0.0
        
        if patterns["spelling_errors"] > 3:
            linguistic_score += 0.3
        if patterns["grammar_issues"] > 2:
            linguistic_score += 0.2
        if patterns["suspicious_formatting"]:
            linguistic_score += 0.2
        if patterns["character_encoding_issues"]:
            linguistic_score += 0.1
        if patterns["excessive_punctuation"]:
            linguistic_score += 0.2
        
        linguistic_score = min(linguistic_score, 1.0)
        
        return {
            "patterns": patterns,
            "linguistic_score": linguistic_score
        }
    
    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze email headers for spoofing and other indicators."""
        analysis = {
            "spoofing_indicators": [],
            "authentication_failures": [],
            "suspicious_routing": False,
            "header_score": 0.0
        }
        
        # Check for common spoofing indicators
        from_header = headers.get("From", "").lower()
        reply_to = headers.get("Reply-To", "").lower()
        
        if reply_to and reply_to != from_header:
            analysis["spoofing_indicators"].append("reply_to_mismatch")
            analysis["header_score"] += 0.3
        
        # Check for suspicious return path
        return_path = headers.get("Return-Path", "").lower()
        if return_path and from_header and return_path not in from_header:
            analysis["spoofing_indicators"].append("return_path_mismatch")
            analysis["header_score"] += 0.2
        
        # Check authentication headers
        spf_result = headers.get("Received-SPF", "").lower()
        if "fail" in spf_result:
            analysis["authentication_failures"].append("spf_fail")
            analysis["header_score"] += 0.4
        
        dkim_result = headers.get("Authentication-Results", "").lower()
        if "dkim=fail" in dkim_result:
            analysis["authentication_failures"].append("dkim_fail")
            analysis["header_score"] += 0.4
        
        analysis["header_score"] = min(analysis["header_score"], 1.0)
        
        return analysis
    
    def _count_spelling_errors(self, content: str) -> int:
        """Count obvious spelling errors (simplified)."""
        # Simple heuristic for obvious misspellings
        suspicious_patterns = [
            r'\\b\\w*([aeiou])\\1{2,}\\w*\\b',  # Too many repeated vowels
            r'\\b\\w*([bcdfghjklmnpqrstvwxyz])\\1{2,}\\w*\\b',  # Too many repeated consonants
            r'\\b[bcdfghjklmnpqrstvwxyz]{4,}\\b',  # Too many consecutive consonants
        ]
        
        error_count = 0
        for pattern in suspicious_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            error_count += len(matches)
        
        return min(error_count, 10)  # Cap at 10
    
    def _detect_grammar_issues(self, content: str) -> int:
        """Detect obvious grammar issues (simplified)."""
        issues = 0
        
        # Multiple spaces
        if re.search(r'  +', content):
            issues += 1
        
        # Missing spaces after punctuation
        if re.search(r'[.!?][a-zA-Z]', content):
            issues += 1
        
        # Excessive capitalization
        words = content.split()
        caps_words = [w for w in words if w.isupper() and len(w) > 2]
        if len(caps_words) > len(words) * 0.3:
            issues += 1
        
        return min(issues, 5)
    
    def _detect_suspicious_formatting(self, content: str) -> bool:
        """Detect suspicious text formatting."""
        # Look for mixed character sets, unusual spacing, etc.
        
        # Check for unusual character combinations
        if re.search(r'[А-Я]', content):  # Cyrillic characters
            return True
        
        # Check for zero-width characters or unusual Unicode
        suspicious_chars = ['\\u200b', '\\u200c', '\\u200d', '\\ufeff']
        for char in suspicious_chars:
            if char in content:
                return True
        
        return False
    
    def _detect_encoding_issues(self, content: str) -> bool:
        """Detect character encoding issues."""
        # Look for common encoding artifacts
        encoding_artifacts = ['â€™', 'â€œ', 'â€', 'Ã¡', 'Ã©', 'Ã­']
        
        return any(artifact in content for artifact in encoding_artifacts)
    
    def _detect_excessive_punctuation(self, content: str) -> bool:
        """Detect excessive use of punctuation."""
        # Count punctuation marks
        punct_count = sum(1 for char in content if char in string.punctuation)
        total_chars = len(content)
        
        if total_chars > 0:
            punct_ratio = punct_count / total_chars
            return punct_ratio > 0.15  # More than 15% punctuation
        
        return False
    
    def _calculate_content_risk(
        self,
        keyword_analysis: Dict[str, Any],
        urgency_analysis: Dict[str, Any],
        credential_analysis: Dict[str, Any],
        linguistic_analysis: Dict[str, Any],
        header_analysis: Dict[str, Any]
    ) -> float:
        """Calculate overall content risk score."""
        
        # Weight different analysis components
        weights = {
            "keywords": 0.25,
            "urgency": 0.20,
            "credentials": 0.25,
            "linguistic": 0.15,
            "headers": 0.15
        }
        
        # Calculate weighted score
        risk_score = 0.0
        
        # Keyword score (phishing keywords increase risk, legitimate decrease it)
        keyword_score = keyword_analysis.get("phishing_score", 0) - keyword_analysis.get("legitimacy_score", 0) * 0.5
        risk_score += max(keyword_score, 0) * weights["keywords"]
        
        # Urgency score
        risk_score += urgency_analysis.get("urgency_score", 0) * weights["urgency"]
        
        # Credential request score
        risk_score += credential_analysis.get("credential_score", 0) * weights["credentials"]
        
        # Linguistic score
        risk_score += linguistic_analysis.get("linguistic_score", 0) * weights["linguistic"]
        
        # Header score
        risk_score += header_analysis.get("header_score", 0) * weights["headers"]
        
        return min(risk_score, 1.0)
    
    def _extract_indicators(
        self,
        keyword_analysis: Dict[str, Any],
        urgency_analysis: Dict[str, Any],
        credential_analysis: Dict[str, Any],
        linguistic_analysis: Dict[str, Any]
    ) -> List[str]:
        """Extract human-readable indicators from analysis."""
        indicators = []
        
        # Keyword indicators
        phishing_keywords = keyword_analysis.get("phishing_keywords", [])
        if phishing_keywords:
            categories = set(k["category"] for k in phishing_keywords)
            for category in categories:
                indicators.append(f"Contains {category} phishing keywords")
        
        # Urgency indicators
        if urgency_analysis.get("has_time_pressure"):
            indicators.append("Uses urgent language and time pressure")
        
        # Credential indicators
        if credential_analysis.get("requests_credentials"):
            indicators.append("Requests sensitive information or credentials")
        
        # Linguistic indicators
        patterns = linguistic_analysis.get("patterns", {})
        if patterns.get("spelling_errors", 0) > 3:
            indicators.append("Contains multiple spelling errors")
        if patterns.get("grammar_issues", 0) > 2:
            indicators.append("Contains grammar issues")
        if patterns.get("suspicious_formatting"):
            indicators.append("Suspicious text formatting detected")
        
        return indicators
    
    def _generate_content_summary(self, risk_score: float, indicators: List[str]) -> str:
        """Generate human-readable summary of content analysis."""
        if risk_score >= 0.8:
            risk_level = "Very High"
        elif risk_score >= 0.6:
            risk_level = "High"
        elif risk_score >= 0.4:
            risk_level = "Medium"
        elif risk_score >= 0.2:
            risk_level = "Low"
        else:
            risk_level = "Very Low"
        
        summary = f"{risk_level} risk content detected."
        
        if indicators:
            top_indicators = indicators[:3]  # Limit to top 3
            summary += f" Key concerns: {', '.join(top_indicators).lower()}."
        
        return summary
    
    def _load_phishing_keywords(self) -> Dict[str, List[str]]:
        """Load phishing keyword categories."""
        return {
            "urgency": [
                "urgent", "immediate", "asap", "expires", "deadline",
                "act now", "time sensitive", "limited time", "hurry"
            ],
            "threats": [
                "suspend", "terminated", "blocked", "frozen", "locked",
                "cancelled", "closed", "deactivated", "restricted"
            ],
            "verification": [
                "verify", "confirm", "validate", "update", "authenticate",
                "secure", "protect", "reactivate", "restore"
            ],
            "financial": [
                "refund", "payment", "billing", "invoice", "charge",
                "transaction", "unauthorized", "fraud", "suspicious activity"
            ],
            "credential_harvesting": [
                "username", "password", "pin", "ssn", "social security",
                "credit card", "bank account", "login", "sign in"
            ]
        }
    
    def _load_legitimate_keywords(self) -> Dict[str, List[str]]:
        """Load legitimate business keyword categories."""
        return {
            "business": [
                "newsletter", "update", "meeting", "conference", "schedule",
                "agenda", "team", "project", "deadline", "report"
            ],
            "services": [
                "support", "help", "assistance", "service", "maintenance",
                "upgrade", "feature", "improvement", "enhancement"
            ],
            "notifications": [
                "notification", "alert", "reminder", "notice", "information",
                "announcement", "news", "updates", "bulletin"
            ]
        }
    
    def _load_urgency_patterns(self) -> List[Dict[str, Any]]:
        """Load urgency detection patterns."""
        return [
            {
                "name": "immediate_action",
                "pattern": r"\\b(immediate|urgent|asap|right away|now)\\b",
                "severity": 0.8
            },
            {
                "name": "time_limit",
                "pattern": r"\\b(\\d+\\s*(hours?|days?|minutes?)\\s*(left|remaining)|expires?\\s*(in|within)|deadline)",
                "severity": 0.9
            },
            {
                "name": "consequences",
                "pattern": r"\\b(will be (suspended|terminated|closed|locked)|lose access|permanent)",
                "severity": 0.7
            },
            {
                "name": "action_required",
                "pattern": r"\\b(action required|must (verify|confirm|update|act)|required to)",
                "severity": 0.6
            }
        ]
    
    def _load_credential_patterns(self) -> List[Dict[str, Any]]:
        """Load credential request detection patterns."""
        return [
            {
                "name": "password_request",
                "pattern": r"\\b(enter|provide|confirm|update|verify)\\s+(your\\s+)?(password|pin|passcode)",
                "type": "password",
                "risk_level": 0.9
            },
            {
                "name": "login_request",
                "pattern": r"\\b(sign in|log in|login|enter (your )?credentials)",
                "type": "credentials",
                "risk_level": 0.8
            },
            {
                "name": "personal_info",
                "pattern": r"\\b(social security|ssn|date of birth|mother's maiden name)",
                "type": "personal_info",
                "risk_level": 0.9
            },
            {
                "name": "financial_info",
                "pattern": r"\\b(credit card|bank account|routing number|account number)",
                "type": "financial",
                "risk_level": 0.95
            }
        ]


# Global instance
content_analyzer = ContentAnalyzer()