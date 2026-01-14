"""
Feedback Loop Service for PhishNet
===================================
Phase 7 Implementation: Continuous learning from analyst feedback.

Features:
- Mark false positive / true positive
- Domain reputation cache (benign domains gain trust)
- Signal weight tuning based on recurring FPs
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class FeedbackType(str, Enum):
    """Analyst feedback types"""
    FALSE_POSITIVE = "false_positive"  # Flagged but legitimate
    TRUE_POSITIVE = "true_positive"    # Correctly flagged
    FALSE_NEGATIVE = "false_negative"  # Missed threat
    TRUE_NEGATIVE = "true_negative"    # Correctly passed


@dataclass
class FeedbackEntry:
    """Single feedback entry"""
    email_id: str
    feedback_type: FeedbackType
    domain: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    analyst_id: Optional[str] = None
    notes: Optional[str] = None
    
    # What was flagged
    original_verdict: str = ""
    original_score: float = 0.0
    flagging_signals: List[str] = field(default_factory=list)


@dataclass
class DomainReputation:
    """Learned domain reputation"""
    domain: str
    fp_count: int = 0
    tp_count: int = 0
    trust_weight: float = 0.0  # -1 to +1 (-1 = bad, +1 = trusted)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    def update_from_feedback(self, feedback: FeedbackType):
        """Update reputation based on feedback"""
        if feedback == FeedbackType.FALSE_POSITIVE:
            self.fp_count += 1
            self.trust_weight = min(1.0, self.trust_weight + 0.1)
        elif feedback == FeedbackType.TRUE_POSITIVE:
            self.tp_count += 1
            self.trust_weight = max(-1.0, self.trust_weight - 0.2)
        
        self.last_updated = datetime.utcnow()


class FeedbackLoopService:
    """
    Phase 7: Analyst Feedback Processing
    
    Learns from analyst corrections to reduce recurring false positives.
    """
    
    # In-memory storage (use database in production)
    _domain_reputations: Dict[str, DomainReputation] = {}
    _signal_weights: Dict[str, float] = {}
    _feedback_history: List[FeedbackEntry] = []
    
    # Configuration
    FP_THRESHOLD_FOR_TRUST = 3  # FPs needed to gain trust weight
    SIGNAL_WEIGHT_DECAY = 0.05  # How much to reduce signal weight per FP
    
    def __init__(self):
        self._initialize_signal_weights()
    
    def _initialize_signal_weights(self):
        """Initialize default signal weights"""
        self._signal_weights = {
            'http_only': 1.0,
            'suspicious_tld': 1.0,
            'high_entropy_url': 1.0,
            'redirect_chain': 1.0,
            'low_alignment': 1.0,
            'vt_malicious': 1.0,
            'auth_failure': 1.0,
            'phishing_keywords': 1.0
        }
    
    def record_feedback(self, feedback: FeedbackEntry) -> None:
        """Record analyst feedback and update learning"""
        self._feedback_history.append(feedback)
        
        # Update domain reputation
        if feedback.domain:
            self._update_domain_reputation(
                feedback.domain, 
                feedback.feedback_type
            )
        
        # Update signal weights for false positives
        if feedback.feedback_type == FeedbackType.FALSE_POSITIVE:
            self._adjust_signal_weights(feedback.flagging_signals)
        
        logger.info(
            f"Feedback recorded: {feedback.feedback_type.value} for "
            f"domain={feedback.domain}, signals={feedback.flagging_signals}"
        )
    
    def _update_domain_reputation(
        self, 
        domain: str, 
        feedback: FeedbackType
    ):
        """Update domain reputation based on feedback"""
        from app.services.domain_identity import get_registrable_domain
        registrable = get_registrable_domain(domain)
        
        if registrable not in self._domain_reputations:
            self._domain_reputations[registrable] = DomainReputation(
                domain=registrable
            )
        
        self._domain_reputations[registrable].update_from_feedback(feedback)
    
    def _adjust_signal_weights(self, signals: List[str]):
        """Reduce weight of signals that cause false positives"""
        for signal in signals:
            if signal in self._signal_weights:
                new_weight = max(
                    0.3,  # Minimum weight
                    self._signal_weights[signal] - self.SIGNAL_WEIGHT_DECAY
                )
                self._signal_weights[signal] = new_weight
                logger.info(
                    f"Signal weight adjusted: {signal} = {new_weight:.2f}"
                )
    
    def get_domain_trust(self, domain: str) -> float:
        """Get trust weight for a domain (-1 to +1)"""
        from app.services.domain_identity import get_registrable_domain
        registrable = get_registrable_domain(domain)
        
        if registrable in self._domain_reputations:
            rep = self._domain_reputations[registrable]
            # Only trust if enough FPs and no TPs
            if rep.fp_count >= self.FP_THRESHOLD_FOR_TRUST and rep.tp_count == 0:
                return rep.trust_weight
        
        return 0.0  # Neutral
    
    def get_signal_weight(self, signal: str) -> float:
        """Get current weight for a signal"""
        return self._signal_weights.get(signal, 1.0)
    
    def get_all_signal_weights(self) -> Dict[str, float]:
        """Get all current signal weights"""
        return self._signal_weights.copy()
    
    def get_fp_statistics(self) -> Dict[str, int]:
        """Get false positive statistics by signal"""
        stats = {}
        for entry in self._feedback_history:
            if entry.feedback_type == FeedbackType.FALSE_POSITIVE:
                for signal in entry.flagging_signals:
                    stats[signal] = stats.get(signal, 0) + 1
        return stats
    
    def get_trusted_domains(self) -> List[str]:
        """Get list of domains with positive trust weight"""
        return [
            rep.domain 
            for rep in self._domain_reputations.values()
            if rep.trust_weight > 0.2
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8: HARDENING (SECURITY)
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityGuard:
    """
    Phase 8: Security hardening utilities
    
    - SSRF protection for redirect resolution
    - Rate limiting
    - Input validation
    """
    
    # Private IP ranges (SSRF protection)
    PRIVATE_IP_PATTERNS = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^0\.',
        r'^169\.254\.',  # Link-local
        r'^::1$',        # IPv6 localhost
        r'^fc00:',       # IPv6 private
        r'^fe80:',       # IPv6 link-local
    ]
    
    # Maximum URL length
    MAX_URL_LENGTH = 2048
    
    # Blocked URL schemes
    BLOCKED_SCHEMES = {'file', 'ftp', 'gopher', 'data', 'javascript', 'vbscript'}
    
    @classmethod
    def is_safe_url(cls, url: str) -> tuple:
        """
        Check if URL is safe to fetch (SSRF protection).
        Returns (is_safe, reason)
        """
        import re
        from urllib.parse import urlparse
        
        if not url:
            return False, "Empty URL"
        
        if len(url) > cls.MAX_URL_LENGTH:
            return False, f"URL too long (>{cls.MAX_URL_LENGTH})"
        
        try:
            parsed = urlparse(url)
        except Exception:
            return False, "Invalid URL format"
        
        # Check scheme
        if parsed.scheme.lower() in cls.BLOCKED_SCHEMES:
            return False, f"Blocked scheme: {parsed.scheme}"
        
        if parsed.scheme.lower() not in ('http', 'https'):
            return False, f"Unsupported scheme: {parsed.scheme}"
        
        # Check for private IP addresses
        hostname = parsed.netloc.lower()
        
        # Remove port
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Check against private IP patterns
        for pattern in cls.PRIVATE_IP_PATTERNS:
            if re.match(pattern, hostname):
                return False, "Private IP address blocked"
        
        # Check for localhost variations
        if hostname in ('localhost', 'localhost.localdomain'):
            return False, "Localhost blocked"
        
        return True, "OK"
    
    @classmethod
    def sanitize_url_for_logging(cls, url: str) -> str:
        """Sanitize URL for safe logging (remove credentials)"""
        from urllib.parse import urlparse, urlunparse
        
        try:
            parsed = urlparse(url)
            # Remove username/password
            sanitized = parsed._replace(
                netloc=parsed.hostname or '',
            )
            return urlunparse(sanitized)[:200]
        except Exception:
            return url[:50] + "..."
    
    @classmethod
    def validate_hash(cls, hash_str: str) -> bool:
        """Validate file hash format"""
        import re
        
        # MD5: 32 chars, SHA1: 40 chars, SHA256: 64 chars
        if re.match(r'^[a-fA-F0-9]{32}$', hash_str):
            return True  # MD5
        if re.match(r'^[a-fA-F0-9]{40}$', hash_str):
            return True  # SHA1
        if re.match(r'^[a-fA-F0-9]{64}$', hash_str):
            return True  # SHA256
        
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLETON INSTANCES
# ═══════════════════════════════════════════════════════════════════════════════

feedback_service = FeedbackLoopService()
security_guard = SecurityGuard()


def record_analyst_feedback(
    email_id: str,
    feedback_type: FeedbackType,
    domain: str,
    original_verdict: str = "",
    flagging_signals: List[str] = None,
    analyst_id: str = None,
    notes: str = None
) -> None:
    """Convenience function for recording feedback"""
    entry = FeedbackEntry(
        email_id=email_id,
        feedback_type=feedback_type,
        domain=domain,
        original_verdict=original_verdict,
        flagging_signals=flagging_signals or [],
        analyst_id=analyst_id,
        notes=notes
    )
    feedback_service.record_feedback(entry)


def get_domain_trust_weight(domain: str) -> float:
    """Get learned trust weight for domain"""
    return feedback_service.get_domain_trust(domain)


def is_url_safe_to_fetch(url: str) -> tuple:
    """Check if URL is safe (SSRF protection)"""
    return security_guard.is_safe_url(url)
