"""
AdversarialRiskEngine — Meta-module for detecting evasion patterns.

Computes an adversarial_penalty (0–40) that is subtracted from the
weighted total score to expose stealthy attacks that individual nodes miss.

Convention: low score = low risk = SAFE.
The penalty *reduces* the weighted score, pushing evasive emails toward
PHISHING territory.
"""

from __future__ import annotations

import base64
import logging
import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, unquote

logger = logging.getLogger("phishnet.adversarial_risk")


# ── Homoglyph mapping (Latin look-alikes from Cyrillic, Greek, etc.) ──
_HOMOGLYPH_MAP: Dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h", "\u043a": "k", "\u043c": "m",
    "\u043d": "n", "\u0442": "t", "\u0432": "v", "\u0437": "3",
    # Greek
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03b5": "e",
}

# ── Brand keywords used in impersonation ──
_BRAND_KEYWORDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wells fargo", "bank of america", "citibank",
    "usps", "fedex", "ups", "dhl", "irs", "ssa",
}

# ── Financial / credential action phrases ──
_ACTION_PHRASES = [
    r"verify your (?:account|identity|email)",
    r"confirm your (?:payment|order|subscription)",
    r"update your (?:billing|payment|credit card)",
    r"suspended? (?:your )?account",
    r"unusual (?:sign.in|activity|login)",
    r"reset your password",
    r"click (?:here|below|the link) (?:to|immediately|now)",
    r"within \d+ (?:hours?|minutes?|days?)",
    r"your account (?:will be|has been) (?:locked|closed|suspended)",
    r"enter your (?:credentials|password|ssn|social security)",
]


@dataclass
class AdversarialAssessment:
    """Result of adversarial evasion analysis."""
    penalty: int  # 0–40, subtracted from weighted score
    signals: List[str] = field(default_factory=list)


class AdversarialRiskEngine:
    """
    Detects adversarial evasion patterns that individual analysis nodes
    miss because they evaluate email attributes in isolation.

    Usage::

        engine = AdversarialRiskEngine()
        assessment = engine.assess(body_text, body_html, urls, sender_email,
                                   display_name, subject, auth_results)
        adjusted_score = max(0, weighted_score - assessment.penalty)
    """

    MAX_PENALTY = 40

    # ────────────────────────────────────────────────────
    # PUBLIC API
    # ────────────────────────────────────────────────────

    def assess(
        self,
        body_text: str,
        body_html: str,
        urls: List[str],
        sender_email: str,
        display_name: str,
        subject: str,
        spf_result: str = "none",
        dkim_result: str = "none",
        attachment_names: List[str] = None,
        sender_score: int = 100,
    ) -> AdversarialAssessment:
        """Run all evasion-pattern checks and return cumulative penalty."""
        penalty = 0
        signals: List[str] = []

        checks = [
            self._check_homoglyphs(urls, sender_email, display_name),
            self._check_mixed_encoding(body_text, body_html),
            self._check_high_entropy_urls(urls),
            self._check_grammar_urgency_finance(body_text, subject),
            self._check_brand_unknown_domain(sender_email, display_name, subject),
            self._check_base64_hidden_links(body_text, body_html),
            self._check_double_extension(attachment_names or []),
            self._check_sender_auth_mismatch(sender_score, spf_result, dkim_result, display_name, sender_email),
        ]

        for p, sigs in checks:
            penalty += p
            signals.extend(sigs)

        penalty = min(penalty, self.MAX_PENALTY)
        if signals:
            logger.info(f"Adversarial penalty={penalty}, signals={signals}")
        return AdversarialAssessment(penalty=penalty, signals=signals)

    # ────────────────────────────────────────────────────
    # INDIVIDUAL CHECKS
    # ────────────────────────────────────────────────────

    def _check_homoglyphs(
        self, urls: List[str], sender_email: str, display_name: str,
    ) -> tuple:
        """Detect Unicode homoglyphs in URLs, sender, or display name."""
        penalty, signals = 0, []
        texts_to_check = [sender_email, display_name] + urls
        for text in texts_to_check:
            for char in text:
                if char in _HOMOGLYPH_MAP:
                    penalty = 15
                    signals.append(f"Homoglyph '{char}' (looks like '{_HOMOGLYPH_MAP[char]}')")
                    return penalty, signals  # one detection is enough
        return penalty, signals

    def _check_mixed_encoding(self, body_text: str, body_html: str) -> tuple:
        """Detect mixed character encodings in body (evasion technique)."""
        penalty, signals = 0, []
        combined = body_text + body_html
        if not combined:
            return 0, []

        # Check for mix of ASCII + non-ASCII in supposedly English text
        ascii_chars = sum(1 for c in combined if ord(c) < 128)
        non_ascii = sum(1 for c in combined if ord(c) >= 128 and not c.isspace())
        total = len(combined)

        if total > 50 and non_ascii > 0:
            ratio = non_ascii / total
            if 0.01 < ratio < 0.15:  # Suspicious mix (not pure non-English)
                penalty = 10
                signals.append(f"Mixed encoding: {non_ascii} non-ASCII in {total} chars")

        return penalty, signals

    def _check_high_entropy_urls(self, urls: List[str]) -> tuple:
        """Detect URLs with suspiciously high entropy (random strings)."""
        penalty, signals = 0, []
        for url in urls:
            try:
                parsed = urlparse(url)
                path_query = (parsed.path or "") + (parsed.query or "")
                if len(path_query) < 20:
                    continue
                entropy = self._shannon_entropy(path_query)
                if entropy > 4.5:
                    penalty = max(penalty, 10)
                    signals.append(f"High-entropy URL (H={entropy:.2f}): {url[:60]}")
            except Exception:
                continue
        return penalty, signals

    def _check_grammar_urgency_finance(self, body_text: str, subject: str) -> tuple:
        """Detect perfect grammar + high urgency + financial context pattern."""
        penalty, signals = 0, []
        text = (body_text + " " + subject).lower()

        # Count action phrase matches
        action_matches = sum(1 for pat in _ACTION_PHRASES if re.search(pat, text))

        # Urgency words
        urgency_words = ["immediately", "urgent", "asap", "expire",
                         "suspended", "locked", "unauthorized", "alert",
                         "within 24", "within 48", "right away", "act now"]
        urgency_count = sum(1 for w in urgency_words if w in text)

        # Financial context
        finance_words = ["account", "payment", "invoice", "transaction",
                         "credit card", "billing", "bank", "wire transfer",
                         "bitcoin", "cryptocurrency", "gift card"]
        finance_count = sum(1 for w in finance_words if w in text)

        # Grammar-perfect phishing: action phrases + urgency + finance
        if action_matches >= 2 and urgency_count >= 1:
            penalty = 15
            signals.append(
                f"Urgency+action pattern: {action_matches} actions, "
                f"{urgency_count} urgency, {finance_count} financial"
            )
        elif action_matches >= 1 and urgency_count >= 1 and finance_count >= 1:
            penalty = 10
            signals.append("Financial action with urgency detected")

        return penalty, signals

    def _check_brand_unknown_domain(
        self, sender_email: str, display_name: str, subject: str,
    ) -> tuple:
        """Detect brand name in display/subject from an unknown domain."""
        penalty, signals = 0, []
        combined = (display_name + " " + subject).lower()

        # Extract sender domain
        domain = ""
        if "@" in sender_email:
            domain = sender_email.split("@")[1].lower()

        for brand in _BRAND_KEYWORDS:
            if brand in combined:
                # Check if sender domain actually belongs to the brand
                brand_root = brand.replace(" ", "").replace("of", "")
                if brand_root not in domain:
                    penalty = 10
                    signals.append(f"Brand '{brand}' in display/subject but sender domain is '{domain}'")
                    break

        return penalty, signals

    def _check_base64_hidden_links(self, body_text: str, body_html: str) -> tuple:
        """Detect base64-encoded blocks that hide links."""
        penalty, signals = 0, []
        combined = body_text + " " + body_html

        # Find base64 blocks > 200 characters
        b64_pattern = re.compile(r'[A-Za-z0-9+/=]{200,}')
        matches = b64_pattern.findall(combined)

        for match in matches:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if re.search(r'https?://', decoded):
                    penalty = 15
                    signals.append("Base64 block hides URL")
                    break
            except Exception:
                continue

        return penalty, signals

    def _check_double_extension(self, attachment_names: List[str]) -> tuple:
        """Detect double-extension filenames (e.g., invoice.pdf.exe)."""
        penalty, signals = 0, []
        dangerous_exts = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
                          ".vbs", ".js", ".wsf", ".msi", ".ps1"}

        for name in attachment_names:
            parts = name.rsplit(".", 2)
            if len(parts) >= 3:
                final_ext = "." + parts[-1].lower()
                if final_ext in dangerous_exts:
                    penalty = 15
                    signals.append(f"Double extension: {name}")
                    break

        return penalty, signals

    def _check_sender_auth_mismatch(
        self, sender_score: int, spf_result: str, dkim_result: str,
        display_name: str, sender_email: str,
    ) -> tuple:
        """Detect sender with low score + authentication failure."""
        penalty, signals = 0, []

        auth_fail = spf_result.lower() in ("fail", "softfail") or dkim_result.lower() == "fail"

        if sender_score < 20 and auth_fail:
            penalty = 15
            signals.append(f"Sender score={sender_score} with auth failure (SPF={spf_result}, DKIM={dkim_result})")

        # Display name vs email mismatch with SPF fail
        if spf_result.lower() in ("fail", "softfail"):
            dn_lower = display_name.lower()
            domain = sender_email.split("@")[1].lower() if "@" in sender_email else ""
            domain_root = domain.split(".")[0] if domain else ""
            if domain_root and domain_root not in dn_lower and len(dn_lower) > 3:
                penalty = max(penalty, 10)
                signals.append(f"SPF fail + display name '{display_name}' doesn't match domain '{domain}'")

        return penalty, signals

    # ────────────────────────────────────────────────────
    # UTILITIES
    # ────────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
