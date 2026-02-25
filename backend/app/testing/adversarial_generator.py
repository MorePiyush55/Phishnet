"""
PhishNet Adversarial Generator
================================
Generates adversarial phishing emails to stress-test the detection engine.

Attack Vectors Simulated (15 total):
    1. Unicode Homoglyph Domains
    2. URL Shorteners / Redirects
    3. Base64 Encoded Payloads
    4. Grammar-Perfect Phishing (AI-style)
    5. Zero-Day Domain Spoofing
    6. Double Extension Attachments
    7. Benign-Looking Spear Phishing
    8. Encoded URL Parameters
    9. Look-alike Brand Impersonation
    10. Multi-Technique Combined
    11. Polymorphic Phishing (structure mutation)
    12. AI-Generated Spear Phishing (hyper-personalized)
    13. Domain Age Simulation (passes all auth)
    14. Legitimate Email with Hidden Malicious Link
    15. Internal Address Spoofing

The system must survive all of these to be enterprise-grade.
"""

import base64
import hashlib
import logging
import random
import string
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .dataset_loader import EmailSample

logger = logging.getLogger("phishnet.testing.adversarial_generator")


# ═══════════════════════════════════════════════════════════════
# HOMOGLYPH MAPS
# ═══════════════════════════════════════════════════════════════

# Latin → Cyrillic / Greek / special character substitutions
HOMOGLYPH_MAP = {
    "a": ["а", "ɑ", "α"],      # Cyrillic а, Latin alpha, Greek alpha
    "e": ["е", "ε", "ё"],      # Cyrillic е, Greek epsilon
    "o": ["о", "о", "ο"],      # Cyrillic о, Greek omicron
    "p": ["р", "ρ"],            # Cyrillic р, Greek rho
    "c": ["с", "ϲ"],            # Cyrillic с
    "d": ["ԁ"],                 # Cyrillic ԁ
    "i": ["і", "ι"],            # Cyrillic і, Greek iota
    "l": ["ӏ", "Ι", "1"],      # Cyrillic palochka, Greek Iota, digit 1
    "n": ["ո", "ṇ"],           # Armenian
    "s": ["ѕ"],                 # Cyrillic ѕ
    "t": ["ţ", "τ"],           # Cedilla, Greek tau
    "x": ["х", "χ"],           # Cyrillic х, Greek chi
    "y": ["у", "γ"],           # Cyrillic у, Greek gamma
    "g": ["ɡ", "ɢ"],           # IPA variants
    "m": ["м", "ṃ"],           # Cyrillic м
    "w": ["ω", "ш"],           # Greek omega, Cyrillic sha
}

# Common URL shortener services
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "rebrand.ly", "shorturl.at",
]

# Suspicious TLDs
SUSPICIOUS_TLDS = [
    ".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".club", ".work", ".click", ".link",
    ".info", ".biz", ".online", ".site", ".website",
]

# Dangerous file extensions
DANGEROUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".dll",
    ".hta", ".cpl", ".inf", ".reg", ".rgs", ".sct",
]

# Brand targets for impersonation
BRAND_TARGETS = [
    {"name": "Microsoft", "domain": "microsoft.com", "display": "Microsoft Account Team"},
    {"name": "Google", "domain": "google.com", "display": "Google Security"},
    {"name": "Apple", "domain": "apple.com", "display": "Apple Support"},
    {"name": "PayPal", "domain": "paypal.com", "display": "PayPal Security"},
    {"name": "Amazon", "domain": "amazon.com", "display": "Amazon.com"},
    {"name": "Netflix", "domain": "netflix.com", "display": "Netflix Support"},
    {"name": "Dropbox", "domain": "dropbox.com", "display": "Dropbox"},
    {"name": "LinkedIn", "domain": "linkedin.com", "display": "LinkedIn"},
    {"name": "Facebook", "domain": "facebook.com", "display": "Facebook Security"},
    {"name": "Bank of America", "domain": "bankofamerica.com", "display": "Bank of America"},
]


# ═══════════════════════════════════════════════════════════════
# ADVERSARIAL GENERATOR
# ═══════════════════════════════════════════════════════════════

class AdversarialGenerator:
    """
    Generates adversarial phishing emails designed to evade detection.
    
    Each generator method produces emails with specific evasion techniques.
    All generated samples are labeled as PHISHING ground truth for evaluation.
    """

    def __init__(self, random_seed: int = 42):
        self.rng = random.Random(random_seed)
        self._counter = 0

    def _next_id(self, prefix: str = "adv_gen") -> str:
        self._counter += 1
        return f"{prefix}_{self._counter:04d}"

    # ─── Master Generator ─────────────────────────────────────

    def generate_full_adversarial_suite(self, count_per_type: int = 3) -> List[EmailSample]:
        """
        Generate a comprehensive adversarial dataset covering all 15 attack vectors.
        
        Args:
            count_per_type: Number of samples per attack type.
        
        Returns:
            List of adversarial EmailSample objects.
        """
        samples: List[EmailSample] = []

        generators = [
            ("homoglyph", self.generate_homoglyph_attacks),
            ("url_shortener", self.generate_url_shortener_attacks),
            ("base64_payload", self.generate_encoded_payload_attacks),
            ("grammar_perfect", self.generate_grammar_perfect_phishing),
            ("zero_day_domain", self.generate_zero_day_domain_attacks),
            ("double_extension", self.generate_double_extension_attacks),
            ("bec_gift_card", self.generate_bec_gift_card_attacks),
            ("encoded_redirect", self.generate_encoded_redirect_attacks),
            ("brand_impersonation", self.generate_brand_impersonation_attacks),
            ("mixed_technique", self.generate_mixed_technique_attacks),
            ("polymorphic", self.generate_polymorphic_attacks),
            ("ai_spear_phishing", self.generate_ai_spear_phishing_attacks),
            ("domain_age_spoof", self.generate_domain_age_spoof_attacks),
            ("legit_malicious_link", self.generate_legit_with_malicious_link_attacks),
            ("internal_spoof", self.generate_internal_spoof_attacks),
        ]

        for attack_type, generator in generators:
            try:
                batch = generator(count=count_per_type)
                samples.extend(batch)
                logger.info(f"Generated {len(batch)} {attack_type} samples")
            except Exception as e:
                logger.error(f"Failed to generate {attack_type} samples: {e}")

        logger.info(f"Total adversarial samples generated: {len(samples)}")
        return samples

    # ─── Attack Type 1: Unicode Homoglyph Domains ────────────

    def generate_homoglyph_attacks(self, count: int = 3) -> List[EmailSample]:
        """Generate emails with Unicode homoglyph domain spoofing."""
        samples = []
        for _ in range(count):
            brand = self.rng.choice(BRAND_TARGETS)
            spoofed_domain = self._homoglyph_domain(brand["domain"])
            sender = f"security@{spoofed_domain}"

            samples.append(EmailSample(
                id=self._next_id("adv_homo"),
                sender=sender,
                sender_display_name=brand["display"],
                subject=f"Security Alert from {brand['name']}",
                body=f"We detected suspicious activity on your {brand['name']} account. "
                     f"Please verify your identity immediately to prevent account suspension. "
                     f"This is an automated security measure for your protection.",
                links=[f"https://{spoofed_domain}/verify-identity"],
                body_html=f'<a href="https://{spoofed_domain}/verify-identity">Verify Now</a>',
                headers={
                    "Authentication-Results": "spf=none; dkim=none; dmarc=none",
                    "Received-SPF": "none",
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="adversarial",
                metadata={"attack_type": "homoglyph", "target_brand": brand["name"]},
            ))
        return samples

    # ─── Attack Type 2: URL Shorteners ────────────────────────

    def generate_url_shortener_attacks(self, count: int = 3) -> List[EmailSample]:
        """Generate emails using URL shorteners to hide malicious destinations."""
        samples = []
        for _ in range(count):
            brand = self.rng.choice(BRAND_TARGETS)
            shortener = self.rng.choice(URL_SHORTENERS)
            short_id = ''.join(self.rng.choices(string.ascii_letters + string.digits, k=7))
            short_url = f"https://{shortener}/{short_id}"

            samples.append(EmailSample(
                id=self._next_id("adv_short"),
                sender=f"alert@{brand['domain']}-notifications.com",
                sender_display_name=brand["display"],
                subject=f"Important: Action Required on Your {brand['name']} Account",
                body=f"We need you to confirm recent changes to your {brand['name']} account. "
                     f"Click the secure link below to review activity and confirm your identity.",
                links=[short_url],
                body_html=f'<a href="{short_url}">Review Account Activity</a>',
                headers={
                    "Authentication-Results": "spf=softfail; dkim=none; dmarc=none",
                    "Received-SPF": "softfail",
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="adversarial",
                metadata={"attack_type": "url_shortener", "shortener": shortener},
            ))
        return samples

    # ─── Attack Type 3: Base64 Encoded Payloads ──────────────

    def generate_encoded_payload_attacks(self, count: int = 3) -> List[EmailSample]:
        """Generate emails with Base64-encoded malicious URLs in parameters."""
        samples = []
        for _ in range(count):
            # Hide malicious URL inside base64 parameter
            malicious_url = self.rng.choice([
                "http://malware-payload.ru/dropper",
                "http://credential-steal.tk/login",
                "http://phish-kit.xyz/capture",
            ])
            encoded = base64.b64encode(malicious_url.encode()).decode()

            redirect_domain = f"redirect-service-{self.rng.randint(1000,9999)}.com"
            redirect_url = f"https://{redirect_domain}/r?dest={encoded}"

            samples.append(EmailSample(
                id=self._next_id("adv_b64"),
                sender=f"noreply@{redirect_domain}",
                sender_display_name="Document Sharing Service",
                subject="Shared Document: Q4 Financial Report",
                body="A document has been shared with you. Click below to view it securely. "
                     "This link will expire in 24 hours.",
                links=[redirect_url],
                body_html=f'<a href="{redirect_url}">View Secure Document</a>',
                headers={
                    "Authentication-Results": "spf=pass; dkim=pass; dmarc=none",
                    "Received-SPF": "pass",
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="adversarial",
                metadata={"attack_type": "base64_payload", "encoded_target": malicious_url},
            ))
        return samples

    # ─── Attack Type 4: Grammar-Perfect AI Phishing ──────────

    def generate_grammar_perfect_phishing(self, count: int = 3) -> List[EmailSample]:
        """Generate grammatically perfect, professional-sounding phishing emails."""
        templates = [
            {
                "sender": "compliance@regulatory-updates.com",
                "display": "Compliance Department",
                "subject": "Annual Security Compliance Certification Required",
                "body": (
                    "Dear Colleague,\n\n"
                    "As part of our annual security compliance review mandated by SOC 2 Type II "
                    "requirements, all employees must complete their security certification renewal "
                    "by the end of this quarter.\n\n"
                    "The certification process takes approximately 10 minutes and involves verifying "
                    "your current access credentials and reviewing updated security policies.\n\n"
                    "Please complete this requirement at your earliest convenience using the secure "
                    "portal linked below. Failure to complete certification may result in temporary "
                    "access restrictions per our Information Security Policy (ISP-2026-004).\n\n"
                    "Best regards,\nInformation Security Division"
                ),
            },
            {
                "sender": "treasury@wire-processing-dept.com",
                "display": "Treasury Operations",
                "subject": "Re: Approved Vendor Payment - Wire Transfer #WT-2026-0891",
                "body": (
                    "Following up on the approved vendor payment discussed in yesterday's meeting. "
                    "The finance committee has approved the wire transfer for the consulting "
                    "engagement with Meridian Strategic Partners.\n\n"
                    "Amount: $187,500.00\n"
                    "Reference: WT-2026-0891\n"
                    "Beneficiary: Meridian Strategic Partners LLC\n\n"
                    "Please process this wire transfer today using the secure payment portal. "
                    "The vendor has confirmed they need funds received by end of business Friday "
                    "to maintain our preferred pricing terms.\n\n"
                    "Regards,\nTreasury Operations"
                ),
            },
            {
                "sender": "partner-relations@investment-firm.com",
                "display": "Jensen & Associates - Private Equity",
                "subject": "Confidential: Investment Opportunity - Time Sensitive",
                "body": (
                    "Dear Investor,\n\n"
                    "I'm reaching out regarding an exclusive pre-IPO investment opportunity "
                    "that our research team has identified. Based on your investment profile, "
                    "I believe this would align well with your portfolio strategy.\n\n"
                    "The company is a late-stage fintech startup with $50M ARR and significant "
                    "institutional backing. The allocation window closes this Friday.\n\n"
                    "I've prepared a detailed investment memorandum with financial projections "
                    "and risk analysis. Please review the attached document and confirm your "
                    "interest through our secure investor portal.\n\n"
                    "This opportunity is subject to accredited investor verification.\n\n"
                    "Warm regards,\nMichael Jensen, CFA\nManaging Partner"
                ),
            },
        ]

        samples = []
        for i in range(count):
            template = templates[i % len(templates)]
            tld = self.rng.choice(SUSPICIOUS_TLDS)
            portal_domain = f"secure-portal-{self.rng.randint(100,999)}{tld}"

            samples.append(EmailSample(
                id=self._next_id("adv_perf"),
                sender=template["sender"],
                sender_display_name=template["display"],
                subject=template["subject"],
                body=template["body"],
                links=[f"https://{portal_domain}/login"],
                body_html=f'<p>{template["body"]}</p><a href="https://{portal_domain}/login">Access Portal</a>',
                headers={
                    "Authentication-Results": "spf=pass; dkim=pass; dmarc=none",
                    "Received-SPF": "pass",
                },
                ground_truth="PHISHING",
                category="SPEAR_PHISHING",
                difficulty="adversarial",
                metadata={"attack_type": "grammar_perfect"},
            ))
        return samples

    # ─── Attack Type 5: Zero-Day Domain Spoofing ─────────────

    def generate_zero_day_domain_attacks(self, count: int = 3) -> List[EmailSample]:
        """Generate emails from brand-new domains with no reputation history."""
        samples = []
        for _ in range(count):
            # Generate a fresh domain registered "today"
            words = ["secure", "verify", "auth", "login", "account", "portal", "service"]
            domain = f"{self.rng.choice(words)}-{self.rng.choice(words)}-{self.rng.randint(1,999)}.com"
            
            brand = self.rng.choice(BRAND_TARGETS)

            samples.append(EmailSample(
                id=self._next_id("adv_0day"),
                sender=f"{brand['name'].lower().replace(' ', '')}@{domain}",
                sender_display_name=brand["display"],
                subject=f"{brand['name']} Account Verification Required",
                body=f"For your security, we require periodic verification of your {brand['name']} "
                     f"account credentials. This is a standard security procedure.\n\n"
                     f"Please verify your account within 48 hours to avoid service interruption.",
                links=[f"https://{domain}/verify"],
                headers={
                    "Authentication-Results": "spf=none; dkim=none; dmarc=none",
                    "Received-SPF": "none",
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="adversarial",
                metadata={"attack_type": "zero_day_domain", "domain": domain},
            ))
        return samples

    # ─── Attack Type 6: Double Extension Attachments ─────────

    def generate_double_extension_attacks(self, count: int = 3) -> List[EmailSample]:
        """Generate emails with double-extension attachment tricks."""
        samples = []
        benign_exts = [".pdf", ".docx", ".xlsx", ".png", ".jpg"]
        
        for _ in range(count):
            benign = self.rng.choice(benign_exts)
            dangerous = self.rng.choice(DANGEROUS_EXTENSIONS)
            filename = f"Invoice_2026{benign}{dangerous}"

            samples.append(EmailSample(
                id=self._next_id("adv_dext"),
                sender=f"billing@invoice-{self.rng.randint(100,999)}.com",
                sender_display_name="Accounts Payable",
                subject=f"Invoice #{self.rng.randint(10000,99999)} - Payment Due",
                body="Please find your invoice attached. Payment is due within 10 business days. "
                     "If you have questions about this invoice, contact our billing department.",
                attachments=[{
                    "filename": filename,
                    "content_type": "application/octet-stream",
                }],
                headers={
                    "Authentication-Results": "spf=pass; dkim=none; dmarc=none",
                    "Received-SPF": "pass",
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="adversarial",
                metadata={"attack_type": "double_extension", "filename": filename},
            ))
        return samples

    # ─── Attack Type 7: BEC / Gift Card Scams ────────────────

    def generate_bec_gift_card_attacks(self, count: int = 3) -> List[EmailSample]:
        """Generate Business Email Compromise / gift card scam emails."""
        ceo_names = ["Robert Chen", "Sarah Williams", "James Miller", "Patricia Davis"]
        
        samples = []
        for _ in range(count):
            ceo = self.rng.choice(ceo_names)
            first_name = ceo.split()[0]

            samples.append(EmailSample(
                id=self._next_id("adv_bec"),
                sender=f"{first_name.lower()}@company-exec.com",
                sender_display_name=ceo,
                subject=self.rng.choice([
                    "Quick favor", "Need your help", "Urgent request", "Are you available?",
                ]),
                body=self.rng.choice([
                    f"Hey, are you at your desk? I need a favor. Can you purchase "
                    f"{self.rng.randint(3,10)} Amazon gift cards at ${self.rng.choice([100, 200, 500])} "
                    f"each? I'll reimburse you right away. Send me the codes when done. "
                    f"Can't call right now, in a meeting. - {first_name}",
                    
                    f"I need you to handle something urgently for me. Purchase Google Play "
                    f"gift cards totaling ${self.rng.randint(1,5) * 500} and email me the "
                    f"redemption codes. This is for a client appreciation event. "
                    f"Please keep this between us for now. Thanks, {first_name}",
                    
                    f"Are you busy? I need you to wire ${self.rng.randint(10,50) * 1000} "
                    f"to a vendor urgently. Regular payment process is too slow. "
                    f"I'll send you the account details. Please treat this as confidential. "
                    f"- {first_name}",
                ]),
                links=[],
                attachments=[],
                headers={
                    "Authentication-Results": "spf=none; dkim=none; dmarc=none",
                    "Received-SPF": "none",
                },
                ground_truth="PHISHING",
                category="SPEAR_PHISHING",
                difficulty="adversarial",
                metadata={"attack_type": "bec_gift_card", "impersonated": ceo},
            ))
        return samples

    # ─── Attack Type 8: Encoded Redirect URLs ────────────────

    def generate_encoded_redirect_attacks(self, count: int = 3) -> List[EmailSample]:
        """Generate emails with URL-encoded or obfuscated redirect chains."""
        samples = []
        for _ in range(count):
            # Create an obfuscated redirect chain
            final_target = f"http://credential-harvest-{self.rng.randint(1000,9999)}.tk/login"
            # URL-encode the target
            encoded_target = final_target.replace(":", "%3A").replace("/", "%2F")
            
            # Use a legitimate-looking redirect service
            redirect_url = f"https://redirect-{self.rng.randint(100,999)}.com/go?url={encoded_target}"

            samples.append(EmailSample(
                id=self._next_id("adv_redir"),
                sender=f"system@notification-{self.rng.randint(100,999)}.com",
                sender_display_name="System Notification",
                subject="Document Review Required",
                body="A document requires your review and approval. "
                     "Click the link below to access the secure document viewer.",
                links=[redirect_url],
                body_html=f'<a href="{redirect_url}">Review Document</a>',
                headers={
                    "Authentication-Results": "spf=pass; dkim=none; dmarc=none",
                    "Received-SPF": "pass",
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="adversarial",
                metadata={"attack_type": "encoded_redirect", "final_target": final_target},
            ))
        return samples

    # ─── Attack Type 9: Brand Impersonation ──────────────────

    def generate_brand_impersonation_attacks(self, count: int = 3) -> List[EmailSample]:
        """Generate brand impersonation emails with typosquatting domains."""
        samples = []
        for _ in range(count):
            brand = self.rng.choice(BRAND_TARGETS)
            typo_domain = self._typosquat_domain(brand["domain"])

            samples.append(EmailSample(
                id=self._next_id("adv_brand"),
                sender=f"no-reply@{typo_domain}",
                sender_display_name=brand["display"],
                subject=f"Your {brand['name']} account needs attention",
                body=f"We noticed that your {brand['name']} account information is out of date. "
                     f"To continue using our services without interruption, please update your "
                     f"account information by clicking the link below.\n\n"
                     f"This is a routine security check and should only take a moment.",
                links=[f"https://{typo_domain}/update-account"],
                body_html=f'<a href="https://{typo_domain}/update-account">Update Account</a>',
                headers={
                    "Authentication-Results": "spf=softfail; dkim=none; dmarc=fail",
                    "Received-SPF": "softfail",
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="hard",
                metadata={"attack_type": "brand_impersonation", "brand": brand["name"], "typo_domain": typo_domain},
            ))
        return samples

    # ─── Attack Type 10: Mixed Technique ─────────────────────

    def generate_mixed_technique_attacks(self, count: int = 3) -> List[EmailSample]:
        """Generate emails combining multiple evasion techniques."""
        samples = []
        for _ in range(count):
            brand = self.rng.choice(BRAND_TARGETS)
            
            # Combine: homoglyph domain + URL shortener + base64 attachment name
            spoofed_domain = self._homoglyph_domain(brand["domain"])
            shortener = self.rng.choice(URL_SHORTENERS)
            short_id = ''.join(self.rng.choices(string.ascii_letters + string.digits, k=7))
            
            # Encoded attachment filename
            benign_ext = self.rng.choice([".pdf", ".docx"])
            dangerous_ext = self.rng.choice([".exe", ".js", ".scr"])
            filename = f"Urgent_Notice{benign_ext}{dangerous_ext}"

            samples.append(EmailSample(
                id=self._next_id("adv_mixed"),
                sender=f"urgent@{spoofed_domain}",
                sender_display_name=brand["display"],
                subject=f"URGENT: {brand['name']} Security Breach - Immediate Action Required",
                body=f"Dear Valued Customer,\n\n"
                     f"We have detected unauthorized access to your {brand['name']} account "
                     f"from an unrecognized device. To secure your account, you must:\n\n"
                     f"1. Click the verification link below\n"
                     f"2. Review the attached security report\n"
                     f"3. Update your password immediately\n\n"
                     f"Failure to act within 12 hours will result in account termination.",
                links=[f"https://{shortener}/{short_id}"],
                attachments=[{
                    "filename": filename,
                    "content_type": "application/octet-stream",
                }],
                headers={
                    "Authentication-Results": "spf=none; dkim=none; dmarc=fail",
                    "Received-SPF": "none",
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="adversarial",
                metadata={
                    "attack_type": "mixed_technique",
                    "techniques": ["homoglyph", "url_shortener", "double_extension"],
                },
            ))
        return samples

    # ─── Attack Type 11: Polymorphic Phishing ─────────────────

    def generate_polymorphic_attacks(self, count: int = 3) -> List[EmailSample]:
        """
        Generate polymorphic phishing emails that mutate structure per instance.
        Each email uses randomized sentence ordering, synonym substitution,
        and varied formatting to evade signature-based detection.
        """
        samples = []
        action_phrases = [
            "Click the link below to restore access",
            "Use the secure portal to verify your identity",
            "Follow the instructions at the link provided",
            "Access the verification page immediately",
            "Complete the security check via the button below",
        ]
        urgency_phrases = [
            "Your account will be suspended within {hours} hours",
            "Failure to act will result in permanent data loss",
            "Immediate action is required to prevent unauthorized access",
            "This is your final notice before account termination",
            "Time-sensitive: your account access expires soon",
        ]
        greeting_styles = [
            "Dear Valued Customer,", "Dear Account Holder,", "Hello,",
            "Dear User,", "Attention:", "Important Notice:",
        ]
        closing_styles = [
            "Security Team", "Account Protection Division",
            "Fraud Prevention Unit", "Customer Safety Department",
            "Trust & Safety Team",
        ]

        for _ in range(count):
            brand = self.rng.choice(BRAND_TARGETS)
            tld = self.rng.choice(SUSPICIOUS_TLDS)
            domain = f"{brand['name'].lower().replace(' ', '')}-security-{self.rng.randint(100,999)}{tld}"
            hours = self.rng.choice([6, 12, 24, 48])

            # Build polymorphic body from shuffled components
            greeting = self.rng.choice(greeting_styles)
            urgency = self.rng.choice(urgency_phrases).format(hours=hours)
            action = self.rng.choice(action_phrases)
            closing = self.rng.choice(closing_styles)

            middle_sentences = [
                f"We have detected unusual activity on your {brand['name']} account.",
                f"An unauthorized attempt was made to access your account from an unrecognized device.",
                f"For your protection, we have temporarily restricted certain account features.",
            ]
            self.rng.shuffle(middle_sentences)

            body = f"{greeting}\n\n{'  '.join(middle_sentences)}\n\n{urgency}.\n\n{action}.\n\nRegards,\n{closing}"

            samples.append(EmailSample(
                id=self._next_id("adv_poly"),
                sender=f"{self.rng.choice(['alert','protect','verify','secure'])}@{domain}",
                sender_display_name=brand["display"],
                subject=self.rng.choice([
                    f"[Action Required] {brand['name']} Account Alert",
                    f"{brand['name']}: Suspicious Activity Detected",
                    f"Security Notice - {brand['name']} Account",
                    f"URGENT: Verify Your {brand['name']} Identity",
                ]),
                body=body,
                links=[f"https://{domain}/verify-{self.rng.randint(10000,99999)}"],
                body_html=f'<p>{body}</p><a href="https://{domain}/verify">Verify Now</a>',
                headers={
                    "Authentication-Results": f"spf={self.rng.choice(['fail','softfail','none'])}; dkim=none; dmarc=fail",
                    "Received-SPF": self.rng.choice(["fail", "softfail", "none"]),
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="adversarial",
                metadata={"attack_type": "polymorphic", "mutation_seed": self.rng.randint(0, 99999)},
            ))
        return samples

    # ─── Attack Type 12: AI-Generated Spear Phishing ──────────

    def generate_ai_spear_phishing_attacks(self, count: int = 3) -> List[EmailSample]:
        """
        Generate hyper-personalized AI-style spear phishing that uses
        target-specific context, no typos, perfect grammar, and
        contextually appropriate references to bypass content filters.
        """
        samples = []
        scenarios = [
            {
                "sender": "m.roberts@partner-advisory.com",
                "display": "Michael Roberts - Advisory Board",
                "subjects": [
                    "Follow-up: Board strategy session action items",
                    "Re: Q{q} strategic initiative - next steps",
                ],
                "body_template": (
                    "Hi {target_name},\n\n"
                    "Thank you for the productive discussion during Tuesday's advisory session. "
                    "As agreed, I've prepared the strategic framework document incorporating "
                    "the competitive analysis we reviewed.\n\n"
                    "Key points to address before the {day} deadline:\n"
                    "1. Market entry timing for the {region} expansion\n"
                    "2. Updated financial projections based on revised assumptions\n"
                    "3. Risk mitigation strategy for the regulatory changes\n\n"
                    "I've uploaded the materials to our shared workspace. Please review "
                    "and provide your feedback by end of week.\n\n"
                    "Best regards,\nMichael"
                ),
            },
            {
                "sender": "accounting@vendor-systems.net",
                "display": "Accounts Receivable - TechVendor Inc",
                "subjects": [
                    "Invoice #{num} - Updated payment instructions",
                    "IMPORTANT: Banking details change notification",
                ],
                "body_template": (
                    "Dear Accounts Payable Team,\n\n"
                    "Please be advised that effective immediately, TechVendor Inc has "
                    "transitioned our banking services to a new financial institution. "
                    "This change was necessitated by our recent corporate restructuring.\n\n"
                    "All future payments, including the outstanding ${amount} for Invoice #{num}, "
                    "should be directed to the new account details provided in the attached "
                    "document. The previous bank account will be closed on {day}.\n\n"
                    "We apologize for any inconvenience. Please confirm receipt of this "
                    "notification and update your records accordingly.\n\n"
                    "Regards,\nAccounts Receivable Department\nTechVendor Inc"
                ),
            },
            {
                "sender": "talent@executive-search.io",
                "display": "Alexandra Chen - Executive Search Partners",
                "subjects": [
                    "Confidential: VP Engineering opportunity",
                    "Executive opportunity - {company} (confidential)",
                ],
                "body_template": (
                    "Dear {target_name},\n\n"
                    "I represent Executive Search Partners and I'm reaching out regarding "
                    "a confidential VP of Engineering search for a pre-IPO technology company "
                    "backed by Sequoia and Andreessen Horowitz.\n\n"
                    "The role comes with:\n"
                    "- Base salary: $400K-$500K\n"
                    "- Pre-IPO equity: 0.5-1.0%\n"
                    "- Full executive benefits package\n\n"
                    "Your background at {company} makes you an exceptional candidate. "
                    "I'd love to share more details over a brief call this week.\n\n"
                    "Could you review the position brief I've attached and let me know "
                    "your interest level? Given the confidential nature, I've secured "
                    "the document with a verification step.\n\n"
                    "Warm regards,\nAlexandra Chen\nManaging Partner"
                ),
            },
        ]

        target_names = ["David", "Sarah", "James", "Emily", "Michael", "Jessica"]
        companies = ["Google", "Meta", "Stripe", "Databricks", "Snowflake"]
        regions = ["APAC", "EMEA", "Latin America", "Southeast Asia"]

        for _ in range(count):
            scenario = self.rng.choice(scenarios)
            target = self.rng.choice(target_names)
            company = self.rng.choice(companies)
            region = self.rng.choice(regions)
            day = self.rng.choice(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"])
            q = self.rng.randint(1, 4)
            num = self.rng.randint(10000, 99999)
            amount = f"{self.rng.randint(10, 200) * 1000:,}"

            subj = self.rng.choice(scenario["subjects"]).format(q=q, num=num, company=company)
            body = scenario["body_template"].format(
                target_name=target, day=day, region=region,
                q=q, num=num, amount=amount, company=company,
            )

            tld = self.rng.choice([".com", ".io", ".net"])
            link_domain = scenario["sender"].split("@")[1]

            samples.append(EmailSample(
                id=self._next_id("adv_aisp"),
                sender=scenario["sender"],
                sender_display_name=scenario["display"],
                subject=subj,
                body=body,
                links=[f"https://{link_domain}/shared/{self.rng.randint(100000,999999)}"],
                attachments=[{
                    "filename": f"{'Brief' if 'talent' in scenario['sender'] else 'Document'}_{num}.pdf",
                    "content_type": "application/pdf",
                }],
                headers={
                    "Authentication-Results": "spf=pass; dkim=pass; dmarc=none",
                    "Received-SPF": "pass",
                },
                ground_truth="PHISHING",
                category="SPEAR_PHISHING",
                difficulty="adversarial",
                metadata={"attack_type": "ai_spear_phishing", "target_name": target},
            ))
        return samples

    # ─── Attack Type 13: Domain Age Simulation ────────────────

    def generate_domain_age_spoof_attacks(self, count: int = 3) -> List[EmailSample]:
        """
        Generate emails from domains that appear legitimate by mimicking
        aged domain characteristics: proper SPF/DKIM, professional formatting,
        but with recently registered lookalike domains.
        """
        samples = []
        legitimate_patterns = [
            {"pattern": "{brand}-notifications.com", "display": "{brand} Notifications"},
            {"pattern": "secure-{brand}.org", "display": "{brand} Security Center"},
            {"pattern": "{brand}-alerts.net", "display": "{brand} Alert System"},
            {"pattern": "my{brand}account.com", "display": "{brand} Account Services"},
            {"pattern": "{brand}-support-center.com", "display": "{brand} Support"},
        ]

        for _ in range(count):
            brand = self.rng.choice(BRAND_TARGETS)
            brand_lower = brand["name"].lower().replace(" ", "")
            pattern = self.rng.choice(legitimate_patterns)
            domain = pattern["pattern"].format(brand=brand_lower)
            display = pattern["display"].format(brand=brand["name"])

            samples.append(EmailSample(
                id=self._next_id("adv_dage"),
                sender=f"no-reply@{domain}",
                sender_display_name=display,
                subject=f"{brand['name']} Account Verification - Annual Review",
                body=(
                    f"Dear {brand['name']} Customer,\n\n"
                    f"As part of our annual account review process, we kindly request "
                    f"that you verify your account information to ensure continued "
                    f"access to all {brand['name']} services.\n\n"
                    f"This is a routine security measure conducted in accordance with "
                    f"our updated privacy policy and industry compliance standards.\n\n"
                    f"Please complete the verification process within 7 business days.\n\n"
                    f"Thank you for your continued trust in {brand['name']}.\n\n"
                    f"Sincerely,\n{brand['name']} Account Services"
                ),
                links=[f"https://{domain}/verify-account"],
                body_html=f'<a href="https://{domain}/verify-account">Verify Account</a>',
                headers={
                    # Passes auth because attacker controls the lookalike domain
                    "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
                    "Received-SPF": "pass",
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="adversarial",
                metadata={
                    "attack_type": "domain_age_spoof",
                    "target_brand": brand["name"],
                    "spoofed_domain": domain,
                    "note": "Passes all auth checks; detection must rely on domain reputation/age",
                },
            ))
        return samples

    # ─── Attack Type 14: Legitimate Email with Malicious Link ─

    def generate_legit_with_malicious_link_attacks(self, count: int = 3) -> List[EmailSample]:
        """
        Generate emails that look completely legitimate in every way —
        proper sender, proper auth, professional content — but contain
        one malicious link hidden among legitimate ones.
        
        This tests link analysis node isolation.
        """
        samples = []
        scenarios = [
            {
                "sender": "team-updates@company-{id}.com",
                "display": "Team Updates",
                "subject": "Weekly Engineering Update - Week {week}",
                "body": (
                    "Hi team,\n\n"
                    "Here's this week's engineering update:\n\n"
                    "1. Backend API performance improved by 15%\n"
                    "2. New monitoring dashboard is live\n"
                    "3. Security audit findings have been addressed\n\n"
                    "Please review the updated documentation and complete "
                    "the security training module by end of week.\n\n"
                    "Best,\nEngineering Team"
                ),
                "legit_links": [
                    "https://confluence.company.com/wiki/updates",
                    "https://grafana.company.com/dashboards",
                ],
            },
            {
                "sender": "project-mgmt@org-{id}.com",
                "display": "Project Management Office",
                "subject": "Project {proj} - Sprint Review Materials",
                "body": (
                    "Hi all,\n\n"
                    "The sprint review materials for Project {proj} are ready. "
                    "Please review before tomorrow's meeting.\n\n"
                    "Agenda:\n"
                    "- Sprint velocity review\n"
                    "- Demo of new features\n"
                    "- Retrospective action items\n\n"
                    "Meeting link and documents are below.\n\n"
                    "Thanks,\nPMO"
                ),
                "legit_links": [
                    "https://zoom.us/j/{zoom_id}",
                ],
            },
        ]

        for _ in range(count):
            scenario = self.rng.choice(scenarios)
            company_id = self.rng.randint(100, 999)
            week = self.rng.randint(1, 52)
            proj = self.rng.choice(["Atlas", "Phoenix", "Titan", "Nova"])
            zoom_id = self.rng.randint(1000000000, 9999999999)

            sender = scenario["sender"].format(id=company_id)
            subject = scenario["subject"].format(week=week, proj=proj)
            body = scenario["body"].format(proj=proj)

            # Mix legitimate links with one malicious link
            legit = [l.format(zoom_id=zoom_id) for l in scenario["legit_links"]]
            malicious = f"https://docs-review-{self.rng.randint(100,999)}{self.rng.choice(SUSPICIOUS_TLDS)}/shared"
            all_links = legit + [malicious]
            self.rng.shuffle(all_links)

            samples.append(EmailSample(
                id=self._next_id("adv_lmal"),
                sender=sender,
                sender_display_name=scenario["display"],
                subject=subject,
                body=body,
                links=all_links,
                body_html=' '.join(f'<a href="{l}">Link</a>' for l in all_links),
                headers={
                    "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
                    "Received-SPF": "pass",
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="adversarial",
                metadata={
                    "attack_type": "legit_with_malicious_link",
                    "malicious_link": malicious,
                    "note": "Only one link is malicious; tests link node isolation",
                },
            ))
        return samples

    # ─── Attack Type 15: Internal Spoof ──────────────────────

    def generate_internal_spoof_attacks(self, count: int = 3) -> List[EmailSample]:
        """
        Generate emails that spoof internal company addresses.
        The From header shows an internal address but envelope sender
        and auth results reveal the spoofing.
        """
        samples = []
        internal_roles = [
            ("ceo", "CEO", "Urgent: Need your help with something"),
            ("cfo", "CFO", "Wire transfer approval needed"),
            ("hr", "HR Department", "Updated compensation - confidential"),
            ("it-admin", "IT Administrator", "System maintenance: credentials required"),
            ("legal", "Legal Department", "Confidential: Compliance matter"),
        ]

        for _ in range(count):
            role_prefix, role_display, subject = self.rng.choice(internal_roles)
            target_domain = self.rng.choice([
                "company.com", "megacorp.com", "enterprise-inc.com",
                "globaltech.io", "bigfirm.com",
            ])
            fake_name = f"{self.rng.choice(['Robert','Sarah','James','Emily','Michael'])} {self.rng.choice(['Chen','Williams','Johnson','Davis','Miller'])}"

            # Spoofed From header shows internal address
            spoofed_from = f"{role_prefix}@{target_domain}"
            # But actual envelope sender is external
            actual_sender_domain = f"mail-{self.rng.randint(100,999)}.{self.rng.choice(['xyz','top','club'])}"

            bodies = [
                f"Hi,\n\nI need you to handle something urgently and confidentially. "
                f"I'm in meetings all day and can't call. Can you process a wire transfer "
                f"for ${self.rng.randint(10,100) * 1000:,}? I'll send you the details shortly.\n\n"
                f"- {fake_name}",

                f"Team,\n\nDue to a critical security incident, all employees must "
                f"re-verify their credentials through the internal portal below. "
                f"This is mandatory and must be completed within 2 hours.\n\n"
                f"- {role_display}",

                f"Hi,\n\nHR has finalized the compensation adjustments for Q{self.rng.randint(1,4)}. "
                f"Your updated offer letter is attached. Please review and sign via the "
                f"secure portal before Friday.\n\n"
                f"Regards,\n{fake_name}\n{role_display}",
            ]

            portal_domain = f"internal-portal-{self.rng.randint(100,999)}{self.rng.choice(SUSPICIOUS_TLDS)}"

            samples.append(EmailSample(
                id=self._next_id("adv_intsp"),
                sender=spoofed_from,
                sender_display_name=f"{fake_name} ({role_display})",
                subject=subject,
                body=self.rng.choice(bodies),
                links=[f"https://{portal_domain}/verify"],
                attachments=[{"filename": "Confidential_Document.pdf", "content_type": "application/pdf"}] if self.rng.random() < 0.4 else [],
                headers={
                    # Auth fails because the actual sender domain doesn't match
                    "Authentication-Results": f"spf=fail; dkim=none; dmarc=fail",
                    "Received-SPF": "fail",
                    "Return-Path": f"bounce@{actual_sender_domain}",
                },
                ground_truth="PHISHING",
                category="ADVERSARIAL_OBFUSCATED",
                difficulty="adversarial",
                metadata={
                    "attack_type": "internal_spoof",
                    "spoofed_address": spoofed_from,
                    "actual_sender_domain": actual_sender_domain,
                    "impersonated_role": role_display,
                },
            ))
        return samples

    # ─── Domain Manipulation Helpers ──────────────────────────

    def _homoglyph_domain(self, domain: str) -> str:
        """Replace 1-2 characters in a domain with Unicode homoglyphs."""
        name, tld = domain.rsplit(".", 1)
        chars = list(name)
        
        # Find replaceable positions
        replaceable = [(i, c) for i, c in enumerate(chars) if c.lower() in HOMOGLYPH_MAP]
        
        if not replaceable:
            return f"{name}-secure.{tld}"

        # Replace 1-2 characters
        num_replacements = min(len(replaceable), self.rng.randint(1, 2))
        positions = self.rng.sample(replaceable, num_replacements)
        
        for idx, char in positions:
            options = HOMOGLYPH_MAP.get(char.lower(), [])
            if options:
                chars[idx] = self.rng.choice(options)

        return f"{''.join(chars)}.{tld}"

    def _typosquat_domain(self, domain: str) -> str:
        """Generate a typosquatting variant of a domain."""
        name, tld = domain.rsplit(".", 1)
        
        technique = self.rng.choice([
            "swap",       # Swap adjacent characters
            "double",     # Double a character
            "drop",       # Drop a character
            "insert",     # Insert a character
            "hyphen",     # Add hyphen
            "tld_change", # Change TLD
        ])

        if technique == "swap" and len(name) > 2:
            i = self.rng.randint(0, len(name) - 2)
            chars = list(name)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            return f"{''.join(chars)}.{tld}"
        elif technique == "double" and len(name) > 1:
            i = self.rng.randint(0, len(name) - 1)
            return f"{name[:i+1]}{name[i]}{name[i+1:]}.{tld}"
        elif technique == "drop" and len(name) > 2:
            i = self.rng.randint(1, len(name) - 1)
            return f"{name[:i]}{name[i+1:]}.{tld}"
        elif technique == "insert":
            i = self.rng.randint(1, len(name))
            extra = self.rng.choice(string.ascii_lowercase)
            return f"{name[:i]}{extra}{name[i:]}.{tld}"
        elif technique == "hyphen":
            i = self.rng.randint(1, len(name) - 1)
            return f"{name[:i]}-{name[i:]}.{tld}"
        elif technique == "tld_change":
            new_tld = self.rng.choice(["net", "org", "co", "info", "io"])
            return f"{name}.{new_tld}"

        return f"{name}-secure.{tld}"

    # ─── Inject Into Existing Dataset ─────────────────────────

    def inject_into_dataset(
        self,
        existing_samples: List[EmailSample],
        count_per_type: int = 2,
    ) -> List[EmailSample]:
        """
        Generate adversarial samples and inject into an existing dataset.
        
        Returns the combined list (original + adversarial).
        """
        adversarial = self.generate_full_adversarial_suite(count_per_type)
        combined = existing_samples + adversarial
        logger.info(
            f"Injected {len(adversarial)} adversarial samples into "
            f"{len(existing_samples)} existing samples → {len(combined)} total"
        )
        return combined
