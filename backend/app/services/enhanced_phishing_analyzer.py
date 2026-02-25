"""
Enhanced Phishing Analysis Service
Integrates advanced features from ThePhish and email-phishing-detection-add-in projects

Features:
1. Sender Analysis: Display name vs email comparison, IP extraction
2. Content Analysis: Phishing keywords, body text analysis
3. Link Analysis: Encoding, HTTP/HTTPS, redirection, duplication
4. Authentication: SPF, DKIM, DMARC verification
5. Attachment Analysis: File counting, dangerous file types
6. Scoring System: Percentage-based scoring for each section
"""

import re
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, unquote
from difflib import SequenceMatcher
import base64
from dataclasses import dataclass, field
import hashlib
from collections import Counter


@dataclass
class SenderAnalysis:
    """Sender information analysis results"""
    display_name: str
    email_address: str
    sender_ip: Optional[str]
    name_email_similarity: float
    similarity_description: str
    score: int  # 0-100 percentage score
    indicators: List[str] = field(default_factory=list)


@dataclass
class ContentAnalysis:
    """Email content analysis results"""
    body_text: str
    body_html: str
    phishing_keywords_found: List[str]
    keyword_count: int
    urgency_level: str
    score: int  # 0-100 percentage score
    indicators: List[str] = field(default_factory=list)


@dataclass
class LinkAnalysis:
    """Link analysis results"""
    total_links: int
    unique_links: int
    duplicate_links: int
    https_links: int
    http_links: int
    encoded_links: int
    redirect_links: int
    suspicious_tlds: List[str]
    link_details: List[Dict[str, Any]]
    https_score: int
    encoding_score: int
    redirect_score: int
    duplication_score: int
    overall_score: int  # 0-100 percentage score
    indicators: List[str] = field(default_factory=list)
    # Phase 0: Sender-link alignment (higher = more aligned, safer)
    sender_alignment_score: float = 1.0  # 0-1 scale
    aligned_links: int = 0  # Links to same_org or known_vendor
    unrelated_links: int = 0  # Links to unknown domains


@dataclass
class AuthenticationAnalysis:
    """Email authentication protocols analysis"""
    spf_result: str
    spf_score: int
    spf_description: str
    dkim_result: str
    dkim_score: int
    dkim_description: str
    dmarc_result: str
    dmarc_score: int
    dmarc_description: str
    overall_score: int  # 0-100 percentage score
    indicators: List[str] = field(default_factory=list)


@dataclass
class AttachmentAnalysis:
    """Email attachments analysis"""
    total_attachments: int
    attachment_names: List[str]
    attachment_types: List[str]
    attachment_hashes: List[str]
    dangerous_extensions: List[str]
    score: int  # 0-100 percentage score
    indicators: List[str] = field(default_factory=list)


@dataclass
class ComprehensivePhishingAnalysis:
    """Complete phishing analysis results"""
    sender: SenderAnalysis
    content: ContentAnalysis
    links: LinkAnalysis
    authentication: AuthenticationAnalysis
    attachments: AttachmentAnalysis
    total_score: int  # 0-100 percentage score
    final_verdict: str  # SAFE, SUSPICIOUS, PHISHING
    confidence: float  # 0-1
    risk_factors: List[str]


class EnhancedPhishingAnalyzer:
    """
    Enhanced phishing analysis engine with advanced detection capabilities
    Based on ThePhish and email-phishing-detection-add-in methodologies
    """
    
    # Phishing keywords database (expanded list)
    PHISHING_KEYWORDS = [
        # Urgency keywords
        'urgent', 'immediate', 'action required', 'act now', 'limited time',
        'expires', 'suspended', 'locked', 'verify', 'confirm', 'update',
        'validate', 'reactivate', 'restore', 'secure', 'alert',
        
        # Financial/Banking
        'account', 'bank', 'credit card', 'payment', 'transaction',
        'billing', 'invoice', 'refund', 'wire transfer', 'deposit',
        'withdraw', 'balance', 'fraud', 'unauthorized',
        
        # Threats
        'suspended', 'closed', 'blocked', 'restricted', 'compromised',
        'breach', 'security', 'unusual activity', 'suspicious',
        
        # Call to action
        'click here', 'download', 'open attachment', 'reset password',
        'change password', 'login', 'sign in', 'access', 'retrieve',
        
        # Rewards/Prizes
        'winner', 'prize', 'reward', 'congratulations', 'claim',
        'free', 'bonus', 'gift', 'promotion', 'discount',
        
        # Authority impersonation
        'irs', 'fbi', 'police', 'government', 'ceo', 'manager',
        'administrator', 'support', 'helpdesk', 'customer service'
    ]
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = [
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
        '.jar', '.zip', '.rar', '.7z', '.iso', '.dmg', '.pkg', '.deb',
        '.msi', '.app', '.dll', '.sys', '.drv', '.bin', '.dat',
        '.ps1', '.psm1', '.sh', '.bash', '.py', '.pl', '.rb',
        '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm'
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws', '.info',
        '.biz', '.top', '.xyz', '.club', '.work', '.click', '.link',
        '.sbs', '.cfd', '.cyou', '.lol', '.fun', '.buzz', '.surf',
        '.rest', '.icu', '.store', '.site', '.online', '.live',
        '.su', '.to', '.cm', '.monster', '.digital', '.network'
    ]
    
    # Well-known platforms that send legitimate automated notifications
    # When sender domain matches AND authentication passes, boost trust
    TRUSTED_NOTIFICATION_DOMAINS = {
        # Code / Dev platforms
        'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
        'npmjs.com', 'pypi.org', 'docker.com',
        
        # Major tech companies
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'meta.com', 'facebook.com', 'x.com', 'twitter.com',
        
        # Cloud / Hosting
        'vercel.com', 'netlify.com', 'heroku.com', 'render.com',
        'digitalocean.com', 'cloudflare.com',
        
        # Productivity / SaaS
        'slack.com', 'notion.so', 'atlassian.com', 'trello.com',
        'asana.com', 'monday.com', 'figma.com', 'canva.com',
        'zoom.us', 'dropbox.com', 'stripe.com', 'paypal.com',
        
        # Social / Media
        'linkedin.com', 'youtube.com', 'reddit.com', 'medium.com',
        'twitch.tv', 'spotify.com',
    }
    
    # Common automated sender prefixes (noreply@, notifications@, etc.)
    AUTOMATED_SENDER_PREFIXES = {
        'noreply', 'no-reply', 'no_reply', 'donotreply', 'do-not-reply',
        'notifications', 'notification', 'notify',
        'mailer', 'mailer-daemon', 'postmaster',
        'updates', 'update', 'alert', 'alerts',
        'info', 'support', 'team', 'service', 'system',
        'mail', 'admin', 'contact', 'hello', 'news',
        'digest', 'bot', 'automation', 'builds', 'ci',
    }
    
    def analyze_email(self, email_content: bytes) -> ComprehensivePhishingAnalysis:
        """
        Perform comprehensive phishing analysis on email (synchronous wrapper).
        
        Args:
            email_content: Raw email content in bytes
            
        Returns:
            ComprehensivePhishingAnalysis object with all analysis results
        """
        # Parse email
        msg = BytesParser(policy=policy.default).parsebytes(email_content)
        
        # Run all 5 modules in PARALLEL using ThreadPoolExecutor
        # This is 2-3x faster than sequential execution
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                'sender': executor.submit(self.analyze_sender, msg),
                'content': executor.submit(self.analyze_content, msg),
                'links': executor.submit(self.analyze_links, msg),
                'auth': executor.submit(self.analyze_authentication, msg),
                'attachments': executor.submit(self.analyze_attachments, msg),
            }
            
            # Collect results
            sender_analysis = futures['sender'].result()
            content_analysis = futures['content'].result()
            link_analysis = futures['links'].result()
            auth_analysis = futures['auth'].result()
            attachment_analysis = futures['attachments'].result()
        
        # Calculate total score (weighted average with dynamic trust)
        total_score = self._calculate_total_score(
            sender_analysis.score,
            content_analysis.score,
            link_analysis.overall_score,
            auth_analysis.overall_score,
            attachment_analysis.score
        )
        
        # ── Adversarial penalty layer ──
        # Detect evasion patterns that individual nodes miss
        from app.services.adversarial_risk_engine import AdversarialRiskEngine
        adv_engine = AdversarialRiskEngine()
        
        # Extract body text for adversarial checks
        body_text = content_analysis.body_text or ""
        body_html = content_analysis.body_html or ""
        subject = str(msg.get("Subject", ""))
        urls = []
        if link_analysis.total_links > 0:
            import re as _re
            urls = _re.findall(r'https?://[^\s<>"]+', body_text + " " + body_html)
        
        adv_assessment = adv_engine.assess(
            body_text=body_text,
            body_html=body_html,
            urls=urls,
            sender_email=sender_analysis.email_address,
            display_name=sender_analysis.display_name,
            subject=subject,
            spf_result=auth_analysis.spf_result,
            dkim_result=auth_analysis.dkim_result,
            attachment_names=attachment_analysis.attachment_names,
            sender_score=sender_analysis.score,
        )
        
        # Apply adversarial penalty (reduces score → pushes toward PHISHING)
        total_score = max(0, total_score - adv_assessment.penalty)
        
        # Determine final verdict (includes hard risk overrides)
        final_verdict, confidence = self._determine_verdict(
            total_score,
            sender_analysis,
            content_analysis,
            link_analysis,
            auth_analysis,
            attachment_analysis
        )
        
        # Collect risk factors
        risk_factors = self._collect_risk_factors(
            sender_analysis,
            content_analysis,
            link_analysis,
            auth_analysis,
            attachment_analysis
        )
        # Add adversarial signals to risk factors
        risk_factors.extend(adv_assessment.signals)
        
        return ComprehensivePhishingAnalysis(
            sender=sender_analysis,
            content=content_analysis,
            links=link_analysis,
            authentication=auth_analysis,
            attachments=attachment_analysis,
            total_score=total_score,
            final_verdict=final_verdict,
            confidence=confidence,
            risk_factors=risk_factors
        )
    
    def analyze_sender(self, msg: email.message.Message) -> SenderAnalysis:
        """
        Analyze sender information
        Checks: display name vs email similarity, IP address extraction,
                trusted notification domain recognition
        """
        # Extract sender info
        from_header = msg.get('From', '')
        display_name, email_address = email.utils.parseaddr(from_header)
        
        # Extract sender IP from Received headers
        sender_ip = self._extract_sender_ip(msg)
        
        # Extract sender domain for trust checks
        sender_domain = email_address.split('@')[-1].lower() if '@' in email_address else ''
        sender_local = email_address.split('@')[0].lower() if '@' in email_address else ''
        from app.services.domain_identity import get_registrable_domain
        sender_reg_domain = get_registrable_domain(sender_domain)
        
        # Check if sender is a known trusted notification domain
        is_trusted_sender = sender_reg_domain in self.TRUSTED_NOTIFICATION_DOMAINS
        is_automated_prefix = sender_local in self.AUTOMATED_SENDER_PREFIXES
        
        # Calculate name-email similarity
        similarity, description = self._calculate_name_email_similarity(
            display_name, email_address
        )
        
        # Calculate score (0-100)
        score = int(similarity * 100)
        
        # TRUST BOOST: For known trusted notification senders
        # noreply@github.com, notifications@google.com, etc.
        # These have low name-email similarity by design (e.g., "GitHub" vs "noreply")
        if is_trusted_sender:
            if is_automated_prefix:
                # Automated sender from trusted platform - expected pattern
                # Boost to high score since this is normal behavior
                score = max(score, 95)
                description = f"Trusted notification sender ({sender_reg_domain})"
            else:
                # Non-automated prefix but from trusted domain - still boost
                score = max(score, 85)
                description = f"Known platform sender ({sender_reg_domain})"
        elif is_automated_prefix and not is_trusted_sender:
            # Automated prefix from unknown domain - slightly more trustworthy
            # than random display name mismatch but not a full boost
            score = max(score, int(similarity * 100) + 10)
        
        # Identify indicators
        indicators = []
        if similarity < 0.3 and not is_trusted_sender:
            indicators.append("Low similarity between display name and email")
        if self._check_suspicious_display_name(display_name, sender_reg_domain):
            indicators.append("Suspicious display name detected")
            score = max(0, score - 20)
        if self._check_free_email_domain(email_address):
            indicators.append("Free email domain used")
            # Only penalize free email if sender is NOT forwarding a trusted email
            if not is_trusted_sender:
                score = max(0, score - 10)
        if is_trusted_sender:
            indicators.append(f"✓ Known trusted platform: {sender_reg_domain}")
        
        return SenderAnalysis(
            display_name=display_name,
            email_address=email_address,
            sender_ip=sender_ip,
            name_email_similarity=similarity,
            similarity_description=description,
            score=score,
            indicators=indicators
        )
    
    def analyze_content(self, msg: email.message.Message) -> ContentAnalysis:
        """
        Analyze email content for phishing indicators
        Checks: phishing keywords, urgency level, suspicious patterns
        """
        # Extract body text and HTML
        body_text = ""
        body_html = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif content_type == "text/html":
                    body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        
        # Find phishing keywords
        phishing_keywords_found = self._find_phishing_keywords(body_text)
        keyword_count = len(phishing_keywords_found)
        
        # Determine urgency level
        urgency_level = self._determine_urgency_level(body_text)
        
        # Calculate score (0-100, higher is safer)
        score = 100
        if keyword_count > 0:
            score -= min(50, keyword_count * 5)  # Reduce score based on keywords
        
        if urgency_level == "HIGH":
            score -= 30
        elif urgency_level == "MEDIUM":
            score -= 15
        
        score = max(0, score)
        
        # Identify indicators
        indicators = []
        if keyword_count >= 5:
            indicators.append(f"Multiple phishing keywords detected ({keyword_count})")
        if urgency_level in ["HIGH", "MEDIUM"]:
            indicators.append(f"Urgency level: {urgency_level}")
        
        return ContentAnalysis(
            body_text=body_text[:500],  # First 500 chars
            body_html=body_html[:500],
            phishing_keywords_found=phishing_keywords_found,
            keyword_count=keyword_count,
            urgency_level=urgency_level,
            score=score,
            indicators=indicators
        )
    
    def analyze_links(self, msg: email.message.Message) -> LinkAnalysis:
        """
        Analyze links in email
        Checks: encoding, HTTP/HTTPS usage, redirection, duplication, sender alignment
        
        PHASE 0 CHANGES:
        - Added sender-link alignment analysis
        - HTTP score considers aligned domains (doesn't penalize aligned HTTP)
        - Uses eTLD+1 for domain comparisons
        """
        from app.services.domain_identity import SenderLinkAlignment, get_registrable_domain
        
        # Extract sender email for alignment check
        sender_email = msg.get('From', '')
        if '<' in sender_email:
            # Extract email from "Name <email@domain.com>" format
            import re
            match = re.search(r'<([^>]+)>', sender_email)
            sender_email = match.group(1) if match else sender_email
        
        # Extract all links from email
        links = self._extract_links(msg)
        
        total_links = len(links)
        unique_links = len(set(links))
        duplicate_links = total_links - unique_links
        
        # Analyze link characteristics
        https_links = 0
        http_links = 0
        encoded_links = 0
        redirect_links = 0
        suspicious_tlds = []
        link_details = []
        
        # PHASE 0: Track alignment
        aligned_links = 0
        unrelated_links = 0
        
        # Get sender-link alignment analysis
        alignment_result = SenderLinkAlignment.analyze_email_links(sender_email, links)
        sender_alignment_score = alignment_result.get('alignment_score', 1.0)
        aligned_links = alignment_result.get('same_org_count', 0) + alignment_result.get('vendor_count', 0)
        unrelated_links = alignment_result.get('unrelated_count', 0)
        trusted_platform_links = alignment_result.get('trusted_platform_count', 0)
        
        for link in links:
            parsed = urlparse(link)
            domain = parsed.netloc.lower()
            
            # Check protocol
            if parsed.scheme == 'https':
                https_links += 1
            elif parsed.scheme == 'http':
                http_links += 1
            
            # Check for encoding
            if link != unquote(link):
                encoded_links += 1
            
            # Check for redirection keywords
            if 'redirect' in link.lower() or 'r?' in link or '/r/' in link:
                redirect_links += 1
            
            # Check for suspicious TLDs
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    suspicious_tlds.append(domain)
                    break
            
            link_details.append({
                'url': link,
                'protocol': parsed.scheme,
                'domain': domain,
                'registrable_domain': get_registrable_domain(domain),
                'path': parsed.path,
                'is_encoded': link != unquote(link),
                'is_redirect': 'redirect' in link.lower()
            })
        
        # PHASE 0: Calculate sub-scores with alignment awareness
        # HTTPS score now considers alignment - aligned HTTP links get partial credit
        if total_links == 0:
            https_score = 100
        else:
            # Base HTTPS score
            base_https_score = int((https_links / total_links) * 100)
            
            # Aligned HTTP links get 70% credit (they're less risky)
            if aligned_links > 0 and https_links == 0:
                aligned_http_bonus = int((aligned_links / total_links) * 70)
                https_score = min(80, base_https_score + aligned_http_bonus)
            else:
                https_score = base_https_score
        
        encoding_score = 100 if total_links == 0 else int(((total_links - encoded_links) / total_links) * 100)
        redirect_score = 100 if total_links == 0 else int(((total_links - redirect_links) / total_links) * 100)
        duplication_score = 100 if total_links <= 1 else int(((total_links - duplicate_links) / total_links) * 100)
        
        # PHASE 0: Alignment score contributes to overall score
        alignment_score_weighted = int(sender_alignment_score * 100)
        
        # Overall link score (now includes alignment)
        overall_score = int((https_score + encoding_score + redirect_score + duplication_score + alignment_score_weighted) / 5)
        
        # TRUSTED DOMAIN BOOST: When most links go to trusted platforms,
        # boost the overall score since these are inherently safe destinations
        if total_links > 0 and trusted_platform_links > 0:
            trusted_ratio = trusted_platform_links / total_links
            if trusted_ratio >= 0.8:
                # 80%+ links to trusted platforms → strong boost
                overall_score = max(overall_score, 95)
            elif trusted_ratio >= 0.5:
                # 50%+ links to trusted platforms → moderate boost
                overall_score = max(overall_score, 85)
            elif trusted_ratio >= 0.3:
                # 30%+ links to trusted platforms → small boost
                overall_score = max(overall_score, int(overall_score * 1.1))
        
        # Identify indicators (PHASE 0: improved messaging)
        indicators = []
        if http_links > 0:
            if aligned_links == http_links:
                indicators.append(f"{http_links} HTTP link(s) to aligned/known domains")
            elif aligned_links > 0:
                indicators.append(f"{http_links - aligned_links} HTTP link(s) to unknown domains")
            else:
                indicators.append(f"{http_links} HTTP (non-secure) link(s) found")
        if encoded_links > 0:
            indicators.append(f"{encoded_links} encoded link(s) detected")
        if redirect_links > 0:
            indicators.append(f"{redirect_links} redirect link(s) found")
        if len(suspicious_tlds) > 0:
            indicators.append(f"Suspicious TLDs detected: {', '.join(set(suspicious_tlds))}")
        if duplicate_links > 2:
            indicators.append(f"{duplicate_links} duplicate links")
        if unrelated_links > 0:
            indicators.append(f"{unrelated_links} link(s) to unrelated domains")
        if trusted_platform_links > 0:
            indicators.append(f"✓ {trusted_platform_links} link(s) to trusted platforms")
        
        return LinkAnalysis(
            total_links=total_links,
            unique_links=unique_links,
            duplicate_links=duplicate_links,
            https_links=https_links,
            http_links=http_links,
            encoded_links=encoded_links,
            redirect_links=redirect_links,
            suspicious_tlds=list(set(suspicious_tlds)),
            link_details=link_details[:10],  # First 10 links
            https_score=https_score,
            encoding_score=encoding_score,
            redirect_score=redirect_score,
            duplication_score=duplication_score,
            overall_score=overall_score,
            indicators=indicators,
            # PHASE 0: New alignment fields
            sender_alignment_score=sender_alignment_score,
            aligned_links=aligned_links,
            unrelated_links=unrelated_links
        )

    
    def analyze_authentication(self, msg: email.message.Message) -> AuthenticationAnalysis:
        """
        Analyze email authentication protocols
        Checks: SPF, DKIM, DMARC results from headers
        """
        # Extract authentication results from headers
        auth_results = msg.get('Authentication-Results', '')
        received_spf = msg.get('Received-SPF', '')
        
        # Parse SPF
        spf_result, spf_score, spf_description = self._parse_spf(auth_results, received_spf)
        
        # Parse DKIM
        dkim_result, dkim_score, dkim_description = self._parse_dkim(auth_results)
        
        # Parse DMARC
        dmarc_result, dmarc_score, dmarc_description = self._parse_dmarc(auth_results)
        
        # Calculate overall authentication score
        overall_score = int((spf_score + dkim_score + dmarc_score) / 3)
        
        # Identify indicators
        indicators = []
        if spf_result in ['fail', 'softfail', 'none']:
            indicators.append(f"SPF check {spf_result}")
        if dkim_result in ['fail', 'none']:
            indicators.append(f"DKIM check {dkim_result}")
        if dmarc_result in ['fail', 'none']:
            indicators.append(f"DMARC check {dmarc_result}")
        
        return AuthenticationAnalysis(
            spf_result=spf_result,
            spf_score=spf_score,
            spf_description=spf_description,
            dkim_result=dkim_result,
            dkim_score=dkim_score,
            dkim_description=dkim_description,
            dmarc_result=dmarc_result,
            dmarc_score=dmarc_score,
            dmarc_description=dmarc_description,
            overall_score=overall_score,
            indicators=indicators
        )
    
    def analyze_attachments(self, msg: email.message.Message) -> AttachmentAnalysis:
        """
        Analyze email attachments
        Checks: file count, file types, dangerous extensions
        """
        attachments = []
        attachment_types = []
        attachment_hashes = []
        dangerous_extensions = []
        
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
                    
                    # Get file extension
                    ext = '.' + filename.split('.')[-1] if '.' in filename else ''
                    attachment_types.append(ext)
                    
                    # Check for dangerous extensions
                    if ext.lower() in [e.lower() for e in self.DANGEROUS_EXTENSIONS]:
                        dangerous_extensions.append(filename)
                    
                    # Calculate hash
                    payload = part.get_payload(decode=True)
                    if payload:
                        file_hash = hashlib.sha256(payload).hexdigest()
                        attachment_hashes.append(file_hash)
        
        total_attachments = len(attachments)
        
        # Calculate score (0-100, higher is safer)
        score = 100
        if total_attachments > 0:
            score -= min(30, total_attachments * 10)
        if len(dangerous_extensions) > 0:
            score -= 50
        
        score = max(0, score)
        
        # Identify indicators
        indicators = []
        if len(dangerous_extensions) > 0:
            indicators.append(f"Dangerous file types: {', '.join(dangerous_extensions)}")
        if total_attachments > 3:
            indicators.append(f"Multiple attachments ({total_attachments})")
        
        return AttachmentAnalysis(
            total_attachments=total_attachments,
            attachment_names=attachments,
            attachment_types=list(set(attachment_types)),
            attachment_hashes=attachment_hashes,
            dangerous_extensions=dangerous_extensions,
            score=score,
            indicators=indicators
        )
    
    # Helper methods
    
    def _extract_sender_ip(self, msg: email.message.Message) -> Optional[str]:
        """Extract sender IP address from Received headers"""
        received_headers = msg.get_all('Received', [])
        for header in received_headers:
            # Look for IP pattern
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            matches = re.findall(ip_pattern, header)
            if matches:
                return matches[0]
        return None
    
    def _calculate_name_email_similarity(self, display_name: str, email_address: str) -> Tuple[float, str]:
        """Calculate similarity between display name and email address"""
        if not display_name or not email_address:
            return 0.0, "No similarity"
        
        # Normalize
        name_normalized = re.sub(r'[^a-z0-9]', '', display_name.lower())
        email_local = email_address.split('@')[0].lower()
        email_normalized = re.sub(r'[^a-z0-9]', '', email_local)
        
        # Calculate similarity using SequenceMatcher
        similarity = SequenceMatcher(None, name_normalized, email_normalized).ratio()
        
        if similarity >= 0.8:
            description = "Name found in email"
        elif similarity >= 0.6:
            description = "Most parts of name found in email"
        elif similarity >= 0.4:
            description = "Parts of name found in email"
        elif similarity >= 0.2:
            description = "Some similarity in name and email"
        elif similarity > 0:
            description = "Minimal similarity"
        else:
            description = "No similarity"
        
        return similarity, description
    
    def _check_suspicious_display_name(self, display_name: str, sender_reg_domain: str = '') -> bool:
        """
        Check if display name contains suspicious patterns.
        
        IMPORTANT: If the display name matches the actual sender domain,
        it's NOT suspicious (e.g., "Google" from google.com is expected).
        """
        suspicious_patterns = [
            r'paypal',
            r'amazon',
            r'microsoft',
            r'apple',
            r'google',
            r'bank',
            r'security',
            r'support',
            r'admin',
            r'ceo',
            r'manager'
        ]
        
        name_lower = display_name.lower()
        
        for pattern in suspicious_patterns:
            if re.search(pattern, name_lower):
                # If the display name matches the actual sender domain,
                # it's EXPECTED, not suspicious
                # e.g., "Google" from google.com, "Amazon" from amazon.com
                if sender_reg_domain and pattern in sender_reg_domain.lower():
                    continue  # This is legitimate, skip this pattern
                return True
        
        return False
    
    def _check_free_email_domain(self, email_address: str) -> bool:
        """Check if email uses free email domain"""
        free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
        domain = email_address.split('@')[-1].lower()
        return domain in free_domains
    
    def _find_phishing_keywords(self, text: str) -> List[str]:
        """Find phishing keywords in text"""
        text_lower = text.lower()
        found_keywords = []
        
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def _determine_urgency_level(self, text: str) -> str:
        """Determine urgency level of email content"""
        urgency_keywords_high = ['urgent', 'immediate', 'now', 'expires', 'suspended', 'locked']
        urgency_keywords_medium = ['soon', 'today', 'quickly', 'important', 'attention']
        
        text_lower = text.lower()
        
        high_count = sum(1 for keyword in urgency_keywords_high if keyword in text_lower)
        medium_count = sum(1 for keyword in urgency_keywords_medium if keyword in text_lower)
        
        if high_count >= 2:
            return "HIGH"
        elif high_count >= 1 or medium_count >= 2:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _extract_links(self, msg: email.message.Message) -> List[str]:
        """Extract all links from email"""
        links = []
        
        # Extract from HTML body
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                # Find href attributes
                href_pattern = r'href=["\']([^"\']+)["\']'
                found_links = re.findall(href_pattern, html_content)
                links.extend(found_links)
        
        # Extract from plain text
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                text_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                # Find URLs
                url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
                found_urls = re.findall(url_pattern, text_content)
                links.extend(found_urls)
        
        return links
    
    def _parse_spf(self, auth_results: str, received_spf: str) -> Tuple[str, int, str]:
        """Parse SPF authentication result"""
        spf_results = {
            'pass': (100, "The SPF record designates the host to be allowed to send"),
            'fail': (0, "The SPF record has designated the host as NOT being allowed to send"),
            'softfail': (0, "The SPF record has designated the host as NOT being allowed to send but is in transition"),
            'neutral': (0, "The SPF record specifies explicitly that nothing can be said about validity"),
            'none': (0, "The domain does not have an SPF record"),
            'permerror': (0, "A permanent error has occurred"),
            'temperror': (0, "A transient error has occurred")
        }
        
        # Try to extract SPF result
        spf_pattern = r'spf=(\w+)'
        match = re.search(spf_pattern, auth_results.lower())
        if not match and received_spf:
            match = re.search(spf_pattern, received_spf.lower())
        
        if match:
            result = match.group(1)
            if result in spf_results:
                score, description = spf_results[result]
                return result, score, description
        
        return 'unknown', 50, "SPF result unknown"
    
    def _parse_dkim(self, auth_results: str) -> Tuple[str, int, str]:
        """Parse DKIM authentication result"""
        dkim_results = {
            'pass': (100, "The email has DKIM Signature and passed the verification check"),
            'fail': (0, "The email message has a DKIM signature but there was an error causing a verification failure"),
            'none': (0, "The email message has not been signed with DKIM")
        }
        
        # Try to extract DKIM result
        dkim_pattern = r'dkim=(\w+)'
        match = re.search(dkim_pattern, auth_results.lower())
        
        if match:
            result = match.group(1)
            if result in dkim_results:
                score, description = dkim_results[result]
                return result, score, description
        
        return 'unknown', 50, "DKIM result unknown"
    
    def _parse_dmarc(self, auth_results: str) -> Tuple[str, int, str]:
        """Parse DMARC authentication result"""
        dmarc_results = {
            'pass': (100, "Email is authenticated against established DKIM and SPF standards"),
            'fail': (0, "Email failed to authenticate"),
            'none': (0, "Email is NOT authenticated against established DKIM and SPF standards"),
            'bestguesspass': (50, "Either SPF or DKIM failed to authenticate or the email body from address did not align with the domain")
        }
        
        # Try to extract DMARC result
        dmarc_pattern = r'dmarc=(\w+)'
        match = re.search(dmarc_pattern, auth_results.lower())
        
        if match:
            result = match.group(1)
            if result in dmarc_results:
                score, description = dmarc_results[result]
                return result, score, description
        
        return 'unknown', 50, "DMARC result unknown"
    
    # Dynamic node trust: reliability factors derived from adversarial testing.
    # Nodes with low accuracy get reduced influence; strong nodes get boosted.
    _NODE_RELIABILITY = {
        'sender': 0.90,       # Measured 64.4% accuracy — strong
        'content': 0.40,      # Measured 2.2% accuracy — boosted for keyword detection
        'links': 0.80,        # Boosted: URL analysis is critical for phishing detection
        'auth': 0.90,         # Measured 66.7% accuracy — strong
        'attachments': 0.50,  # Measured 11.1% accuracy — slightly boosted
    }

    def _calculate_total_score(self, sender_score: int, content_score: int, 
                               link_score: int, auth_score: int, attachment_score: int) -> int:
        """Calculate weighted total score with dynamic node trust.

        Uses effective_weight = base_weight * node_reliability so that
        weak nodes (content, links) cannot mask strong signals from
        reliable nodes (sender, auth).
        """
        base_weights = {
            'sender': 0.15,
            'content': 0.20,
            'links': 0.20,
            'auth': 0.30,
            'attachments': 0.15,
        }

        # Apply reliability scaling
        effective = {}
        for node, bw in base_weights.items():
            effective[node] = bw * self._NODE_RELIABILITY.get(node, 1.0)

        # Normalise so effective weights still sum to 1.0
        total_ew = sum(effective.values()) or 1.0
        for node in effective:
            effective[node] /= total_ew

        scores = {
            'sender': sender_score,
            'content': content_score,
            'links': link_score,
            'auth': auth_score,
            'attachments': attachment_score,
        }

        total = sum(scores[n] * effective[n] for n in scores)

        # TRUST BOOST: Fully authenticated + all nodes strong
        if auth_score == 100:
            min_other = min(sender_score, content_score, link_score, attachment_score)
            if min_other >= 80:
                total = max(total, 95)
            elif min_other >= 60:
                total = max(total, 85)

        # SINGLE-NODE FLOOR OVERRIDE:
        # If ANY reliable node scores critically low (< 30), that is a
        # strong adversarial signal.  Cap the total so it cannot stay
        # in the SAFE zone.  This prevents 4 clean nodes from masking
        # 1 node that clearly detected an attack.
        min_score = min(sender_score, content_score, link_score,
                        auth_score, attachment_score)
        if min_score < 30:
            total = min(total, 55)  # Forces at least SUSPICIOUS verdict
        elif min_score < 50:
            total = min(total, 70)  # Prevents SAFE verdict

        return int(total)
    
    def _determine_verdict(self, total_score: int, sender: SenderAnalysis,
                          content: ContentAnalysis, links: LinkAnalysis,
                          auth: AuthenticationAnalysis, attachments: AttachmentAnalysis) -> Tuple[str, float]:
        """Determine final verdict with hard risk overrides.

        Pipeline:
            1. Hard kill-switch overrides (deterministic → PHISHING)
            2. Link-risk dominance (malicious link overrides safe content)
            3. Score-based thresholds (<60 PHISHING, <75 SUSPICIOUS)
        """
        # ── STEP 1: HARD RISK OVERRIDES (kill-switches) ──────────────
        # These fire regardless of weighted average.
        auth_fail = auth.spf_result == 'fail' or auth.dkim_result == 'fail'

        # 1a. Sender critically low + authentication failure
        if sender.score < 20 and auth_fail:
            return "PHISHING", 0.95

        # 1b. Double-extension attachment detected
        if attachments.dangerous_extensions:
            for name in attachments.attachment_names:
                parts = name.rsplit('.', 2)
                if len(parts) >= 3 and parts[-1].lower() in (
                    'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'js',
                    'wsf', 'msi', 'ps1',
                ):
                    return "PHISHING", 0.95

        # 1c. SPF fail + display name doesn't match sender domain
        if auth.spf_result == 'fail':
            domain = sender.email_address.split('@')[1].lower() if '@' in sender.email_address else ''
            domain_root = domain.split('.')[0] if domain else ''
            if domain_root and domain_root not in sender.display_name.lower():
                return "PHISHING", 0.90

        # 1d. Dangerous attachments + any auth failure
        if len(attachments.dangerous_extensions) > 0 and auth_fail:
            return "PHISHING", 0.92

        # ── STEP 2: LINK-RISK DOMINANCE ──────────────────────────────
        # If link analysis flags significant risk, safe content cannot
        # dilute the verdict.
        if links.overall_score < 40 and content.score >= 70:
            return "PHISHING", 0.85
        # Broader link-risk: even moderate link risk with safe content
        if links.overall_score < 70 and content.score >= 80:
            return "SUSPICIOUS", 0.70

        # ── STEP 2a: UNRELATED-LINK OVERRIDE ─────────────────────────
        # If links go to domains unrelated to the sender, that is a
        # strong phishing signal even when individual node scores are
        # high.  Adversarial "legit_with_malicious_link" attacks
        # specifically exploit node independence here.
        if links.unrelated_links > 0:
            # Check for suspicious TLDs in unrelated links
            if links.suspicious_tlds:
                return "PHISHING", 0.88
            # Any unrelated link with imperfect alignment is suspicious
            if links.sender_alignment_score < 0.9:
                return "SUSPICIOUS", 0.75

        # ── STEP 2b: SENDER-FLOOR OVERRIDE ──────────────────────────
        # A very suspicious sender alone warrants at least SUSPICIOUS
        if sender.score < 30:
            return "PHISHING", 0.85

        # ── STEP 3: STANDARD CRITICAL FLAGS ──────────────────────────
        critical_flags = 0
        if len(attachments.dangerous_extensions) > 0:
            critical_flags += 1
        if auth.spf_result == 'fail':
            critical_flags += 1
        if auth.dkim_result == 'fail':
            critical_flags += 1
        if links.unrelated_links > 0 and links.https_links == 0:
            if auth.overall_score < 80:
                critical_flags += 1

        # ── STEP 4: VERDICT ARBITRATION ──────────────────────────────
        is_fully_authenticated = (
            auth.spf_result == 'pass' and
            auth.dkim_result == 'pass' and
            auth.dmarc_result == 'pass'
        )
        is_well_aligned = links.sender_alignment_score >= 0.7

        # Updated thresholds: stricter boundaries
        if critical_flags >= 2 or total_score < 60:
            return "PHISHING", 0.9
        elif total_score < 75 or critical_flags >= 1:
            if is_fully_authenticated and is_well_aligned and critical_flags == 0 and sender.score >= 50:
                return "SAFE", 0.75
            return "SUSPICIOUS", 0.7
        else:
            return "SAFE", min(0.95, total_score / 100)
    
    def _collect_risk_factors(self, sender: SenderAnalysis, content: ContentAnalysis,
                             links: LinkAnalysis, auth: AuthenticationAnalysis,
                             attachments: AttachmentAnalysis) -> List[str]:
        """Collect all risk factors from analyses"""
        risk_factors = []
        risk_factors.extend(sender.indicators)
        risk_factors.extend(content.indicators)
        risk_factors.extend(links.indicators)
        risk_factors.extend(auth.indicators)
        risk_factors.extend(attachments.indicators)
        return risk_factors
    
    # ═══════════════════════════════════════════════════════════════
    # ASYNC THREAT INTELLIGENCE ENHANCEMENT METHODS
    # ═══════════════════════════════════════════════════════════════
    
    async def enhance_with_threat_intel(
        self, 
        result: ComprehensivePhishingAnalysis
    ) -> ComprehensivePhishingAnalysis:
        """
        Enhance analysis results with external threat intelligence.
        
        - Uses VirusTotal for URL scanning
        - Uses AbuseIPDB for IP reputation
        
        Modifies result in-place and returns it.
        """
        import asyncio
        
        # Run enhancements in parallel
        await asyncio.gather(
            self._enhance_links_with_virustotal(result),
            self._enhance_sender_with_abuseipdb(result),
            return_exceptions=True
        )
        
        # Recalculate verdict if enhancements found threats
        self._recalculate_verdict_if_needed(result)
        
        return result
    
    async def _enhance_links_with_virustotal(
        self, 
        result: ComprehensivePhishingAnalysis
    ) -> None:
        """Scan suspicious links with VirusTotal."""
        try:
            from app.services.virustotal import create_virustotal_client
            
            vt = create_virustotal_client()
            if not vt.api_key:
                return
            
            # Get links to scan (prioritize suspicious ones)
            links_to_scan = []
            for link_info in result.links.link_details[:5]:
                url = link_info.get('url', '')
                if url.startswith(('http://', 'https://')):
                    # Prioritize: HTTP, encoded, or redirect links
                    is_priority = (
                        link_info.get('protocol') == 'http' or
                        link_info.get('is_encoded', False) or
                        link_info.get('is_redirect', False)
                    )
                    links_to_scan.append((url, is_priority))
            
            # Sort by priority, scan up to 3
            links_to_scan.sort(key=lambda x: x[1], reverse=True)
            malicious_count = 0
            
            for url, _ in links_to_scan[:3]:
                try:
                    scan_result = await vt.scan(url)
                    verdict = scan_result.get('verdict', 'unknown')
                    
                    if verdict in ('malicious', 'suspicious'):
                        malicious_count += 1
                        result.links.indicators.append(
                            f"🛡️ VirusTotal: {url[:40]}... flagged as {verdict}"
                        )
                        
                        # Update link score
                        result.links.overall_score = max(0, result.links.overall_score - 30)
                        
                except Exception as e:
                    pass  # Continue with other links
            
            if malicious_count > 0:
                result.risk_factors.append(
                    f"VirusTotal detected {malicious_count} malicious/suspicious URL(s)"
                )
                
        except ImportError:
            pass  # VirusTotal not available
        except Exception as e:
            pass  # Don't fail analysis if VT fails
    
    async def _enhance_sender_with_abuseipdb(
        self, 
        result: ComprehensivePhishingAnalysis
    ) -> None:
        """Check sender IP reputation with AbuseIPDB."""
        try:
            from app.services.abuseipdb import AbuseIPDBClient
            
            abuseipdb = AbuseIPDBClient()
            if not abuseipdb.api_key:
                return
            
            sender_ip = result.sender.sender_ip
            if not sender_ip:
                return
            
            # Check IP reputation
            try:
                check_result = await abuseipdb.analyze(
                    sender_ip, 
                    analysis_type=None  # Will use IP_REPUTATION
                )
                
                if check_result.threat_score > 0.5:
                    result.sender.indicators.append(
                        f"🌐 AbuseIPDB: Sender IP {sender_ip} has abuse score {check_result.threat_score:.0%}"
                    )
                    result.sender.score = max(0, result.sender.score - 25)
                    result.risk_factors.append(
                        f"Sender IP flagged by AbuseIPDB (score: {check_result.threat_score:.0%})"
                    )
                    
            except Exception as e:
                pass  # Continue analysis if check fails
                
        except ImportError:
            pass  # AbuseIPDB not available
        except Exception as e:
            pass  # Don't fail analysis if AIPDB fails
    
    def _recalculate_verdict_if_needed(
        self, 
        result: ComprehensivePhishingAnalysis
    ) -> None:
        """Recalculate verdict if threat intel found new threats."""
        
        # Check if we have new high-severity indicators
        vt_threats = sum(1 for r in result.risk_factors if 'VirusTotal' in r)
        abuseipdb_threats = sum(1 for r in result.risk_factors if 'AbuseIPDB' in r)
        
        if vt_threats > 0 or abuseipdb_threats > 0:
            # Recalculate total score
            new_total_score = self._calculate_total_score(
                result.sender.score,
                result.content.score,
                result.links.overall_score,
                result.authentication.overall_score,
                result.attachments.score
            )
            result.total_score = new_total_score
            
            # Upgrade verdict if needed
            if vt_threats > 0 and result.final_verdict == "SAFE":
                result.final_verdict = "SUSPICIOUS"
                result.confidence = max(result.confidence, 0.85)
            
            if vt_threats >= 2 or (vt_threats > 0 and abuseipdb_threats > 0):
                result.final_verdict = "PHISHING"
                result.confidence = max(result.confidence, 0.9)
