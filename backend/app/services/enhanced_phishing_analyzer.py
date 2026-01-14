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
        '.biz', '.top', '.xyz', '.club', '.work', '.click', '.link'
    ]
    
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
        
        # Calculate total score (weighted average)
        total_score = self._calculate_total_score(
            sender_analysis.score,
            content_analysis.score,
            link_analysis.overall_score,
            auth_analysis.overall_score,
            attachment_analysis.score
        )
        
        # Determine final verdict
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
        Checks: display name vs email similarity, IP address extraction
        """
        # Extract sender info
        from_header = msg.get('From', '')
        display_name, email_address = email.utils.parseaddr(from_header)
        
        # Extract sender IP from Received headers
        sender_ip = self._extract_sender_ip(msg)
        
        # Calculate name-email similarity
        similarity, description = self._calculate_name_email_similarity(
            display_name, email_address
        )
        
        # Calculate score (0-100)
        score = int(similarity * 100)
        
        # Identify indicators
        indicators = []
        if similarity < 0.3:
            indicators.append("Low similarity between display name and email")
        if self._check_suspicious_display_name(display_name):
            indicators.append("Suspicious display name detected")
            score = max(0, score - 20)
        if self._check_free_email_domain(email_address):
            indicators.append("Free email domain used")
            score = max(0, score - 10)
        
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
        Checks: encoding, HTTP/HTTPS usage, redirection, duplication
        """
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
        
        for link in links:
            parsed = urlparse(link)
            
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
            domain = parsed.netloc.lower()
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    suspicious_tlds.append(domain)
                    break
            
            link_details.append({
                'url': link,
                'protocol': parsed.scheme,
                'domain': parsed.netloc,
                'path': parsed.path,
                'is_encoded': link != unquote(link),
                'is_redirect': 'redirect' in link.lower()
            })
        
        # Calculate sub-scores
        https_score = 100 if total_links == 0 else int((https_links / total_links) * 100)
        encoding_score = 100 if total_links == 0 else int(((total_links - encoded_links) / total_links) * 100)
        redirect_score = 100 if total_links == 0 else int(((total_links - redirect_links) / total_links) * 100)
        duplication_score = 100 if total_links <= 1 else int(((total_links - duplicate_links) / total_links) * 100)
        
        # Overall link score (average of sub-scores)
        overall_score = int((https_score + encoding_score + redirect_score + duplication_score) / 4)
        
        # Identify indicators
        indicators = []
        if http_links > 0:
            indicators.append(f"{http_links} HTTP (non-secure) links found")
        if encoded_links > 0:
            indicators.append(f"{encoded_links} encoded links detected")
        if redirect_links > 0:
            indicators.append(f"{redirect_links} redirect links found")
        if len(suspicious_tlds) > 0:
            indicators.append(f"Suspicious TLDs detected: {', '.join(set(suspicious_tlds))}")
        if duplicate_links > 2:
            indicators.append(f"{duplicate_links} duplicate links")
        
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
            indicators=indicators
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
    
    def _check_suspicious_display_name(self, display_name: str) -> bool:
        """Check if display name contains suspicious patterns"""
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
        return any(re.search(pattern, name_lower) for pattern in suspicious_patterns)
    
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
    
    def _calculate_total_score(self, sender_score: int, content_score: int, 
                               link_score: int, auth_score: int, attachment_score: int) -> int:
        """Calculate weighted total score"""
        # Weighted average (authentication is most important)
        weights = {
            'sender': 0.15,
            'content': 0.20,
            'links': 0.20,
            'auth': 0.30,
            'attachments': 0.15
        }
        
        total = (
            sender_score * weights['sender'] +
            content_score * weights['content'] +
            link_score * weights['links'] +
            auth_score * weights['auth'] +
            attachment_score * weights['attachments']
        )
        
        return int(total)
    
    def _determine_verdict(self, total_score: int, sender: SenderAnalysis,
                          content: ContentAnalysis, links: LinkAnalysis,
                          auth: AuthenticationAnalysis, attachments: AttachmentAnalysis) -> Tuple[str, float]:
        """Determine final verdict and confidence level"""
        # Critical red flags
        critical_flags = 0
        if len(attachments.dangerous_extensions) > 0:
            critical_flags += 1
        if auth.spf_result == 'fail':
            critical_flags += 1
        if auth.dkim_result == 'fail':
            critical_flags += 1
        if links.http_links > 0 and links.https_links == 0:
            critical_flags += 1
        
        # Determine verdict
        if critical_flags >= 2 or total_score < 30:
            return "PHISHING", 0.9
        elif total_score < 50 or critical_flags >= 1:
            return "SUSPICIOUS", 0.7
        elif total_score < 70:
            return "SUSPICIOUS", 0.5
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
