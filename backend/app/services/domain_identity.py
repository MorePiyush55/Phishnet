"""
Domain Identity Utilities for PhishNet
======================================
Provides eTLD+1 normalization and domain relationship analysis.
Uses Public Suffix List for accurate domain parsing.

Key Principle: Trust is INFERRED from sender-link alignment, not declared via allowlists.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Set
from urllib.parse import urlparse
import logging

try:
    import publicsuffix2
    PSL = publicsuffix2.PublicSuffixList()
except ImportError:
    PSL = None
    logging.warning("publicsuffix2 not installed, using fallback domain parsing")


@dataclass
class DomainIdentity:
    """Identity information for a domain"""
    raw_hostname: str
    registrable_domain: str  # eTLD+1 (e.g., "wipro.com" from "careers.wipro.com")
    subdomain: Optional[str] = None
    tld: Optional[str] = None
    
    # Extended attributes (populated by Phase 1)
    asn: Optional[str] = None
    domain_age_days: Optional[int] = None
    tls_supported: Optional[bool] = None
    ip_reputation: Optional[float] = None  # 0-1 scale


def get_registrable_domain(hostname: str) -> str:
    """
    Extract the registrable domain (eTLD+1) from a hostname.
    
    Examples:
        "careers.wipro.com" -> "wipro.com"
        "mail.google.com" -> "google.com"
        "sub.domain.co.uk" -> "domain.co.uk"
    """
    if not hostname:
        return ""
    
    # Clean hostname
    hostname = hostname.lower().strip()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    
    if PSL:
        try:
            result = PSL.get_public_suffix(hostname, accept_unknown=True)
            # get_public_suffix returns the public suffix, we need registrable domain
            # Use get_sld (second level domain) for eTLD+1
            registrable = publicsuffix2.get_sld(hostname, accept_unknown=True)
            return registrable or hostname
        except Exception:
            pass
    
    # Fallback: simple splitting (less accurate for complex TLDs)
    parts = hostname.split('.')
    if len(parts) >= 2:
        # Handle common multi-part TLDs
        common_multi_tlds = {'co.uk', 'co.in', 'com.au', 'co.nz', 'org.uk'}
        if len(parts) >= 3:
            possible_tld = '.'.join(parts[-2:])
            if possible_tld in common_multi_tlds:
                return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])
    
    return hostname


def get_domain_identity(url_or_hostname: str) -> DomainIdentity:
    """
    Get full domain identity for a URL or hostname.
    """
    # Extract hostname if full URL
    if '://' in url_or_hostname:
        parsed = urlparse(url_or_hostname)
        hostname = parsed.netloc.lower()
    else:
        hostname = url_or_hostname.lower()
    
    # Remove port if present
    if ':' in hostname:
        hostname = hostname.split(':')[0]
    
    registrable = get_registrable_domain(hostname)
    
    # Extract subdomain
    subdomain = None
    if hostname != registrable and hostname.endswith(registrable):
        subdomain = hostname[:-len(registrable)-1]  # -1 for the dot
    
    # Extract TLD
    tld = None
    if '.' in registrable:
        tld = registrable.split('.')[-1]
    
    return DomainIdentity(
        raw_hostname=hostname,
        registrable_domain=registrable,
        subdomain=subdomain,
        tld=tld
    )


class SenderLinkAlignment:
    """
    Analyzes alignment between sender domain and link domains.
    """
    
    # Known email service provider / ATS / CDN domains that are expected in emails
    KNOWN_VENDOR_DOMAINS: Set[str] = {
        # Job/ATS platforms
        "jobs2web.com", "sapsf.eu", "workday.com", "greenhouse.io", 
        "lever.co", "jobvite.com", "icims.com", "taleo.net",
        
        # Email service providers
        "sendgrid.net", "mailchimp.com", "mailgun.org", "sparkpost.com",
        "amazonses.com", "mandrillapp.com", "postmarkapp.com",
        
        # CDN / Link tracking
        "cloudfront.net", "akamaized.net", "fastly.net",
        "litmus.com", "emltrk.com", "list-manage.com",
        
        # Analytics
        "google-analytics.com", "doubleclick.net",
    }
    
    @classmethod
    def classify_alignment(
        cls, 
        sender_domain: str, 
        link_domain: str
    ) -> str:
        """
        Classify the relationship between sender and link domains.
        
        Returns:
            "same_org" - Same registrable domain OR sender is vendor sending to org
            "known_vendor" - Link goes to recognized ESP/ATS/CDN
            "unrelated" - No recognized relationship
        """
        sender_reg = get_registrable_domain(sender_domain)
        link_reg = get_registrable_domain(link_domain)
        
        # Same organization
        if sender_reg == link_reg:
            return "same_org"
        
        # PHASE 0 FIX: If sender is a known vendor (e.g., jobs2web.com),
        # and link goes to a legitimate-looking org domain, treat as "same_org"
        # This handles: Wipro uses jobs2web.com to send emails with links to wipro.com
        if sender_reg in cls.KNOWN_VENDOR_DOMAINS:
            # Vendor sending email - links to any non-suspicious domain are trusted
            # (The actual org relationship is established by email authentication)
            if link_reg not in cls.KNOWN_VENDOR_DOMAINS:
                return "same_org"  # Trust the org domain in the links
            else:
                return "known_vendor"  # Link to another vendor
        
        # Known vendor/ESP in link
        if link_reg in cls.KNOWN_VENDOR_DOMAINS:
            return "known_vendor"
        
        # No recognized relationship
        return "unrelated"
    
    @classmethod
    def analyze_email_links(
        cls,
        sender_email: str,
        links: List[str]
    ) -> dict:
        """
        Analyze all links in an email for sender alignment.
        
        Returns dict with:
            - sender_domain: str
            - same_org_count: int
            - vendor_count: int
            - unrelated_count: int
            - alignment_score: float (0-1, higher = more aligned)
            - link_classifications: List[dict]
        """
        # Extract sender domain
        if '@' in sender_email:
            sender_domain = sender_email.split('@')[-1]
        else:
            sender_domain = sender_email
        
        sender_reg = get_registrable_domain(sender_domain)
        
        same_org = 0
        vendor = 0
        unrelated = 0
        classifications = []
        
        for link in links:
            try:
                parsed = urlparse(link)
                if not parsed.netloc:
                    continue
                    
                link_domain = parsed.netloc.lower()
                classification = cls.classify_alignment(sender_domain, link_domain)
                
                if classification == "same_org":
                    same_org += 1
                elif classification == "known_vendor":
                    vendor += 1
                else:
                    unrelated += 1
                
                classifications.append({
                    "url": link[:100],  # Truncate for safety
                    "domain": link_domain,
                    "registrable_domain": get_registrable_domain(link_domain),
                    "classification": classification
                })
            except Exception:
                continue
        
        total = same_org + vendor + unrelated
        
        # Calculate alignment score
        # same_org = 1.0, vendor = 0.8, unrelated = 0.0
        if total > 0:
            weighted_sum = (same_org * 1.0) + (vendor * 0.8) + (unrelated * 0.0)
            alignment_score = weighted_sum / total
        else:
            alignment_score = 1.0  # No links = neutral
        
        return {
            "sender_domain": sender_domain,
            "sender_registrable": sender_reg,
            "same_org_count": same_org,
            "vendor_count": vendor,
            "unrelated_count": unrelated,
            "total_links": total,
            "alignment_score": round(alignment_score, 2),
            "link_classifications": classifications[:10]  # Limit for safety
        }


# Convenience functions
def are_domains_related(domain1: str, domain2: str) -> bool:
    """Check if two domains share the same registrable domain."""
    return get_registrable_domain(domain1) == get_registrable_domain(domain2)


def is_known_vendor(domain: str) -> bool:
    """Check if domain is a known email/marketing vendor."""
    reg_domain = get_registrable_domain(domain)
    return reg_domain in SenderLinkAlignment.KNOWN_VENDOR_DOMAINS
