"""
PII Sanitization and Data Minimization
Redacts sensitive information before sending to third-party services.
"""

import re
import hashlib
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs
from email.utils import parseaddr
import json

logger = logging.getLogger(__name__)

class PIISanitizer:
    """
    Sanitizes PII from content before sending to third-party services.
    Implements data minimization principles.
    """
    
    def __init__(self):
        # Regex patterns for PII detection
        self.patterns = {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone_us': re.compile(r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b'),
            'ssn': re.compile(r'\b(?!000|666|9\d{2})\d{3}[-.\s]?(?!00)\d{2}[-.\s]?(?!0000)\d{4}\b'),
            'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'account_number': re.compile(r'\b(?:account|acct)[\s#:]*([0-9]{6,20})\b', re.IGNORECASE),
            'routing_number': re.compile(r'\b[0-9]{9}\b'),  # US bank routing numbers
            'passport': re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'),
            'license_plate': re.compile(r'\b[A-Z0-9]{2,3}[-\s]?[A-Z0-9]{2,4}\b'),
            'api_key': re.compile(r'\b[A-Za-z0-9]{20,}\b'),  # Generic API keys
            'uuid': re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.IGNORECASE),
            'bitcoin_address': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'private_key': re.compile(r'-----BEGIN [A-Z\s]*PRIVATE KEY-----.*?-----END [A-Z\s]*PRIVATE KEY-----', re.DOTALL),
        }
        
        # Patterns for URLs that might contain sensitive data
        self.sensitive_url_params = {
            'auth', 'token', 'key', 'secret', 'password', 'pass', 'pwd',
            'session', 'sessionid', 'sid', 'cookie', 'api_key', 'apikey',
            'access_token', 'refresh_token', 'bearer', 'oauth_token'
        }
        
        # Common PII field names in forms/JSON
        self.pii_field_names = {
            'email', 'email_address', 'e_mail', 'mail',
            'phone', 'phone_number', 'telephone', 'mobile', 'cell',
            'ssn', 'social_security_number', 'social_security',
            'credit_card', 'creditcard', 'cc_number', 'card_number',
            'account_number', 'account', 'acct_number', 'acct',
            'password', 'passwd', 'pwd', 'passphrase',
            'first_name', 'last_name', 'full_name', 'name',
            'address', 'street', 'city', 'state', 'zip', 'postal_code',
            'dob', 'date_of_birth', 'birthday', 'birthdate'
        }
    
    def sanitize_for_third_party(self, 
                                content: str, 
                                service: str,
                                preserve_structure: bool = True) -> Dict[str, Any]:
        """
        Sanitize content for third-party service consumption.
        
        Args:
            content: Content to sanitize
            service: Target service (virustotal, gemini, urlvoid, etc.)
            preserve_structure: Whether to preserve original structure
            
        Returns:
            Dict with sanitized content and metadata
        """
        try:
            original_hash = hashlib.sha256(content.encode()).hexdigest()
            
            # Apply service-specific sanitization
            if service.lower() in ['virustotal', 'urlvoid', 'abuseipdb']:
                sanitized = self._sanitize_for_threat_intel(content)
            elif service.lower() in ['gemini', 'openai', 'anthropic']:
                sanitized = self._sanitize_for_llm(content)
            else:
                sanitized = self._sanitize_general(content)
            
            # Extract and hash any removed PII for audit
            pii_found = self._detect_pii_types(content)
            
            return {
                'sanitized_content': sanitized,
                'original_hash': original_hash,
                'sanitized_hash': hashlib.sha256(sanitized.encode()).hexdigest(),
                'pii_types_found': pii_found,
                'service': service,
                'redaction_count': len(pii_found),
                'preserve_structure': preserve_structure
            }
            
        except Exception as e:
            logger.error(f"Error sanitizing content for {service}: {e}")
            raise
    
    def _sanitize_for_threat_intel(self, content: str) -> str:
        """Sanitize content for threat intelligence services"""
        # For threat intel, we primarily need URLs and hashes
        # Remove all PII but preserve URLs and suspicious indicators
        
        sanitized = content
        
        # Replace emails with domain-only for threat analysis
        sanitized = re.sub(
            self.patterns['email'],
            lambda m: f"[EMAIL_REDACTED]@{m.group().split('@')[1]}",
            sanitized
        )
        
        # Replace phone numbers completely
        sanitized = re.sub(self.patterns['phone_us'], '[PHONE_REDACTED]', sanitized)
        
        # Replace SSNs completely
        sanitized = re.sub(self.patterns['ssn'], '[SSN_REDACTED]', sanitized)
        
        # Replace credit cards completely
        sanitized = re.sub(self.patterns['credit_card'], '[CREDITCARD_REDACTED]', sanitized)
        
        # Replace account numbers
        sanitized = re.sub(self.patterns['account_number'], r'account [ACCOUNT_REDACTED]', sanitized)
        
        # Keep IP addresses as they may be threat indicators
        # Keep URLs but sanitize sensitive parameters
        sanitized = self._sanitize_urls(sanitized)
        
        return sanitized
    
    def _sanitize_for_llm(self, content: str) -> str:
        """Sanitize content for LLM analysis"""
        # For LLM analysis, we want to preserve structure while removing PII
        
        sanitized = content
        
        # Replace emails with placeholder that preserves structure
        sanitized = re.sub(
            self.patterns['email'],
            '[EMAIL_ADDRESS]',
            sanitized
        )
        
        # Replace phone numbers with structure-preserving placeholder
        sanitized = re.sub(
            self.patterns['phone_us'],
            '[PHONE_NUMBER]',
            sanitized
        )
        
        # Replace SSNs
        sanitized = re.sub(self.patterns['ssn'], '[SSN]', sanitized)
        
        # Replace credit cards
        sanitized = re.sub(self.patterns['credit_card'], '[CREDIT_CARD]', sanitized)
        
        # Replace account numbers
        sanitized = re.sub(self.patterns['account_number'], r'account [ACCOUNT_NUMBER]', sanitized)
        
        # Replace IP addresses (might be internal IPs)
        sanitized = re.sub(self.patterns['ip_address'], '[IP_ADDRESS]', sanitized)
        
        # Sanitize URLs while preserving domain structure for analysis
        sanitized = self._sanitize_urls_for_llm(sanitized)
        
        # Replace API keys and secrets
        sanitized = re.sub(self.patterns['private_key'], '[PRIVATE_KEY_REDACTED]', sanitized)
        
        return sanitized
    
    def _sanitize_general(self, content: str) -> str:
        """General sanitization for unknown services"""
        # Conservative approach - redact all PII
        
        sanitized = content
        
        for pattern_name, pattern in self.patterns.items():
            placeholder = f'[{pattern_name.upper()}_REDACTED]'
            sanitized = re.sub(pattern, placeholder, sanitized)
        
        return sanitized
    
    def _sanitize_urls(self, content: str) -> str:
        """Sanitize URLs by removing sensitive parameters"""
        import re
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        def sanitize_url(match):
            url = match.group(0)
            try:
                parsed = urlparse(url)
                
                if parsed.query:
                    # Parse query parameters
                    params = parse_qs(parsed.query)
                    
                    # Remove sensitive parameters
                    clean_params = {}
                    for key, values in params.items():
                        if key.lower() not in self.sensitive_url_params:
                            clean_params[key] = values
                        else:
                            clean_params[key] = ['[REDACTED]']
                    
                    # Rebuild URL
                    clean_query = urlencode(clean_params, doseq=True)
                    clean_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, clean_query, parsed.fragment
                    ))
                    return clean_url
                
                return url
                
            except Exception:
                # If URL parsing fails, return original
                return url
        
        # Find and sanitize URLs
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        return url_pattern.sub(sanitize_url, content)
    
    def _sanitize_urls_for_llm(self, content: str) -> str:
        """Sanitize URLs for LLM while preserving structure"""
        import re
        from urllib.parse import urlparse
        
        def sanitize_url_llm(match):
            url = match.group(0)
            try:
                parsed = urlparse(url)
                
                # Preserve domain and path structure for analysis
                # But remove sensitive query parameters
                if parsed.query and any(param in parsed.query.lower() 
                                      for param in self.sensitive_url_params):
                    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?[PARAMS_REDACTED]"
                    return clean_url
                
                return url
                
            except Exception:
                return url
        
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        return url_pattern.sub(sanitize_url_llm, content)
    
    def _detect_pii_types(self, content: str) -> List[str]:
        """Detect types of PII present in content"""
        found_types = []
        
        for pii_type, pattern in self.patterns.items():
            if pattern.search(content):
                found_types.append(pii_type)
        
        return found_types
    
    def create_content_fingerprint(self, content: str) -> str:
        """Create content fingerprint for deduplication"""
        # Normalize content and create fingerprint
        normalized = re.sub(r'\s+', ' ', content.lower().strip())
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]
    
    def extract_urls_only(self, content: str) -> List[str]:
        """Extract only URLs from content for threat analysis"""
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        urls = url_pattern.findall(content)
        
        # Sanitize each URL
        sanitized_urls = []
        for url in urls:
            try:
                parsed = urlparse(url)
                # Only keep essential parts for threat analysis
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                sanitized_urls.append(clean_url)
            except Exception:
                continue
        
        return list(set(sanitized_urls))  # Remove duplicates
    
    def extract_domains_only(self, content: str) -> List[str]:
        """Extract only domains for threat intelligence"""
        url_pattern = re.compile(r'https?://([^\s<>"{}|\\^`\[\]/]+)')
        domains = url_pattern.findall(content)
        
        # Also extract domains from email addresses
        email_domains = []
        for match in self.patterns['email'].finditer(content):
            email = match.group()
            if '@' in email:
                domain = email.split('@')[1]
                email_domains.append(domain)
        
        all_domains = domains + email_domains
        return list(set(all_domains))  # Remove duplicates
    
    def sanitize_email_metadata(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize email metadata for storage/analysis.
        Implements data minimization principles.
        """
        try:
            sanitized = {}
            
            # Keep essential metadata only
            if 'subject' in email_data:
                # Sanitize subject but keep structure
                sanitized['subject'] = self._sanitize_for_llm(email_data['subject'])
            
            if 'sender' in email_data:
                # Keep domain, hash the local part
                sender = email_data['sender']
                if '@' in sender:
                    local, domain = sender.split('@', 1)
                    local_hash = hashlib.sha256(local.encode()).hexdigest()[:8]
                    sanitized['sender'] = f"{local_hash}@{domain}"
                else:
                    sanitized['sender'] = hashlib.sha256(sender.encode()).hexdigest()[:8]
            
            if 'timestamp' in email_data:
                sanitized['timestamp'] = email_data['timestamp']
            
            if 'message_id' in email_data:
                # Hash message ID for privacy
                sanitized['message_id_hash'] = hashlib.sha256(
                    email_data['message_id'].encode()
                ).hexdigest()[:16]
            
            # Extract and sanitize URLs
            if 'body' in email_data:
                urls = self.extract_urls_only(email_data['body'])
                sanitized['extracted_urls'] = urls
                
                # Create content fingerprint without PII
                content_hash = self.create_content_fingerprint(
                    self._sanitize_general(email_data['body'])
                )
                sanitized['content_fingerprint'] = content_hash
            
            # Add sanitization metadata
            sanitized['sanitized_at'] = 'now'  # Use proper timestamp in real implementation
            sanitized['sanitization_version'] = '1.0'
            
            return sanitized
            
        except Exception as e:
            logger.error(f"Error sanitizing email metadata: {e}")
            raise
    
    def validate_sanitization(self, original: str, sanitized: str) -> Dict[str, Any]:
        """Validate that sanitization was effective"""
        try:
            # Check for remaining PII
            remaining_pii = self._detect_pii_types(sanitized)
            
            # Calculate redaction effectiveness
            original_pii = self._detect_pii_types(original)
            
            return {
                'effective': len(remaining_pii) == 0,
                'original_pii_types': original_pii,
                'remaining_pii_types': remaining_pii,
                'redaction_rate': 1.0 - (len(remaining_pii) / max(len(original_pii), 1)),
                'content_preserved': len(sanitized) / max(len(original), 1)
            }
            
        except Exception as e:
            logger.error(f"Error validating sanitization: {e}")
            return {'effective': False, 'error': str(e)}

# Global sanitizer instance
_pii_sanitizer = None

def get_pii_sanitizer() -> PIISanitizer:
    """Get global PII sanitizer instance"""
    global _pii_sanitizer
    if _pii_sanitizer is None:
        _pii_sanitizer = PIISanitizer()
    return _pii_sanitizer

def sanitize_for_service(content: str, service: str) -> Dict[str, Any]:
    """Convenience function to sanitize content for a specific service"""
    sanitizer = get_pii_sanitizer()
    return sanitizer.sanitize_for_third_party(content, service)

def validate_no_pii_leaked(content: str) -> bool:
    """Validate that content contains no detectable PII"""
    sanitizer = get_pii_sanitizer()
    pii_types = sanitizer._detect_pii_types(content)
    return len(pii_types) == 0
