"""
Privacy and security layer for third-party API integrations.

This module provides PII sanitization, data redaction, audit logging, and privacy-preserving
transformations before sending data to external services. Ensures GDPR/privacy compliance.
"""

import hashlib
import re
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class PIIType(Enum):
    """Types of PII that can be detected and redacted."""
    EMAIL_ADDRESS = "email_address"
    PHONE_NUMBER = "phone_number"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    NAME = "name"
    ADDRESS = "address"
    DATE_OF_BIRTH = "date_of_birth"
    ACCOUNT_NUMBER = "account_number"
    CUSTOM_IDENTIFIER = "custom_identifier"


class RedactionMethod(Enum):
    """Methods for redacting PII."""
    MASK = "mask"              # Replace with asterisks
    HASH = "hash"              # Replace with hash
    REMOVE = "remove"          # Remove entirely
    TOKENIZE = "tokenize"      # Replace with token
    PARTIAL = "partial"        # Show partial (e.g., first/last chars)


@dataclass
class PIIDetection:
    """Details of detected PII."""
    pii_type: PIIType
    original_value: str
    redacted_value: str
    position: Tuple[int, int]  # Start and end positions
    confidence: float
    method: RedactionMethod


@dataclass
class SanitizationResult:
    """Result of PII sanitization process."""
    sanitized_content: str
    detected_pii: List[PIIDetection] = field(default_factory=list)
    sanitization_applied: bool = False
    original_hash: Optional[str] = None
    sanitized_hash: Optional[str] = None
    
    @property
    def pii_types_found(self) -> Set[PIIType]:
        """Get set of PII types found."""
        return {detection.pii_type for detection in self.detected_pii}
    
    @property
    def total_pii_items(self) -> int:
        """Get total number of PII items detected."""
        return len(self.detected_pii)


class PIISanitizer:
    """Privacy-preserving sanitizer for email content and other data."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.sanitizer")
        
        # PII detection patterns
        self.patterns = {
            PIIType.EMAIL_ADDRESS: re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ),
            PIIType.PHONE_NUMBER: re.compile(
                r'(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})'
            ),
            PIIType.SSN: re.compile(
                r'\b(?!000|666|9\d{2})\d{3}[-.]?(?!00)\d{2}[-.]?(?!0000)\d{4}\b'
            ),
            PIIType.CREDIT_CARD: re.compile(
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
            ),
            PIIType.IP_ADDRESS: re.compile(
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ),
            PIIType.ACCOUNT_NUMBER: re.compile(
                r'\b[Aa]ccount[:\s]*([A-Za-z0-9]{8,20})\b'
            ),
        }
        
        # Common name patterns (basic detection)
        self.name_patterns = [
            re.compile(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b'),  # First Last
            re.compile(r'\b[A-Z]\. [A-Z][a-z]+\b'),      # F. Last
        ]
        
        # Default redaction methods by PII type
        self.default_redaction_methods = {
            PIIType.EMAIL_ADDRESS: RedactionMethod.PARTIAL,
            PIIType.PHONE_NUMBER: RedactionMethod.PARTIAL,
            PIIType.SSN: RedactionMethod.MASK,
            PIIType.CREDIT_CARD: RedactionMethod.MASK,
            PIIType.IP_ADDRESS: RedactionMethod.HASH,
            PIIType.NAME: RedactionMethod.TOKENIZE,
            PIIType.ACCOUNT_NUMBER: RedactionMethod.PARTIAL,
        }
        
        # Token mappings for consistent redaction
        self.token_mappings = {}
        self.token_counter = 0
    
    def sanitize_content(self, content: str, preserve_structure: bool = True) -> SanitizationResult:
        """Sanitize content by detecting and redacting PII."""
        if not content or not content.strip():
            return SanitizationResult(
                sanitized_content=content,
                sanitization_applied=False
            )
        
        original_hash = hashlib.sha256(content.encode()).hexdigest()
        detected_pii = []
        sanitized_content = content
        
        # Process each PII type
        for pii_type, pattern in self.patterns.items():
            matches = list(pattern.finditer(sanitized_content))
            
            for match in reversed(matches):  # Process in reverse to maintain positions
                original_value = match.group()
                redaction_method = self.default_redaction_methods.get(
                    pii_type, RedactionMethod.MASK
                )
                
                redacted_value = self._redact_value(
                    original_value, pii_type, redaction_method
                )
                
                # Replace in content
                start, end = match.span()
                sanitized_content = (
                    sanitized_content[:start] + 
                    redacted_value + 
                    sanitized_content[end:]
                )
                
                detected_pii.append(PIIDetection(
                    pii_type=pii_type,
                    original_value=original_value,
                    redacted_value=redacted_value,
                    position=(start, end),
                    confidence=0.9,  # High confidence for regex matches
                    method=redaction_method
                ))
        
        # Detect names (lower confidence)
        if preserve_structure:
            for pattern in self.name_patterns:
                matches = list(pattern.finditer(sanitized_content))
                
                for match in reversed(matches):
                    original_value = match.group()
                    
                    # Skip if already processed as other PII
                    if any(d.original_value == original_value for d in detected_pii):
                        continue
                    
                    redacted_value = self._redact_value(
                        original_value, PIIType.NAME, RedactionMethod.TOKENIZE
                    )
                    
                    start, end = match.span()
                    sanitized_content = (
                        sanitized_content[:start] + 
                        redacted_value + 
                        sanitized_content[end:]
                    )
                    
                    detected_pii.append(PIIDetection(
                        pii_type=PIIType.NAME,
                        original_value=original_value,
                        redacted_value=redacted_value,
                        position=(start, end),
                        confidence=0.6,  # Lower confidence for name detection
                        method=RedactionMethod.TOKENIZE
                    ))
        
        sanitized_hash = hashlib.sha256(sanitized_content.encode()).hexdigest()
        
        return SanitizationResult(
            sanitized_content=sanitized_content,
            detected_pii=detected_pii,
            sanitization_applied=len(detected_pii) > 0,
            original_hash=original_hash,
            sanitized_hash=sanitized_hash
        )
    
    def _redact_value(self, value: str, pii_type: PIIType, method: RedactionMethod) -> str:
        """Apply redaction method to a value."""
        if method == RedactionMethod.MASK:
            if pii_type == PIIType.EMAIL_ADDRESS:
                # Mask email: user@domain -> u***@domain
                parts = value.split('@')
                if len(parts) == 2:
                    return f"{parts[0][0]}***@{parts[1]}"
                return "***@***.***"
            elif pii_type == PIIType.PHONE_NUMBER:
                # Mask phone: (123) 456-7890 -> (***) ***-7890
                return re.sub(r'\d', '*', value[:-4]) + value[-4:]
            else:
                # Generic masking
                return '*' * len(value)
        
        elif method == RedactionMethod.HASH:
            # Create deterministic hash
            salt = self.config.get('hash_salt', 'phishnet_pii_salt')
            hash_input = f"{salt}:{value}:{pii_type.value}"
            hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
            return f"[HASH_{hash_value.upper()}]"
        
        elif method == RedactionMethod.REMOVE:
            return ""
        
        elif method == RedactionMethod.TOKENIZE:
            # Create consistent token for same value
            if value not in self.token_mappings:
                self.token_counter += 1
                self.token_mappings[value] = f"[{pii_type.value.upper()}_{self.token_counter}]"
            return self.token_mappings[value]
        
        elif method == RedactionMethod.PARTIAL:
            if len(value) <= 4:
                return '*' * len(value)
            elif pii_type == PIIType.EMAIL_ADDRESS:
                # Show first char and domain: user@domain -> u***@domain
                parts = value.split('@')
                if len(parts) == 2:
                    return f"{parts[0][0]}***@{parts[1]}"
                return value
            else:
                # Show first and last 2 chars
                return f"{value[:2]}***{value[-2:]}"
        
        return value  # Fallback
    
    def sanitize_url(self, url: str) -> SanitizationResult:
        """Sanitize URL while preserving structure for analysis."""
        # URLs might contain PII in query parameters
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        try:
            parsed = urlparse(url)
            
            # Sanitize query parameters
            if parsed.query:
                query_params = parse_qs(parsed.query)
                sanitized_params = {}
                detected_pii = []
                
                for key, values in query_params.items():
                    sanitized_values = []
                    for value in values:
                        sanitization = self.sanitize_content(value, preserve_structure=False)
                        sanitized_values.append(sanitization.sanitized_content)
                        detected_pii.extend(sanitization.detected_pii)
                    
                    sanitized_params[key] = sanitized_values
                
                # Reconstruct URL
                sanitized_query = urlencode(sanitized_params, doseq=True)
                sanitized_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, sanitized_query, parsed.fragment
                ))
                
                return SanitizationResult(
                    sanitized_content=sanitized_url,
                    detected_pii=detected_pii,
                    sanitization_applied=len(detected_pii) > 0,
                    original_hash=hashlib.sha256(url.encode()).hexdigest(),
                    sanitized_hash=hashlib.sha256(sanitized_url.encode()).hexdigest()
                )
            
            else:
                # No query parameters, return as-is
                return SanitizationResult(
                    sanitized_content=url,
                    sanitization_applied=False,
                    original_hash=hashlib.sha256(url.encode()).hexdigest(),
                    sanitized_hash=hashlib.sha256(url.encode()).hexdigest()
                )
                
        except Exception as e:
            self.logger.error(f"Error sanitizing URL {url}: {str(e)}")
            # Fallback to content-based sanitization
            return self.sanitize_content(url)
    
    def create_audit_log(self, operation: str, service: str, resource: str, 
                        sanitization: SanitizationResult) -> Dict[str, Any]:
        """Create audit log entry for external API call."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation,
            "service": service,
            "resource_hash": sanitization.original_hash,
            "sanitized_hash": sanitization.sanitized_hash,
            "pii_detected": sanitization.sanitization_applied,
            "pii_types": [pii_type.value for pii_type in sanitization.pii_types_found],
            "pii_count": sanitization.total_pii_items,
            "data_sent_to_external_service": sanitization.sanitized_content[:100] + "..." if len(sanitization.sanitized_content) > 100 else sanitization.sanitized_content,
            "sanitization_methods": [detection.method.value for detection in sanitization.detected_pii]
        }


class PrivacyAwareAPIWrapper:
    """Wrapper that adds privacy protection to API clients."""
    
    def __init__(self, api_client, service_name: str, sanitizer: Optional[PIISanitizer] = None):
        self.api_client = api_client
        self.service_name = service_name
        self.sanitizer = sanitizer or PIISanitizer()
        self.logger = logging.getLogger(f"{__name__}.privacy.{service_name}")
        self.audit_logs = []
    
    async def safe_analyze_url(self, url: str) -> Tuple[Any, Dict[str, Any]]:
        """Analyze URL with privacy protection."""
        # Sanitize URL
        sanitization = self.sanitizer.sanitize_url(url)
        
        # Create audit log
        audit_log = self.sanitizer.create_audit_log(
            operation="analyze_url",
            service=self.service_name,
            resource=url,
            sanitization=sanitization
        )
        self.audit_logs.append(audit_log)
        
        # Log what we're sending
        if sanitization.sanitization_applied:
            self.logger.info(
                f"Sending sanitized URL to {self.service_name}. "
                f"PII types redacted: {list(sanitization.pii_types_found)}"
            )
        
        # Call original API with sanitized data
        result = await self.api_client.analyze_url(sanitization.sanitized_content)
        
        return result, audit_log
    
    async def safe_analyze_content(self, content: str) -> Tuple[Any, Dict[str, Any]]:
        """Analyze content with privacy protection."""
        # Sanitize content
        sanitization = self.sanitizer.sanitize_content(content, preserve_structure=True)
        
        # Create audit log
        audit_log = self.sanitizer.create_audit_log(
            operation="analyze_content",
            service=self.service_name,
            resource=content,
            sanitization=sanitization
        )
        self.audit_logs.append(audit_log)
        
        # Log what we're sending
        if sanitization.sanitization_applied:
            self.logger.info(
                f"Sending sanitized content to {self.service_name}. "
                f"PII types redacted: {list(sanitization.pii_types_found)}"
            )
        
        # Call original API with sanitized data
        if hasattr(self.api_client, 'analyze_content'):
            result = await self.api_client.analyze_content(sanitization.sanitized_content)
        else:
            # Fallback for clients without content analysis
            result = {"error": "Content analysis not supported by this service"}
        
        return result, audit_log
    
    async def safe_analyze_domain(self, domain: str) -> Tuple[Any, Dict[str, Any]]:
        """Analyze domain (typically no PII, but log for audit)."""
        # Domains usually don't contain PII, but create audit log
        sanitization = SanitizationResult(
            sanitized_content=domain,
            sanitization_applied=False,
            original_hash=hashlib.sha256(domain.encode()).hexdigest(),
            sanitized_hash=hashlib.sha256(domain.encode()).hexdigest()
        )
        
        audit_log = self.sanitizer.create_audit_log(
            operation="analyze_domain",
            service=self.service_name,
            resource=domain,
            sanitization=sanitization
        )
        self.audit_logs.append(audit_log)
        
        result = await self.api_client.analyze_domain(domain)
        return result, audit_log
    
    async def safe_analyze_ip(self, ip_address: str) -> Tuple[Any, Dict[str, Any]]:
        """Analyze IP address (log for audit, IP itself might be considered PII)."""
        # IP addresses can be considered PII in some jurisdictions
        sanitization = SanitizationResult(
            sanitized_content=ip_address,
            detected_pii=[PIIDetection(
                pii_type=PIIType.IP_ADDRESS,
                original_value=ip_address,
                redacted_value=ip_address,  # We need the actual IP for reputation check
                position=(0, len(ip_address)),
                confidence=1.0,
                method=RedactionMethod.PARTIAL  # But log that we're exposing it
            )],
            sanitization_applied=False,  # We're not actually redacting it
            original_hash=hashlib.sha256(ip_address.encode()).hexdigest(),
            sanitized_hash=hashlib.sha256(ip_address.encode()).hexdigest()
        )
        
        audit_log = self.sanitizer.create_audit_log(
            operation="analyze_ip",
            service=self.service_name,
            resource=ip_address,
            sanitization=sanitization
        )
        self.audit_logs.append(audit_log)
        
        self.logger.info(f"Sending IP address to {self.service_name} (IP is logged as potential PII)")
        
        result = await self.api_client.analyze_ip(ip_address)
        return result, audit_log
    
    def get_audit_logs(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get audit logs for this session."""
        if limit:
            return self.audit_logs[-limit:]
        return self.audit_logs.copy()
    
    def clear_audit_logs(self):
        """Clear audit logs (call periodically to prevent memory buildup)."""
        self.audit_logs.clear()
    
    def get_privacy_summary(self) -> Dict[str, Any]:
        """Get summary of privacy protection activities."""
        if not self.audit_logs:
            return {"no_activity": True}
        
        pii_types_seen = set()
        operations_with_pii = 0
        total_operations = len(self.audit_logs)
        
        for log in self.audit_logs:
            if log.get("pii_detected"):
                operations_with_pii += 1
                pii_types_seen.update(log.get("pii_types", []))
        
        return {
            "service": self.service_name,
            "total_operations": total_operations,
            "operations_with_pii": operations_with_pii,
            "pii_protection_rate": (operations_with_pii / total_operations * 100) if total_operations > 0 else 0,
            "pii_types_encountered": list(pii_types_seen),
            "last_operation": self.audit_logs[-1]["timestamp"] if self.audit_logs else None
        }


# Example usage and testing
def test_pii_sanitizer():
    """Test PII sanitization functionality."""
    sanitizer = PIISanitizer()
    
    # Test email content with PII
    test_content = """
    Dear John Smith,
    
    Your account john.smith@email.com has been flagged for suspicious activity.
    Please call us at (555) 123-4567 to verify your identity.
    
    Your account number is ACC123456789.
    Your SSN on file is 123-45-6789.
    
    Please visit https://example.com/verify?user=john.smith@email.com&token=abc123
    """
    
    result = sanitizer.sanitize_content(test_content)
    
    print(f"PII detected: {result.sanitization_applied}")
    print(f"PII types found: {result.pii_types_found}")
    print(f"Total PII items: {result.total_pii_items}")
    print(f"\nSanitized content:\n{result.sanitized_content}")
    
    for detection in result.detected_pii:
        print(f"- {detection.pii_type.value}: {detection.original_value} -> {detection.redacted_value}")


if __name__ == "__main__":
    test_pii_sanitizer()