"""
Threat Intelligence Integration Package.

This package provides secure, cached, and resilient integrations with third-party
threat intelligence services including VirusTotal, AbuseIPDB, and Google Gemini.
"""

from .base import (
    ThreatIntelligenceAdapter,
    ThreatIntelligence, 
    APIResponse,
    APIStatus,
    ThreatLevel,
    ResourceType,
    APIQuota,
    AdapterError,
    QuotaExceededError,
    RateLimitError,
    CircuitOpenError,
    TimeoutError,
    UnauthorizedError,
    calculate_threat_score,
    normalize_url,
    extract_domain,
    is_valid_ip,
    is_valid_domain,
    is_valid_file_hash
)

from .virustotal import VirusTotalClient
from .abuseipdb import AbuseIPDBClient  
from .gemini import GeminiClient

__all__ = [
    # Base classes and interfaces
    'ThreatIntelligenceAdapter',
    'ThreatIntelligence',
    'APIResponse', 
    'APIStatus',
    'ThreatLevel',
    'ResourceType',
    'APIQuota',
    
    # Exceptions
    'AdapterError',
    'QuotaExceededError',
    'RateLimitError', 
    'CircuitOpenError',
    'TimeoutError',
    'UnauthorizedError',
    
    # Utility functions
    'calculate_threat_score',
    'normalize_url',
    'extract_domain',
    'is_valid_ip',
    'is_valid_domain',
    'is_valid_file_hash',
    
    # Client implementations
    'VirusTotalClient',
    'AbuseIPDBClient',
    'GeminiClient'
]

# Version information
__version__ = "1.0.0"
__author__ = "PhishNet Team"
__description__ = "Secure third-party threat intelligence integrations"