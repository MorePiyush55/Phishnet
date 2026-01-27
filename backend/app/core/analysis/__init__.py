"""
Core Analysis Engine
====================
Mode-agnostic email analysis components.

This package contains the shared analysis logic used by all modes:
- PhishingAnalyzer: Main analysis engine
- ThreatIntelligence: VirusTotal, AbuseIPDB integration
- Scoring: Threat scoring algorithms

The analysis engine does NOT know about email sources.
It only cares about email content (headers, body, attachments).
"""

# Re-export main components for convenience
# These will be populated as we migrate files

__all__ = []
