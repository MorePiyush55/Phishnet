"""Minimal link redirect analyzer shim for tests.

Provides a LinkRedirectAnalyzer with a simple analyze(url) method that returns a dict.
"""

from typing import Dict, Any

class LinkRedirectAnalyzer:
    def __init__(self):
        pass

    def analyze(self, url: str) -> Dict[str, Any]:
        # Simple deterministic placeholder: returns the original url and a safe flag.
        return {
            "original_url": url,
            "final_url": url,
            "redirect_chain": [url],
            "risk": "low",
        }

__all__ = ["LinkRedirectAnalyzer"]
