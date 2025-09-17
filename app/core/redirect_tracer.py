"""Minimal RedirectTracer used by tests.

Implements a tiny trace method returning a list of visited URLs. Tests patch
behavior when needed, so no real network calls are performed here.
"""

from typing import List

class RedirectTracer:
    def trace(self, url: str, max_hops: int = 5) -> List[str]:
        # Return a simple list representing the redirect chain
        return [url]

__all__ = ["RedirectTracer"]
