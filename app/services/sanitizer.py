"""Content sanitizer shim for tests.

Exports `content_sanitizer` function used by tests; real implementation
lives elsewhere and tests typically patch behavior.
"""

def content_sanitizer(text: str) -> str:
    # Very small no-op sanitizer used during import; tests patch for behavior.
    return text

__all__ = ["content_sanitizer"]
