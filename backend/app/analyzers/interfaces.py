"""Analyzer protocol used by unit tests."""

from typing import Protocol, Any, Dict


class BaseAnalyzer(Protocol):
    async def analyze_url(self, url: str) -> Any:
        ...


__all__ = ["BaseAnalyzer"]
