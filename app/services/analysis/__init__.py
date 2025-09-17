"""Compatibility shim to satisfy test imports under app.services.analysis.*

This package re-exports a few historically relocated modules from
`app.services` so that tests importing from
`app.services.analysis.link_redirect_analyzer` continue to work until
the codebase is consolidated.
"""

from app.services.link_redirect_analyzer import LinkRedirectAnalyzer

__all__ = ["LinkRedirectAnalyzer"]
"""Analysis services package - handles AI, link analysis, and scoring."""

from .ai_analyzer import ai_analyzer, analyze_email_with_ai
from .link_analyzer import analyze_email_links, link_analyzer
from .scoring import ScoringEngine

__all__ = [
    "ai_analyzer", 
    "analyze_email_with_ai",
    "analyze_email_links", 
    "link_analyzer",
    "ScoringEngine"
]
