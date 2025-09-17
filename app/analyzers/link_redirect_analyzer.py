"""Compatibility layer exposing LinkRedirectAnalyzer for older import paths."""
from app.services.link_analyzer import LinkRedirectionAnalyzer as LinkRedirectAnalyzer, LinkAnalysisResult

__all__ = ["LinkRedirectAnalyzer", "LinkAnalysisResult"]
