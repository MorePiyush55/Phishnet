"""Shim for PhishNetOrchestrator used in tests."""

from .analysis_orchestrator import AnalysisOrchestrator

class PhishNetOrchestrator:
    def __init__(self):
        self.analysis = AnalysisOrchestrator()

    def analyze(self, email_id: str) -> dict:
        return self.analysis.analyze_email(email_id)

__all__ = ["PhishNetOrchestrator"]
