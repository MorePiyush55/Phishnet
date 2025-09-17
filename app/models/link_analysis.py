"""Compatibility shim: expose link analysis models at app.models.link_analysis

Re-exports link-analysis related models from the analysis package so legacy
imports like `from app.models import link_analysis` continue to work during
test collection.
"""

from app.models.analysis.link_analysis import LinkAnalysis, EmailAIResults, EmailIndicators

__all__ = ["LinkAnalysis", "EmailAIResults", "EmailIndicators"]
