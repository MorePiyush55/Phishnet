from .analysis_orchestrator import AnalysisOrchestrator
from .phishnet_orchestrator import PhishNetOrchestrator

__all__ = ["AnalysisOrchestrator", "PhishNetOrchestrator"]
"""Orchestrator package - single source of truth for pipeline coordination.

This module prefers to expose a concrete implementation from
`app.core.orchestrator` when available. During early test collection the
core implementation may not be importable, so we fall back to the
compatibility shim in `app.orchestrator.main`.
"""

try:
	from app.core.orchestrator import PhishNetOrchestrator, get_orchestrator  # type: ignore
	# Also expose ThreatOrchestrator if present in core
	try:
		from app.core.orchestrator import ThreatOrchestrator  # type: ignore
	except Exception:
		ThreatOrchestrator = None
except Exception:
	# Fall back to the lightweight compatibility shim
	from app.orchestrator.main import PhishNetOrchestrator  # type: ignore

	def get_orchestrator():
		"""Return a new shim orchestrator instance when core isn't importable."""
		return PhishNetOrchestrator()

# If ThreatOrchestrator not available from core, try to import from threat_orchestrator module
if 'ThreatOrchestrator' not in globals() or globals().get('ThreatOrchestrator') is None:
	try:
		from app.orchestrator.threat_orchestrator import ThreatOrchestrator  # type: ignore
	except Exception:
		# Last resort: try the sandbox orchestrator in the package
		try:
			from app.orchestrator.sandbox_integrated_orchestrator import SandboxIntegratedOrchestrator as ThreatOrchestrator  # type: ignore
		except Exception:
			ThreatOrchestrator = None

__all__ = ["PhishNetOrchestrator", "get_orchestrator"]
