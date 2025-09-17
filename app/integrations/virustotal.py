"""Compatibility shim for VirusTotal integration used by tests. Re-exports the VirusTotalClient from services."""

from app.services.virustotal import VirusTotalClient

# Some tests expect a VirusTotalAdapter class to be importable from this package
try:
	from app.orchestrator.threat_orchestrator import VirusTotalAdapter
except Exception:
	VirusTotalAdapter = None

__all__ = ["VirusTotalClient", "VirusTotalAdapter"]
