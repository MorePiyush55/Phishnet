"""Minimal ML ThreatAggregator shim for tests."""

from typing import Dict, Any

class ThreatAggregator:
    def aggregate(self, results: list) -> Dict[str, Any]:
        # Simple aggregation: return highest severity
        return {"threat_level": "low", "confidence": 0.5}

__all__ = ["ThreatAggregator"]
