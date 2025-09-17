"""Minimal threat aggregator shim used for import-time stability in tests.

Provides a `ThreatResult` dataclass placeholder and `ThreatAggregator` class
that tests can patch.
"""

from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class ThreatResult:
    threat_level: str = "LOW"
    score: float = 0.0
    details: Dict[str, Any] = None

class ThreatAggregator:
    def aggregate(self, *args, **kwargs) -> ThreatResult:
        return ThreatResult()

__all__ = ["ThreatResult", "ThreatAggregator"]
