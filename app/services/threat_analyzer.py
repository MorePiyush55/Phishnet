"""Compatibility dataclass for threat analysis results used by tests."""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import time


@dataclass
class ThreatAnalysisResult:
    scan_id: str
    overall_threat_level: str
    confidence_score: float
    subject_analysis: Dict[str, Any]
    body_analysis: Dict[str, Any]
    link_analysis: List[Dict[str, Any]]
    sender_analysis: Dict[str, Any]
    timestamp: float = time.time()


__all__ = ["ThreatAnalysisResult"]
