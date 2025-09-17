from pydantic import BaseModel
from typing import Dict, Any

class ThreatResult(BaseModel):
    level: str = "LOW"
    score: float = 0.0
    details: Dict[str, Any] = {}

class ThreatLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

__all__ = ["ThreatResult", "ThreatLevel"]
