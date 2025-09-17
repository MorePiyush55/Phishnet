from pydantic import BaseModel
from typing import Optional

class ScoringRequest(BaseModel):
    email_id: str

class ScoringResponse(BaseModel):
    score: float
    reason: Optional[str]

__all__ = ["ScoringRequest", "ScoringResponse"]
