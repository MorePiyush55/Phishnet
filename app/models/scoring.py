"""Compatibility shim: expose scoring models at app.models.scoring

Re-exports scoring-related models from the analysis package.
"""

from app.models.analysis.scoring import (
    EmailAction, ActionType, ActionStatus, EmailScore, ScoringRule
)

__all__ = [
    "EmailAction", "ActionType", "ActionStatus", "EmailScore", "ScoringRule"
]
