"""
PhishNet User Feedback Model
===============================
Beanie Document model for storing user-submitted feedback on email analyses.
Supports false positive/negative reporting for continuous model improvement.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any

from beanie import Document, Indexed
from pydantic import Field
from pymongo import IndexModel, ASCENDING, DESCENDING


class FeedbackType(str, Enum):
    """Type of feedback submitted by the user."""
    FALSE_POSITIVE = "false_positive"   # Flagged as phishing but was safe
    FALSE_NEGATIVE = "false_negative"   # Marked safe but was phishing
    CORRECT = "correct"                 # Verdict was accurate


class UserFeedback(Document):
    """
    User feedback on email analysis results.
    
    Used to track false positives / false negatives across the system
    and feed back into model improvement pipelines.
    """

    # Link to the analysis that was reviewed
    email_analysis_id: Indexed(str)
    user_id: Indexed(str)

    # Feedback details
    feedback_type: FeedbackType
    original_verdict: str = Field(description="The system's original verdict (PHISHING / SUSPICIOUS / SAFE)")
    correct_verdict: Optional[str] = Field(None, description="What the user believes the correct verdict should be")
    user_comment: Optional[str] = Field(None, max_length=2000)

    # Context for model improvement
    original_score: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "user_feedback"
        indexes = [
            IndexModel([("email_analysis_id", ASCENDING)]),
            IndexModel([("user_id", ASCENDING), ("created_at", DESCENDING)]),
            IndexModel([("feedback_type", ASCENDING)]),
            IndexModel([("created_at", DESCENDING)]),
        ]
