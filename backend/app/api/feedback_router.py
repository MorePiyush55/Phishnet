"""
PhishNet User Feedback API
============================
REST endpoints for submitting and querying user feedback on email analyses.

Endpoints:
    POST /api/v1/feedback          -- Submit feedback on an analysis
    GET  /api/v1/feedback/stats    -- Aggregate FP/FN statistics
    GET  /api/v1/feedback/recent   -- List recent feedback entries
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.config.logging import get_logger
from app.models.feedback import FeedbackType, UserFeedback

logger = get_logger(__name__)

router = APIRouter(prefix="/feedback", tags=["User Feedback"])


# ---------------------------------------------------------------------------
# Request / Response Schemas
# ---------------------------------------------------------------------------

class FeedbackSubmission(BaseModel):
    """Request body for submitting feedback."""
    email_analysis_id: str
    user_id: str
    feedback_type: FeedbackType
    original_verdict: str
    correct_verdict: Optional[str] = None
    user_comment: Optional[str] = Field(None, max_length=2000)
    original_score: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FeedbackResponse(BaseModel):
    """Single feedback entry returned to the client."""
    id: str
    email_analysis_id: str
    user_id: str
    feedback_type: str
    original_verdict: str
    correct_verdict: Optional[str] = None
    user_comment: Optional[str] = None
    created_at: datetime


class FeedbackStats(BaseModel):
    """Aggregate statistics about user feedback."""
    total_feedback: int
    false_positives: int
    false_negatives: int
    correct: int
    false_positive_rate: float
    false_negative_rate: float


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=FeedbackResponse, status_code=201)
async def submit_feedback(body: FeedbackSubmission):
    """
    Submit user feedback on an email analysis result.
    
    Use this when a user disagrees with the system's verdict or wants
    to confirm the result was correct.
    """
    try:
        feedback = UserFeedback(
            email_analysis_id=body.email_analysis_id,
            user_id=body.user_id,
            feedback_type=body.feedback_type,
            original_verdict=body.original_verdict,
            correct_verdict=body.correct_verdict,
            user_comment=body.user_comment,
            original_score=body.original_score,
            metadata=body.metadata,
        )
        await feedback.insert()

        logger.info(
            f"Feedback submitted: type={body.feedback_type.value} "
            f"analysis={body.email_analysis_id} user={body.user_id}"
        )

        return FeedbackResponse(
            id=str(feedback.id),
            email_analysis_id=feedback.email_analysis_id,
            user_id=feedback.user_id,
            feedback_type=feedback.feedback_type.value,
            original_verdict=feedback.original_verdict,
            correct_verdict=feedback.correct_verdict,
            user_comment=feedback.user_comment,
            created_at=feedback.created_at,
        )
    except Exception as e:
        logger.error(f"Failed to submit feedback: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit feedback")


@router.get("/stats", response_model=FeedbackStats)
async def get_feedback_stats(
    days: int = Query(30, ge=1, le=365, description="Number of days to aggregate"),
):
    """
    Get aggregate feedback statistics over the requested time window.
    """
    try:
        since = datetime.now(timezone.utc) - timedelta(days=days)

        total = await UserFeedback.find(
            UserFeedback.created_at >= since
        ).count()

        fp_count = await UserFeedback.find(
            UserFeedback.created_at >= since,
            UserFeedback.feedback_type == FeedbackType.FALSE_POSITIVE,
        ).count()

        fn_count = await UserFeedback.find(
            UserFeedback.created_at >= since,
            UserFeedback.feedback_type == FeedbackType.FALSE_NEGATIVE,
        ).count()

        correct_count = await UserFeedback.find(
            UserFeedback.created_at >= since,
            UserFeedback.feedback_type == FeedbackType.CORRECT,
        ).count()

        return FeedbackStats(
            total_feedback=total,
            false_positives=fp_count,
            false_negatives=fn_count,
            correct=correct_count,
            false_positive_rate=fp_count / total if total else 0.0,
            false_negative_rate=fn_count / total if total else 0.0,
        )
    except Exception as e:
        logger.error(f"Failed to get feedback stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get feedback stats")


@router.get("/recent", response_model=List[FeedbackResponse])
async def get_recent_feedback(
    limit: int = Query(20, ge=1, le=100, description="Max entries to return"),
    feedback_type: Optional[str] = Query(None, description="Filter by type: false_positive, false_negative, correct"),
):
    """
    List recent feedback entries, optionally filtered by type.
    """
    try:
        query = UserFeedback.find()

        if feedback_type:
            try:
                ft = FeedbackType(feedback_type)
                query = UserFeedback.find(UserFeedback.feedback_type == ft)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid feedback_type. Must be one of: {[t.value for t in FeedbackType]}",
                )

        entries = await query.sort(-UserFeedback.created_at).limit(limit).to_list()

        return [
            FeedbackResponse(
                id=str(entry.id),
                email_analysis_id=entry.email_analysis_id,
                user_id=entry.user_id,
                feedback_type=entry.feedback_type.value,
                original_verdict=entry.original_verdict,
                correct_verdict=entry.correct_verdict,
                user_comment=entry.user_comment,
                created_at=entry.created_at,
            )
            for entry in entries
        ]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get recent feedback: {e}")
        raise HTTPException(status_code=500, detail="Failed to get recent feedback")
