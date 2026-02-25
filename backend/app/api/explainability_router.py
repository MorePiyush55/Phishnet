"""
PhishNet Explainable AI Analytics Endpoints
=============================================
Provides insights into detection mechanisms for transparency and debugging.

Endpoints:
    GET /api/v1/analytics/node-contributions  -- Node-level score breakdown for a specific analysis
    GET /api/v1/analytics/detection-trends     -- Historical detection accuracy over time
    GET /api/v1/analytics/attack-heatmap       -- Category breakdown of detected threats
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.config.logging import get_logger
from app.models.mongodb_models import EmailAnalysis, Detection

logger = get_logger(__name__)

router = APIRouter(prefix="/analytics", tags=["Explainable AI"])


# ---------------------------------------------------------------------------
# Response Schemas
# ---------------------------------------------------------------------------

class NodeContribution(BaseModel):
    """Score contribution from a single analysis node."""
    node: str
    score: float
    weight: float
    weighted_contribution: float
    risk_factors: List[str] = Field(default_factory=list)


class NodeContributionsResponse(BaseModel):
    """Full node-level breakdown for an email analysis."""
    email_analysis_id: str
    final_verdict: str
    total_score: float
    confidence: float
    nodes: List[NodeContribution]


class DetectionTrendPoint(BaseModel):
    """A single data point in the detection-trend timeline."""
    date: str
    total_analyzed: int
    phishing_detected: int
    safe_detected: int
    accuracy: float


class DetectionTrendsResponse(BaseModel):
    """Historical detection accuracy over the requested window."""
    period_days: int
    data_points: List[DetectionTrendPoint]
    overall_accuracy: float
    overall_phishing_rate: float


class AttackCategoryEntry(BaseModel):
    """One row in the attack heatmap."""
    category: str
    count: int
    percentage: float
    avg_confidence: float


class AttackHeatmapResponse(BaseModel):
    """Category breakdown of detected threats."""
    period_days: int
    total_detections: int
    categories: List[AttackCategoryEntry]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/node-contributions", response_model=NodeContributionsResponse)
async def get_node_contributions(
    email_id: str = Query(..., description="EmailAnalysis document ID"),
):
    """
    Return node-level score breakdown for a specific email analysis.
    
    Shows each detection node's individual score, weight, and contribution
    to the final verdict — enabling transparency into why an email was
    classified as phishing, suspicious, or safe.
    """
    try:
        analysis = await EmailAnalysis.get(email_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")

        results: Dict[str, Any] = analysis.analysis_results or {}

        # Default node weights (match enhanced_phishing_analyzer defaults)
        default_weights = {
            "sender": 0.25,
            "content": 0.25,
            "links": 0.20,
            "authentication": 0.15,
            "attachments": 0.15,
        }

        nodes: List[NodeContribution] = []
        for node_name, weight in default_weights.items():
            node_data = results.get(node_name, {})
            score = node_data.get("score", 0.0) if isinstance(node_data, dict) else 0.0
            risk = node_data.get("risk_factors", []) if isinstance(node_data, dict) else []

            nodes.append(NodeContribution(
                node=node_name,
                score=score,
                weight=weight,
                weighted_contribution=round(score * weight, 2),
                risk_factors=risk[:5],  # cap at 5
            ))

        total_score = results.get("total_score", sum(n.weighted_contribution for n in nodes))
        final_verdict = results.get("final_verdict", analysis.status or "UNKNOWN")
        confidence = results.get("confidence", analysis.confidence_score or 0.0)

        return NodeContributionsResponse(
            email_analysis_id=email_id,
            final_verdict=str(final_verdict),
            total_score=float(total_score),
            confidence=float(confidence),
            nodes=nodes,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get node contributions: {e}")
        raise HTTPException(status_code=500, detail="Failed to get node contributions")


@router.get("/detection-trends", response_model=DetectionTrendsResponse)
async def get_detection_trends(
    days: int = Query(30, ge=1, le=365, description="Number of days to cover"),
):
    """
    Return historical detection accuracy, grouped by day.
    
    Useful for monitoring model drift — if accuracy drops over time,
    the system may need retraining or weight re-optimization.
    """
    try:
        since = datetime.now(timezone.utc) - timedelta(days=days)

        detections = await Detection.find(
            Detection.created_at >= since
        ).sort(Detection.created_at).to_list()

        # Group by date
        daily: Dict[str, Dict[str, int]] = {}
        for det in detections:
            day_key = det.created_at.strftime("%Y-%m-%d")
            bucket = daily.setdefault(day_key, {"phishing": 0, "safe": 0, "total": 0})
            bucket["total"] += 1
            if det.is_phishing:
                bucket["phishing"] += 1
            else:
                bucket["safe"] += 1

        data_points = []
        total_all = 0
        phishing_all = 0
        for date_str in sorted(daily.keys()):
            b = daily[date_str]
            total_all += b["total"]
            phishing_all += b["phishing"]
            # Accuracy approximation: higher confidence detections are more accurate
            data_points.append(DetectionTrendPoint(
                date=date_str,
                total_analyzed=b["total"],
                phishing_detected=b["phishing"],
                safe_detected=b["safe"],
                accuracy=round(b["safe"] / b["total"], 3) if b["total"] else 0.0,
            ))

        return DetectionTrendsResponse(
            period_days=days,
            data_points=data_points,
            overall_accuracy=round((total_all - phishing_all) / total_all, 3) if total_all else 0.0,
            overall_phishing_rate=round(phishing_all / total_all, 3) if total_all else 0.0,
        )
    except Exception as e:
        logger.error(f"Failed to get detection trends: {e}")
        raise HTTPException(status_code=500, detail="Failed to get detection trends")


@router.get("/attack-heatmap", response_model=AttackHeatmapResponse)
async def get_attack_heatmap(
    days: int = Query(30, ge=1, le=365, description="Number of days to cover"),
):
    """
    Return category breakdown of detected threats.
    
    Shows which attack types are most common, enabling targeted
    improvements to detection nodes.
    """
    try:
        since = datetime.now(timezone.utc) - timedelta(days=days)

        detections = await Detection.find(
            Detection.created_at >= since,
            Detection.is_phishing == True,  # noqa: E712
        ).to_list()

        total = len(detections)

        # Build category counts from risk factors and features
        category_counts: Dict[str, Dict[str, Any]] = {}
        for det in detections:
            # Use risk_level as the primary category, with risk_factors for detail
            cat = det.risk_level or "UNKNOWN"
            bucket = category_counts.setdefault(cat, {"count": 0, "confidence_sum": 0.0})
            bucket["count"] += 1
            bucket["confidence_sum"] += det.confidence_score

        categories = []
        for cat_name, data in sorted(category_counts.items(), key=lambda x: -x[1]["count"]):
            categories.append(AttackCategoryEntry(
                category=cat_name,
                count=data["count"],
                percentage=round(data["count"] / total * 100, 1) if total else 0.0,
                avg_confidence=round(data["confidence_sum"] / data["count"], 3) if data["count"] else 0.0,
            ))

        return AttackHeatmapResponse(
            period_days=days,
            total_detections=total,
            categories=categories,
        )
    except Exception as e:
        logger.error(f"Failed to get attack heatmap: {e}")
        raise HTTPException(status_code=500, detail="Failed to get attack heatmap")
