"""
Advanced Analytics Dashboard API for PhishNet Security Operations Center
Provides comprehensive security metrics, threat intelligence, and real-time monitoring
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.config.logging import get_logger
from app.intelligence.threat_intel import threat_intelligence_manager
from app.workflows.incident_manager import incident_manager
from app.workflows.response_automation import response_automation
from app.models.mongodb_models import ThreatIntelligence, Incident

logger = get_logger(__name__)

router = APIRouter(prefix="/analytics", tags=["Analytics Dashboard"])


class DashboardMetrics(BaseModel):
    """Main dashboard metrics response"""
    threat_overview: Dict[str, Any]
    email_analysis: Dict[str, Any]
    incident_summary: Dict[str, Any]
    threat_intelligence: Dict[str, Any]
    real_time_alerts: List[Dict[str, Any]]
    performance_metrics: Dict[str, Any]
    trend_analysis: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ThreatOverview(BaseModel):
    """Threat overview metrics"""
    total_threats_detected: int
    phishing_emails_blocked: int
    malicious_urls_found: int
    suspicious_attachments: int
    threat_score_average: float
    risk_distribution: Dict[str, int]
    top_threat_types: List[Dict[str, Any]]


class EmailAnalysisMetrics(BaseModel):
    """Email analysis metrics"""
    total_emails_analyzed: int
    phishing_detection_rate: float
    false_positive_rate: float
    processing_time_avg_ms: float
    accuracy_score: float
    volume_trends: List[Dict[str, Any]]


class IncidentMetrics(BaseModel):
    """Incident management metrics"""
    active_incidents: int
    resolved_incidents: int
    average_resolution_time: float
    escalated_incidents: int
    incident_severity_breakdown: Dict[str, int]
    response_time_metrics: Dict[str, float]


class ThreatIntelMetrics(BaseModel):
    """Threat intelligence metrics"""
    ioc_count: int
    feed_sources: List[str]
    reputation_scores: Dict[str, float]
    new_threats_24h: int
    threat_actor_tracking: List[Dict[str, Any]]


class RealTimeAlert(BaseModel):
    """Real-time security alert"""
    alert_id: str
    severity: str
    threat_type: str
    description: str
    source: str
    timestamp: datetime
    status: str = "active"


class PerformanceMetrics(BaseModel):
    """System performance metrics"""
    api_response_time: float
    analysis_throughput: int
    system_availability: float
    resource_utilization: Dict[str, float]
    error_rates: Dict[str, float]


@router.get("/dashboard", response_model=DashboardMetrics)
async def get_dashboard_metrics(
    time_range: str = Query("24h", description="Time range: 1h, 24h, 7d, 30d"),
    include_trends: bool = Query(True, description="Include trend analysis")
):
    """
    Get comprehensive dashboard metrics for security operations center
    """
    try:
        logger.info(f"Fetching dashboard metrics for time range: {time_range}")
        
        # Calculate time range
        end_time = datetime.utcnow()
        if time_range == "1h":
            start_time = end_time - timedelta(hours=1)
        elif time_range == "24h":
            start_time = end_time - timedelta(days=1)
        elif time_range == "7d":
            start_time = end_time - timedelta(days=7)
        elif time_range == "30d":
            start_time = end_time - timedelta(days=30)
        else:
            start_time = end_time - timedelta(days=1)
        
        # Gather metrics from all components
        threat_overview = await _get_threat_overview(start_time, end_time)
        email_analysis = await _get_email_analysis_metrics(start_time, end_time)
        incident_summary = await _get_incident_metrics(start_time, end_time)
        threat_intel = await _get_threat_intelligence_metrics(start_time, end_time)
        real_time_alerts = await _get_real_time_alerts()
        performance_metrics = await _get_performance_metrics(start_time, end_time)
        
        trend_analysis = {}
        if include_trends:
            trend_analysis = await _get_trend_analysis(start_time, end_time)
        
        return DashboardMetrics(
            threat_overview=threat_overview,
            email_analysis=email_analysis,
            incident_summary=incident_summary,
            threat_intelligence=threat_intel,
            real_time_alerts=real_time_alerts,
            performance_metrics=performance_metrics,
            trend_analysis=trend_analysis
        )
        
    except Exception as e:
        logger.error(f"Error fetching dashboard metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch dashboard metrics")


@router.get("/threat-overview", response_model=ThreatOverview)
async def get_threat_overview(
    time_range: str = Query("24h", description="Time range for metrics")
):
    """Get threat overview metrics"""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - _parse_time_range(time_range)
        
        return await _get_threat_overview(start_time, end_time)
        
    except Exception as e:
        logger.error(f"Error fetching threat overview: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch threat overview")


@router.get("/email-metrics", response_model=EmailAnalysisMetrics)
async def get_email_analysis_metrics(
    time_range: str = Query("24h", description="Time range for metrics")
):
    """Get email analysis performance metrics"""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - _parse_time_range(time_range)
        
        return await _get_email_analysis_metrics(start_time, end_time)
        
    except Exception as e:
        logger.error(f"Error fetching email metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch email metrics")


@router.get("/incident-metrics", response_model=IncidentMetrics)
async def get_incident_metrics(
    time_range: str = Query("24h", description="Time range for metrics")
):
    """Get incident management metrics"""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - _parse_time_range(time_range)
        
        return await _get_incident_metrics(start_time, end_time)
        
    except Exception as e:
        logger.error(f"Error fetching incident metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch incident metrics")


@router.get("/threat-intel-metrics", response_model=ThreatIntelMetrics)
async def get_threat_intelligence_metrics(
    time_range: str = Query("24h", description="Time range for metrics")
):
    """Get threat intelligence metrics"""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - _parse_time_range(time_range)
        
        return await _get_threat_intelligence_metrics(start_time, end_time)
        
    except Exception as e:
        logger.error(f"Error fetching threat intelligence metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch threat intelligence metrics")


@router.get("/real-time-alerts", response_model=List[RealTimeAlert])
async def get_real_time_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, description="Maximum number of alerts")
):
    """Get real-time security alerts"""
    try:
        alerts = await _get_real_time_alerts(severity, limit)
        return alerts
        
    except Exception as e:
        logger.error(f"Error fetching real-time alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch real-time alerts")


@router.get("/performance-metrics", response_model=PerformanceMetrics)
async def get_performance_metrics(
    time_range: str = Query("24h", description="Time range for metrics")
):
    """Get system performance metrics"""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - _parse_time_range(time_range)
        
        return await _get_performance_metrics(start_time, end_time)
        
    except Exception as e:
        logger.error(f"Error fetching performance metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch performance metrics")


@router.get("/trend-analysis")
async def get_trend_analysis(
    metric_type: str = Query("threats", description="Type of trend analysis"),
    time_range: str = Query("7d", description="Time range for trend analysis"),
    granularity: str = Query("hour", description="Data granularity: hour, day, week")
):
    """Get trend analysis for specific metrics"""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - _parse_time_range(time_range)
        
        trends = await _get_trend_analysis(start_time, end_time, metric_type, granularity)
        return trends
        
    except Exception as e:
        logger.error(f"Error fetching trend analysis: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch trend analysis")


# Helper functions
async def _get_threat_overview(start_time: datetime, end_time: datetime) -> Dict[str, Any]:
    """Get threat overview metrics from threat intelligence"""
    try:
        # Get threat statistics from threat intelligence manager
        threat_stats = await threat_intelligence_manager.get_threat_statistics(start_time, end_time)
        
        return {
            "total_threats_detected": threat_stats.get("total_threats", 0),
            "phishing_emails_blocked": threat_stats.get("phishing_blocked", 0),
            "malicious_urls_found": threat_stats.get("malicious_urls", 0),
            "suspicious_attachments": threat_stats.get("suspicious_files", 0),
            "threat_score_average": threat_stats.get("avg_threat_score", 0.0),
            "risk_distribution": threat_stats.get("risk_distribution", {}),
            "top_threat_types": threat_stats.get("top_threat_types", [])
        }
    except Exception as e:
        logger.error(f"Error getting threat overview: {e}")
        return {
            "total_threats_detected": 0,
            "phishing_emails_blocked": 0,
            "malicious_urls_found": 0,
            "suspicious_attachments": 0,
            "threat_score_average": 0.0,
            "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "top_threat_types": []
        }


async def _get_email_analysis_metrics(start_time: datetime, end_time: datetime) -> Dict[str, Any]:
    """Get email analysis performance metrics"""
    try:
        # Mock data - replace with actual database queries
        return {
            "total_emails_analyzed": 1247,
            "phishing_detection_rate": 0.923,
            "false_positive_rate": 0.027,
            "processing_time_avg_ms": 342.5,
            "accuracy_score": 0.956,
            "volume_trends": [
                {"time": "2025-10-09T00:00:00Z", "count": 52},
                {"time": "2025-10-09T01:00:00Z", "count": 48},
                {"time": "2025-10-09T02:00:00Z", "count": 61}
            ]
        }
    except Exception as e:
        logger.error(f"Error getting email analysis metrics: {e}")
        return {}


async def _get_incident_metrics(start_time: datetime, end_time: datetime) -> Dict[str, Any]:
    """Get incident management metrics"""
    try:
        incident_stats = await incident_manager.get_incident_statistics(start_time, end_time)
        
        return {
            "active_incidents": incident_stats.get("active_count", 0),
            "resolved_incidents": incident_stats.get("resolved_count", 0),
            "average_resolution_time": incident_stats.get("avg_resolution_time", 0.0),
            "escalated_incidents": incident_stats.get("escalated_count", 0),
            "incident_severity_breakdown": incident_stats.get("severity_breakdown", {}),
            "response_time_metrics": incident_stats.get("response_times", {})
        }
    except Exception as e:
        logger.error(f"Error getting incident metrics: {e}")
        return {}


async def _get_threat_intelligence_metrics(start_time: datetime, end_time: datetime) -> Dict[str, Any]:
    """Get threat intelligence metrics"""
    try:
        intel_stats = await threat_intelligence_manager.get_intelligence_statistics(start_time, end_time)
        
        return {
            "ioc_count": intel_stats.get("total_iocs", 0),
            "feed_sources": intel_stats.get("active_sources", []),
            "reputation_scores": intel_stats.get("reputation_summary", {}),
            "new_threats_24h": intel_stats.get("new_threats_24h", 0),
            "threat_actor_tracking": intel_stats.get("threat_actors", [])
        }
    except Exception as e:
        logger.error(f"Error getting threat intelligence metrics: {e}")
        return {}


async def _get_real_time_alerts(severity: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Get real-time security alerts"""
    try:
        # Get active alerts from incident manager
        alerts = await incident_manager.get_active_alerts(severity, limit)
        
        return [
            {
                "alert_id": alert.get("id", ""),
                "severity": alert.get("severity", "LOW"),
                "threat_type": alert.get("threat_type", "Unknown"),
                "description": alert.get("description", ""),
                "source": alert.get("source", "PhishNet"),
                "timestamp": alert.get("timestamp", datetime.utcnow()),
                "status": alert.get("status", "active")
            }
            for alert in alerts
        ]
    except Exception as e:
        logger.error(f"Error getting real-time alerts: {e}")
        return []


async def _get_performance_metrics(start_time: datetime, end_time: datetime) -> Dict[str, Any]:
    """Get system performance metrics"""
    try:
        # Mock performance data - replace with actual monitoring
        return {
            "api_response_time": 142.5,
            "analysis_throughput": 350,
            "system_availability": 99.97,
            "resource_utilization": {
                "cpu": 23.4,
                "memory": 67.8,
                "disk": 45.2
            },
            "error_rates": {
                "api_errors": 0.012,
                "analysis_errors": 0.008,
                "system_errors": 0.003
            }
        }
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}")
        return {}


async def _get_trend_analysis(
    start_time: datetime, 
    end_time: datetime, 
    metric_type: str = "threats", 
    granularity: str = "hour"
) -> Dict[str, Any]:
    """Get trend analysis for metrics"""
    try:
        if metric_type == "threats":
            return await _get_threat_trends(start_time, end_time, granularity)
        elif metric_type == "emails":
            return await _get_email_trends(start_time, end_time, granularity)
        elif metric_type == "incidents":
            return await _get_incident_trends(start_time, end_time, granularity)
        else:
            return {}
    except Exception as e:
        logger.error(f"Error getting trend analysis: {e}")
        return {}


async def _get_threat_trends(start_time: datetime, end_time: datetime, granularity: str) -> Dict[str, Any]:
    """Get threat trend analysis"""
    try:
        # Mock trend data - replace with actual analytics
        return {
            "trend_direction": "increasing",
            "percentage_change": 12.5,
            "data_points": [
                {"timestamp": "2025-10-09T00:00:00Z", "value": 23},
                {"timestamp": "2025-10-09T01:00:00Z", "value": 27},
                {"timestamp": "2025-10-09T02:00:00Z", "value": 31}
            ],
            "forecast": [
                {"timestamp": "2025-10-09T03:00:00Z", "predicted_value": 34},
                {"timestamp": "2025-10-09T04:00:00Z", "predicted_value": 38}
            ]
        }
    except Exception as e:
        logger.error(f"Error getting threat trends: {e}")
        return {}


async def _get_email_trends(start_time: datetime, end_time: datetime, granularity: str) -> Dict[str, Any]:
    """Get email analysis trend analysis"""
    # Similar implementation for email trends
    return {}


async def _get_incident_trends(start_time: datetime, end_time: datetime, granularity: str) -> Dict[str, Any]:
    """Get incident trend analysis"""
    # Similar implementation for incident trends
    return {}


def _parse_time_range(time_range: str) -> timedelta:
    """Parse time range string to timedelta"""
    if time_range == "1h":
        return timedelta(hours=1)
    elif time_range == "24h":
        return timedelta(days=1)
    elif time_range == "7d":
        return timedelta(days=7)
    elif time_range == "30d":
        return timedelta(days=30)
    else:
        return timedelta(days=1)