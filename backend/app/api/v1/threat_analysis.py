"""
Enhanced Threat Analysis API with Sandbox Integration

Provides comprehensive threat analysis endpoints that leverage the sandbox-integrated
orchestrator for deep URL analysis and cloaking detection.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from datetime import datetime
import asyncio
import uuid

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models.core.user import User
from app.models.core.email import Email
from app.orchestrator.enhanced_threat_orchestrator import ThreatAnalysisRequest
from app.orchestrator.sandbox_integrated_orchestrator import (
    analyze_threat_with_sandbox,
    SandboxAnalysisResult
)
from app.config.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/threat-analysis", tags=["threat-analysis"])


# Request/Response Models
class ThreatAnalysisRequestModel(BaseModel):
    """Request model for threat analysis."""
    urls_to_analyze: List[str] = Field(..., description="URLs to analyze for threats")
    analysis_depth: str = Field(default="comprehensive", description="Analysis depth: basic, standard, comprehensive")
    priority: str = Field(default="normal", description="Analysis priority: low, normal, high, urgent")
    user_agent: Optional[str] = Field(None, description="User agent for analysis")
    enable_sandbox: bool = Field(default=True, description="Enable sandbox analysis for suspicious URLs")
    max_analysis_time: Optional[int] = Field(default=300, description="Maximum analysis time in seconds")


class SandboxResultModel(BaseModel):
    """Model for sandbox analysis results."""
    job_id: str
    target_url: str
    analysis_time: str
    duration_ms: int
    cloaking_detected: bool
    security_findings: List[str]
    threat_score: float
    confidence: float
    screenshots: List[Dict[str, Any]]
    dom_snapshots: List[Dict[str, Any]]
    network_logs: Dict[str, Any]
    console_logs: Dict[str, Any]
    archive_url: Optional[str]
    bot_user_analysis: Dict[str, Any]
    real_user_analysis: Dict[str, Any]
    cloaking_evidence: List[str]


class EnhancedThreatAnalysisResponse(BaseModel):
    """Enhanced threat analysis response with sandbox integration."""
    scan_request_id: str
    threat_level: str
    threat_score: float
    confidence: float
    analysis_start_time: float
    analysis_duration_seconds: float
    
    # Standard analysis results
    url_analysis_score: float
    ip_reputation_score: float
    content_analysis_score: float
    malicious_urls: List[str]
    suspicious_ips: List[str]
    phishing_indicators: List[str]
    services_used: List[str]
    services_failed: List[str]
    
    # Enhanced fields
    explanation: str
    recommendations: List[str]
    confidence_reasoning: str
    
    # Sandbox-specific fields
    sandbox_analysis_count: Optional[int] = 0
    cloaking_detected: Optional[bool] = False
    sandbox_results: Optional[Dict[str, SandboxResultModel]] = None
    
    class Config:
        from_attributes = True


class ThreatAnalysisStatusResponse(BaseModel):
    """Response for analysis status check."""
    scan_request_id: str
    status: str  # queued, processing, completed, failed
    progress: float  # 0.0 to 1.0
    estimated_completion: Optional[datetime]
    current_stage: str
    services_completed: List[str]
    services_remaining: List[str]


# Endpoints
@router.post("/analyze", response_model=EnhancedThreatAnalysisResponse)
async def analyze_threats(
    request: ThreatAnalysisRequestModel,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Perform comprehensive threat analysis with sandbox integration.
    
    This endpoint analyzes URLs for threats using multiple security services
    and includes sandbox analysis for suspicious URLs to detect cloaking
    and other advanced evasion techniques.
    """
    if not request.urls_to_analyze:
        raise HTTPException(status_code=400, detail="No URLs provided for analysis")
    
    if len(request.urls_to_analyze) > 20:
        raise HTTPException(
            status_code=400, 
            detail="Too many URLs (max 20 per request)"
        )
    
    # Create threat analysis request
    scan_request_id = str(uuid.uuid4())
    
    threat_request = ThreatAnalysisRequest(
        scan_request_id=scan_request_id,
        user_id=str(current_user.id),
        urls_to_analyze=request.urls_to_analyze,
        analysis_depth=request.analysis_depth,
        priority=request.priority,
        user_agent=request.user_agent
    )
    
    logger.info(
        f"Starting threat analysis for user {current_user.id}: "
        f"{len(request.urls_to_analyze)} URLs, priority={request.priority}"
    )
    
    try:
        # Perform enhanced threat analysis with sandbox integration
        result = await analyze_threat_with_sandbox(threat_request)
        
        # Convert sandbox results to response model
        sandbox_results_dict = {}
        if hasattr(result, 'sandbox_results') and result.sandbox_results:
            for url, sandbox_result in result.sandbox_results.items():
                sandbox_results_dict[url] = SandboxResultModel(
                    job_id=sandbox_result.job_id,
                    target_url=sandbox_result.target_url,
                    analysis_time=sandbox_result.analysis_time,
                    duration_ms=sandbox_result.duration_ms,
                    cloaking_detected=sandbox_result.cloaking_detected,
                    security_findings=sandbox_result.security_findings,
                    threat_score=sandbox_result.threat_score,
                    confidence=sandbox_result.confidence,
                    screenshots=sandbox_result.screenshots,
                    dom_snapshots=sandbox_result.dom_snapshots,
                    network_logs=sandbox_result.network_logs,
                    console_logs=sandbox_result.console_logs,
                    archive_url=sandbox_result.archive_url,
                    bot_user_analysis=sandbox_result.bot_user_analysis,
                    real_user_analysis=sandbox_result.real_user_analysis,
                    cloaking_evidence=sandbox_result.cloaking_evidence
                )
        
        # Create response
        response = EnhancedThreatAnalysisResponse(
            scan_request_id=result.scan_request_id,
            threat_level=result.threat_level,
            threat_score=result.threat_score,
            confidence=result.confidence,
            analysis_start_time=result.analysis_start_time,
            analysis_duration_seconds=result.analysis_duration_seconds,
            url_analysis_score=result.url_analysis_score,
            ip_reputation_score=result.ip_reputation_score,
            content_analysis_score=result.content_analysis_score,
            malicious_urls=result.malicious_urls,
            suspicious_ips=result.suspicious_ips,
            phishing_indicators=result.phishing_indicators,
            services_used=result.services_used,
            services_failed=result.services_failed,
            explanation=result.explanation,
            recommendations=result.recommendations,
            confidence_reasoning=result.confidence_reasoning,
            sandbox_analysis_count=getattr(result, 'sandbox_analysis_count', 0),
            cloaking_detected=getattr(result, 'cloaking_detected', False),
            sandbox_results=sandbox_results_dict if sandbox_results_dict else None
        )
        
        logger.info(
            f"Threat analysis completed for scan {scan_request_id}: "
            f"threat_score={result.threat_score:.3f}, "
            f"sandbox_urls={len(sandbox_results_dict)}"
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error in threat analysis for scan {scan_request_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/analyze-email/{email_id}", response_model=EnhancedThreatAnalysisResponse)
async def analyze_email_threats(
    email_id: int,
    analysis_depth: str = Query(default="comprehensive", description="Analysis depth"),
    priority: str = Query(default="normal", description="Analysis priority"),
    enable_sandbox: bool = Query(default=True, description="Enable sandbox analysis"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Analyze threats in a specific email with sandbox integration.
    
    Extracts URLs from the email content and performs comprehensive
    threat analysis including sandbox analysis for suspicious URLs.
    """
    # Get email
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    # Check access permissions
    if email.user_id != current_user.id and current_user.role.value not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Extract URLs from email content
    from app.services.sanitizer import ContentSanitizer
    sanitizer = ContentSanitizer()
    content = f"{email.raw_html or ''} {email.raw_text or ''}"
    urls = sanitizer.extract_urls(content)
    
    if not urls:
        raise HTTPException(status_code=400, detail="No URLs found in email")
    
    # Create analysis request
    request = ThreatAnalysisRequestModel(
        urls_to_analyze=urls[:10],  # Limit to first 10 URLs
        analysis_depth=analysis_depth,
        priority=priority,
        enable_sandbox=enable_sandbox
    )
    
    # Perform analysis
    return await analyze_threats(request, BackgroundTasks(), db, current_user)


@router.get("/status/{scan_request_id}", response_model=ThreatAnalysisStatusResponse)
async def get_analysis_status(
    scan_request_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get the status of a threat analysis request.
    
    Note: This is a placeholder for future async analysis implementation.
    Currently, all analyses are synchronous.
    """
    # This would typically check a cache or database for analysis status
    # For now, return a simple completed status
    return ThreatAnalysisStatusResponse(
        scan_request_id=scan_request_id,
        status="completed",
        progress=1.0,
        current_stage="analysis_complete",
        services_completed=["url_analyzer", "ip_reputation", "content_analysis", "sandbox"],
        services_remaining=[]
    )


@router.get("/sandbox-results/{job_id}", response_model=SandboxResultModel)
async def get_sandbox_results(
    job_id: str,
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    """
    Get detailed sandbox analysis results for a specific job.
    
    Provides access to screenshots, DOM snapshots, and detailed
    security findings from sandbox analysis.
    """
    try:
        # Import sandbox orchestrator
        import sys
        import os
        sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'sandbox'))
        
        from orchestrator import ThreatOrchestrator
        
        orchestrator = ThreatOrchestrator()
        
        # Get detailed results and summary
        result_data = await orchestrator.get_job_result(job_id)
        summary = await orchestrator.get_analysis_summary(job_id)
        
        if not result_data:
            raise HTTPException(status_code=404, detail="Sandbox results not found")
        
        # Convert to response model
        sandbox_result = SandboxResultModel(
            job_id=job_id,
            target_url=result_data.get('target_url', ''),
            analysis_time=result_data.get('analysis_time', ''),
            duration_ms=result_data.get('duration_ms', 0),
            cloaking_detected=result_data.get('cloaking_detected', False),
            security_findings=result_data.get('security_findings', []),
            threat_score=result_data.get('threat_score', 0.0),
            confidence=result_data.get('confidence', 0.0),
            screenshots=summary.get('artifacts', {}).get('screenshot', []) if summary else [],
            dom_snapshots=summary.get('artifacts', {}).get('dom_snapshot', []) if summary else [],
            network_logs=result_data.get('network_logs', {}),
            console_logs=result_data.get('console_logs', {}),
            archive_url=summary.get('archive_url') if summary else None,
            bot_user_analysis=result_data.get('bot_user_analysis', {}),
            real_user_analysis=result_data.get('real_user_analysis', {}),
            cloaking_evidence=result_data.get('cloaking_evidence', [])
        )
        
        return sandbox_result
        
    except Exception as e:
        logger.error(f"Error retrieving sandbox results for job {job_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve results: {str(e)}")


@router.get("/health")
async def get_threat_analysis_health():
    """
    Get health status of threat analysis services including sandbox.
    """
    try:
        # Check sandbox health
        import sys
        import os
        sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'sandbox'))
        
        from orchestrator import ThreatOrchestrator
        
        orchestrator = ThreatOrchestrator()
        sandbox_health = await orchestrator.get_health_status()
        
        return {
            "status": "healthy",
            "services": {
                "threat_orchestrator": "available",
                "sandbox": "available" if sandbox_health.get('status') == 'healthy' else "degraded",
                "url_analyzer": "available",
                "ip_reputation": "available",
                "content_analysis": "available"
            },
            "sandbox_details": sandbox_health,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error checking threat analysis health: {e}")
        return {
            "status": "degraded",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
