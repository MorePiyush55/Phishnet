"""
Enhanced Link Redirect Analysis API Endpoints

Provides comprehensive REST API for link redirect analysis, cloaking detection,
TLS validation, and security assessment with detailed visualization data.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl, Field, validator
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import time
import asyncio
import structlog

from app.services.link_redirect_analyzer import LinkRedirectAnalyzer
from app.services.interfaces import AnalysisType
from app.core.security import get_current_user
from app.models.user import User

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/redirect-analysis", tags=["Link Redirect Analysis"])

# Initialize analyzer
link_analyzer = LinkRedirectAnalyzer()


# Request/Response Models
class LinkAnalysisRequest(BaseModel):
    """Request model for link analysis."""
    url: HttpUrl = Field(..., description="URL to analyze for redirects and cloaking")
    include_cloaking_detection: bool = Field(True, description="Whether to perform cloaking detection")
    max_redirects: Optional[int] = Field(10, ge=1, le=20, description="Maximum redirects to follow")
    timeout_seconds: Optional[int] = Field(30, ge=5, le=60, description="Analysis timeout in seconds")
    user_agents: Optional[List[str]] = Field(None, description="Custom user agents for cloaking detection")
    
    @validator('url')
    def validate_url_scheme(cls, v):
        if v.scheme not in ['http', 'https']:
            raise ValueError('Only HTTP and HTTPS URLs are supported')
        return v


class TLSCertificateResponse(BaseModel):
    """TLS certificate information response."""
    subject: str
    issuer: str
    common_name: str
    san_list: List[str]
    not_before: datetime
    not_after: datetime
    is_valid: bool
    is_self_signed: bool
    is_expired: bool
    hostname_matches: bool
    fingerprint_sha256: str
    serial_number: str
    signature_algorithm: str
    issuer_organization: str
    validation_errors: List[str]


class RedirectHopResponse(BaseModel):
    """Redirect hop information response."""
    hop_number: int
    url: str
    method: str
    status_code: int
    redirect_type: str
    location_header: Optional[str]
    hostname: str
    ip_address: Optional[str]
    tls_certificate: Optional[TLSCertificateResponse]
    response_time_ms: int
    content_hash: str
    content_length: int
    headers: Dict[str, str]
    meta_refresh_delay: Optional[int]
    javascript_redirects: List[str]
    suspicious_patterns: List[str]
    timestamp: datetime
    final_effective_url: str


class CloakingAnalysisResponse(BaseModel):
    """Cloaking detection analysis response."""
    cloaking_detected: bool
    cloaking_confidence: float
    cloaking_indicators: List[str]
    browser_behavior: Dict[str, Any]
    content_differences: Dict[str, Any]
    js_behavior: Dict[str, Any]
    cross_ua_differences: Dict[str, Any]


class SecurityFindingsResponse(BaseModel):
    """Security findings response."""
    ip_domain_mismatch: bool
    cert_hostname_mismatch: bool
    suspicious_tld: bool
    suspicious_patterns: List[str]
    domain_reputation: Dict[str, Any]
    ssl_issues: List[str]


class AnalysisSummaryResponse(BaseModel):
    """Analysis summary response."""
    total_redirects: int
    final_destination: str
    cloaking_detected: bool
    cloaking_confidence: float
    threat_score: float
    unique_domains: int
    https_coverage: float
    suspicious_patterns_count: int
    analysis_duration_ms: int


class LinkAnalysisResponse(BaseModel):
    """Complete link analysis response."""
    analysis_id: str
    original_url: str
    final_url: str
    threat_score: float
    confidence: float
    verdict: str
    explanation: str
    threat_indicators: List[str]
    redirect_chain: List[RedirectHopResponse]
    cloaking_analysis: CloakingAnalysisResponse
    security_findings: SecurityFindingsResponse
    analysis_summary: AnalysisSummaryResponse
    timing_analysis: Dict[str, int]
    analysis_metadata: Dict[str, Any]
    timestamp: datetime
    execution_time_ms: int
    cached: bool = False


class QuickScanRequest(BaseModel):
    """Request model for quick URL scan."""
    url: HttpUrl = Field(..., description="URL to quickly scan")
    
    @validator('url')
    def validate_url_scheme(cls, v):
        if v.scheme not in ['http', 'https']:
            raise ValueError('Only HTTP and HTTPS URLs are supported')
        return v


class QuickScanResponse(BaseModel):
    """Quick scan response."""
    url: str
    verdict: str  # safe, suspicious, malicious
    threat_score: float
    confidence: float
    redirect_count: int
    final_url: str
    cloaking_detected: bool
    key_indicators: List[str]
    analysis_time_ms: int


class BulkAnalysisRequest(BaseModel):
    """Request model for bulk URL analysis."""
    urls: List[HttpUrl] = Field(..., max_items=50, description="URLs to analyze (max 50)")
    include_cloaking: bool = Field(True, description="Include cloaking detection")
    
    @validator('urls')
    def validate_urls(cls, v):
        for url in v:
            if url.scheme not in ['http', 'https']:
                raise ValueError(f'URL {url} has unsupported scheme')
        return v


class BulkAnalysisResponse(BaseModel):
    """Bulk analysis response."""
    analysis_id: str
    total_urls: int
    completed: int
    failed: int
    results: List[QuickScanResponse]
    analysis_summary: Dict[str, Any]
    timestamp: datetime


# API Endpoints

@router.post("/analyze", response_model=LinkAnalysisResponse)
async def analyze_link_redirects(
    request: LinkAnalysisRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """
    Perform comprehensive link redirect analysis including cloaking detection.
    
    This endpoint provides detailed analysis of URL redirect chains, TLS certificates,
    cloaking detection across multiple user agents, and comprehensive security assessment.
    """
    try:
        logger.info("Starting comprehensive link analysis", 
                   url=str(request.url), 
                   user_id=current_user.id)
        
        start_time = time.time()
        
        # Configure analyzer parameters
        if request.max_redirects:
            link_analyzer.max_redirects = request.max_redirects
        if request.timeout_seconds:
            link_analyzer.max_analysis_time = request.timeout_seconds
        
        # Perform analysis
        analysis_result = await link_analyzer.analyze(str(request.url), AnalysisType.URL_SCAN)
        
        # Check if result was cached
        cached = (time.time() - start_time) < 1.0  # Fast response indicates cache hit
        
        # Transform to response format
        raw_data = analysis_result.raw_response
        
        response = LinkAnalysisResponse(
            analysis_id=f"link_analysis_{int(time.time())}_{current_user.id}",
            original_url=str(request.url),
            final_url=raw_data.get('final_url', str(request.url)),
            threat_score=analysis_result.threat_score,
            confidence=analysis_result.confidence,
            verdict=analysis_result.verdict or "unknown",
            explanation=analysis_result.explanation or "Analysis completed",
            threat_indicators=raw_data.get('threat_indicators', []),
            redirect_chain=[
                RedirectHopResponse(**hop) for hop in raw_data.get('redirect_chain', [])
            ],
            cloaking_analysis=CloakingAnalysisResponse(
                cloaking_detected=raw_data.get('cloaking_detected', False),
                cloaking_confidence=raw_data.get('cloaking_confidence', 0.0),
                cloaking_indicators=raw_data.get('cloaking_indicators', []),
                browser_behavior=raw_data.get('browser_behavior', {}),
                content_differences=raw_data.get('content_differences', {}),
                js_behavior=raw_data.get('js_behavior', {}),
                cross_ua_differences=raw_data.get('cross_ua_differences', {})
            ),
            security_findings=SecurityFindingsResponse(
                ip_domain_mismatch=raw_data.get('security_findings', {}).get('ip_domain_mismatch', False),
                cert_hostname_mismatch=raw_data.get('security_findings', {}).get('cert_hostname_mismatch', False),
                suspicious_tld=raw_data.get('security_findings', {}).get('suspicious_tld', False),
                suspicious_patterns=raw_data.get('security_findings', {}).get('suspicious_patterns', []),
                domain_reputation=raw_data.get('security_findings', {}).get('domain_reputation', {}),
                ssl_issues=raw_data.get('security_findings', {}).get('ssl_issues', [])
            ),
            analysis_summary=AnalysisSummaryResponse(**raw_data.get('analysis_summary', {})),
            timing_analysis=raw_data.get('timing_analysis', {}),
            analysis_metadata=raw_data.get('analysis_metadata', {}),
            timestamp=datetime.fromtimestamp(analysis_result.timestamp),
            execution_time_ms=analysis_result.execution_time_ms,
            cached=cached
        )
        
        # Log analysis completion
        background_tasks.add_task(
            log_analysis_completion,
            current_user.id,
            str(request.url),
            analysis_result.threat_score,
            analysis_result.execution_time_ms
        )
        
        logger.info("Link analysis completed", 
                   url=str(request.url),
                   threat_score=analysis_result.threat_score,
                   execution_time_ms=analysis_result.execution_time_ms)
        
        return response
        
    except Exception as e:
        logger.error("Link analysis failed", url=str(request.url), error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/quick-scan", response_model=QuickScanResponse)
async def quick_link_scan(
    request: QuickScanRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Perform quick link scan for basic redirect and threat detection.
    
    This endpoint provides fast analysis with essential information about redirects
    and basic threat indicators without comprehensive cloaking detection.
    """
    try:
        logger.info("Starting quick link scan", url=str(request.url), user_id=current_user.id)
        
        start_time = time.time()
        
        # Use unified scan method for quick analysis
        scan_result = await link_analyzer.scan(str(request.url))
        
        execution_time_ms = int((time.time() - start_time) * 1000)
        
        response = QuickScanResponse(
            url=str(request.url),
            verdict=scan_result.get('verdict', 'unknown'),
            threat_score=scan_result.get('threat_score', 0.0),
            confidence=scan_result.get('confidence', 0.0),
            redirect_count=len(scan_result.get('redirect_chain', [])),
            final_url=scan_result.get('raw_data', {}).get('final_url', str(request.url)),
            cloaking_detected=scan_result.get('cloaking_detected', False),
            key_indicators=scan_result.get('indicators', [])[:5],  # Top 5 indicators
            analysis_time_ms=execution_time_ms
        )
        
        logger.info("Quick scan completed", 
                   url=str(request.url),
                   verdict=response.verdict,
                   execution_time_ms=execution_time_ms)
        
        return response
        
    except Exception as e:
        logger.error("Quick scan failed", url=str(request.url), error=str(e))
        raise HTTPException(status_code=500, detail=f"Quick scan failed: {str(e)}")


@router.post("/bulk-analyze", response_model=BulkAnalysisResponse)
async def bulk_analyze_links(
    request: BulkAnalysisRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """
    Perform bulk analysis of multiple URLs.
    
    Analyzes up to 50 URLs simultaneously with quick scan methodology.
    Results include summary statistics and individual URL assessments.
    """
    try:
        logger.info("Starting bulk link analysis", 
                   url_count=len(request.urls), 
                   user_id=current_user.id)
        
        start_time = time.time()
        analysis_id = f"bulk_analysis_{int(start_time)}_{current_user.id}"
        
        # Process URLs concurrently with limit
        semaphore = asyncio.Semaphore(10)  # Limit concurrent requests
        
        async def analyze_single_url(url: str) -> QuickScanResponse:
            async with semaphore:
                try:
                    scan_start = time.time()
                    scan_result = await link_analyzer.scan(url)
                    scan_time = int((time.time() - scan_start) * 1000)
                    
                    return QuickScanResponse(
                        url=url,
                        verdict=scan_result.get('verdict', 'unknown'),
                        threat_score=scan_result.get('threat_score', 0.0),
                        confidence=scan_result.get('confidence', 0.0),
                        redirect_count=len(scan_result.get('redirect_chain', [])),
                        final_url=scan_result.get('raw_data', {}).get('final_url', url),
                        cloaking_detected=scan_result.get('cloaking_detected', False),
                        key_indicators=scan_result.get('indicators', [])[:3],
                        analysis_time_ms=scan_time
                    )
                except Exception as e:
                    logger.warning(f"Individual URL analysis failed: {url}: {e}")
                    return QuickScanResponse(
                        url=url,
                        verdict='error',
                        threat_score=0.0,
                        confidence=0.0,
                        redirect_count=0,
                        final_url=url,
                        cloaking_detected=False,
                        key_indicators=[f'scan_error: {str(e)}'],
                        analysis_time_ms=0
                    )
        
        # Execute all analyses
        results = await asyncio.gather(*[
            analyze_single_url(str(url)) for url in request.urls
        ])
        
        # Calculate summary statistics
        completed = sum(1 for r in results if r.verdict != 'error')
        failed = len(results) - completed
        
        threat_counts = {
            'safe': sum(1 for r in results if r.verdict == 'safe'),
            'suspicious': sum(1 for r in results if r.verdict == 'suspicious'),
            'malicious': sum(1 for r in results if r.verdict == 'malicious'),
            'error': failed
        }
        
        avg_threat_score = sum(r.threat_score for r in results) / len(results) if results else 0.0
        total_redirects = sum(r.redirect_count for r in results)
        cloaking_detected = sum(1 for r in results if r.cloaking_detected)
        
        analysis_summary = {
            'threat_distribution': threat_counts,
            'average_threat_score': round(avg_threat_score, 3),
            'total_redirects_detected': total_redirects,
            'cloaking_instances': cloaking_detected,
            'analysis_duration_ms': int((time.time() - start_time) * 1000)
        }
        
        response = BulkAnalysisResponse(
            analysis_id=analysis_id,
            total_urls=len(request.urls),
            completed=completed,
            failed=failed,
            results=results,
            analysis_summary=analysis_summary,
            timestamp=datetime.utcnow()
        )
        
        # Background logging
        background_tasks.add_task(
            log_bulk_analysis_completion,
            current_user.id,
            len(request.urls),
            completed,
            failed,
            avg_threat_score
        )
        
        logger.info("Bulk analysis completed", 
                   analysis_id=analysis_id,
                   total_urls=len(request.urls),
                   completed=completed,
                   failed=failed)
        
        return response
        
    except Exception as e:
        logger.error("Bulk analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Bulk analysis failed: {str(e)}")


@router.get("/health")
async def health_check():
    """
    Check the health status of the link redirect analyzer service.
    """
    try:
        health_status = await link_analyzer.health_check()
        
        return {
            "status": health_status.status.value,
            "service": "link_redirect_analyzer",
            "timestamp": datetime.utcnow().isoformat(),
            "details": {
                "max_redirects": link_analyzer.max_redirects,
                "max_analysis_time": link_analyzer.max_analysis_time,
                "user_agents_available": len(link_analyzer.user_agents),
                "browser_ready": link_analyzer._browser is not None
            }
        }
        
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unavailable",
                "service": "link_redirect_analyzer",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )


@router.get("/statistics")
async def get_analysis_statistics(
    days: int = Query(7, ge=1, le=30, description="Number of days to include in statistics"),
    current_user: User = Depends(get_current_user)
):
    """
    Get link analysis statistics for the current user.
    """
    try:
        # This would typically query a database for user's analysis history
        # For now, return a placeholder response
        
        return {
            "user_id": current_user.id,
            "period_days": days,
            "statistics": {
                "total_analyses": 0,
                "urls_analyzed": 0,
                "threats_detected": 0,
                "cloaking_instances": 0,
                "average_threat_score": 0.0,
                "most_common_indicators": [],
                "analysis_trends": {}
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error("Statistics retrieval failed", error=str(e))
        raise HTTPException(status_code=500, detail="Statistics retrieval failed")


# Background task functions
async def log_analysis_completion(user_id: int, url: str, threat_score: float, execution_time_ms: int):
    """Log analysis completion for analytics."""
    try:
        logger.info("Analysis logged", 
                   user_id=user_id,
                   url=url,
                   threat_score=threat_score,
                   execution_time_ms=execution_time_ms)
        # Here you would typically store to database
    except Exception as e:
        logger.warning(f"Analysis logging failed: {e}")


async def log_bulk_analysis_completion(user_id: int, total_urls: int, completed: int, 
                                     failed: int, avg_threat_score: float):
    """Log bulk analysis completion for analytics."""
    try:
        logger.info("Bulk analysis logged",
                   user_id=user_id,
                   total_urls=total_urls,
                   completed=completed,
                   failed=failed,
                   avg_threat_score=avg_threat_score)
        # Here you would typically store to database
    except Exception as e:
        logger.warning(f"Bulk analysis logging failed: {e}")