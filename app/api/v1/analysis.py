"""API endpoints for advanced email analysis features."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models.core.user import User
from app.models.core.email import Email
from app.models.analysis.link_analysis import LinkAnalysis, EmailAIResults, EmailIndicators
from app.schemas.analysis import (
    LinkAnalysisResponse, LinkAnalysisDetail, LinkChainViewer,
    EmailAIResultsResponse, AIAnalysisRequest, AIAnalysisResponse,
    EmailIndicatorsResponse, ThreatIntelResponse, ThreatBadge,
    EmailAnalysisSummary, BulkAnalysisRequest, BulkAnalysisResponse,
    AnalysisDashboard
)
from app.orchestrator.utils import process_email_comprehensive
from app.services.link_analyzer import analyze_email_links
from app.services.ai_analyzer import analyze_email_with_ai
from app.services.threat_intel import analyze_email_threat_intel
from app.config.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/analysis", tags=["analysis"])


# Link Analysis Endpoints
@router.get("/links/{email_id}", response_model=List[LinkAnalysisResponse])
async def get_email_link_analysis(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get link analysis results for an email."""
    # Check if user has access to this email
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    if email.user_id != current_user.id and current_user.role.value not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get link analysis results
    link_analyses = db.query(LinkAnalysis).filter(LinkAnalysis.email_id == email_id).all()
    
    return [LinkAnalysisResponse.from_orm(analysis) for analysis in link_analyses]


@router.get("/links/detail/{link_id}", response_model=LinkAnalysisDetail)
async def get_link_analysis_detail(
    link_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed link analysis with full redirect chain."""
    link_analysis = db.query(LinkAnalysis).filter(LinkAnalysis.id == link_id).first()
    if not link_analysis:
        raise HTTPException(status_code=404, detail="Link analysis not found")
    
    # Check access permissions
    email = db.query(Email).filter(Email.id == link_analysis.email_id).first()
    if email.user_id != current_user.id and current_user.role.value not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Convert to detailed response with redirect steps
    detail = LinkAnalysisDetail.from_orm(link_analysis)
    
    # Parse redirect chain into steps
    if link_analysis.redirect_chain:
        from app.schemas.analysis import RedirectStep
        detail.redirect_steps = [
            RedirectStep(**step) for step in link_analysis.redirect_chain
        ]
    
    return detail


@router.post("/links/analyze/{email_id}")
async def trigger_link_analysis(
    email_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    """Trigger link analysis for an email."""
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    # Extract URLs from email content
    from app.services.sanitizer import ContentSanitizer
    sanitizer = ContentSanitizer()
    content = f"{email.raw_html or ''} {email.raw_text or ''}"
    urls = sanitizer.extract_urls(content)
    
    if not urls:
        raise HTTPException(status_code=400, detail="No URLs found in email")
    
    # Start background analysis
    background_tasks.add_task(analyze_email_links, email_id, urls[:10])  # Limit to 10 URLs
    
    return {"message": f"Link analysis started for {len(urls[:10])} URLs", "urls": urls[:10]}


@router.get("/links/chain/{link_id}", response_model=LinkChainViewer)
async def get_link_chain_viewer(
    link_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get link chain data for visualization."""
    link_analysis = db.query(LinkAnalysis).filter(LinkAnalysis.id == link_id).first()
    if not link_analysis:
        raise HTTPException(status_code=404, detail="Link analysis not found")
    
    # Check access permissions
    email = db.query(Email).filter(Email.id == link_analysis.email_id).first()
    if email.user_id != current_user.id and current_user.role.value not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Build chain viewer data
    chain_steps = []
    if link_analysis.redirect_chain:
        from app.schemas.analysis import RedirectStep
        chain_steps = [RedirectStep(**step) for step in link_analysis.redirect_chain]
    
    return LinkChainViewer(
        link_id=link_id,
        original_url=link_analysis.original_url,
        final_url=link_analysis.final_url or link_analysis.original_url,
        chain_steps=chain_steps,
        risk_assessment={
            "risk_score": link_analysis.risk_score,
            "risk_reasons": link_analysis.risk_reasons or [],
            "domain_mismatch": link_analysis.domain_mismatch,
            "has_punycode": link_analysis.has_punycode,
            "is_lookalike": link_analysis.is_lookalike
        },
        visual_data={
            "total_steps": link_analysis.redirect_count,
            "has_javascript": link_analysis.has_javascript_redirect == "yes",
            "has_meta_refresh": link_analysis.has_meta_redirect == "yes",
            "analysis_duration": link_analysis.analysis_duration
        }
    )


# AI Analysis Endpoints
@router.get("/ai/{email_id}", response_model=EmailAIResultsResponse)
async def get_email_ai_analysis(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get AI analysis results for an email."""
    # Check access permissions
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    if email.user_id != current_user.id and current_user.role.value not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get AI analysis results
    ai_result = db.query(EmailAIResults).filter(EmailAIResults.email_id == email_id).first()
    if not ai_result:
        raise HTTPException(status_code=404, detail="AI analysis not found")
    
    return EmailAIResultsResponse.from_orm(ai_result)


@router.post("/ai/analyze/{email_id}", response_model=AIAnalysisResponse)
async def trigger_ai_analysis(
    email_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    """Trigger AI analysis for an email."""
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    # Prepare content for AI analysis
    content_text = email.raw_text or ""
    if not content_text and email.sanitized_html:
        # Extract text from HTML
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(email.sanitized_html, 'html.parser')
        content_text = soup.get_text()
    
    if len(content_text.strip()) < 10:
        raise HTTPException(status_code=400, detail="Insufficient content for AI analysis")
    
    # Extract domains for context
    from app.services.sanitizer import ContentSanitizer
    sanitizer = ContentSanitizer()
    content = f"{email.raw_html or ''} {email.raw_text or ''}"
    urls = sanitizer.extract_urls(content)
    domains = []
    for url in urls:
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc.lower()
            if domain:
                domains.append(domain)
        except:
            continue
    
    # Start background analysis
    background_tasks.add_task(
        analyze_email_with_ai,
        email_id,
        email.subject or "",
        email.sender,
        content_text,
        email.sanitized_html,
        list(set(domains))
    )
    
    return AIAnalysisResponse(
        is_phishing=False,  # Placeholder
        confidence=0.0,
        risk_score=0.0,
        reasoning="Analysis started in background",
        summary="AI analysis in progress",
        indicators=["analysis_pending"]
    )


# Threat Intelligence Endpoints
@router.get("/threats/{email_id}", response_model=List[EmailIndicatorsResponse])
async def get_email_threat_intel(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get threat intelligence results for an email."""
    # Check access permissions
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    if email.user_id != current_user.id and current_user.role.value not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get threat intelligence results
    indicators = db.query(EmailIndicators).filter(EmailIndicators.email_id == email_id).all()
    
    return [EmailIndicatorsResponse.from_orm(indicator) for indicator in indicators]


@router.get("/threats/badges/{email_id}", response_model=List[ThreatBadge])
async def get_threat_badges(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get threat indicator badges for UI display."""
    # Check access permissions
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    if email.user_id != current_user.id and current_user.role.value not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get indicators and convert to badges
    indicators = db.query(EmailIndicators).filter(EmailIndicators.email_id == email_id).all()
    
    badges = []
    for indicator in indicators:
        reputation = indicator.reputation_score or 0.0
        
        if reputation > 0.8:
            threat_level = "malicious"
            color = "red"
            icon = "warning"
        elif reputation > 0.5:
            threat_level = "suspicious"
            color = "orange"
            icon = "alert"
        else:
            threat_level = "safe"
            color = "green"
            icon = "check"
        
        badge = ThreatBadge(
            indicator=indicator.indicator,
            indicator_type=indicator.indicator_type,
            threat_level=threat_level,
            confidence=reputation,
            source=indicator.source,
            tooltip=f"{indicator.source}: {threat_level} ({reputation:.0%} confidence)",
            color=color,
            icon=icon
        )
        badges.append(badge)
    
    return badges


@router.post("/threats/analyze/{email_id}")
async def trigger_threat_analysis(
    email_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    """Trigger threat intelligence analysis for an email."""
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    # Start background analysis
    content = f"{email.raw_html or ''} {email.raw_text or ''}"
    headers = email.raw_headers or ""
    
    background_tasks.add_task(analyze_email_threat_intel, email_id, content, headers)
    
    return {"message": "Threat intelligence analysis started"}


# Comprehensive Analysis Endpoints
@router.get("/summary/{email_id}", response_model=EmailAnalysisSummary)
async def get_analysis_summary(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive analysis summary for an email."""
    # Check access permissions
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    if email.user_id != current_user.id and current_user.role.value not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get all analysis results
    link_analyses = db.query(LinkAnalysis).filter(LinkAnalysis.email_id == email_id).all()
    ai_result = db.query(EmailAIResults).filter(EmailAIResults.email_id == email_id).first()
    threat_indicators = db.query(EmailIndicators).filter(EmailIndicators.email_id == email_id).all()
    
    # Build summary
    from app.schemas.analysis import LinkAnalysisResponse, EmailIndicatorsResponse
    
    summary = EmailAnalysisSummary(
        email_id=email_id,
        overall_risk_score=email.score or 0.0,
        risk_level="unknown" if not email.score else (
            "high" if email.score > 0.7 else
            "medium" if email.score > 0.4 else "low"
        ),
        analysis_status="completed" if email.analyzed_at else "pending",
        link_analysis=[LinkAnalysisResponse.from_orm(link) for link in link_analyses],
        ai_analysis=EmailAIResultsResponse.from_orm(ai_result) if ai_result else None,
        threat_intel=[EmailIndicatorsResponse.from_orm(indicator) for indicator in threat_indicators],
        total_links=len(link_analyses),
        suspicious_links=len([link for link in link_analyses if link.risk_score > 0.5]),
        malicious_indicators=len([ind for ind in threat_indicators if (ind.reputation_score or 0) > 0.7])
    )
    
    return summary


@router.post("/comprehensive/{email_id}", response_model=EmailAnalysisSummary)
async def trigger_comprehensive_analysis(
    email_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    """Trigger comprehensive analysis for an email."""
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    # Start comprehensive analysis
    background_tasks.add_task(process_email_comprehensive, email_id)
    
    return EmailAnalysisSummary(
        email_id=email_id,
        overall_risk_score=0.0,
        risk_level="unknown",
        analysis_status="processing",
        total_links=0,
        suspicious_links=0,
        malicious_indicators=0,
        risk_factors=["Analysis in progress"],
        recommendations=["Please wait for analysis to complete"]
    )


# Bulk Analysis Endpoints
@router.post("/bulk", response_model=BulkAnalysisResponse)
async def trigger_bulk_analysis(
    request: BulkAnalysisRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    """Trigger bulk analysis for multiple emails."""
    # Validate email IDs
    valid_emails = db.query(Email).filter(Email.id.in_(request.email_ids)).all()
    
    if len(valid_emails) != len(request.email_ids):
        invalid_ids = set(request.email_ids) - set(email.id for email in valid_emails)
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid email IDs: {list(invalid_ids)}"
        )
    
    # Generate job ID
    import uuid
    job_id = str(uuid.uuid4())
    
    # Start background processing
    for email_id in request.email_ids:
        background_tasks.add_task(process_email_comprehensive, email_id)
    
    return BulkAnalysisResponse(
        job_id=job_id,
        status="queued",
        total_emails=len(request.email_ids),
        processed_emails=0,
        failed_emails=0
    )


# Dashboard Endpoints
@router.get("/dashboard", response_model=AnalysisDashboard)
async def get_analysis_dashboard(
    days: int = Query(7, ge=1, le=30),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    """Get analysis dashboard data."""
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_
    
    # Date range
    since_date = datetime.utcnow() - timedelta(days=days)
    
    # Basic statistics
    total_analyzed = db.query(Email).filter(
        and_(Email.analyzed_at.isnot(None), Email.analyzed_at >= since_date)
    ).count()
    
    high_risk_emails = db.query(Email).filter(
        and_(Email.score > 0.7, Email.analyzed_at >= since_date)
    ).count()
    
    quarantined_emails = db.query(Email).filter(
        and_(Email.status == "quarantined", Email.analyzed_at >= since_date)
    ).count()
    
    # Get recent analyses (limit to 10)
    recent_emails = db.query(Email).filter(
        Email.analyzed_at >= since_date
    ).order_by(Email.analyzed_at.desc()).limit(10).all()
    
    recent_analyses = []
    for email in recent_emails:
        summary = EmailAnalysisSummary(
            email_id=email.id,
            overall_risk_score=email.score or 0.0,
            risk_level="high" if (email.score or 0) > 0.7 else "medium" if (email.score or 0) > 0.4 else "low",
            analysis_status="completed" if email.analyzed_at else "pending",
            total_links=0,  # Would need to query separately
            suspicious_links=0,
            malicious_indicators=0
        )
        recent_analyses.append(summary)
    
    # Top malicious domains (simplified)
    malicious_domains = db.query(
        EmailIndicators.indicator,
        func.count(EmailIndicators.id).label('count')
    ).filter(
        and_(
            EmailIndicators.indicator_type == 'domain',
            EmailIndicators.reputation_score > 0.7,
            EmailIndicators.first_seen >= since_date
        )
    ).group_by(EmailIndicators.indicator).order_by(func.count(EmailIndicators.id).desc()).limit(5).all()
    
    top_domains = [
        {"domain": domain, "count": count}
        for domain, count in malicious_domains
    ]
    
    return AnalysisDashboard(
        total_emails_analyzed=total_analyzed,
        high_risk_emails=high_risk_emails,
        quarantined_emails=quarantined_emails,
        false_positives=0,  # Would need separate tracking
        recent_analyses=recent_analyses,
        avg_analysis_time=None,  # Would need separate calculation
        success_rate=None,  # Would need separate calculation
        top_malicious_domains=top_domains,
        top_threat_types=[]  # Would need separate analysis
    )
