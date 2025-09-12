"""
Links API v1 - Link analysis endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, HttpUrl
from datetime import datetime
import asyncio

from app.core.database import get_db
from app.models.email import Email
from app.models.user import User
from app.api.v1.auth import get_current_user
from app.services.email_processor import EmailProcessor

router = APIRouter()

# Request/Response Models
class LinkDetail(BaseModel):
    original: str
    final: str
    risk: str  # low, medium, high
    reasons: List[str]
    chain: List[str]  # redirect chain
    analysis_timestamp: datetime

class EmailLinksResponse(BaseModel):
    email_id: int
    links: List[LinkDetail]
    total_links: int
    high_risk_count: int

class LinkAnalysisRequest(BaseModel):
    url: HttpUrl

class LinkAnalysisResult(BaseModel):
    url: str
    final_url: str
    risk_score: float
    risk_level: str
    reasons: List[str]
    redirect_chain: List[str]
    domain_reputation: Optional[dict] = None
    threat_intel: Optional[dict] = None
    analysis_timestamp: datetime

# Endpoints
@router.get("/emails/{email_id}/links", response_model=EmailLinksResponse)
async def get_email_links(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all links from an email with analysis results
    
    **Contract**: GET /api/v1/emails/{id}/links
    - Output: { links:[ {original, final, risk, reasons, chain[]} ] }
    """
    
    email = db.query(Email).filter(Email.id == email_id).first()
    
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    # Get email processor instance
    processor = EmailProcessor()
    
    # Extract and analyze links
    try:
        # Get links from email metadata or re-extract
        if hasattr(email, 'links_analyzed') and email.links_analyzed:
            # Use cached analysis if available
            links_data = email.links_metadata or []
        else:
            # Re-analyze links
            links_data = await processor.extract_and_analyze_links(email.body_html or email.body_text)
            
            # Cache results
            email.links_metadata = links_data
            email.links_analyzed = datetime.utcnow()
            db.commit()
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Link analysis failed: {str(e)}")
    
    # Format response
    links = []
    high_risk_count = 0
    
    for link_data in links_data:
        risk_level = link_data.get('risk_level', 'low')
        if risk_level == 'high':
            high_risk_count += 1
            
        links.append(LinkDetail(
            original=link_data.get('original_url', ''),
            final=link_data.get('final_url', ''),
            risk=risk_level,
            reasons=link_data.get('risk_reasons', []),
            chain=link_data.get('redirect_chain', []),
            analysis_timestamp=datetime.fromisoformat(link_data.get('analyzed_at', datetime.utcnow().isoformat()))
        ))
    
    return EmailLinksResponse(
        email_id=email_id,
        links=links,
        total_links=len(links),
        high_risk_count=high_risk_count
    )

@router.post("/analyze", response_model=LinkAnalysisResult)
async def analyze_link(
    request: LinkAnalysisRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Analyze a single URL ad-hoc
    
    **Contract**: POST /api/v1/links/analyze
    - Input: { url }
    - Output: LinkAnalysisResult (ad-hoc)
    """
    
    processor = EmailProcessor()
    
    try:
        # Analyze the single URL
        analysis_result = await processor.analyze_single_url(str(request.url))
        
        return LinkAnalysisResult(
            url=str(request.url),
            final_url=analysis_result.get('final_url', str(request.url)),
            risk_score=analysis_result.get('risk_score', 0.0),
            risk_level=analysis_result.get('risk_level', 'low'),
            reasons=analysis_result.get('risk_reasons', []),
            redirect_chain=analysis_result.get('redirect_chain', []),
            domain_reputation=analysis_result.get('domain_reputation'),
            threat_intel=analysis_result.get('threat_intel'),
            analysis_timestamp=datetime.utcnow()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL analysis failed: {str(e)}")

@router.get("/stats")
async def get_link_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get link analysis statistics
    """
    
    # This would query the database for link statistics
    # For now, return mock data
    
    return {
        "total_links_analyzed": 1250,
        "high_risk_links": 45,
        "medium_risk_links": 123,
        "low_risk_links": 1082,
        "blocked_domains": 23,
        "redirect_chains_found": 234,
        "avg_risk_score": 0.23
    }
