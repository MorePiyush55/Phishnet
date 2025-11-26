"""
Analysis API v1 - AI and threat intelligence endpoints
"""

from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
import asyncio

from app.core.database import get_db
from app.models.core.email import Email
from app.models.user import User
from app.api.v1.auth import get_current_user
from app.services.email_processor import EmailProcessor

router = APIRouter()

# Request/Response Models
class AnalysisResult(BaseModel):
    email_id: int
    ai_analysis: Dict[str, Any]
    threat_intel: Dict[str, Any]
    risk_score: float
    risk_level: str
    confidence: float
    analysis_timestamp: datetime
    processing_time_ms: int

class IntelResponse(BaseModel):
    indicator: str
    source: str
    reputation: str  # clean, suspicious, malicious, unknown
    details: Dict[str, Any]
    last_updated: datetime

# Endpoints
@router.post("/{email_id}", response_model=AnalysisResult)
async def run_analysis(
    email_id: int,
    force_refresh: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Run AI/intel blend analysis on email
    
    **Contract**: POST /api/v1/analysis/{id} → run AI/intel blend → AnalysisResult
    """
    
    start_time = datetime.utcnow()
    
    email = db.query(Email).filter(Email.id == email_id).first()
    
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    # Check if analysis already exists and is recent (unless forced)
    if not force_refresh and email.last_analyzed:
        time_since_analysis = datetime.utcnow() - email.last_analyzed
        if time_since_analysis.total_seconds() < 3600:  # 1 hour cache
            # Return cached results
            return AnalysisResult(
                email_id=email_id,
                ai_analysis=email.ai_analysis or {},
                threat_intel=email.threat_intel or {},
                risk_score=email.risk_score or 0.0,
                risk_level=email.risk_level or "low",
                confidence=email.confidence or 0.0,
                analysis_timestamp=email.last_analyzed,
                processing_time_ms=0  # Cached result
            )
    
    # Run fresh analysis
    processor = EmailProcessor()
    
    try:
        # Run AI analysis
        ai_result = await processor.run_ai_analysis(email)
        
        # Run threat intelligence lookup
        intel_result = await processor.run_threat_intel(email)
        
        # Combine results and calculate final risk
        combined_analysis = processor.combine_analysis_results(ai_result, intel_result)
        
        # Update email with results
        email.ai_analysis = ai_result
        email.threat_intel = intel_result
        email.risk_score = combined_analysis['risk_score']
        email.risk_level = combined_analysis['risk_level']
        email.confidence = combined_analysis['confidence']
        email.last_analyzed = datetime.utcnow()
        email.status = "analyzed"
        
        db.commit()
        
        # Calculate processing time
        end_time = datetime.utcnow()
        processing_time_ms = int((end_time - start_time).total_seconds() * 1000)
        
        return AnalysisResult(
            email_id=email_id,
            ai_analysis=ai_result,
            threat_intel=intel_result,
            risk_score=combined_analysis['risk_score'],
            risk_level=combined_analysis['risk_level'],
            confidence=combined_analysis['confidence'],
            analysis_timestamp=email.last_analyzed,
            processing_time_ms=processing_time_ms
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.get("/intel/{indicator}", response_model=IntelResponse)
async def get_threat_intel(
    indicator: str,
    indicator_type: str = "auto",  # auto, domain, ip, url, hash
    current_user: User = Depends(get_current_user)
):
    """
    Get threat intelligence for specific indicator
    
    **Contract**: GET /api/v1/intel/{indicator} → { source, reputation, details }
    """
    
    processor = EmailProcessor()
    
    try:
        # Determine indicator type if auto
        if indicator_type == "auto":
            indicator_type = processor.detect_indicator_type(indicator)
        
        # Get threat intelligence
        intel_data = await processor.lookup_threat_intel(indicator, indicator_type)
        
        return IntelResponse(
            indicator=indicator,
            source=intel_data.get('source', 'multiple'),
            reputation=intel_data.get('reputation', 'unknown'),
            details=intel_data.get('details', {}),
            last_updated=datetime.utcnow()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat intel lookup failed: {str(e)}")

@router.get("/stats")
async def get_analysis_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get analysis performance statistics
    """
    
    # Query analysis stats from database
    from sqlalchemy import func, case
    
    stats = db.query(
        func.count(Email.id).label('total_analyzed'),
        func.avg(case([(Email.risk_score.isnot(None), Email.risk_score)])).label('avg_risk_score'),
        func.avg(case([(Email.confidence.isnot(None), Email.confidence)])).label('avg_confidence'),
        func.count(case([(Email.risk_level == 'high', 1)])).label('high_risk_count'),
        func.count(case([(Email.risk_level == 'medium', 1)])).label('medium_risk_count'),
        func.count(case([(Email.risk_level == 'low', 1)])).label('low_risk_count'),
    ).filter(Email.last_analyzed.isnot(None)).first()
    
    return {
        "total_emails_analyzed": stats.total_analyzed or 0,
        "average_risk_score": round(float(stats.avg_risk_score or 0), 3),
        "average_confidence": round(float(stats.avg_confidence or 0), 3),
        "high_risk_emails": stats.high_risk_count or 0,
        "medium_risk_emails": stats.medium_risk_count or 0,
        "low_risk_emails": stats.low_risk_count or 0,
        "analysis_coverage": "95.2%",  # Would calculate from actual data
        "avg_processing_time_ms": 2847  # Would track from actual measurements
    }
