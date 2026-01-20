"""
Organization-level Analytics API for Mode 1 (Bulk Forward)
"""

from fastapi import APIRouter, HTTPException, status, Depends
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from app.models.mongodb_models import ForwardedEmailAnalysis
from app.config.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

@router.get("/stats/{org_domain}")
async def get_org_stats(org_domain: str):
    """
    Get aggregated phishing stats for an organization domain.
    Used for the Mode 1 Bulk Forward Dashboard.
    """
    try:
        query = {"org_domain": org_domain.lower()}
        logger.info(f"Fetching stats for organization: {org_domain}")
        
        # Total counts
        total_checks = await ForwardedEmailAnalysis.find(query).count()
        
        if total_checks == 0:
            logger.info(f"No checks found for organization: {org_domain}")
            return {
                "success": True,
                "org_domain": org_domain,
                "total_checks": 0,
                "verdict_counts": {"PHISHING": 0, "SUSPICIOUS": 0, "SAFE": 0},
                "recent_history": []
            }
            
        phishing_count = await ForwardedEmailAnalysis.find(
            {"org_domain": org_domain.lower(), "risk_level": "PHISHING"}
        ).count()
        
        suspicious_count = await ForwardedEmailAnalysis.find(
            {"org_domain": org_domain.lower(), "risk_level": "SUSPICIOUS"}
        ).count()
        
        safe_count = total_checks - (phishing_count + suspicious_count)
        
        # Recent history
        history = await ForwardedEmailAnalysis.find(query).sort("-created_at").limit(20).to_list()
        
        return {
            "success": True,
            "org_domain": org_domain,
            "total_checks": total_checks,
            "verdict_counts": {
                "PHISHING": phishing_count,
                "SUSPICIOUS": suspicious_count,
                "SAFE": safe_count
            },
            "recent_history": history
        }
        
    except Exception as e:
        logger.error(f"Failed to fetch organization stats for {org_domain}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Backend error: {str(e)}"
        )

@router.get("/threats")
async def get_all_org_threats(limit: int = 50):
    """
    Get recent threats across all organizations.
    Used for a global SOC view.
    """
    try:
        threats = await ForwardedEmailAnalysis.find(
            ForwardedEmailAnalysis.risk_level != "SAFE"
        ).sort("-created_at").limit(limit).to_list()
        
        return {
            "success": True,
            "count": len(threats),
            "threats": threats
        }
    except Exception as e:
        logger.error(f"Failed to fetch global threats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
