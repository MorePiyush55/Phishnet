"""Email analysis API routes."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.services.email_processor import email_processor
from app.schemas.email import (
    EmailRequest, EmailAnalysisResponse, DetectionResult,
    EmailListResponse, DetectionListResponse
)
from app.config.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()


@router.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(
    email_request: EmailRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Analyze email for phishing detection."""
    try:
        # Analyze email
        detection_result = await email_processor.analyze_email(
            email_request, current_user.id, db
        )
        
        # Generate recommendations
        recommendations = _generate_recommendations(detection_result)
        
        # Generate threat indicators
        threat_indicators = _generate_threat_indicators(detection_result)
        
        return EmailAnalysisResponse(
            email={
                "email_id": detection_result.detection_id,  # Using detection_id as email_id for now
                "subject": email_request.subject,
                "sender": email_request.sender or "unknown",
                "recipients": email_request.recipients or [],
                "content_hash": "hash",  # This would be from the email model
                "size_bytes": len(email_request.content.encode('utf-8')),
                "received_at": detection_result.created_at
            },
            detection=detection_result,
            recommendations=recommendations,
            threat_indicators=threat_indicators
        )
        
    except Exception as e:
        logger.error(f"Email analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze email"
        )


@router.post("/analyze-file")
async def analyze_email_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Analyze email from uploaded file."""
    # Validate file type
    if not file.filename or not any(
        file.filename.endswith(ext) for ext in ['.eml', '.msg', '.txt']
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. Supported: .eml, .msg, .txt"
        )
    
    # Validate file size
    if file.size and file.size > 10 * 1024 * 1024:  # 10MB
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File too large. Maximum size: 10MB"
        )
    
    try:
        # Read file content
        content = await file.read()
        content_str = content.decode('utf-8', errors='ignore')
        
        # Create email request
        email_request = EmailRequest(
            content=content_str,
            content_type="text/plain"
        )
        
        # Analyze email
        detection_result = await email_processor.analyze_email(
            email_request, current_user.id, db
        )
        
        return {
            "filename": file.filename,
            "detection": detection_result,
            "recommendations": _generate_recommendations(detection_result),
            "threat_indicators": _generate_threat_indicators(detection_result)
        }
        
    except Exception as e:
        logger.error(f"File analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze email file"
        )


@router.get("/history", response_model=DetectionListResponse)
async def get_detection_history(
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's detection history."""
    try:
        detections = await email_processor.get_detection_history(
            current_user.id, db, limit, offset
        )
        
        # Get total count
        total = db.query(Detection).filter(Detection.user_id == current_user.id).count()
        
        return DetectionListResponse(
            detections=detections,
            total=total,
            page=offset // limit + 1,
            size=limit,
            has_next=offset + limit < total,
            has_prev=offset > 0
        )
        
    except Exception as e:
        logger.error(f"Failed to get detection history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve detection history"
        )


@router.get("/stats")
async def get_detection_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detection statistics for current user."""
    try:
        stats = await email_processor.get_detection_stats(current_user.id, db)
        return stats
        
    except Exception as e:
        logger.error(f"Failed to get detection stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve detection statistics"
        )


@router.get("/detection/{detection_id}", response_model=DetectionResult)
async def get_detection(
    detection_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get specific detection result."""
    from app.models.detection import Detection
    
    detection = db.query(Detection).filter(
        Detection.id == detection_id,
        Detection.user_id == current_user.id
    ).first()
    
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found"
        )
    
    return DetectionResult(
        detection_id=detection.id,
        is_phishing=detection.is_phishing,
        confidence_score=detection.confidence_score,
        risk_level=detection.risk_level,
        model_version=detection.model_version,
        model_type=detection.model_type,
        features=detection.features,
        risk_factors=detection.risk_factors,
        processing_time_ms=detection.processing_time_ms,
        created_at=detection.created_at
    )


def _generate_recommendations(detection_result: DetectionResult) -> List[str]:
    """Generate recommendations based on detection result."""
    recommendations = []
    
    if detection_result.is_phishing:
        recommendations.append("This email appears to be a phishing attempt.")
        recommendations.append("Do not click on any links or download attachments.")
        recommendations.append("Do not provide any personal or financial information.")
        recommendations.append("Report this email to your IT security team.")
        
        if detection_result.risk_level in ["HIGH", "CRITICAL"]:
            recommendations.append("Consider blocking the sender's email address.")
            recommendations.append("Scan your system for malware if you interacted with this email.")
    else:
        recommendations.append("This email appears to be legitimate.")
        recommendations.append("Exercise normal caution when handling email content.")
    
    # Add specific recommendations based on risk factors
    if detection_result.risk_factors:
        for factor in detection_result.risk_factors:
            if "JavaScript" in factor:
                recommendations.append("Be cautious of emails containing JavaScript code.")
            elif "shortened URLs" in factor:
                recommendations.append("Avoid clicking on shortened URLs without verification.")
            elif "forms" in factor:
                recommendations.append("Be wary of emails requesting information through forms.")
    
    return recommendations


def _generate_threat_indicators(detection_result: DetectionResult) -> dict:
    """Generate threat indicators for visualization."""
    return {
        "risk_level": detection_result.risk_level,
        "confidence_score": detection_result.confidence_score,
        "is_phishing": detection_result.is_phishing,
        "risk_factors_count": len(detection_result.risk_factors or []),
        "processing_time": detection_result.processing_time_ms,
        "model_type": detection_result.model_type,
        "threat_score": detection_result.confidence_score * 100
    }
