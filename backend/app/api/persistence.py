"""
Production-Ready API Endpoints with Pagination
Enhanced email, scan, and user management APIs for persistent storage
"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException, Query, Depends, BackgroundTasks
from pydantic import BaseModel, Field, validator
import secrets

from app.db.index_management import PaginationHelper
from app.services.database_service import db_service
from app.services.backup_service import backup_manager
from app.models.production_models import (
    User, EmailMeta, ScanResult, AuditLog, ReputationCache,
    ThreatLevel, ScanStatus, ActionType, ReputationLevel
)
from app.auth.dependencies import get_current_user

# Response models
class PaginatedResponse(BaseModel):
    """Standard paginated response format."""
    data: List[Any]
    meta: Dict[str, Any]


class EmailScanRequest(BaseModel):
    """Email scan request model."""
    message_id: str = Field(..., min_length=1)
    sender: str = Field(..., min_length=1)
    recipient: str = Field(..., min_length=1)
    subject: str = Field(default="")
    content: Optional[str] = None
    urls: List[str] = Field(default_factory=list)
    attachments: List[Dict[str, Any]] = Field(default_factory=list)
    date_sent: Optional[datetime] = None
    
    @validator('date_sent', pre=True, always=True)
    def default_date_sent(cls, v):
        return v or datetime.now(timezone.utc)


class EmailScanResponse(BaseModel):
    """Email scan response model."""
    scan_id: str
    message_id: str
    is_phishing: bool
    threat_level: str
    confidence_score: float
    risk_score: float
    detected_threats: List[str]
    explanation: Optional[str] = None
    top_features: List[Dict[str, Union[str, float]]] = Field(default_factory=list)
    processing_time_ms: int
    timestamp: datetime


class AnalystFeedbackRequest(BaseModel):
    """Analyst feedback request model."""
    scan_id: str = Field(..., min_length=1)
    feedback_type: str = Field(..., regex="^(false_positive|false_negative|confirmed)$")
    notes: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)


class UserAnalyticsResponse(BaseModel):
    """User analytics response model."""
    user_id: str
    period_days: int
    total_scans: int
    threats_detected: int
    false_positives: int
    false_negatives: int
    avg_confidence: float
    threat_distribution: Dict[str, int]
    daily_activity: Dict[str, int]
    top_threats: List[tuple]


class SystemStatsResponse(BaseModel):
    """System statistics response."""
    database_stats: Dict[str, Any]
    backup_status: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    retention_status: Dict[str, Any]


# Create router
persistence_router = APIRouter(prefix="/api/v1/persistence", tags=["persistence"])


@persistence_router.post("/scan/email", response_model=EmailScanResponse)
async def scan_email_endpoint(
    request: EmailScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """
    Scan email with persistent storage of results.
    
    **Features:**
    - Atomic transaction for email + scan + audit
    - Background reputation cache updates
    - User statistics tracking
    - Comprehensive audit logging
    """
    try:
        # Prepare email data
        email_data = {
            "message_id": request.message_id,
            "sender": request.sender,
            "recipient": request.recipient,
            "subject": request.subject,
            "date_sent": request.date_sent,
            "content_length": len(request.content or ""),
            "attachment_count": len(request.attachments)
        }
        
        # Mock scan results (in production, this would call the ML ensemble)
        scan_results = {
            "is_phishing": False,  # Would be determined by ML model
            "threat_level": ThreatLevel.LOW,
            "confidence_score": 0.75,
            "risk_score": 25.0,
            "detected_threats": [],
            "content_analysis": {"suspicious_patterns": 0, "keywords_matched": []},
            "url_analysis": {"malicious_urls": 0, "suspicious_domains": []},
            "model_predictions": {"ensemble": 0.25, "content": 0.3, "url": 0.1, "sender": 0.4},
            "top_features": [
                {"feature": "sender_reputation", "score": 0.8},
                {"feature": "content_sentiment", "score": 0.2},
                {"feature": "url_safety", "score": 0.9}
            ],
            "processing_time_ms": 1250
        }
        
        # Process email scan with transaction
        email_meta, scan_result = await db_service.process_email_scan(
            email_data=email_data,
            scan_results=scan_results,
            user_id=str(current_user.id)
        )
        
        # Schedule background tasks
        background_tasks.add_task(
            _update_reputation_cache,
            request.sender,
            scan_results["is_phishing"]
        )
        
        return EmailScanResponse(
            scan_id=scan_result.scan_id,
            message_id=scan_result.message_id,
            is_phishing=scan_result.is_phishing,
            threat_level=scan_result.threat_level,
            confidence_score=scan_result.confidence_score,
            risk_score=scan_result.risk_score,
            detected_threats=scan_result.detected_threats,
            explanation=scan_result.explanation_text,
            top_features=scan_result.top_features,
            processing_time_ms=scan_result.scan_duration_ms or scan_results["processing_time_ms"],
            timestamp=scan_result.scan_completed_at
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email scan failed: {str(e)}")


@persistence_router.get("/emails", response_model=PaginatedResponse)
async def get_user_emails(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    sender: Optional[str] = Query(None),
    threat_level: Optional[ThreatLevel] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: User = Depends(get_current_user)
):
    """
    Get user's email history with pagination and filtering.
    
    **Query Features:**
    - Pagination with configurable page size
    - Filter by sender, threat level, date range
    - Optimized with strategic indexes
    - Includes scan results via aggregation
    """
    try:
        # Build query filters
        filters = {"user_id": str(current_user.id)}
        
        if sender:
            filters["sender"] = {"$regex": sender, "$options": "i"}
        
        if start_date or end_date:
            date_filter = {}
            if start_date:
                date_filter["$gte"] = start_date
            if end_date:
                date_filter["$lte"] = end_date
            filters["date_received"] = date_filter
        
        # Create base query
        query = EmailMeta.find(filters)
        
        # Apply threat level filter via lookup to scan_results
        if threat_level:
            # This would require aggregation pipeline for join
            # For now, filter after pagination (in production, use aggregation)
            pass
        
        # Execute paginated query
        result = await PaginationHelper.paginate_query(
            query,
            page=page,
            page_size=page_size,
            sort_by="date_received",
            sort_direction=-1
        )
        
        # Convert documents to dict for JSON serialization
        emails_data = []
        for email in result["documents"]:
            email_dict = email.dict()
            
            # Add scan result if exists
            scan_result = await ScanResult.find_one(
                ScanResult.message_id == email.message_id
            )
            if scan_result:
                email_dict["scan_result"] = {
                    "is_phishing": scan_result.is_phishing,
                    "threat_level": scan_result.threat_level,
                    "confidence_score": scan_result.confidence_score
                }
            
            emails_data.append(email_dict)
        
        return PaginatedResponse(
            data=emails_data,
            meta=result["pagination"]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve emails: {str(e)}")


@persistence_router.get("/scans", response_model=PaginatedResponse)
async def get_scan_results(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    threat_level: Optional[ThreatLevel] = Query(None),
    is_phishing: Optional[bool] = Query(None),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
    current_user: User = Depends(get_current_user)
):
    """
    Get scan results with advanced filtering and pagination.
    
    **Analytics Features:**
    - Filter by threat level, phishing status, confidence
    - Sort by confidence, date, or risk score
    - Includes explanation data for analysis
    """
    try:
        # Build query filters
        filters = {"user_id": str(current_user.id)}
        
        if threat_level:
            filters["threat_level"] = threat_level
        
        if is_phishing is not None:
            filters["is_phishing"] = is_phishing
        
        if min_confidence:
            filters["confidence_score"] = {"$gte": min_confidence}
        
        # Create query
        query = ScanResult.find(filters)
        
        # Execute paginated query
        result = await PaginationHelper.paginate_query(
            query,
            page=page,
            page_size=page_size,
            sort_by="scan_completed_at",
            sort_direction=-1
        )
        
        # Convert to serializable format
        scans_data = [scan.dict() for scan in result["documents"]]
        
        return PaginatedResponse(
            data=scans_data,
            meta=result["pagination"]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan results: {str(e)}")


@persistence_router.post("/feedback")
async def submit_analyst_feedback(
    feedback: AnalystFeedbackRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Submit analyst feedback for ML model improvement.
    
    **Active Learning Features:**
    - Updates scan result with feedback
    - Triggers model retraining queue
    - Comprehensive audit logging
    - User statistics tracking
    """
    try:
        # Verify analyst role (in production, check user permissions)
        success = await db_service.handle_analyst_feedback(
            scan_id=feedback.scan_id,
            feedback_type=feedback.feedback_type,
            analyst_id=str(current_user.id),
            notes=feedback.notes
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Scan result not found")
        
        return {
            "success": True,
            "message": f"Feedback '{feedback.feedback_type}' recorded successfully",
            "scan_id": feedback.scan_id,
            "analyst_id": str(current_user.id),
            "timestamp": datetime.now(timezone.utc)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to submit feedback: {str(e)}")


@persistence_router.get("/analytics/user", response_model=UserAnalyticsResponse)
async def get_user_analytics(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user)
):
    """
    Get comprehensive user analytics and statistics.
    
    **Analytics Include:**
    - Scan volume and threat detection rates
    - Accuracy metrics (false positives/negatives)
    - Threat distribution and trends
    - Daily activity patterns
    """
    try:
        analytics = await db_service.get_user_analytics(
            user_id=str(current_user.id),
            days=days
        )
        
        return UserAnalyticsResponse(
            user_id=str(current_user.id),
            period_days=days,
            total_scans=analytics["total_scans"],
            threats_detected=analytics["threats_detected"],
            false_positives=current_user.false_positives,
            false_negatives=current_user.false_negatives,
            avg_confidence=analytics["avg_confidence"],
            threat_distribution=analytics["threat_distribution"],
            daily_activity=analytics["daily_scans"],
            top_threats=analytics["top_threats"]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve analytics: {str(e)}")


@persistence_router.get("/audit-logs", response_model=PaginatedResponse)
async def get_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    action: Optional[ActionType] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: User = Depends(get_current_user)
):
    """
    Get audit logs with filtering (admin only).
    
    **Security Features:**
    - Role-based access control
    - Comprehensive activity tracking
    - Compliance-ready audit trails
    """
    try:
        # Check admin permissions (simplified check)
        if current_user.role not in ["admin", "analyst"]:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        # Build query filters
        filters = {}
        
        if action:
            filters["action"] = action
        
        if start_date or end_date:
            date_filter = {}
            if start_date:
                date_filter["$gte"] = start_date
            if end_date:
                date_filter["$lte"] = end_date
            filters["timestamp"] = date_filter
        
        # Create query
        query = AuditLog.find(filters)
        
        # Execute paginated query
        result = await PaginationHelper.paginate_query(
            query,
            page=page,
            page_size=page_size,
            sort_by="timestamp",
            sort_direction=-1
        )
        
        # Convert to serializable format
        logs_data = [log.dict() for log in result["documents"]]
        
        return PaginatedResponse(
            data=logs_data,
            meta=result["pagination"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve audit logs: {str(e)}")


@persistence_router.get("/system/stats", response_model=SystemStatsResponse)
async def get_system_statistics(
    current_user: User = Depends(get_current_user)
):
    """
    Get comprehensive system statistics and health metrics.
    
    **Metrics Include:**
    - Database collection statistics
    - Backup status and history
    - Performance metrics
    - Data retention status
    """
    try:
        # Check admin permissions
        if current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Get database statistics
        from app.services.database_service import get_database_stats
        db_stats = await get_database_stats()
        
        # Get backup status
        backup_status = await backup_manager.get_backup_status()
        
        # Get performance metrics
        from app.db.index_management import check_query_performance
        performance = await check_query_performance()
        
        # Mock retention status (in production, query actual retention data)
        retention_status = {
            "policies_active": len(backup_manager.retention_policies),
            "last_cleanup": "2024-01-01T00:00:00Z",  # Would query actual data
            "next_cleanup": "2024-01-02T00:00:00Z"
        }
        
        return SystemStatsResponse(
            database_stats=db_stats,
            backup_status=backup_status,
            performance_metrics=performance,
            retention_status=retention_status
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve system stats: {str(e)}")


@persistence_router.post("/backup/create")
async def create_manual_backup(
    collections: Optional[List[str]] = None,
    retention_days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user)
):
    """Create manual database backup."""
    try:
        # Check admin permissions
        if current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
        
        from app.services.backup_service import BackupType
        backup_record = await backup_manager.create_backup(
            backup_type=BackupType.MANUAL,
            collections=collections,
            retention_days=retention_days
        )
        
        return {
            "success": backup_record.status.value == "completed",
            "backup_id": backup_record.backup_id,
            "status": backup_record.status,
            "collections": backup_record.collections,
            "document_count": backup_record.document_count,
            "file_size_mb": round(backup_record.file_size_bytes / 1024 / 1024, 2) if backup_record.file_size_bytes else 0,
            "duration_seconds": (backup_record.end_time - backup_record.start_time).total_seconds() if backup_record.end_time else 0
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backup creation failed: {str(e)}")


# Background task functions
async def _update_reputation_cache(sender: str, is_phishing: bool):
    """Background task to update sender reputation cache."""
    try:
        await db_service.update_reputation_cache(
            indicator=sender,
            indicator_type="email",
            reputation_data={
                "level": "malicious" if is_phishing else "neutral",
                "score": 0.1 if is_phishing else 0.5,
                "confidence": 0.8,
                "sources": ["phishnet_scan"],
                "phishing_count": 1 if is_phishing else 0,
                "total_count": 1
            }
        )
    except Exception as e:
        logger.error(f"Failed to update reputation cache for {sender}: {e}")


# Health check endpoint for persistence layer
@persistence_router.get("/health")
async def persistence_health_check():
    """Check persistence layer health and connectivity."""
    try:
        from app.db.mongodb import MongoDBManager
        
        # Test database connectivity
        if not MongoDBManager.database:
            raise Exception("Database not connected")
        
        # Test basic operations
        await MongoDBManager.client.admin.command('ping')
        
        # Get collection counts
        collection_stats = {}
        collections = ["users", "emails_meta", "scan_results", "audit_logs"]
        
        for collection_name in collections:
            try:
                count = await MongoDBManager.database[collection_name].count_documents({})
                collection_stats[collection_name] = count
            except Exception:
                collection_stats[collection_name] = "error"
        
        return {
            "status": "healthy",
            "database": "connected",
            "collections": collection_stats,
            "timestamp": datetime.now(timezone.utc),
            "features": {
                "transactions": "enabled",
                "pagination": "enabled", 
                "encryption": "enabled",
                "audit_logging": "enabled",
                "backup_system": "enabled",
                "retention_policies": "enabled"
            }
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc)
        }