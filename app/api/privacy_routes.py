"""
Privacy Dashboard API Routes
GDPR Article 15/17 compliance - data access, export, and deletion.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
import json
import io
import zipfile

from app.core.database import get_db
from app.core.auth import get_current_user
from app.services.consent_manager import get_consent_manager
from app.core.audit_logger import get_audit_logger, AuditEventType
from app.core.retention_manager import get_retention_manager
from app.core.rate_limiter import rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/privacy", tags=["privacy"])

# Pydantic models

class DataSummaryResponse(BaseModel):
    """User data summary response"""
    user_id: str
    total_artifacts: int
    total_size_bytes: int
    categories: Dict[str, Any]
    retention_preferences: Dict[str, Any]
    upcoming_expirations: List[Dict[str, Any]]
    consent_status: str
    data_processing_summary: Dict[str, Any]

class AuditTrailResponse(BaseModel):
    """Audit trail response"""
    user_id: str
    total_events: int
    events: List[Dict[str, Any]]
    date_range: Dict[str, str]
    event_types: List[str]

class DataExportResponse(BaseModel):
    """Data export response"""
    export_id: str
    status: str
    requested_at: str
    estimated_size_bytes: int
    includes: List[str]
    download_url: Optional[str] = None

class RetentionUpdateRequest(BaseModel):
    """Request to update retention preferences"""
    preferences: Dict[str, int]

class DataDeletionRequest(BaseModel):
    """Request to delete specific data"""
    categories: List[str]
    confirm_deletion: bool = False

# Endpoints

@router.get("/dashboard", response_model=DataSummaryResponse)
async def get_privacy_dashboard(
    current_user = Depends(get_current_user),
    consent_manager = Depends(get_consent_manager),
    retention_manager = Depends(get_retention_manager)
):
    """
    Get privacy dashboard with complete data summary (GDPR Article 15).
    """
    try:
        logger.info(f"Privacy dashboard requested by user {current_user.id}")
        
        # Get user consent status
        consent = await consent_manager.get_user_consent(current_user.id)
        
        # Get data summary
        data_summary = retention_manager.get_user_data_summary(current_user.id)
        
        if 'error' in data_summary:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=data_summary['error']
            )
        
        # Get data processing summary
        processing_summary = await _get_data_processing_summary(current_user.id)
        
        # Audit the dashboard access
        audit_logger = get_audit_logger()
        audit_logger.log_event(
            AuditEventType.USER_VIEW_RESULTS,
            "User accessed privacy dashboard",
            details={
                'user_id': current_user.id,
                'total_artifacts': data_summary['total_artifacts'],
                'total_size_bytes': data_summary['total_size_bytes']
            }
        )
        
        return DataSummaryResponse(
            user_id=current_user.id,
            total_artifacts=data_summary['total_artifacts'],
            total_size_bytes=data_summary['total_size_bytes'],
            categories=data_summary['categories'],
            retention_preferences=data_summary['retention_preferences'],
            upcoming_expirations=data_summary['upcoming_expirations'],
            consent_status="active" if consent and consent.is_consent_valid else "inactive",
            data_processing_summary=processing_summary
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting privacy dashboard for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving privacy dashboard"
        )

@router.get("/audit-trail", response_model=AuditTrailResponse)
async def get_audit_trail(
    days: int = Query(30, ge=1, le=365, description="Number of days to retrieve"),
    event_types: Optional[str] = Query(None, description="Comma-separated event types"),
    current_user = Depends(get_current_user),
    audit_logger = Depends(get_audit_logger)
):
    """
    Get user's audit trail showing all actions (GDPR Article 15).
    """
    try:
        logger.info(f"Audit trail requested by user {current_user.id} for {days} days")
        
        # Parse event types filter
        event_type_filter = None
        if event_types:
            from app.core.audit_logger import AuditEventType
            try:
                event_type_filter = [
                    AuditEventType(et.strip()) for et in event_types.split(',')
                ]
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid event type: {e}"
                )
        
        # Get audit events
        start_date = datetime.utcnow() - timedelta(days=days)
        events = audit_logger.get_user_audit_trail(
            user_id=current_user.id,
            start_date=start_date,
            event_types=event_type_filter,
            limit=1000
        )
        
        # Get unique event types
        unique_event_types = list(set(event['event_type'] for event in events))
        
        # Audit the audit trail access
        audit_logger.log_event(
            AuditEventType.USER_VIEW_RESULTS,
            f"User accessed audit trail for {days} days",
            details={
                'user_id': current_user.id,
                'days_requested': days,
                'events_returned': len(events),
                'event_types_filter': event_types
            }
        )
        
        return AuditTrailResponse(
            user_id=current_user.id,
            total_events=len(events),
            events=events,
            date_range={
                'start': start_date.isoformat(),
                'end': datetime.utcnow().isoformat()
            },
            event_types=unique_event_types
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting audit trail for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving audit trail"
        )

@router.post("/export-data", response_model=DataExportResponse)
@rate_limit("data_export", max_requests=5, window_seconds=3600)  # 5 exports per hour
async def request_data_export(
    request: Request,
    include_categories: Optional[str] = Query(None, description="Comma-separated categories"),
    current_user = Depends(get_current_user),
    audit_logger = Depends(get_audit_logger)
):
    """
    Request complete data export (GDPR Article 15).
    """
    try:
        logger.info(f"Data export requested by user {current_user.id}")
        
        # Parse categories
        categories = []
        if include_categories:
            categories = [cat.strip() for cat in include_categories.split(',')]
        
        # Generate export ID
        import uuid
        export_id = str(uuid.uuid4())
        
        # Schedule export generation (async background task)
        export_task_id = await _schedule_data_export(
            current_user.id, 
            export_id, 
            categories
        )
        
        # Audit the export request
        audit_logger.log_event(
            AuditEventType.USER_EXPORT_DATA,
            "User requested data export",
            details={
                'user_id': current_user.id,
                'export_id': export_id,
                'categories': categories,
                'task_id': export_task_id
            }
        )
        
        return DataExportResponse(
            export_id=export_id,
            status="scheduled",
            requested_at=datetime.utcnow().isoformat(),
            estimated_size_bytes=0,  # Will be calculated during export
            includes=categories or ["all"]
        )
        
    except Exception as e:
        logger.error(f"Error requesting data export for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error scheduling data export"
        )

@router.get("/export-status/{export_id}")
async def get_export_status(
    export_id: str,
    current_user = Depends(get_current_user)
):
    """
    Get status of data export request.
    """
    try:
        # Get export status from Redis/database
        status_info = await _get_export_status(export_id, current_user.id)
        
        if not status_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Export not found"
            )
        
        return status_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting export status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving export status"
        )

@router.get("/download-export/{export_id}")
async def download_data_export(
    export_id: str,
    current_user = Depends(get_current_user),
    audit_logger = Depends(get_audit_logger)
):
    """
    Download completed data export.
    """
    try:
        logger.info(f"Data export download requested: {export_id}")
        
        # Verify export belongs to user and is ready
        export_info = await _get_export_status(export_id, current_user.id)
        
        if not export_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Export not found"
            )
        
        if export_info['status'] != 'completed':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Export not ready: {export_info['status']}"
            )
        
        # Get export file
        export_data = await _get_export_data(export_id)
        
        # Audit the download
        audit_logger.log_event(
            AuditEventType.USER_EXPORT_DATA,
            "User downloaded data export",
            details={
                'user_id': current_user.id,
                'export_id': export_id,
                'size_bytes': len(export_data)
            }
        )
        
        # Return as streaming response
        return StreamingResponse(
            io.BytesIO(export_data),
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename=phishnet_data_export_{export_id}.zip"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading export {export_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error downloading export"
        )

@router.put("/retention-preferences")
async def update_retention_preferences(
    update_request: RetentionUpdateRequest,
    current_user = Depends(get_current_user),
    retention_manager = Depends(get_retention_manager),
    audit_logger = Depends(get_audit_logger)
):
    """
    Update user's data retention preferences.
    """
    try:
        logger.info(f"Retention preferences update by user {current_user.id}")
        
        # Update preferences
        result = retention_manager.update_user_retention_preferences(
            current_user.id,
            update_request.preferences
        )
        
        # Audit the update
        audit_logger.log_event(
            AuditEventType.CONSENT_UPDATED,
            "User updated retention preferences",
            details={
                'user_id': current_user.id,
                'preferences': update_request.preferences,
                'validation_result': result
            }
        )
        
        if not result['success']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    'message': 'Validation errors in retention preferences',
                    'errors': result.get('validation_errors', [])
                }
            )
        
        return {
            'success': True,
            'message': 'Retention preferences updated successfully',
            'validated_preferences': result['validated_preferences']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating retention preferences: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating retention preferences"
        )

@router.post("/delete-data")
@rate_limit("data_deletion", max_requests=3, window_seconds=3600)  # 3 deletions per hour
async def delete_user_data(
    deletion_request: DataDeletionRequest,
    current_user = Depends(get_current_user),
    audit_logger = Depends(get_audit_logger)
):
    """
    Delete user data by category (GDPR Article 17).
    """
    try:
        logger.warning(f"Data deletion requested by user {current_user.id}")
        
        if not deletion_request.confirm_deletion:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Deletion confirmation required"
            )
        
        # Schedule data deletion
        deletion_id = await _schedule_data_deletion(
            current_user.id,
            deletion_request.categories
        )
        
        # Audit the deletion request
        audit_logger.log_event(
            AuditEventType.USER_DELETE_DATA,
            "User requested data deletion",
            details={
                'user_id': current_user.id,
                'categories': deletion_request.categories,
                'deletion_id': deletion_id
            }
        )
        
        return {
            'success': True,
            'message': 'Data deletion scheduled',
            'deletion_id': deletion_id,
            'categories': deletion_request.categories,
            'estimated_completion': (datetime.utcnow() + timedelta(hours=24)).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scheduling data deletion: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error scheduling data deletion"
        )

@router.get("/retention-policies")
async def get_retention_policies(
    retention_manager = Depends(get_retention_manager)
):
    """
    Get available retention policies and user configurability.
    """
    try:
        policies_info = retention_manager.get_retention_policies_info()
        return policies_info
        
    except Exception as e:
        logger.error(f"Error getting retention policies: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving retention policies"
        )

@router.get("/scan-logs")
async def get_scan_logs(
    days: int = Query(30, ge=1, le=90, description="Number of days"),
    current_user = Depends(get_current_user),
    audit_logger = Depends(get_audit_logger)
):
    """
    Get user's scan logs showing what was scanned and why.
    """
    try:
        # Get scan-related audit events
        from app.core.audit_logger import AuditEventType
        scan_event_types = [
            AuditEventType.SCAN_STARTED,
            AuditEventType.SCAN_COMPLETED,
            AuditEventType.EMAIL_ANALYZED,
            AuditEventType.THREAT_DETECTED
        ]
        
        start_date = datetime.utcnow() - timedelta(days=days)
        scan_events = audit_logger.get_user_audit_trail(
            user_id=current_user.id,
            start_date=start_date,
            event_types=scan_event_types,
            limit=500
        )
        
        # Audit the access
        audit_logger.log_event(
            AuditEventType.USER_VIEW_RESULTS,
            "User viewed scan logs",
            details={
                'user_id': current_user.id,
                'days_requested': days,
                'events_returned': len(scan_events)
            }
        )
        
        return {
            'user_id': current_user.id,
            'scan_logs': scan_events,
            'date_range': {
                'start': start_date.isoformat(),
                'end': datetime.utcnow().isoformat()
            },
            'total_scans': len([e for e in scan_events if e['event_type'] == 'scan_completed'])
        }
        
    except Exception as e:
        logger.error(f"Error getting scan logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving scan logs"
        )

# Helper functions

async def _get_data_processing_summary(user_id: str) -> Dict[str, Any]:
    """Get summary of data processing activities"""
    try:
        consent_manager = get_consent_manager()
        consent = await consent_manager.get_user_consent(user_id)
        
        if not consent:
            return {'status': 'no_consent'}
        
        return {
            'ai_analysis_enabled': not consent.opt_out_ai_analysis,
            'persistent_storage_enabled': not consent.opt_out_persistent_storage,
            'threat_intel_sharing': consent.share_threat_intelligence,
            'data_region': consent.data_processing_region,
            'last_processing': consent.consent_updated_at.isoformat() if consent.consent_updated_at else None
        }
        
    except Exception as e:
        logger.error(f"Error getting data processing summary: {e}")
        return {'error': str(e)}

async def _schedule_data_export(user_id: str, export_id: str, categories: List[str]) -> str:
    """Schedule background data export"""
    try:
        from app.core.redis_client import get_redis_client
        redis_client = get_redis_client()
        
        # Store export request
        export_request = {
            'export_id': export_id,
            'user_id': user_id,
            'categories': categories,
            'status': 'scheduled',
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Add to export queue
        await redis_client.lpush('data_export_queue', json.dumps(export_request))
        
        # Store export status
        status_key = f"export_status:{export_id}"
        await redis_client.setex(status_key, 86400, json.dumps(export_request))  # 24 hour TTL
        
        return export_id
        
    except Exception as e:
        logger.error(f"Error scheduling data export: {e}")
        raise

async def _get_export_status(export_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Get export status"""
    try:
        from app.core.redis_client import get_redis_client
        redis_client = get_redis_client()
        
        status_key = f"export_status:{export_id}"
        status_data = await redis_client.get(status_key)
        
        if not status_data:
            return None
        
        status_info = json.loads(status_data)
        
        # Verify ownership
        if status_info.get('user_id') != user_id:
            return None
        
        return status_info
        
    except Exception as e:
        logger.error(f"Error getting export status: {e}")
        return None

async def _get_export_data(export_id: str) -> bytes:
    """Get export data file"""
    try:
        from app.core.redis_client import get_redis_client
        redis_client = get_redis_client()
        
        # Get export data from Redis or file storage
        data_key = f"export_data:{export_id}"
        export_data = await redis_client.get(data_key)
        
        if not export_data:
            raise ValueError("Export data not found")
        
        return export_data
        
    except Exception as e:
        logger.error(f"Error getting export data: {e}")
        raise

async def _schedule_data_deletion(user_id: str, categories: List[str]) -> str:
    """Schedule background data deletion"""
    try:
        from app.core.redis_client import get_redis_client
        import uuid
        
        redis_client = get_redis_client()
        deletion_id = str(uuid.uuid4())
        
        # Store deletion request
        deletion_request = {
            'deletion_id': deletion_id,
            'user_id': user_id,
            'categories': categories,
            'status': 'scheduled',
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Add to deletion queue
        await redis_client.lpush('data_deletion_queue', json.dumps(deletion_request))
        
        return deletion_id
        
    except Exception as e:
        logger.error(f"Error scheduling data deletion: {e}")
        raise
