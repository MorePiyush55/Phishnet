"""
Audit Log API endpoints for retrieving and managing audit trail data.

Provides secure access to audit logs with proper filtering and pagination.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, asc

from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.schemas.audit_log import AuditLogResponse, AuditLogFilters, AuditLogStats
from app.core.security import get_current_user
from app.models.user import User
from app.config.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/audit", tags=["Audit Logs"])


@router.get("/logs", response_model=Dict[str, Any])
async def get_audit_logs(
    # Pagination
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=1000, description="Items per page"),
    
    # Filtering
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    category: Optional[str] = Query(None, description="Filter by category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    
    # Date filtering
    start_date: Optional[datetime] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[datetime] = Query(None, description="End date (ISO format)"),
    
    # Security filtering
    suspicious_only: bool = Query(False, description="Show only suspicious activities"),
    security_violations_only: bool = Query(False, description="Show only security violations"),
    
    # Search
    search: Optional[str] = Query(None, description="Search in description"),
    
    # Sorting
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order (asc/desc)"),
    
    # Dependencies
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve audit logs with comprehensive filtering and pagination.
    
    Requires authenticated user with audit access permissions.
    """
    
    # Check permissions (only admins and security analysts can view audit logs)
    if not current_user.is_admin and current_user.role not in ['security_analyst', 'compliance_officer']:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions to access audit logs"
        )
    
    try:
        # Build query
        query = db.query(AuditLog)
        
        # Apply filters
        filters = []
        
        if user_id is not None:
            filters.append(AuditLog.user_id == user_id)
        
        if action:
            filters.append(AuditLog.action.ilike(f"%{action}%"))
        
        if category:
            filters.append(AuditLog.category == category)
        
        if severity:
            filters.append(AuditLog.severity == severity)
        
        if resource_type:
            filters.append(AuditLog.resource_type == resource_type)
        
        if start_date:
            filters.append(AuditLog.created_at >= start_date)
        
        if end_date:
            filters.append(AuditLog.created_at <= end_date)
        
        if suspicious_only:
            filters.append(AuditLog.is_suspicious == True)
        
        if security_violations_only:
            filters.append(AuditLog.security_violation == True)
        
        if search:
            filters.append(AuditLog.description.ilike(f"%{search}%"))
        
        # Apply all filters
        if filters:
            query = query.filter(and_(*filters))
        
        # Apply sorting
        sort_column = getattr(AuditLog, sort_by, AuditLog.created_at)
        if sort_order.lower() == "desc":
            query = query.order_by(desc(sort_column))
        else:
            query = query.order_by(asc(sort_column))
        
        # Get total count for pagination
        total_count = query.count()
        
        # Apply pagination
        offset = (page - 1) * limit
        audit_logs = query.offset(offset).limit(limit).all()
        
        # Convert to response format
        logs_data = []
        for log in audit_logs:
            log_dict = log.to_dict()
            # Remove sensitive data for non-admin users
            if not current_user.is_admin:
                log_dict.pop('user_agent', None)
                log_dict.pop('details', None)
            logs_data.append(log_dict)
        
        # Calculate pagination info
        total_pages = (total_count + limit - 1) // limit
        has_next = page < total_pages
        has_prev = page > 1
        
        # Log the audit log access
        access_log = AuditLog.create_system_event(
            user_id=current_user.id,
            action="audit_log_access",
            category="audit",
            description=f"User accessed audit logs (page {page}, {len(logs_data)} records)",
            details={
                "filters": {
                    "user_id": user_id,
                    "action": action,
                    "category": category,
                    "severity": severity,
                    "start_date": start_date.isoformat() if start_date else None,
                    "end_date": end_date.isoformat() if end_date else None,
                    "search": search
                },
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total_count": total_count
                }
            },
            user_ip=None,  # Would be extracted from request in real implementation
            user_agent=None  # Would be extracted from request in real implementation
        )
        db.add(access_log)
        db.commit()
        
        return {
            "logs": logs_data,
            "pagination": {
                "page": page,
                "limit": limit,
                "total_count": total_count,
                "total_pages": total_pages,
                "has_next": has_next,
                "has_prev": has_prev
            },
            "filters_applied": {
                "user_id": user_id,
                "action": action,
                "category": category,
                "severity": severity,
                "resource_type": resource_type,
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None,
                "suspicious_only": suspicious_only,
                "security_violations_only": security_violations_only,
                "search": search
            }
        }
        
    except Exception as e:
        logger.error(f"Error retrieving audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audit logs")


@router.get("/stats", response_model=Dict[str, Any])
async def get_audit_stats(
    # Date range for statistics
    start_date: Optional[datetime] = Query(None, description="Start date for stats"),
    end_date: Optional[datetime] = Query(None, description="End date for stats"),
    
    # Dependencies
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get audit log statistics and summary information.
    """
    
    # Check permissions
    if not current_user.is_admin and current_user.role not in ['security_analyst', 'compliance_officer']:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions to access audit statistics"
        )
    
    try:
        # Default to last 30 days if no dates provided
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)
        
        # Base query with date filter
        base_query = db.query(AuditLog).filter(
            and_(
                AuditLog.created_at >= start_date,
                AuditLog.created_at <= end_date
            )
        )
        
        # Count by category
        category_stats = {}
        categories = ['auth', 'email', 'scan', 'admin', 'security', 'api']
        for category in categories:
            count = base_query.filter(AuditLog.category == category).count()
            category_stats[category] = count
        
        # Count by severity
        severity_stats = {}
        severities = ['info', 'warning', 'error', 'critical']
        for severity in severities:
            count = base_query.filter(AuditLog.severity == severity).count()
            severity_stats[severity] = count
        
        # Security statistics
        suspicious_count = base_query.filter(AuditLog.is_suspicious == True).count()
        violation_count = base_query.filter(AuditLog.security_violation == True).count()
        
        # Top actions
        from sqlalchemy import func
        top_actions = (
            base_query
            .with_entities(AuditLog.action, func.count(AuditLog.id).label('count'))
            .group_by(AuditLog.action)
            .order_by(desc('count'))
            .limit(10)
            .all()
        )
        
        # Top users (if admin)
        top_users = []
        if current_user.is_admin:
            top_users = (
                base_query
                .filter(AuditLog.user_id.isnot(None))
                .with_entities(AuditLog.user_id, func.count(AuditLog.id).label('count'))
                .group_by(AuditLog.user_id)
                .order_by(desc('count'))
                .limit(10)
                .all()
            )
        
        # Daily activity (last 7 days)
        daily_activity = []
        for i in range(7):
            day_start = (end_date - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            
            count = db.query(AuditLog).filter(
                and_(
                    AuditLog.created_at >= day_start,
                    AuditLog.created_at < day_end
                )
            ).count()
            
            daily_activity.append({
                "date": day_start.date().isoformat(),
                "count": count
            })
        
        # Reverse to show oldest first
        daily_activity.reverse()
        
        return {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "total_logs": base_query.count()
            },
            "category_breakdown": category_stats,
            "severity_breakdown": severity_stats,
            "security_summary": {
                "suspicious_activities": suspicious_count,
                "security_violations": violation_count,
                "security_ratio": round((suspicious_count + violation_count) / max(base_query.count(), 1) * 100, 2)
            },
            "top_actions": [{"action": action, "count": count} for action, count in top_actions],
            "top_users": [{"user_id": user_id, "count": count} for user_id, count in top_users] if current_user.is_admin else [],
            "daily_activity": daily_activity,
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error generating audit statistics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate audit statistics")


@router.get("/export")
async def export_audit_logs(
    format: str = Query("csv", description="Export format (csv, json)"),
    
    # Same filtering options as get_audit_logs
    user_id: Optional[int] = Query(None),
    action: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    
    # Dependencies
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Export audit logs in various formats for compliance reporting.
    """
    
    # Check permissions (only admins and compliance officers can export)
    if not current_user.is_admin and current_user.role != 'compliance_officer':
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions to export audit logs"
        )
    
    # Limit export to prevent abuse
    MAX_EXPORT_RECORDS = 10000
    
    try:
        # Build query (similar to get_audit_logs but without pagination)
        query = db.query(AuditLog)
        
        # Apply filters
        filters = []
        if user_id is not None:
            filters.append(AuditLog.user_id == user_id)
        if action:
            filters.append(AuditLog.action.ilike(f"%{action}%"))
        if category:
            filters.append(AuditLog.category == category)
        if severity:
            filters.append(AuditLog.severity == severity)
        if start_date:
            filters.append(AuditLog.created_at >= start_date)
        if end_date:
            filters.append(AuditLog.created_at <= end_date)
        
        if filters:
            query = query.filter(and_(*filters))
        
        # Limit records for export
        query = query.order_by(desc(AuditLog.created_at)).limit(MAX_EXPORT_RECORDS)
        
        audit_logs = query.all()
        
        # Log the export action
        export_log = AuditLog.create_admin_action(
            user_id=current_user.id,
            action="audit_log_export",
            description=f"User exported {len(audit_logs)} audit log records in {format} format",
            details={
                "export_format": format,
                "record_count": len(audit_logs),
                "filters": {
                    "user_id": user_id,
                    "action": action,
                    "category": category,
                    "severity": severity,
                    "start_date": start_date.isoformat() if start_date else None,
                    "end_date": end_date.isoformat() if end_date else None
                }
            }
        )
        db.add(export_log)
        db.commit()
        
        # Convert to requested format
        if format.lower() == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=[
                'id', 'created_at', 'user_id', 'action', 'category', 
                'severity', 'description', 'resource_type', 'resource_id',
                'user_ip', 'is_suspicious', 'security_violation'
            ])
            writer.writeheader()
            
            for log in audit_logs:
                writer.writerow({
                    'id': log.id,
                    'created_at': log.created_at.isoformat(),
                    'user_id': log.user_id,
                    'action': log.action,
                    'category': log.category,
                    'severity': log.severity,
                    'description': log.description,
                    'resource_type': log.resource_type,
                    'resource_id': log.resource_id,
                    'user_ip': log.user_ip,
                    'is_suspicious': log.is_suspicious,
                    'security_violation': log.security_violation
                })
            
            from fastapi.responses import Response
            return Response(
                content=output.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
            )
        
        elif format.lower() == "json":
            import json
            from fastapi.responses import Response
            
            logs_data = [log.to_dict() for log in audit_logs]
            export_data = {
                "export_metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "exported_by": current_user.id,
                    "record_count": len(logs_data),
                    "filters_applied": {
                        "user_id": user_id,
                        "action": action,
                        "category": category,
                        "severity": severity,
                        "start_date": start_date.isoformat() if start_date else None,
                        "end_date": end_date.isoformat() if end_date else None
                    }
                },
                "audit_logs": logs_data
            }
            
            return Response(
                content=json.dumps(export_data, indent=2),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"}
            )
        
        else:
            raise HTTPException(status_code=400, detail="Unsupported export format")
        
    except Exception as e:
        logger.error(f"Error exporting audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to export audit logs")
