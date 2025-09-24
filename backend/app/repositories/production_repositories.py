"""Production-ready repository pattern for MongoDB operations."""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, TypeVar, Generic
from uuid import UUID

from beanie import Document
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError

from app.db.production_persistence import production_db_manager

logger = logging.getLogger(__name__)

T = TypeVar('T', bound=Document)

class BaseRepository(ABC, Generic[T]):
    """Base repository with common CRUD operations."""
    
    def __init__(self, model_class: type[T]):
        self.model_class = model_class
        self.collection_name = model_class.Settings.name
    
    async def create(self, data: Dict[str, Any]) -> T:
        """Create a new document."""
        try:
            document = self.model_class(**data)
            await document.save()
            logger.info(f"Created {self.collection_name} document: {document.id}")
            return document
        except Exception as e:
            logger.error(f"Failed to create {self.collection_name}: {e}")
            raise
    
    async def get_by_id(self, doc_id: str) -> Optional[T]:
        """Get document by ID."""
        try:
            return await self.model_class.get(doc_id)
        except Exception as e:
            logger.error(f"Failed to get {self.collection_name} by ID {doc_id}: {e}")
            return None
    
    async def get_by_field(self, field: str, value: Any) -> Optional[T]:
        """Get document by specific field."""
        try:
            return await self.model_class.find_one({field: value})
        except Exception as e:
            logger.error(f"Failed to get {self.collection_name} by {field}: {e}")
            return None
    
    async def update(self, doc_id: str, update_data: Dict[str, Any]) -> Optional[T]:
        """Update document by ID."""
        try:
            document = await self.get_by_id(doc_id)
            if document:
                update_data["updated_at"] = datetime.now(timezone.utc)
                for key, value in update_data.items():
                    setattr(document, key, value)
                await document.save()
                logger.info(f"Updated {self.collection_name} document: {doc_id}")
                return document
            return None
        except Exception as e:
            logger.error(f"Failed to update {self.collection_name}: {e}")
            raise
    
    async def delete(self, doc_id: str) -> bool:
        """Delete document by ID."""
        try:
            document = await self.get_by_id(doc_id)
            if document:
                await document.delete()
                logger.info(f"Deleted {self.collection_name} document: {doc_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete {self.collection_name}: {e}")
            return False
    
    async def list_all(self, limit: int = 100, skip: int = 0) -> List[T]:
        """List all documents with pagination."""
        try:
            return await self.model_class.find_all().skip(skip).limit(limit).to_list()
        except Exception as e:
            logger.error(f"Failed to list {self.collection_name}: {e}")
            return []
    
    async def count(self, filter_dict: Optional[Dict[str, Any]] = None) -> int:
        """Count documents matching filter."""
        try:
            if filter_dict:
                return await self.model_class.find(filter_dict).count()
            return await self.model_class.find_all().count()
        except Exception as e:
            logger.error(f"Failed to count {self.collection_name}: {e}")
            return 0


class UserRepository(BaseRepository):
    """Repository for User operations."""
    
    def __init__(self):
        from app.models.mongodb_models import User
        super().__init__(User)
    
    async def get_by_email(self, email: str) -> Optional:
        """Get user by email."""
        return await self.get_by_field("email", email)
    
    async def get_by_username(self, username: str) -> Optional:
        """Get user by username."""
        return await self.get_by_field("username", username)
    
    async def create_user(self, user_data: Dict[str, Any]) -> Optional:
        """Create a new user with validation."""
        try:
            # Check if user already exists
            existing = await self.get_by_email(user_data["email"])
            if existing:
                raise ValueError(f"User with email {user_data['email']} already exists")
            
            existing = await self.get_by_username(user_data["username"])
            if existing:
                raise ValueError(f"User with username {user_data['username']} already exists")
            
            return await self.create(user_data)
            
        except DuplicateKeyError:
            raise ValueError("User with this email or username already exists")
    
    async def update_oauth_tokens(self, user_id: str, token_data: Dict[str, Any]) -> Optional:
        """Update OAuth tokens for user."""
        try:
            update_data = {
                "gmail_access_token": token_data.get("access_token"),
                "gmail_refresh_token": token_data.get("refresh_token"),
                "gmail_token_expires_at": token_data.get("expires_at")
            }
            return await self.update(user_id, update_data)
        except Exception as e:
            logger.error(f"Failed to update OAuth tokens for user {user_id}: {e}")
            return None
    
    async def get_users_with_tokens(self) -> List:
        """Get all users with OAuth tokens."""
        try:
            return await self.model_class.find({
                "gmail_access_token": {"$ne": None}
            }).to_list()
        except Exception as e:
            logger.error(f"Failed to get users with tokens: {e}")
            return []


class EmailAnalysisRepository(BaseRepository):
    """Repository for EmailAnalysis operations."""
    
    def __init__(self):
        from app.models.mongodb_models import EmailAnalysis
        super().__init__(EmailAnalysis)
    
    async def get_by_gmail_id(self, gmail_message_id: str) -> Optional:
        """Get email analysis by Gmail message ID."""
        return await self.get_by_field("gmail_message_id", gmail_message_id)
    
    async def get_user_analyses(self, user_id: str, limit: int = 50, skip: int = 0) -> List:
        """Get email analyses for a user."""
        try:
            return await self.model_class.find(
                {"user_id": user_id}
            ).sort([("created_at", DESCENDING)]).skip(skip).limit(limit).to_list()
        except Exception as e:
            logger.error(f"Failed to get user analyses: {e}")
            return []
    
    async def get_by_threat_level(self, threat_level: str, limit: int = 100) -> List:
        """Get analyses by threat level."""
        try:
            return await self.model_class.find(
                {"threat_level": threat_level}
            ).sort([("created_at", DESCENDING)]).limit(limit).to_list()
        except Exception as e:
            logger.error(f"Failed to get analyses by threat level: {e}")
            return []
    
    async def get_recent_analyses(self, days: int = 7, limit: int = 100) -> List:
        """Get recent analyses within specified days."""
        try:
            cutoff_date = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            cutoff_date = cutoff_date.replace(day=cutoff_date.day - days)
            
            return await self.model_class.find({
                "created_at": {"$gte": cutoff_date}
            }).sort([("created_at", DESCENDING)]).limit(limit).to_list()
        except Exception as e:
            logger.error(f"Failed to get recent analyses: {e}")
            return []
    
    async def create_or_update_analysis(self, analysis_data: Dict[str, Any]) -> Optional:
        """Create new analysis or update existing one."""
        try:
            # Check if analysis already exists
            existing = await self.get_by_gmail_id(analysis_data["gmail_message_id"])
            
            if existing:
                # Update existing analysis
                return await self.update(str(existing.id), analysis_data)
            else:
                # Create new analysis
                return await self.create(analysis_data)
                
        except Exception as e:
            logger.error(f"Failed to create/update analysis: {e}")
            raise
    
    async def get_threat_statistics(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Get threat statistics, optionally filtered by user."""
        try:
            collection = production_db_manager.database[self.collection_name]
            
            # Build match criteria
            match_criteria = {}
            if user_id:
                match_criteria["user_id"] = user_id
            
            # Aggregation pipeline for threat statistics
            pipeline = [
                {"$match": match_criteria},
                {"$group": {
                    "_id": "$threat_level",
                    "count": {"$sum": 1},
                    "avg_confidence": {"$avg": "$confidence_score"},
                    "max_confidence": {"$max": "$confidence_score"},
                    "min_confidence": {"$min": "$confidence_score"}
                }},
                {"$sort": {"count": -1}}
            ]
            
            threat_stats = []
            async for doc in collection.aggregate(pipeline):
                threat_stats.append(doc)
            
            # Get total count
            total = await self.count(match_criteria if match_criteria else None)
            
            # Get recent activity
            week_ago = datetime.now(timezone.utc).replace(day=datetime.now(timezone.utc).day - 7)
            recent_criteria = {**match_criteria, "created_at": {"$gte": week_ago}}
            recent_count = await self.count(recent_criteria)
            
            return {
                "total_analyses": total,
                "recent_analyses_7_days": recent_count,
                "threat_breakdown": threat_stats,
                "query_timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get threat statistics: {e}")
            return {}


class ThreatIntelligenceRepository(BaseRepository):
    """Repository for ThreatIntelligence operations."""
    
    def __init__(self):
        from app.models.mongodb_models import ThreatIntelligence
        super().__init__(ThreatIntelligence)
    
    async def get_by_indicator(self, indicator: str) -> Optional:
        """Get threat intelligence by indicator."""
        return await self.get_by_field("indicator", indicator)
    
    async def get_by_type(self, indicator_type: str, limit: int = 100) -> List:
        """Get threat intelligence by indicator type."""
        try:
            return await self.model_class.find(
                {"indicator_type": indicator_type}
            ).sort([("last_seen", DESCENDING)]).limit(limit).to_list()
        except Exception as e:
            logger.error(f"Failed to get threats by type: {e}")
            return []
    
    async def add_or_update_threat(self, threat_data: Dict[str, Any]) -> Optional:
        """Add new threat or update existing one."""
        try:
            existing = await self.get_by_indicator(threat_data["indicator"])
            
            if existing:
                # Update last seen and other fields
                update_data = {
                    "last_seen": datetime.now(timezone.utc),
                    "confidence_score": threat_data.get("confidence_score", existing.confidence_score),
                    "threat_level": threat_data.get("threat_level", existing.threat_level),
                    "metadata": {**existing.metadata, **threat_data.get("metadata", {})}
                }
                return await self.update(str(existing.id), update_data)
            else:
                # Create new threat intelligence
                threat_data["first_seen"] = datetime.now(timezone.utc)
                threat_data["last_seen"] = datetime.now(timezone.utc)
                return await self.create(threat_data)
                
        except Exception as e:
            logger.error(f"Failed to add/update threat intelligence: {e}")
            raise
    
    async def cleanup_expired_threats(self) -> int:
        """Clean up expired threat intelligence."""
        try:
            collection = production_db_manager.database[self.collection_name]
            
            result = await collection.delete_many({
                "expires_at": {"$lt": datetime.now(timezone.utc)}
            })
            
            if result.deleted_count > 0:
                logger.info(f"Cleaned up {result.deleted_count} expired threats")
            
            return result.deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired threats: {e}")
            return 0


class AnalysisJobRepository(BaseRepository):
    """Repository for AnalysisJob operations."""
    
    def __init__(self):
        from app.models.mongodb_models import AnalysisJob
        super().__init__(AnalysisJob)
    
    async def get_by_job_id(self, job_id: str) -> Optional:
        """Get job by job ID."""
        return await self.get_by_field("job_id", job_id)
    
    async def get_pending_jobs(self, limit: int = 10) -> List:
        """Get pending jobs ordered by priority."""
        try:
            return await self.model_class.find({
                "status": "pending"
            }).sort([("priority", DESCENDING), ("created_at", ASCENDING)]).limit(limit).to_list()
        except Exception as e:
            logger.error(f"Failed to get pending jobs: {e}")
            return []
    
    async def get_user_jobs(self, user_id: str, limit: int = 50) -> List:
        """Get jobs for a user."""
        try:
            return await self.model_class.find(
                {"user_id": user_id}
            ).sort([("created_at", DESCENDING)]).limit(limit).to_list()
        except Exception as e:
            logger.error(f"Failed to get user jobs: {e}")
            return []
    
    async def update_job_status(self, job_id: str, status: str, **kwargs) -> Optional:
        """Update job status and optional fields."""
        try:
            update_data = {"status": status}
            
            if status == "running":
                update_data["started_at"] = datetime.now(timezone.utc)
            elif status in ["completed", "failed"]:
                update_data["completed_at"] = datetime.now(timezone.utc)
            
            # Add any additional fields
            update_data.update(kwargs)
            
            job = await self.get_by_job_id(job_id)
            if job:
                return await self.update(str(job.id), update_data)
            return None
            
        except Exception as e:
            logger.error(f"Failed to update job status: {e}")
            return None


class AuditLogRepository(BaseRepository):
    """Repository for AuditLog operations."""
    
    def __init__(self):
        from app.models.mongodb_models import AuditLog
        super().__init__(AuditLog)
    
    async def log_event(self, event_data: Dict[str, Any]) -> Optional:
        """Log an audit event."""
        try:
            event_data["timestamp"] = datetime.now(timezone.utc)
            return await self.create(event_data)
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            return None
    
    async def get_user_events(self, user_id: str, limit: int = 100) -> List:
        """Get audit events for a user."""
        try:
            return await self.model_class.find(
                {"user_id": user_id}
            ).sort([("timestamp", DESCENDING)]).limit(limit).to_list()
        except Exception as e:
            logger.error(f"Failed to get user events: {e}")
            return []
    
    async def get_events_by_type(self, event_type: str, limit: int = 100) -> List:
        """Get audit events by type."""
        try:
            return await self.model_class.find(
                {"event_type": event_type}
            ).sort([("timestamp", DESCENDING)]).limit(limit).to_list()
        except Exception as e:
            logger.error(f"Failed to get events by type: {e}")
            return []
    
    async def cleanup_old_logs(self, days_to_keep: int = 90) -> int:
        """Clean up old audit logs."""
        try:
            cutoff_date = datetime.now(timezone.utc).replace(day=datetime.now(timezone.utc).day - days_to_keep)
            
            collection = production_db_manager.database[self.collection_name]
            result = await collection.delete_many({
                "timestamp": {"$lt": cutoff_date}
            })
            
            if result.deleted_count > 0:
                logger.info(f"Cleaned up {result.deleted_count} old audit logs")
            
            return result.deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup old audit logs: {e}")
            return 0


# Global repository instances
user_repository = UserRepository()
email_analysis_repository = EmailAnalysisRepository()
threat_intelligence_repository = ThreatIntelligenceRepository()
analysis_job_repository = AnalysisJobRepository()
audit_log_repository = AuditLogRepository()

# Dependency injection functions
async def get_user_repo() -> UserRepository:
    """Get user repository."""
    return user_repository

async def get_email_analysis_repo() -> EmailAnalysisRepository:
    """Get email analysis repository."""
    return email_analysis_repository

async def get_threat_intel_repo() -> ThreatIntelligenceRepository:
    """Get threat intelligence repository."""
    return threat_intelligence_repository

async def get_analysis_job_repo() -> AnalysisJobRepository:
    """Get analysis job repository."""
    return analysis_job_repository

async def get_audit_log_repo() -> AuditLogRepository:
    """Get audit log repository."""
    return audit_log_repository