"""
Production Backup and Retention Management
Handles automated backups, point-in-time recovery, and data retention policies
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum
import logging
from pathlib import Path

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import PyMongoError
from pydantic import BaseModel, Field

from app.config.settings import get_settings
from app.db.mongodb import MongoDBManager
from app.services.database_service import db_service
from app.models.production_models import AuditLog, ActionType

logger = logging.getLogger(__name__)
settings = get_settings()


class BackupType(str, Enum):
    """Types of database backups."""
    FULL = "full"
    INCREMENTAL = "incremental"
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class BackupStatus(str, Enum):
    """Backup operation status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class RetentionPolicy(BaseModel):
    """Data retention policy configuration."""
    collection_name: str
    retention_days: int
    field_name: str = "created_at"  # Field to check for retention
    archive_before_delete: bool = True
    compliance_requirements: List[str] = Field(default_factory=list)


class BackupRecord(BaseModel):
    """Backup operation record."""
    backup_id: str
    backup_type: BackupType
    status: BackupStatus
    collections: List[str]
    start_time: datetime
    end_time: Optional[datetime] = None
    file_path: Optional[str] = None
    file_size_bytes: Optional[int] = None
    document_count: Dict[str, int] = Field(default_factory=dict)
    error_message: Optional[str] = None
    retention_until: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BackupManager:
    """Manages database backups and retention policies."""
    
    def __init__(self):
        self.backup_dir = Path(getattr(settings, 'BACKUP_DIRECTORY', './backups'))
        self.backup_dir.mkdir(exist_ok=True)
        
        # Default retention policies for production collections
        self.retention_policies = [
            RetentionPolicy(
                collection_name="audit_logs",
                retention_days=365,  # 1 year for compliance
                compliance_requirements=["security", "audit"]
            ),
            RetentionPolicy(
                collection_name="scan_results",
                retention_days=1095,  # 3 years for threat intelligence
                compliance_requirements=["security", "threat_intel"]
            ),
            RetentionPolicy(
                collection_name="emails_meta",
                retention_days=365,  # 1 year
                field_name="date_received"
            ),
            RetentionPolicy(
                collection_name="oauth_credentials",
                retention_days=90,  # 3 months after expiry
                field_name="expires_at"
            ),
            RetentionPolicy(
                collection_name="refresh_tokens",
                retention_days=0,  # Auto-expire via TTL index
                field_name="expires_at"
            ),
            RetentionPolicy(
                collection_name="reputation_cache",
                retention_days=30,  # 1 month cache
                field_name="expires_at"
            )
        ]
        
    async def create_backup(
        self,
        backup_type: BackupType = BackupType.SCHEDULED,
        collections: Optional[List[str]] = None,
        retention_days: int = 30
    ) -> BackupRecord:
        """Create database backup."""
        
        backup_id = f"backup_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        
        # Determine collections to backup
        if not collections:
            collections = [
                "users", "oauth_credentials", "emails_meta", 
                "scan_results", "audit_logs", "refresh_tokens", 
                "reputation_cache"
            ]
        
        backup_record = BackupRecord(
            backup_id=backup_id,
            backup_type=backup_type,
            status=BackupStatus.PENDING,
            collections=collections,
            start_time=datetime.now(timezone.utc),
            retention_until=datetime.now(timezone.utc) + timedelta(days=retention_days)
        )
        
        try:
            logger.info(f"🔄 Starting backup {backup_id}")
            backup_record.status = BackupStatus.IN_PROGRESS
            
            # Create backup directory
            backup_path = self.backup_dir / backup_id
            backup_path.mkdir(exist_ok=True)
            
            total_documents = 0
            
            # Backup each collection
            for collection_name in collections:
                try:
                    doc_count = await self._backup_collection(
                        collection_name, 
                        backup_path
                    )
                    backup_record.document_count[collection_name] = doc_count
                    total_documents += doc_count
                    logger.info(f"✅ Backed up {collection_name}: {doc_count} documents")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to backup {collection_name}: {e}")
                    backup_record.document_count[collection_name] = 0
            
            # Create backup metadata
            metadata = {
                "phishnet_version": getattr(settings, 'VERSION', '1.0.0'),
                "mongodb_version": await self._get_mongodb_version(),
                "backup_time": backup_record.start_time.isoformat(),
                "total_documents": total_documents,
                "collections": backup_record.document_count
            }
            
            metadata_file = backup_path / "metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Calculate backup size
            backup_size = sum(f.stat().st_size for f in backup_path.rglob('*') if f.is_file())
            
            # Complete backup record
            backup_record.end_time = datetime.now(timezone.utc)
            backup_record.status = BackupStatus.COMPLETED
            backup_record.file_path = str(backup_path)
            backup_record.file_size_bytes = backup_size
            backup_record.metadata = metadata
            
            # Log backup completion
            await db_service.log_audit_event(
                action=ActionType.CONFIG_CHANGE,
                resource_type="backup",
                resource_id=backup_id,
                description=f"Database backup completed: {total_documents} documents",
                details={
                    "backup_type": backup_type,
                    "collections": collections,
                    "size_mb": round(backup_size / 1024 / 1024, 2),
                    "duration_seconds": (backup_record.end_time - backup_record.start_time).total_seconds()
                }
            )
            
            logger.info(f"✅ Backup {backup_id} completed: {backup_size / 1024 / 1024:.2f} MB")
            
        except Exception as e:
            backup_record.status = BackupStatus.FAILED
            backup_record.error_message = str(e)
            backup_record.end_time = datetime.now(timezone.utc)
            
            logger.error(f"❌ Backup {backup_id} failed: {e}")
            
            # Log backup failure
            await db_service.log_audit_event(
                action=ActionType.CONFIG_CHANGE,
                resource_type="backup",
                resource_id=backup_id,
                description=f"Database backup failed: {str(e)}",
                details={"error": str(e), "backup_type": backup_type}
            )
        
        return backup_record
    
    async def _backup_collection(self, collection_name: str, backup_path: Path) -> int:
        """Backup a single collection to BSON file."""
        if not MongoDBManager.database:
            raise RuntimeError("Database not connected")
        
        collection = MongoDBManager.database[collection_name]
        
        # Export to JSON file (more portable than BSON)
        backup_file = backup_path / f"{collection_name}.json"
        document_count = 0
        
        with open(backup_file, 'w') as f:
            f.write('[\n')
            
            async for doc in collection.find():
                if document_count > 0:
                    f.write(',\n')
                
                # Convert ObjectId and datetime to strings for JSON serialization
                doc_json = json.dumps(doc, default=self._json_serializer, indent=2)
                f.write(doc_json)
                document_count += 1
            
            f.write('\n]')
        
        return document_count
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for MongoDB types."""
        from bson import ObjectId
        
        if isinstance(obj, ObjectId):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    async def _get_mongodb_version(self) -> str:
        """Get MongoDB server version."""
        try:
            if MongoDBManager.client:
                server_info = await MongoDBManager.client.server_info()
                return server_info.get('version', 'unknown')
        except Exception:
            pass
        return 'unknown'
    
    async def restore_backup(self, backup_id: str, collections: Optional[List[str]] = None) -> bool:
        """Restore database from backup."""
        
        backup_path = self.backup_dir / backup_id
        if not backup_path.exists():
            logger.error(f"❌ Backup {backup_id} not found")
            return False
        
        try:
            logger.info(f"🔄 Starting restore from backup {backup_id}")
            
            # Load backup metadata
            metadata_file = backup_path / "metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                logger.info(f"📋 Backup metadata: {metadata['total_documents']} documents")
            
            # Determine collections to restore
            if not collections:
                collections = [f.stem for f in backup_path.glob('*.json') if f.stem != 'metadata']
            
            total_restored = 0
            
            # Restore each collection
            for collection_name in collections:
                restored_count = await self._restore_collection(collection_name, backup_path)
                total_restored += restored_count
                logger.info(f"✅ Restored {collection_name}: {restored_count} documents")
            
            # Log restore completion
            await db_service.log_audit_event(
                action=ActionType.CONFIG_CHANGE,
                resource_type="restore",
                resource_id=backup_id,
                description=f"Database restore completed: {total_restored} documents",
                details={
                    "backup_id": backup_id,
                    "collections": collections,
                    "total_documents": total_restored
                }
            )
            
            logger.info(f"✅ Restore from backup {backup_id} completed: {total_restored} documents")
            return True
            
        except Exception as e:
            logger.error(f"❌ Restore from backup {backup_id} failed: {e}")
            
            await db_service.log_audit_event(
                action=ActionType.CONFIG_CHANGE,
                resource_type="restore",
                resource_id=backup_id,
                description=f"Database restore failed: {str(e)}",
                details={"error": str(e)}
            )
            
            return False
    
    async def _restore_collection(self, collection_name: str, backup_path: Path) -> int:
        """Restore a single collection from backup."""
        if not MongoDBManager.database:
            raise RuntimeError("Database not connected")
        
        backup_file = backup_path / f"{collection_name}.json"
        if not backup_file.exists():
            logger.warning(f"⚠️ Backup file not found: {backup_file}")
            return 0
        
        collection = MongoDBManager.database[collection_name]
        
        # Load and insert documents
        with open(backup_file, 'r') as f:
            documents = json.load(f)
        
        if documents:
            # Convert string IDs back to ObjectIds
            for doc in documents:
                if '_id' in doc and isinstance(doc['_id'], str):
                    from bson import ObjectId
                    doc['_id'] = ObjectId(doc['_id'])
            
            # Insert documents in batches
            batch_size = 1000
            inserted_count = 0
            
            for i in range(0, len(documents), batch_size):
                batch = documents[i:i + batch_size]
                try:
                    result = await collection.insert_many(batch, ordered=False)
                    inserted_count += len(result.inserted_ids)
                except Exception as e:
                    logger.warning(f"⚠️ Batch insert error for {collection_name}: {e}")
            
            return inserted_count
        
        return 0
    
    async def apply_retention_policies(self) -> Dict[str, int]:
        """Apply data retention policies across all collections."""
        
        deletion_stats = {}
        
        for policy in self.retention_policies:
            try:
                if policy.retention_days <= 0:
                    continue  # Skip collections with TTL or no retention
                
                deleted_count = await self._apply_collection_retention(policy)
                deletion_stats[policy.collection_name] = deleted_count
                
                if deleted_count > 0:
                    logger.info(f"🗑️ Retention policy applied to {policy.collection_name}: {deleted_count} documents deleted")
                
            except Exception as e:
                logger.error(f"❌ Failed to apply retention policy for {policy.collection_name}: {e}")
                deletion_stats[policy.collection_name] = -1  # Error marker
        
        # Log retention policy execution
        total_deleted = sum(count for count in deletion_stats.values() if count > 0)
        await db_service.log_audit_event(
            action=ActionType.CONFIG_CHANGE,
            resource_type="retention",
            description=f"Retention policies applied: {total_deleted} documents deleted",
            details=deletion_stats
        )
        
        return deletion_stats
    
    async def _apply_collection_retention(self, policy: RetentionPolicy) -> int:
        """Apply retention policy to a specific collection."""
        if not MongoDBManager.database:
            return 0
        
        collection = MongoDBManager.database[policy.collection_name]
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=policy.retention_days)
        
        # Find documents to delete
        query = {policy.field_name: {"$lt": cutoff_date}}
        
        if policy.archive_before_delete:
            # Archive documents before deletion (implementation depends on requirements)
            pass
        
        # Delete old documents
        result = await collection.delete_many(query)
        return result.deleted_count
    
    async def cleanup_old_backups(self, retention_days: int = 30) -> int:
        """Clean up old backup files."""
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        deleted_count = 0
        
        for backup_path in self.backup_dir.iterdir():
            if backup_path.is_dir():
                # Parse backup timestamp from directory name
                try:
                    backup_date_str = backup_path.name.split('_')[1] + '_' + backup_path.name.split('_')[2]
                    backup_date = datetime.strptime(backup_date_str, '%Y%m%d_%H%M%S').replace(tzinfo=timezone.utc)
                    
                    if backup_date < cutoff_date:
                        # Remove old backup directory
                        import shutil
                        shutil.rmtree(backup_path)
                        deleted_count += 1
                        logger.info(f"🗑️ Deleted old backup: {backup_path.name}")
                        
                except (ValueError, IndexError) as e:
                    logger.warning(f"⚠️ Could not parse backup date from {backup_path.name}: {e}")
        
        if deleted_count > 0:
            await db_service.log_audit_event(
                action=ActionType.CONFIG_CHANGE,
                resource_type="backup_cleanup",
                description=f"Old backup cleanup: {deleted_count} backups deleted",
                details={"retention_days": retention_days, "deleted_count": deleted_count}
            )
        
        return deleted_count
    
    async def get_backup_status(self) -> Dict[str, Any]:
        """Get current backup system status."""
        
        backup_files = list(self.backup_dir.glob('backup_*'))
        
        status = {
            "backup_directory": str(self.backup_dir),
            "total_backups": len(backup_files),
            "disk_usage_mb": 0,
            "latest_backup": None,
            "retention_policies": len(self.retention_policies),
            "policies": [
                {
                    "collection": policy.collection_name,
                    "retention_days": policy.retention_days,
                    "compliance": policy.compliance_requirements
                }
                for policy in self.retention_policies
            ]
        }
        
        # Calculate total backup size
        try:
            total_size = sum(
                sum(f.stat().st_size for f in backup_path.rglob('*') if f.is_file())
                for backup_path in backup_files
            )
            status["disk_usage_mb"] = round(total_size / 1024 / 1024, 2)
        except Exception as e:
            logger.warning(f"Could not calculate backup disk usage: {e}")
        
        # Find latest backup
        if backup_files:
            latest_backup = max(backup_files, key=lambda x: x.stat().st_mtime)
            status["latest_backup"] = {
                "name": latest_backup.name,
                "created": datetime.fromtimestamp(latest_backup.stat().st_mtime, timezone.utc).isoformat(),
                "size_mb": round(
                    sum(f.stat().st_size for f in latest_backup.rglob('*') if f.is_file()) / 1024 / 1024, 
                    2
                )
            }
        
        return status


# Global backup manager instance
backup_manager = BackupManager()


# Scheduled tasks
async def run_scheduled_backup():
    """Run scheduled backup (called by task scheduler)."""
    try:
        backup_record = await backup_manager.create_backup(
            backup_type=BackupType.SCHEDULED,
            retention_days=30
        )
        
        if backup_record.status == BackupStatus.COMPLETED:
            logger.info(f"✅ Scheduled backup completed: {backup_record.backup_id}")
        else:
            logger.error(f"❌ Scheduled backup failed: {backup_record.error_message}")
            
        return backup_record.status == BackupStatus.COMPLETED
        
    except Exception as e:
        logger.error(f"❌ Scheduled backup task failed: {e}")
        return False


async def run_retention_cleanup():
    """Run data retention cleanup (called by task scheduler)."""
    try:
        # Apply retention policies
        deletion_stats = await backup_manager.apply_retention_policies()
        
        # Clean up old backups
        old_backups_deleted = await backup_manager.cleanup_old_backups()
        
        logger.info(f"✅ Retention cleanup completed: {sum(deletion_stats.values())} documents, {old_backups_deleted} backups")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Retention cleanup failed: {e}")
        return False


# Configuration for MongoDB Atlas automated backups
MONGODB_ATLAS_BACKUP_CONFIG = {
    "point_in_time_recovery": {
        "enabled": True,
        "retention_hours": 72,  # 3 days
        "description": "MongoDB Atlas provides automatic point-in-time recovery"
    },
    "automated_backups": {
        "enabled": True,
        "frequency": "daily",
        "retention_days": 7,
        "description": "Daily automated backups with 7-day retention"
    },
    "cloud_provider_backups": {
        "enabled": True,
        "retention_policy": "30_days",
        "cross_region_replication": True,
        "description": "Cloud provider backup with cross-region replication"
    },
    "compliance": {
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "backup_encryption": True,
        "audit_logging": True
    }
}


def get_atlas_backup_info() -> Dict[str, Any]:
    """Get MongoDB Atlas backup configuration information."""
    return {
        "message": "MongoDB Atlas provides enterprise-grade automated backups",
        "configuration": MONGODB_ATLAS_BACKUP_CONFIG,
        "recommendations": [
            "Enable automated backups in MongoDB Atlas console",
            "Configure appropriate retention periods for compliance",
            "Test backup restoration procedures regularly",
            "Monitor backup success through Atlas monitoring",
            "Set up alerts for backup failures"
        ],
        "setup_url": "https://www.mongodb.com/docs/atlas/backup/cloud-backup/",
        "additional_features": {
            "application_level_backups": "Implemented in PhishNet for fine-grained control",
            "retention_policies": "Automated cleanup of expired data",
            "audit_trail": "All backup operations logged for compliance"
        }
    }