"""Production MongoDB Atlas integration and data persistence manager."""

import os
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union
from contextlib import asynccontextmanager

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
from pymongo import ASCENDING, DESCENDING, IndexModel
from pymongo.errors import DuplicateKeyError, ConnectionFailure, ServerSelectionTimeoutError
from beanie import init_beanie, Document

from app.config.settings import settings
from app.models.mongodb_models import DOCUMENT_MODELS, User, EmailAnalysis, ThreatIntelligence, AnalysisJob, AuditLog

logger = logging.getLogger(__name__)

class ProductionDatabaseManager:
    """Production MongoDB Atlas database manager with connection pooling and error handling."""
    
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.database: Optional[AsyncIOMotorDatabase] = None
        self.is_connected: bool = False
        self.connection_retries: int = 3
        self.connection_timeout: int = 10000  # 10 seconds
        
    async def connect_to_atlas(self) -> None:
        """Connect to MongoDB Atlas with production settings."""
        try:
            mongodb_uri = settings.get_mongodb_uri()
            if not mongodb_uri:
                raise ValueError("MONGODB_URI not configured for production")
            
            logger.info("Connecting to MongoDB Atlas...")
            
            # Production connection settings
            self.client = AsyncIOMotorClient(
                mongodb_uri,
                maxPoolSize=20,  # Maximum connections in pool
                minPoolSize=5,   # Minimum connections in pool
                maxIdleTimeMS=30000,  # 30 seconds
                serverSelectionTimeoutMS=self.connection_timeout,
                connectTimeoutMS=self.connection_timeout,
                socketTimeoutMS=self.connection_timeout,
                retryWrites=True,
                retryReads=True,
                w="majority",  # Write concern for data safety
                readPreference="primary"  # Read from primary for consistency
            )
            
            self.database = self.client[settings.MONGODB_DATABASE]
            
            # Test connection with ping
            await self.client.admin.command('ping')
            self.is_connected = True
            
            logger.info(f"Successfully connected to MongoDB Atlas database: {settings.MONGODB_DATABASE}")
            
            # Initialize Beanie ODM
            await self.initialize_beanie()
            
            # Create indexes for performance
            await self.create_production_indexes()
            
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB Atlas: {e}")
            self.is_connected = False
            raise
    
    async def initialize_beanie(self) -> None:
        """Initialize Beanie ODM with document models."""
        try:
            await init_beanie(database=self.database, document_models=DOCUMENT_MODELS)
            logger.info("Beanie ODM initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Beanie: {e}")
            raise
    
    async def create_production_indexes(self) -> None:
        """Create production indexes for optimal performance."""
        try:
            # Users collection indexes
            users_collection = self.database.users
            await users_collection.create_index([("email", ASCENDING)], unique=True, background=True)
            await users_collection.create_index([("username", ASCENDING)], unique=True, background=True)
            await users_collection.create_index([("created_at", DESCENDING)], background=True)
            await users_collection.create_index([("is_active", ASCENDING)], background=True)
            
            # Email analyses collection indexes
            emails_collection = self.database.email_analyses
            await emails_collection.create_index([("user_id", ASCENDING), ("created_at", DESCENDING)], background=True)
            await emails_collection.create_index([("gmail_message_id", ASCENDING)], unique=True, background=True)
            await emails_collection.create_index([("status", ASCENDING)], background=True)
            await emails_collection.create_index([("threat_level", ASCENDING)], background=True)
            await emails_collection.create_index([("sender", ASCENDING)], background=True)
            await emails_collection.create_index([("received_at", DESCENDING)], background=True)
            await emails_collection.create_index([("confidence_score", DESCENDING)], background=True)
            
            # Threat intelligence collection indexes
            threats_collection = self.database.threat_intelligence
            await threats_collection.create_index([("indicator", ASCENDING)], unique=True, background=True)
            await threats_collection.create_index([("indicator_type", ASCENDING)], background=True)
            await threats_collection.create_index([("threat_type", ASCENDING)], background=True)
            await threats_collection.create_index([("threat_level", ASCENDING)], background=True)
            await threats_collection.create_index([("last_seen", DESCENDING)], background=True)
            await threats_collection.create_index([("expires_at", ASCENDING)], background=True)
            
            # Analysis jobs collection indexes
            jobs_collection = self.database.analysis_jobs
            await jobs_collection.create_index([("job_id", ASCENDING)], unique=True, background=True)
            await jobs_collection.create_index([("user_id", ASCENDING), ("created_at", DESCENDING)], background=True)
            await jobs_collection.create_index([("status", ASCENDING)], background=True)
            await jobs_collection.create_index([("priority", DESCENDING), ("created_at", ASCENDING)], background=True)
            await jobs_collection.create_index([("job_type", ASCENDING)], background=True)
            
            # Audit logs collection indexes
            audit_collection = self.database.audit_logs
            await audit_collection.create_index([("timestamp", DESCENDING)], background=True)
            await audit_collection.create_index([("event_type", ASCENDING)], background=True)
            await audit_collection.create_index([("user_id", ASCENDING), ("timestamp", DESCENDING)], background=True)
            await audit_collection.create_index([("resource_type", ASCENDING), ("resource_id", ASCENDING)], background=True)
            
            # OAuth sessions collection indexes (for persistent sessions)
            sessions_collection = self.database.oauth_sessions
            await sessions_collection.create_index([("session_id", ASCENDING)], unique=True, background=True)
            await sessions_collection.create_index([("user_id", ASCENDING)], background=True)
            await sessions_collection.create_index([("expires_at", ASCENDING)], background=True)
            await sessions_collection.create_index([("ip_address", ASCENDING)], background=True)
            
            logger.info("Production indexes created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create production indexes: {e}")
            # Don't raise - indexes are optimization, not critical
    
    async def disconnect(self) -> None:
        """Disconnect from MongoDB Atlas."""
        if self.client:
            self.client.close()
            self.is_connected = False
            logger.info("Disconnected from MongoDB Atlas")
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on database connection."""
        try:
            if not self.is_connected or not self.client:
                return {"status": "disconnected", "error": "No active connection"}
            
            # Ping database
            start_time = datetime.now()
            await self.client.admin.command('ping')
            ping_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Get database stats
            stats = await self.database.command("dbStats")
            
            return {
                "status": "healthy",
                "ping_ms": round(ping_time, 2),
                "database": settings.MONGODB_DATABASE,
                "collections": stats.get("collections", 0),
                "data_size_mb": round(stats.get("dataSize", 0) / 1024 / 1024, 2),
                "storage_size_mb": round(stats.get("storageSize", 0) / 1024 / 1024, 2),
                "indexes": stats.get("indexes", 0)
            }
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {"status": "unhealthy", "error": str(e)}
    
    async def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics for all collections."""
        try:
            stats = {}
            
            for model in DOCUMENT_MODELS:
                collection_name = model.Settings.name
                collection = self.database[collection_name]
                
                # Get collection stats
                count = await collection.count_documents({})
                stats[collection_name] = {
                    "document_count": count,
                    "collection": collection_name
                }
                
                # Add specific stats for email analyses
                if collection_name == "email_analyses":
                    # Count by status
                    pipeline = [
                        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
                    ]
                    status_counts = []
                    async for doc in collection.aggregate(pipeline):
                        status_counts.append(doc)
                    stats[collection_name]["status_breakdown"] = status_counts
                    
                    # Count by threat level
                    pipeline = [
                        {"$match": {"threat_level": {"$ne": None}}},
                        {"$group": {"_id": "$threat_level", "count": {"$sum": 1}}}
                    ]
                    threat_counts = []
                    async for doc in collection.aggregate(pipeline):
                        threat_counts.append(doc)
                    stats[collection_name]["threat_level_breakdown"] = threat_counts
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get collection stats: {e}")
            return {"error": str(e)}
    
    @asynccontextmanager
    async def transaction(self):
        """Create a database transaction context."""
        if not self.client:
            raise RuntimeError("Database not connected")
        
        session = self.client.start_session()
        try:
            async with session.start_transaction():
                yield session
        except Exception as e:
            logger.error(f"Transaction failed: {e}")
            raise
        finally:
            await session.end_session()


class PersistentSessionManager:
    """Manage OAuth sessions with MongoDB persistence instead of in-memory storage."""
    
    def __init__(self, db_manager: ProductionDatabaseManager):
        self.db_manager = db_manager
        self.collection_name = "oauth_sessions"
    
    async def store_session(self, session_data: Dict[str, Any]) -> str:
        """Store session in MongoDB."""
        try:
            collection = self.db_manager.database[self.collection_name]
            
            # Add timestamps
            session_data["created_at"] = datetime.now(timezone.utc)
            session_data["updated_at"] = datetime.now(timezone.utc)
            
            result = await collection.insert_one(session_data)
            logger.info(f"Session stored in MongoDB: {session_data.get('session_id')}")
            return str(result.inserted_id)
            
        except Exception as e:
            logger.error(f"Failed to store session: {e}")
            raise
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session from MongoDB."""
        try:
            collection = self.db_manager.database[self.collection_name]
            
            session = await collection.find_one({"session_id": session_id})
            if session:
                # Check if session is expired
                if session.get("expires_at") and session["expires_at"] < datetime.now(timezone.utc):
                    await self.delete_session(session_id)
                    return None
                
                # Update last accessed
                await collection.update_one(
                    {"session_id": session_id},
                    {"$set": {"last_accessed": datetime.now(timezone.utc)}}
                )
                
                return session
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get session: {e}")
            return None
    
    async def update_session(self, session_id: str, update_data: Dict[str, Any]) -> bool:
        """Update session in MongoDB."""
        try:
            collection = self.db_manager.database[self.collection_name]
            
            update_data["updated_at"] = datetime.now(timezone.utc)
            
            result = await collection.update_one(
                {"session_id": session_id},
                {"$set": update_data}
            )
            
            return result.modified_count > 0
            
        except Exception as e:
            logger.error(f"Failed to update session: {e}")
            return False
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete session from MongoDB."""
        try:
            collection = self.db_manager.database[self.collection_name]
            
            result = await collection.delete_one({"session_id": session_id})
            return result.deleted_count > 0
            
        except Exception as e:
            logger.error(f"Failed to delete session: {e}")
            return False
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions from MongoDB."""
        try:
            collection = self.db_manager.database[self.collection_name]
            
            # Delete sessions that are expired
            result = await collection.delete_many({
                "expires_at": {"$lt": datetime.now(timezone.utc)}
            })
            
            if result.deleted_count > 0:
                logger.info(f"Cleaned up {result.deleted_count} expired sessions")
            
            return result.deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")
            return 0
    
    async def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all active sessions for a user."""
        try:
            collection = self.db_manager.database[self.collection_name]
            
            cursor = collection.find({
                "user_id": user_id,
                "expires_at": {"$gt": datetime.now(timezone.utc)}
            }).sort("created_at", DESCENDING)
            
            sessions = []
            async for session in cursor:
                sessions.append(session)
            
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to get user sessions: {e}")
            return []


class ProductionEmailAnalysisPersistence:
    """Handle email analysis data persistence in MongoDB."""
    
    def __init__(self, db_manager: ProductionDatabaseManager):
        self.db_manager = db_manager
    
    async def store_email_analysis(self, analysis_data: Dict[str, Any]) -> str:
        """Store email analysis in MongoDB."""
        try:
            # Create EmailAnalysis document
            email_analysis = EmailAnalysis(**analysis_data)
            await email_analysis.save()
            
            logger.info(f"Email analysis stored: {email_analysis.gmail_message_id}")
            return str(email_analysis.id)
            
        except DuplicateKeyError:
            # Email already analyzed, update instead
            existing = await EmailAnalysis.find_one({"gmail_message_id": analysis_data["gmail_message_id"]})
            if existing:
                for key, value in analysis_data.items():
                    setattr(existing, key, value)
                existing.updated_at = datetime.now(timezone.utc)
                await existing.save()
                logger.info(f"Email analysis updated: {existing.gmail_message_id}")
                return str(existing.id)
            raise
            
        except Exception as e:
            logger.error(f"Failed to store email analysis: {e}")
            raise
    
    async def get_email_analysis(self, gmail_message_id: str) -> Optional[Dict[str, Any]]:
        """Get email analysis from MongoDB."""
        try:
            analysis = await EmailAnalysis.find_one({"gmail_message_id": gmail_message_id})
            if analysis:
                return analysis.dict()
            return None
            
        except Exception as e:
            logger.error(f"Failed to get email analysis: {e}")
            return None
    
    async def get_user_email_analyses(self, user_id: str, limit: int = 50, skip: int = 0) -> List[Dict[str, Any]]:
        """Get email analyses for a user with pagination."""
        try:
            analyses = await EmailAnalysis.find(
                {"user_id": user_id}
            ).sort([("created_at", DESCENDING)]).skip(skip).limit(limit).to_list()
            
            return [analysis.dict() for analysis in analyses]
            
        except Exception as e:
            logger.error(f"Failed to get user email analyses: {e}")
            return []
    
    async def get_threat_statistics(self, user_id: str) -> Dict[str, Any]:
        """Get threat statistics for a user."""
        try:
            # Count emails by threat level
            pipeline = [
                {"$match": {"user_id": user_id}},
                {"$group": {
                    "_id": "$threat_level",
                    "count": {"$sum": 1},
                    "avg_confidence": {"$avg": "$confidence_score"}
                }}
            ]
            
            collection = self.db_manager.database["email_analyses"]
            threat_stats = []
            async for doc in collection.aggregate(pipeline):
                threat_stats.append(doc)
            
            # Total emails analyzed
            total = await EmailAnalysis.find({"user_id": user_id}).count()
            
            # Recent activity (last 7 days)
            week_ago = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            week_ago = week_ago.replace(day=week_ago.day - 7)
            
            recent = await EmailAnalysis.find({
                "user_id": user_id,
                "created_at": {"$gte": week_ago}
            }).count()
            
            return {
                "total_emails_analyzed": total,
                "recent_activity_7_days": recent,
                "threat_level_breakdown": threat_stats
            }
            
        except Exception as e:
            logger.error(f"Failed to get threat statistics: {e}")
            return {}


# Global instances
production_db_manager = ProductionDatabaseManager()
persistent_session_manager = PersistentSessionManager(production_db_manager)
email_analysis_persistence = ProductionEmailAnalysisPersistence(production_db_manager)

# Dependency injection functions
async def get_production_db() -> ProductionDatabaseManager:
    """Get production database manager."""
    if not production_db_manager.is_connected:
        await production_db_manager.connect_to_atlas()
    return production_db_manager

async def get_persistent_sessions() -> PersistentSessionManager:
    """Get persistent session manager."""
    return persistent_session_manager

async def get_email_persistence() -> ProductionEmailAnalysisPersistence:
    """Get email analysis persistence manager."""
    return email_analysis_persistence