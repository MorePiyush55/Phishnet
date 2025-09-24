"""
Production Index Management
Strategic indexes for optimal query performance
"""

from typing import List, Dict, Any, Optional
import asyncio
from datetime import datetime
from pymongo import IndexModel, ASCENDING, DESCENDING, TEXT
from motor.motor_asyncio import AsyncIOMotorCollection

from app.db.mongodb import MongoDBManager
import logging

logger = logging.getLogger(__name__)


class IndexManager:
    """Manages database indexes for production performance."""
    
    # Strategic compound indexes for common query patterns
    STRATEGIC_INDEXES = {
        "users": [
            # Authentication queries
            IndexModel([("email", ASCENDING)], unique=True, name="idx_users_email"),
            IndexModel([("username", ASCENDING)], unique=True, name="idx_users_username"),
            
            # Admin queries
            IndexModel([("role", ASCENDING), ("is_active", ASCENDING)], name="idx_users_role_active"),
            IndexModel([("created_at", DESCENDING)], name="idx_users_created"),
            
            # Security queries
            IndexModel([("failed_login_attempts", ASCENDING), ("is_locked", ASCENDING)], 
                      name="idx_users_security"),
            IndexModel([("last_login_at", DESCENDING)], name="idx_users_last_login"),
        ],
        
        "oauth_credentials": [
            # Token lookup
            IndexModel([("user_id", ASCENDING), ("provider", ASCENDING)], 
                      unique=True, name="idx_oauth_user_provider"),
            
            # Cleanup queries
            IndexModel([("expires_at", ASCENDING)], name="idx_oauth_expires"),
            IndexModel([("last_used_at", DESCENDING)], name="idx_oauth_last_used"),
            
            # Security audits
            IndexModel([("created_from_ip", ASCENDING)], name="idx_oauth_creation_ip"),
        ],
        
        "emails_meta": [
            # Primary lookups
            IndexModel([("message_id", ASCENDING)], unique=True, name="idx_emails_message_id"),
            IndexModel([("user_id", ASCENDING)], name="idx_emails_user"),
            
            # User email history
            IndexModel([("user_id", ASCENDING), ("date_received", DESCENDING)], 
                      name="idx_emails_user_date"),
            IndexModel([("user_id", ASCENDING), ("sender", ASCENDING), ("date_received", DESCENDING)], 
                      name="idx_emails_user_sender_date"),
            
            # Sender analysis
            IndexModel([("sender", ASCENDING)], name="idx_emails_sender"),
            IndexModel([("sender", ASCENDING), ("date_sent", DESCENDING)], 
                      name="idx_emails_sender_date"),
            
            # Processing status
            IndexModel([("processing_status", ASCENDING)], name="idx_emails_status"),
            IndexModel([("processing_status", ASCENDING), ("date_received", DESCENDING)], 
                      name="idx_emails_status_date"),
            
            # Full-text search
            IndexModel([("sender", TEXT), ("subject", TEXT)], name="idx_emails_text_search"),
        ],
        
        "scan_results": [
            # Primary lookups
            IndexModel([("scan_id", ASCENDING)], unique=True, name="idx_scan_id"),
            IndexModel([("message_id", ASCENDING)], name="idx_scan_message"),
            IndexModel([("user_id", ASCENDING)], name="idx_scan_user"),
            
            # User scan history
            IndexModel([("user_id", ASCENDING), ("scan_completed_at", DESCENDING)], 
                      name="idx_scan_user_completed"),
            
            # Threat analysis
            IndexModel([("is_phishing", ASCENDING)], name="idx_scan_phishing"),
            IndexModel([("threat_level", ASCENDING)], name="idx_scan_threat_level"),
            IndexModel([("threat_level", ASCENDING), ("scan_completed_at", DESCENDING)], 
                      name="idx_scan_threat_date"),
            
            # Performance queries
            IndexModel([("confidence_score", DESCENDING)], name="idx_scan_confidence"),
            IndexModel([("model_version", ASCENDING), ("confidence_score", DESCENDING)], 
                      name="idx_scan_model_confidence"),
            
            # Analytics queries
            IndexModel([("user_id", ASCENDING), ("is_phishing", ASCENDING), 
                       ("scan_completed_at", DESCENDING)], name="idx_scan_user_threat_date"),
            
            # Feedback analysis
            IndexModel([("user_feedback", ASCENDING), ("scan_completed_at", DESCENDING)], 
                      name="idx_scan_feedback"),
            
            # Array indexes
            IndexModel([("detected_threats", ASCENDING)], name="idx_scan_threats_array"),
            IndexModel([("threat_categories", ASCENDING)], name="idx_scan_categories_array"),
        ],
        
        "audit_logs": [
            # Primary queries
            IndexModel([("event_id", ASCENDING)], unique=True, name="idx_audit_event_id"),
            IndexModel([("timestamp", DESCENDING)], name="idx_audit_timestamp"),
            
            # User activity
            IndexModel([("user_id", ASCENDING)], name="idx_audit_user"),
            IndexModel([("user_id", ASCENDING), ("timestamp", DESCENDING)], 
                      name="idx_audit_user_time"),
            
            # Action analysis
            IndexModel([("action", ASCENDING)], name="idx_audit_action"),
            IndexModel([("action", ASCENDING), ("timestamp", DESCENDING)], 
                      name="idx_audit_action_time"),
            
            # Security monitoring
            IndexModel([("ip_address", ASCENDING), ("timestamp", DESCENDING)], 
                      name="idx_audit_ip_time"),
            IndexModel([("success", ASCENDING), ("timestamp", DESCENDING)], 
                      name="idx_audit_success_time"),
            
            # Resource tracking
            IndexModel([("resource_type", ASCENDING), ("resource_id", ASCENDING)], 
                      name="idx_audit_resource"),
            
            # Compliance queries
            IndexModel([("compliance_tags", ASCENDING)], name="idx_audit_compliance"),
            IndexModel([("retention_until", ASCENDING)], name="idx_audit_retention"),
            IndexModel([("severity", ASCENDING), ("timestamp", DESCENDING)], 
                      name="idx_audit_severity"),
        ],
        
        "refresh_tokens": [
            # Primary lookups
            IndexModel([("token_id", ASCENDING)], unique=True, name="idx_token_id"),
            IndexModel([("user_id", ASCENDING)], name="idx_token_user"),
            
            # Token management
            IndexModel([("user_id", ASCENDING), ("revoked", ASCENDING)], 
                      name="idx_token_user_revoked"),
            IndexModel([("token_family", ASCENDING)], name="idx_token_family"),
            
            # Cleanup
            IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0, 
                      name="idx_token_ttl"),
            IndexModel([("revoked", ASCENDING), ("expires_at", ASCENDING)], 
                      name="idx_token_cleanup"),
        ],
        
        "reputation_cache": [
            # Primary lookups
            IndexModel([("indicator", ASCENDING)], unique=True, name="idx_reputation_indicator"),
            IndexModel([("indicator_type", ASCENDING)], name="idx_reputation_type"),
            
            # Reputation queries
            IndexModel([("reputation_level", ASCENDING)], name="idx_reputation_level"),
            IndexModel([("reputation_score", DESCENDING)], name="idx_reputation_score"),
            IndexModel([("indicator_type", ASCENDING), ("reputation_level", ASCENDING)], 
                      name="idx_reputation_type_level"),
            
            # Time-based queries
            IndexModel([("last_updated", DESCENDING)], name="idx_reputation_updated"),
            IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0, 
                      name="idx_reputation_ttl"),
        ]
    }
    
    @classmethod
    async def create_all_indexes(cls) -> Dict[str, int]:
        """Create all strategic indexes for production performance."""
        if not MongoDBManager.database:
            raise RuntimeError("Database not connected")
        
        results = {}
        total_created = 0
        
        for collection_name, indexes in cls.STRATEGIC_INDEXES.items():
            collection = MongoDBManager.database[collection_name]
            created_count = await cls._create_collection_indexes(collection, indexes)
            results[collection_name] = created_count
            total_created += created_count
        
        logger.info(f"✅ Created {total_created} strategic indexes across {len(results)} collections")
        return results
    
    @classmethod
    async def _create_collection_indexes(
        cls, 
        collection: AsyncIOMotorCollection, 
        indexes: List[IndexModel]
    ) -> int:
        """Create indexes for a specific collection."""
        created_count = 0
        
        try:
            # Get existing indexes
            existing_indexes = await collection.list_indexes().to_list(length=None)
            existing_names = {idx.get('name') for idx in existing_indexes}
            
            # Create missing indexes
            indexes_to_create = []
            for index in indexes:
                index_name = index.document.get('name', f"idx_{hash(str(index.document))}")
                
                if index_name not in existing_names:
                    indexes_to_create.append(index)
            
            if indexes_to_create:
                await collection.create_indexes(indexes_to_create)
                created_count = len(indexes_to_create)
                logger.info(f"Created {created_count} indexes for {collection.name}")
            else:
                logger.info(f"All indexes exist for {collection.name}")
                
        except Exception as e:
            logger.error(f"Failed to create indexes for {collection.name}: {e}")
            raise
        
        return created_count
    
    @classmethod
    async def analyze_index_usage(cls) -> Dict[str, Any]:
        """Analyze index usage statistics."""
        if not MongoDBManager.database:
            return {}
        
        stats = {}
        
        for collection_name in cls.STRATEGIC_INDEXES.keys():
            try:
                collection = MongoDBManager.database[collection_name]
                
                # Get index statistics
                index_stats = await collection.aggregate([
                    {"$indexStats": {}}
                ]).to_list(length=None)
                
                stats[collection_name] = {
                    "indexes": len(index_stats),
                    "usage": {
                        stat['name']: {
                            'ops': stat['accesses']['ops'],
                            'since': stat['accesses']['since']
                        }
                        for stat in index_stats
                    }
                }
                
            except Exception as e:
                logger.warning(f"Could not analyze indexes for {collection_name}: {e}")
                stats[collection_name] = {"error": str(e)}
        
        return stats
    
    @classmethod
    async def drop_unused_indexes(cls, min_usage_count: int = 10) -> Dict[str, List[str]]:
        """Drop indexes with low usage (use with caution in production)."""
        dropped = {}
        
        usage_stats = await cls.analyze_index_usage()
        
        for collection_name, stats in usage_stats.items():
            if 'error' in stats:
                continue
            
            collection = MongoDBManager.database[collection_name]
            dropped_indexes = []
            
            for index_name, usage_data in stats['usage'].items():
                # Don't drop system indexes
                if index_name in ['_id_', '_id']:
                    continue
                
                if usage_data['ops'] < min_usage_count:
                    try:
                        await collection.drop_index(index_name)
                        dropped_indexes.append(index_name)
                        logger.info(f"Dropped unused index {index_name} from {collection_name}")
                    except Exception as e:
                        logger.error(f"Failed to drop index {index_name}: {e}")
            
            if dropped_indexes:
                dropped[collection_name] = dropped_indexes
        
        return dropped
    
    @classmethod 
    async def get_index_recommendations(cls) -> List[Dict[str, Any]]:
        """Analyze query patterns and suggest new indexes."""
        recommendations = []
        
        # This would analyze slow query logs in production
        # For now, return strategic recommendations
        strategic_recommendations = [
            {
                "collection": "scan_results",
                "index": [("user_id", 1), ("threat_level", 1), ("confidence_score", -1)],
                "reason": "User threat analysis with confidence ranking",
                "estimated_benefit": "High"
            },
            {
                "collection": "audit_logs", 
                "index": [("user_id", 1), ("action", 1), ("success", 1)],
                "reason": "User activity security monitoring",
                "estimated_benefit": "Medium"
            },
            {
                "collection": "emails_meta",
                "index": [("processing_status", 1), ("date_received", -1)],
                "reason": "Processing queue optimization",
                "estimated_benefit": "High"
            }
        ]
        
        return strategic_recommendations


# Pagination utilities
class PaginationHelper:
    """Helper class for consistent pagination across the application."""
    
    DEFAULT_PAGE_SIZE = 50
    MAX_PAGE_SIZE = 1000
    
    @classmethod
    def validate_pagination_params(
        cls, 
        page: int = 1, 
        page_size: int = DEFAULT_PAGE_SIZE
    ) -> tuple[int, int]:
        """Validate and normalize pagination parameters."""
        page = max(1, page)
        page_size = min(max(1, page_size), cls.MAX_PAGE_SIZE)
        return page, page_size
    
    @classmethod
    def calculate_skip(cls, page: int, page_size: int) -> int:
        """Calculate MongoDB skip value."""
        return (page - 1) * page_size
    
    @classmethod
    async def paginate_query(
        cls,
        query,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        sort_by: Optional[str] = None,
        sort_direction: int = DESCENDING
    ) -> Dict[str, Any]:
        """Execute paginated query with metadata."""
        
        page, page_size = cls.validate_pagination_params(page, page_size)
        skip = cls.calculate_skip(page, page_size)
        
        # Count total documents
        total_count = await query.count()
        
        # Apply pagination and sorting
        paginated_query = query.skip(skip).limit(page_size)
        
        if sort_by:
            paginated_query = paginated_query.sort([(sort_by, sort_direction)])
        
        # Execute query
        documents = await paginated_query.to_list()
        
        # Calculate pagination metadata
        total_pages = (total_count + page_size - 1) // page_size
        has_next = page < total_pages
        has_prev = page > 1
        
        return {
            "documents": documents,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_count": total_count,
                "total_pages": total_pages,
                "has_next": has_next,
                "has_prev": has_prev,
                "next_page": page + 1 if has_next else None,
                "prev_page": page - 1 if has_prev else None
            }
        }
    
    @classmethod
    def create_pagination_response(
        cls,
        documents: List[Any],
        page: int,
        page_size: int, 
        total_count: int
    ) -> Dict[str, Any]:
        """Create standardized pagination response."""
        
        total_pages = (total_count + page_size - 1) // page_size
        
        return {
            "data": documents,
            "meta": {
                "pagination": {
                    "current_page": page,
                    "per_page": page_size,
                    "total": total_count,
                    "last_page": total_pages,
                    "has_more_pages": page < total_pages,
                    "from": ((page - 1) * page_size) + 1 if documents else 0,
                    "to": min(page * page_size, total_count) if documents else 0
                }
            }
        }


# Index initialization function
async def initialize_production_indexes():
    """Initialize all production indexes."""
    try:
        logger.info("🔄 Initializing production database indexes...")
        
        # Create strategic indexes
        results = await IndexManager.create_all_indexes()
        
        # Log results
        total_indexes = sum(results.values())
        logger.info(f"✅ Production indexes initialized: {total_indexes} total")
        
        # Analyze current index usage
        usage_stats = await IndexManager.analyze_index_usage()
        logger.info(f"📊 Index usage analysis complete for {len(usage_stats)} collections")
        
        return {
            "success": True,
            "indexes_created": results,
            "total_indexes": total_indexes,
            "usage_stats": usage_stats
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize indexes: {e}")
        raise


# Performance monitoring
async def check_query_performance() -> Dict[str, Any]:
    """Check database query performance metrics."""
    if not MongoDBManager.database:
        return {"error": "Database not connected"}
    
    try:
        # Get database statistics
        db_stats = await MongoDBManager.database.command("dbStats")
        
        # Get server status for performance metrics
        server_status = await MongoDBManager.client.admin.command("serverStatus")
        
        return {
            "database_stats": {
                "collections": db_stats.get("collections", 0),
                "indexes": db_stats.get("indexes", 0),
                "data_size_mb": round(db_stats.get("dataSize", 0) / 1024 / 1024, 2),
                "index_size_mb": round(db_stats.get("indexSize", 0) / 1024 / 1024, 2)
            },
            "performance_metrics": {
                "connections": server_status.get("connections", {}),
                "opcounters": server_status.get("opcounters", {}),
                "uptime_seconds": server_status.get("uptime", 0)
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Performance check failed: {e}")
        return {"error": str(e)}