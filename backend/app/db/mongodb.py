"""MongoDB database configuration and connection management."""

import os
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from beanie import init_beanie
import logging

from app.config.settings import settings

logger = logging.getLogger(__name__)

class MongoDBManager:
    """MongoDB connection and database management."""
    
    client: Optional[AsyncIOMotorClient] = None
    database: Optional[AsyncIOMotorDatabase] = None
    
    @classmethod
    async def connect_to_mongo(cls) -> None:
        """Create database connection."""
        try:
            # Get MongoDB URI with password substituted
            mongodb_uri = settings.get_mongodb_uri()
            if not mongodb_uri:
                raise ValueError("MONGODB_URI not configured")
            
            logger.info("Connecting to MongoDB...")
            cls.client = AsyncIOMotorClient(mongodb_uri)
            cls.database = cls.client[settings.MONGODB_DATABASE]
            
            # Test the connection
            await cls.client.admin.command('ping')
            logger.info(f"Successfully connected to MongoDB database: {settings.MONGODB_DATABASE}")
            
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
    
    @classmethod
    async def close_mongo_connection(cls) -> None:
        """Close database connection."""
        if cls.client:
            cls.client.close()
            logger.info("Disconnected from MongoDB")
    
    @classmethod
    async def initialize_beanie(cls, document_models: list) -> None:
        """Initialize Beanie ODM with document models."""
        if cls.database is None:
            await cls.connect_to_mongo()
        
        try:
            await init_beanie(database=cls.database, document_models=document_models)
            logger.info("Beanie ODM initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Beanie: {e}")
            raise
    
    @classmethod
    def get_database(cls) -> Optional[AsyncIOMotorDatabase]:
        """Get the database instance."""
        return cls.database


# Convenience functions
async def get_mongo_database() -> AsyncIOMotorDatabase:
    """Get MongoDB database instance."""
    if not MongoDBManager.database:
        await MongoDBManager.connect_to_mongo()
    return MongoDBManager.database


async def ping_mongodb() -> bool:
    """Test MongoDB connection."""
    try:
        if not MongoDBManager.client:
            await MongoDBManager.connect_to_mongo()
        
        await MongoDBManager.client.admin.command('ping')
        return True
    except Exception as e:
        logger.error(f"MongoDB ping failed: {e}")
        return False