"""Database dependency injection for FastAPI routes."""

from typing import AsyncGenerator
from motor.motor_asyncio import AsyncIOMotorDatabase
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

from app.db.mongodb import MongoDBManager, get_mongo_database

# SQLAlchemy Base for compatibility (even though we use MongoDB)
Base = declarative_base()

# Create a dummy engine and SessionLocal for SQLAlchemy compatibility
# These are stubs since we're using MongoDB
engine = create_engine("sqlite:///:memory:")  # Dummy in-memory database
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

async def get_db() -> AsyncGenerator[AsyncIOMotorDatabase, None]:
    """
    FastAPI dependency to get MongoDB database instance.
    
    This is used as a dependency injection for routes that need database access.
    """
    try:
        database = await get_mongo_database()
        yield database
    finally:
        # Connection cleanup handled by MongoDBManager
        pass


# Alias for compatibility
get_database = get_db