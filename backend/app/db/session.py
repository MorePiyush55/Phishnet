"""
Async database session management for PhishNet with Postgres.
Provides connection pooling, dependency injection, and transaction handling.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
    AsyncEngine
)
from sqlalchemy.pool import QueuePool
from sqlalchemy import event
from sqlalchemy.engine import Engine

from app.config.settings import get_settings
from app.models.async_models import AsyncBase

logger = logging.getLogger(__name__)


class AsyncDatabase:
    """Async database manager with connection pooling and session handling."""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.engine: Optional[AsyncEngine] = None
        self.async_session_maker: Optional[async_sessionmaker[AsyncSession]] = None
        
    async def initialize(self) -> None:
        """Initialize the database engine and session factory."""
        logger.info("Initializing async database connection")
        
        # Create async engine with connection pooling
        self.engine = create_async_engine(
            self.database_url,
            # Connection pool settings
            poolclass=QueuePool,
            pool_size=20,
            max_overflow=0,
            pool_pre_ping=True,
            pool_recycle=3600,  # 1 hour
            
            # Performance settings
            echo=get_settings().ENVIRONMENT == "development",
            future=True,
            
            # Connection args for PostgreSQL
            connect_args={
                "server_settings": {
                    "application_name": "phishnet_app",
                    "jit": "off",  # Disable JIT for faster connection
                }
            }
        )
        
        # Create session factory
        self.async_session_maker = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False
        )
        
        logger.info("Database initialization completed")
    
    async def create_tables(self) -> None:
        """Create all database tables."""
        if not self.engine:
            raise RuntimeError("Database not initialized")
            
        logger.info("Creating database tables")
        async with self.engine.begin() as conn:
            await conn.run_sync(AsyncBase.metadata.create_all)
        logger.info("Database tables created successfully")
    
    async def drop_tables(self) -> None:
        """Drop all database tables (use with caution!)."""
        if not self.engine:
            raise RuntimeError("Database not initialized")
            
        logger.warning("Dropping all database tables")
        async with self.engine.begin() as conn:
            await conn.run_sync(AsyncBase.metadata.drop_all)
        logger.info("Database tables dropped")
    
    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session with automatic cleanup."""
        if not self.async_session_maker:
            raise RuntimeError("Database not initialized")
            
        async with self.async_session_maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    @asynccontextmanager
    async def get_transaction(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session with transaction management."""
        if not self.async_session_maker:
            raise RuntimeError("Database not initialized")
            
        async with self.async_session_maker() as session:
            async with session.begin():
                try:
                    yield session
                except Exception:
                    await session.rollback()
                    raise
    
    async def close(self) -> None:
        """Close the database connection."""
        if self.engine:
            logger.info("Closing database connection")
            await self.engine.dispose()
            self.engine = None
            self.async_session_maker = None


# Global database instance
database: Optional[AsyncDatabase] = None


async def init_database() -> AsyncDatabase:
    """Initialize the global database instance."""
    global database
    
    settings = get_settings()
    database = AsyncDatabase(settings.DATABASE_URL)
    await database.initialize()
    
    return database


async def get_database() -> AsyncDatabase:
    """Get the global database instance."""
    if not database:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return database


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for getting a database session."""
    db = await get_database()
    async with db.get_session() as session:
        yield session


async def get_transaction() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for getting a transactional database session."""
    db = await get_database()
    async with db.get_transaction() as session:
        yield session


# Database event listeners for performance monitoring
@event.listens_for(Engine, "before_cursor_execute")
def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """Log slow queries in development."""
    if get_settings().ENVIRONMENT == "development":
        context._query_start_time = logger.info(f"SQL Query: {statement[:100]}...")


@event.listens_for(Engine, "after_cursor_execute")  
def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """Log query execution time."""
    if get_settings().ENVIRONMENT == "development":
        total_time = logger.info("Query completed")


# Health check function
async def check_database_health() -> bool:
    """Check if database is healthy and responsive."""
    try:
        db = await get_database()
        async with db.get_session() as session:
            result = await session.execute("SELECT 1")
            return result.scalar() == 1
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


# Migration utilities
async def run_migrations():
    """Run Alembic migrations programmatically."""
    from alembic.config import Config
    from alembic import command
    import asyncio
    
    logger.info("Running database migrations")
    
    # Run migrations in a thread since Alembic is synchronous
    def run_alembic():
        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head")
    
    await asyncio.get_event_loop().run_in_executor(None, run_alembic)
    logger.info("Migrations completed")


# Cleanup function for application shutdown
async def cleanup_database():
    """Cleanup database connections on application shutdown."""
    global database
    if database:
        await database.close()
        database = None
        logger.info("Database cleanup completed")


# Dependency for getting database session
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency function to get database session."""
    async with get_db_session() as session:
        yield session
