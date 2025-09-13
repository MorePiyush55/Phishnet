"""
Database Health Checker

Checks database connectivity, performance, and integrity.
"""

import asyncio
from typing import Any, Dict, Optional
from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError

from .base import HealthChecker, HealthResult, HealthStatus
from app.config.settings import get_settings


class DatabaseHealthChecker(HealthChecker):
    """Health checker for database connectivity and performance."""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__("database", timeout)
        self.settings = get_settings()
        self._engine = None
        self._session_maker = None
    
    def _get_engine(self):
        """Get database engine, creating if necessary."""
        if self._engine is None:
            self._engine = create_engine(
                self.settings.DATABASE_URL,
                echo=False,
                pool_pre_ping=True,  # Verify connections before use
                pool_recycle=300     # Recycle connections every 5 minutes
            )
        return self._engine
    
    def _get_session_maker(self):
        """Get session maker."""
        if self._session_maker is None:
            engine = self._get_engine()
            self._session_maker = sessionmaker(bind=engine)
        return self._session_maker
    
    async def check_health(self) -> HealthResult:
        """Check database health."""
        try:
            # Basic connectivity test
            engine = self._get_engine()
            
            # Run in thread since SQLAlchemy is sync
            def sync_check():
                with engine.connect() as conn:
                    # Simple query to test connectivity
                    result = conn.execute(text("SELECT 1"))
                    value = result.scalar()
                    if value != 1:
                        raise Exception("Database returned unexpected value")
                    
                    # Get connection pool info
                    pool = engine.pool
                    pool_info = {
                        'size': pool.size(),
                        'checked_in': pool.checkedin(),
                        'checked_out': pool.checkedout(),
                        'invalid': pool.invalid()
                    }
                    
                    return pool_info
            
            # Run sync operations in thread
            loop = asyncio.get_event_loop()
            pool_info = await loop.run_in_executor(None, sync_check)
            
            # Check pool health
            status = HealthStatus.HEALTHY
            message = "Database connection successful"
            
            # Check for concerning pool metrics
            warnings = []
            if pool_info['checked_out'] > pool_info['size'] * 0.8:
                warnings.append("High connection pool utilization")
                status = HealthStatus.DEGRADED
            
            if pool_info['invalid'] > 0:
                warnings.append(f"{pool_info['invalid']} invalid connections in pool")
                status = HealthStatus.DEGRADED
            
            if warnings:
                message = f"Database accessible but with warnings: {'; '.join(warnings)}"
            
            return HealthResult(
                component=self.component_name,
                status=status,
                message=message,
                details={
                    'database_url': self.settings.DATABASE_URL.split('@')[0] + '@[REDACTED]' if '@' in self.settings.DATABASE_URL else self.settings.DATABASE_URL,
                    'pool_info': pool_info,
                    'warnings': warnings if warnings else None
                }
            )
            
        except SQLAlchemyError as e:
            return HealthResult(
                component=self.component_name,
                status=HealthStatus.UNHEALTHY,
                message=f"Database connection failed: {str(e)}",
                details={
                    'error': str(e),
                    'error_type': 'SQLAlchemyError',
                    'database_url': self.settings.DATABASE_URL.split('@')[0] + '@[REDACTED]' if '@' in self.settings.DATABASE_URL else self.settings.DATABASE_URL
                }
            )
        except Exception as e:
            return HealthResult(
                component=self.component_name,
                status=HealthStatus.UNHEALTHY,
                message=f"Database health check failed: {str(e)}",
                details={
                    'error': str(e),
                    'error_type': type(e).__name__
                }
            )
    
    async def check_migrations(self) -> HealthResult:
        """Check if database migrations are up to date."""
        try:
            def sync_migration_check():
                # This would integrate with Alembic or your migration system
                # For now, just verify tables exist
                engine = self._get_engine()
                with engine.connect() as conn:
                    # Check if core tables exist
                    tables_query = text("""
                        SELECT table_name 
                        FROM information_schema.tables 
                        WHERE table_schema = 'public'
                    """) if 'postgresql' in self.settings.DATABASE_URL else text("""
                        SELECT name FROM sqlite_master WHERE type='table'
                    """)
                    
                    result = conn.execute(tables_query)
                    tables = [row[0] for row in result]
                    
                    # Expected core tables
                    expected_tables = ['users', 'emails', 'detections', 'threat_intelligence']
                    missing_tables = [t for t in expected_tables if t not in tables]
                    
                    return {
                        'existing_tables': tables,
                        'missing_tables': missing_tables,
                        'total_tables': len(tables)
                    }
            
            loop = asyncio.get_event_loop()
            migration_info = await loop.run_in_executor(None, sync_migration_check)
            
            if migration_info['missing_tables']:
                return HealthResult(
                    component=f"{self.component_name}_migrations",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Missing database tables: {', '.join(migration_info['missing_tables'])}",
                    details=migration_info
                )
            else:
                return HealthResult(
                    component=f"{self.component_name}_migrations",
                    status=HealthStatus.HEALTHY,
                    message=f"Database schema is up to date ({migration_info['total_tables']} tables)",
                    details=migration_info
                )
                
        except Exception as e:
            return HealthResult(
                component=f"{self.component_name}_migrations",
                status=HealthStatus.UNHEALTHY,
                message=f"Migration check failed: {str(e)}",
                details={'error': str(e), 'error_type': type(e).__name__}
            )
    
    async def check_performance(self) -> HealthResult:
        """Check database performance metrics."""
        try:
            def sync_performance_check():
                engine = self._get_engine()
                import time
                start_time = time.time()
                
                with engine.connect() as conn:
                    # Run a simple query and measure time
                    conn.execute(text("SELECT 1"))
                    
                query_time = (time.time() - start_time) * 1000  # Convert to milliseconds
                
                return {
                    'query_time_ms': query_time
                }
            
            loop = asyncio.get_event_loop()
            perf_info = await loop.run_in_executor(None, sync_performance_check)
            
            # Determine status based on query time
            query_time = perf_info['query_time_ms']
            if query_time > 1000:  # > 1 second
                status = HealthStatus.UNHEALTHY
                message = f"Database performance is poor (query took {query_time:.2f}ms)"
            elif query_time > 100:  # > 100ms
                status = HealthStatus.DEGRADED
                message = f"Database performance is degraded (query took {query_time:.2f}ms)"
            else:
                status = HealthStatus.HEALTHY
                message = f"Database performance is good (query took {query_time:.2f}ms)"
            
            return HealthResult(
                component=f"{self.component_name}_performance",
                status=status,
                message=message,
                details=perf_info
            )
            
        except Exception as e:
            return HealthResult(
                component=f"{self.component_name}_performance",
                status=HealthStatus.UNHEALTHY,
                message=f"Performance check failed: {str(e)}",
                details={'error': str(e), 'error_type': type(e).__name__}
            )
