""""""

Database Health Checker - MongoDB OnlyDatabase Health Checker - MongoDB Only



Checks MongoDB connectivity, performance, and integrity.Checks MongoDB connectivity, performance, and integrity.

""""""



import asyncioimport asyncio

from typing import Any, Dict, Optionalfrom typing import Any, Dict, Optional



from .base import HealthChecker, HealthResult, HealthStatusfrom .base import HealthChecker, HealthResult, HealthStatus

from app.config.settings import get_settingsfrom app.config.settings import get_settings



# MongoDB health check# MongoDB health check

try:try:

    from app.db.mongodb import MongoDBManager    from app.db.mongodb import MongoDBManager

    MONGODB_AVAILABLE = True    MONGODB_AVAILABLE = True

except ImportError:except ImportError:

    MONGODB_AVAILABLE = False    MONGODB_AVAILABLE = False

    MongoDBManager = None    MongoDBManager = None





class DatabaseHealthChecker(HealthChecker):class DatabaseHealthChecker(HealthChecker):

    """Health checker for MongoDB connectivity and performance."""    """Health checker for MongoDB connectivity and performance."""

        

    def __init__(self, timeout: float = 5.0):    def __init__(self, timeout: float = 5.0):

        super().__init__("database", timeout)        super().__init__("database", timeout)

        self.settings = get_settings()        self.settings = get_settings()

            self._engine = None

    async def check_health(self) -> HealthResult:        self._session_maker = None

        """Check MongoDB health."""    

        try:    async def check_health(self) -> HealthResult:

            if not MONGODB_AVAILABLE:        """Check MongoDB health."""

                return HealthResult(        try:

                    component=self.component_name,            if not MONGODB_AVAILABLE:

                    status=HealthStatus.UNHEALTHY,                return HealthResult(

                    message="MongoDB client not available",                    component=self.component_name,

                    details={"error": "MongoDB dependencies not installed"}                    status=HealthStatus.UNHEALTHY,

                )                    message="MongoDB client not available",

                                details={"error": "MongoDB dependencies not installed"}

            if not self.settings.MONGODB_URI:                )

                return HealthResult(            

                    component=self.component_name,            if not self.settings.MONGODB_URI:

                    status=HealthStatus.UNHEALTHY,                return HealthResult(

                    message="MongoDB URI not configured",                    component=self.component_name,

                    details={"error": "MONGODB_URI setting not provided"}                    status=HealthStatus.UNHEALTHY,

                )                    message="MongoDB URI not configured",

                                details={"error": "MONGODB_URI setting not provided"}

            # Check MongoDB connectivity                )

            if MongoDBManager.client is None:            

                return HealthResult(            # Check MongoDB connectivity

                    component=self.component_name,            if MongoDBManager.client is None:

                    status=HealthStatus.UNHEALTHY,                return HealthResult(

                    message="MongoDB client not connected",                    component=self.component_name,

                    details={"error": "MongoDB connection not established"}                    status=HealthStatus.UNHEALTHY,

                )                    message="MongoDB client not connected",

                                details={"error": "MongoDB connection not established"}

            # Ping MongoDB to verify connectivity                )

            await MongoDBManager.client.admin.command('ping')            

                        # Ping MongoDB to verify connectivity

            # Get server info            await MongoDBManager.client.admin.command('ping')

            server_info = await MongoDBManager.client.admin.command('serverStatus')            

                        # Get server info

            # Check database connectivity            server_info = await MongoDBManager.client.admin.command('serverStatus')

            db = MongoDBManager.client[self.settings.MONGODB_DATABASE]            

            collections = await db.list_collection_names()            # Check database connectivity

                        db = MongoDBManager.client[self.settings.MONGODB_DATABASE]

            status = HealthStatus.HEALTHY            collections = await db.list_collection_names()

            message = "MongoDB connection successful"            

                        status = HealthStatus.HEALTHY

            # Check for any concerning metrics            message = "MongoDB connection successful"

            warnings = []            

            if server_info.get('connections', {}).get('current', 0) > 100:            # Check for any concerning metrics

                warnings.append("High number of active connections")            warnings = []

                status = HealthStatus.DEGRADED            if server_info.get('connections', {}).get('current', 0) > 100:

                            warnings.append("High number of active connections")

            if warnings:                status = HealthStatus.DEGRADED

                message = f"MongoDB accessible but with warnings: {'; '.join(warnings)}"            

                        if warnings:

            return HealthResult(                message = f"MongoDB accessible but with warnings: {'; '.join(warnings)}"

                component=self.component_name,            

                status=status,            return HealthResult(

                message=message,                component=self.component_name,

                details={                status=status,

                    "mongodb_version": server_info.get('version', 'unknown'),                message=message,

                    "database": self.settings.MONGODB_DATABASE,                details={

                    "collections": len(collections),                    "mongodb_version": server_info.get('version', 'unknown'),

                    "connections": server_info.get('connections', {}),                    "database": self.settings.MONGODB_DATABASE,

                    "uptime": server_info.get('uptime', 0)                    "collections": len(collections),

                }                    "connections": server_info.get('connections', {}),

            )                    "uptime": server_info.get('uptime', 0)

                            }

        except Exception as e:            )

            return HealthResult(            

                component=self.component_name,        except Exception as e:

                status=HealthStatus.UNHEALTHY,            return HealthResult(

                message=f"MongoDB health check failed: {str(e)}",                component=self.component_name,

                details={                status=HealthStatus.UNHEALTHY,

                    "error": str(e),                message=f"MongoDB health check failed: {str(e)}",

                    "error_type": type(e).__name__,                details={

                    "mongodb_uri_configured": bool(self.settings.MONGODB_URI)                    "error": str(e),

                }                    "error_type": type(e).__name__,

            )                    "mongodb_uri_configured": bool(self.settings.MONGODB_URI)

                }

    async def check_collections(self) -> HealthResult:            )

        """Check if required MongoDB collections exist."""                    'database_url': self.settings.DATABASE_URL.split('@')[0] + '@[REDACTED]' if '@' in self.settings.DATABASE_URL else self.settings.DATABASE_URL,

        try:                    'pool_info': pool_info,

            if not MONGODB_AVAILABLE or MongoDBManager.client is None:                    'warnings': warnings if warnings else None

                return HealthResult(                }

                    component=self.component_name,            )

                    status=HealthStatus.UNHEALTHY,            

                    message="MongoDB not available for collection check",        except SQLAlchemyError as e:

                    details={"error": "MongoDB not connected"}            return HealthResult(

                )                component=self.component_name,

                            status=HealthStatus.UNHEALTHY,

            db = MongoDBManager.client[self.settings.MONGODB_DATABASE]                message=f"Database connection failed: {str(e)}",

            collections = await db.list_collection_names()                details={

                                'error': str(e),

            # Define required collections for PhishNet                    'error_type': 'SQLAlchemyError',

            required_collections = [                    'database_url': self.settings.DATABASE_URL.split('@')[0] + '@[REDACTED]' if '@' in self.settings.DATABASE_URL else self.settings.DATABASE_URL

                "user",                }

                "email_analysis",            )

                "oauth_token",        except Exception as e:

                "audit_log"            return HealthResult(

            ]                component=self.component_name,

                            status=HealthStatus.UNHEALTHY,

            missing_collections = [col for col in required_collections if col not in collections]                message=f"Database health check failed: {str(e)}",

                            details={

            if missing_collections:                    'error': str(e),

                return HealthResult(                    'error_type': type(e).__name__

                    component=self.component_name,                }

                    status=HealthStatus.DEGRADED,            )

                    message=f"Missing collections: {', '.join(missing_collections)}",    

                    details={    async def check_migrations(self) -> HealthResult:

                        "required_collections": required_collections,        """Check if database migrations are up to date."""

                        "existing_collections": collections,        try:

                        "missing_collections": missing_collections            def sync_migration_check():

                    }                # This would integrate with Alembic or your migration system

                )                # For now, just verify tables exist

                            engine = self._get_engine()

            return HealthResult(                with engine.connect() as conn:

                component=self.component_name,                    # Check if core tables exist

                status=HealthStatus.HEALTHY,                    tables_query = text("""

                message="All required collections exist",                        SELECT table_name 

                details={                        FROM information_schema.tables 

                    "required_collections": required_collections,                        WHERE table_schema = 'public'

                    "existing_collections": collections,                    """) if 'postgresql' in self.settings.DATABASE_URL else text("""

                    "total_collections": len(collections)                        SELECT name FROM sqlite_master WHERE type='table'

                }                    """)

            )                    

                                result = conn.execute(tables_query)

        except Exception as e:                    tables = [row[0] for row in result]

            return HealthResult(                    

                component=self.component_name,                    # Expected core tables

                status=HealthStatus.UNHEALTHY,                    expected_tables = ['users', 'emails', 'detections', 'threat_intelligence']

                message=f"Collection check failed: {str(e)}",                    missing_tables = [t for t in expected_tables if t not in tables]

                details={                    

                    "error": str(e),                    return {

                    "error_type": type(e).__name__                        'existing_tables': tables,

                }                        'missing_tables': missing_tables,

            )                        'total_tables': len(tables)
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


class MongoDBHealthChecker(HealthChecker):
    """Health checker for MongoDB connectivity."""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__("mongodb", timeout)
        self.settings = get_settings()
    
    async def _check_connectivity(self) -> HealthResult:
        """Check MongoDB connectivity."""
        if not MONGODB_AVAILABLE:
            return HealthResult(
                component=f"{self.component_name}_connectivity",
                status=HealthStatus.FAIL,
                message="MongoDB support not available (missing dependencies)"
            )
        
        if not self.settings.USE_MONGODB or not self.settings.MONGODB_URI:
            return HealthResult(
                component=f"{self.component_name}_connectivity",
                status=HealthStatus.SKIP,
                message="MongoDB not configured"
            )
        
        try:
            is_connected = await ping_mongodb()
            
            if is_connected:
                return HealthResult(
                    component=f"{self.component_name}_connectivity",
                    status=HealthStatus.PASS,
                    message="MongoDB connection successful"
                )
            else:
                return HealthResult(
                    component=f"{self.component_name}_connectivity",
                    status=HealthStatus.FAIL,
                    message="MongoDB ping failed"
                )
                
        except Exception as e:
            return HealthResult(
                component=f"{self.component_name}_connectivity",
                status=HealthStatus.FAIL,
                message=f"MongoDB connection error: {str(e)}"
            )
    
    async def check_health(self) -> list[HealthResult]:
        """Check MongoDB health."""
        results = []
        
        # Check connectivity
        connectivity_result = await self._check_connectivity()
        results.append(connectivity_result)
        
        return results
            
        except Exception as e:
            return HealthResult(
                component=f"{self.component_name}_performance",
                status=HealthStatus.UNHEALTHY,
                message=f"Performance check failed: {str(e)}",
                details={'error': str(e), 'error_type': type(e).__name__}
            )
