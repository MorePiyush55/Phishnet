"""
Graceful shutdown handler for PhishNet application.
Handles SIGTERM and SIGINT signals for proper application shutdown.
"""

import asyncio
import signal
import sys
import time
import logging
from typing import Set, Callable, Any
from contextlib import asynccontextmanager
from fastapi import FastAPI

logger = logging.getLogger(__name__)

class GracefulShutdownHandler:
    """Handles graceful shutdown of the PhishNet application."""
    
    def __init__(self, app: FastAPI):
        self.app = app
        self.shutdown_event = asyncio.Event()
        self.shutdown_tasks: Set[asyncio.Task] = set()
        self.cleanup_functions: list[Callable] = []
        self.is_shutting_down = False
        self.shutdown_timeout = 30  # seconds
        
    def add_cleanup_function(self, func: Callable):
        """Add a cleanup function to be called during shutdown."""
        self.cleanup_functions.append(func)
    
    def register_shutdown_handlers(self):
        """Register signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            asyncio.create_task(self.shutdown())
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        # Windows doesn't have SIGHUP
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, signal_handler)
    
    async def shutdown(self):
        """Perform graceful shutdown sequence."""
        if self.is_shutting_down:
            logger.warning("Shutdown already in progress")
            return
        
        self.is_shutting_down = True
        start_time = time.time()
        
        logger.info("Starting graceful shutdown sequence...")
        
        try:
            # Step 1: Stop accepting new requests
            logger.info("Step 1: Stopping acceptance of new requests")
            self.shutdown_event.set()
            
            # Step 2: Wait for existing requests to complete
            logger.info("Step 2: Waiting for existing requests to complete")
            await self._wait_for_requests()
            
            # Step 3: Stop background tasks
            logger.info("Step 3: Stopping background tasks")
            await self._stop_background_tasks()
            
            # Step 4: Run cleanup functions
            logger.info("Step 4: Running cleanup functions")
            await self._run_cleanup_functions()
            
            # Step 5: Close database connections
            logger.info("Step 5: Closing database connections")
            await self._close_database_connections()
            
            # Step 6: Close Redis connections
            logger.info("Step 6: Closing Redis connections")
            await self._close_redis_connections()
            
            shutdown_time = time.time() - start_time
            logger.info(f"Graceful shutdown completed in {shutdown_time:.2f} seconds")
            
        except Exception as e:
            logger.error(f"Error during graceful shutdown: {e}")
            
        finally:
            # Force exit if we're taking too long
            if time.time() - start_time > self.shutdown_timeout:
                logger.warning(f"Shutdown timeout ({self.shutdown_timeout}s) exceeded, forcing exit")
                sys.exit(1)
            else:
                sys.exit(0)
    
    async def _wait_for_requests(self, timeout: float = 10.0):
        """Wait for existing HTTP requests to complete."""
        try:
            # This would typically check active request counters
            # For now, we'll add a small delay to allow requests to finish
            await asyncio.sleep(2.0)
            logger.info("Existing requests handling complete")
        except Exception as e:
            logger.error(f"Error waiting for requests: {e}")
    
    async def _stop_background_tasks(self):
        """Stop all background tasks gracefully."""
        try:
            # Cancel all tracked background tasks
            if self.shutdown_tasks:
                logger.info(f"Cancelling {len(self.shutdown_tasks)} background tasks")
                for task in self.shutdown_tasks:
                    if not task.done():
                        task.cancel()
                
                # Wait for tasks to finish cancellation
                await asyncio.gather(*self.shutdown_tasks, return_exceptions=True)
                logger.info("Background tasks stopped")
            
        except Exception as e:
            logger.error(f"Error stopping background tasks: {e}")
    
    async def _run_cleanup_functions(self):
        """Run all registered cleanup functions."""
        try:
            for cleanup_func in self.cleanup_functions:
                try:
                    if asyncio.iscoroutinefunction(cleanup_func):
                        await cleanup_func()
                    else:
                        cleanup_func()
                    logger.debug(f"Cleanup function {cleanup_func.__name__} completed")
                except Exception as e:
                    logger.error(f"Error in cleanup function {cleanup_func.__name__}: {e}")
            
            logger.info("All cleanup functions completed")
            
        except Exception as e:
            logger.error(f"Error running cleanup functions: {e}")
    
    async def _close_database_connections(self):
        """Close database connection pools."""
        try:
            from app.database import database
            if database.is_connected:
                await database.disconnect()
                logger.info("Database connections closed")
        except Exception as e:
            logger.error(f"Error closing database connections: {e}")
    
    async def _close_redis_connections(self):
        """Close Redis connections."""
        try:
            from app.services.redis_service import RedisService
            redis_service = RedisService()
            await redis_service.close()
            logger.info("Redis connections closed")
        except Exception as e:
            logger.error(f"Error closing Redis connections: {e}")
    
    def add_background_task(self, task: asyncio.Task):
        """Track a background task for proper shutdown."""
        self.shutdown_tasks.add(task)
        task.add_done_callback(self.shutdown_tasks.discard)
    
    @asynccontextmanager
    async def lifespan_manager(self, app: FastAPI):
        """FastAPI lifespan context manager for startup/shutdown."""
        # Startup
        logger.info("PhishNet application starting up...")
        self.register_shutdown_handlers()
        
        # Register startup tasks
        startup_tasks = []
        
        try:
            # Initialize database
            from app.database import database
            if not database.is_connected:
                await database.connect()
                logger.info("Database connected")
            
            # Initialize Redis
            from app.services.redis_service import RedisService
            redis_service = RedisService()
            await redis_service.connect()
            logger.info("Redis connected")
            
            # Start background tasks if any
            # startup_tasks.append(asyncio.create_task(some_background_task()))
            
            for task in startup_tasks:
                self.add_background_task(task)
            
            logger.info("PhishNet application startup completed")
            yield
            
        except Exception as e:
            logger.error(f"Application startup failed: {e}")
            raise
        
        finally:
            # Shutdown
            if not self.is_shutting_down:
                await self.shutdown()


# Global shutdown handler instance
shutdown_handler = None

def get_shutdown_handler(app: FastAPI) -> GracefulShutdownHandler:
    """Get or create the global shutdown handler."""
    global shutdown_handler
    if shutdown_handler is None:
        shutdown_handler = GracefulShutdownHandler(app)
    return shutdown_handler

def setup_graceful_shutdown(app: FastAPI) -> GracefulShutdownHandler:
    """Setup graceful shutdown for the FastAPI application."""
    handler = get_shutdown_handler(app)
    
    # Set the lifespan event handler
    app.router.lifespan_context = handler.lifespan_manager
    
    return handler
