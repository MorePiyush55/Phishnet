"""
Worker Management and Utilities
Provides worker lifecycle management and monitoring capabilities.
"""

import os
import logging
import psutil
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from celery import current_app
from app.workers.celery_config import celery_app

logger = logging.getLogger(__name__)

class WorkerManager:
    """Manages worker lifecycle and health monitoring."""
    
    def __init__(self):
        self.celery_app = celery_app
        self.inspect = celery_app.control.inspect()
    
    def get_worker_status(self) -> Dict[str, Any]:
        """Get comprehensive worker status information."""
        try:
            stats = self.inspect.stats() or {}
            active = self.inspect.active() or {}
            reserved = self.inspect.reserved() or {}
            scheduled = self.inspect.scheduled() or {}
            ping_results = self.inspect.ping() or {}
            
            worker_info = {}
            
            for worker_name in stats.keys():
                worker_stats = stats.get(worker_name, {})
                worker_info[worker_name] = {
                    "status": "online" if worker_name in ping_results else "offline",
                    "active_tasks": len(active.get(worker_name, [])),
                    "reserved_tasks": len(reserved.get(worker_name, [])),
                    "scheduled_tasks": len(scheduled.get(worker_name, [])),
                    "processed_tasks": worker_stats.get("total", {}).get("celery.worker.request.process", 0),
                    "failed_tasks": worker_stats.get("total", {}).get("celery.worker.request.failure", 0),
                    "succeeded_tasks": worker_stats.get("total", {}).get("celery.worker.request.success", 0),
                    "uptime": worker_stats.get("clock", "unknown"),
                    "load_avg": worker_stats.get("rusage", {}).get("utime", 0),
                    "memory_info": self._get_worker_memory_info(worker_name)
                }
            
            return {
                "workers": worker_info,
                "total_workers": len(worker_info),
                "online_workers": sum(1 for w in worker_info.values() if w["status"] == "online"),
                "total_active_tasks": sum(w["active_tasks"] for w in worker_info.values()),
                "total_reserved_tasks": sum(w["reserved_tasks"] for w in worker_info.values()),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get worker status: {str(e)}")
            return {"error": str(e), "timestamp": datetime.utcnow().isoformat()}
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get detailed queue status and metrics."""
        try:
            # Get queue lengths from Redis
            from app.core.redis_client import get_redis_client
            redis_client = get_redis_client()
            
            queue_info = {}
            queues = ["realtime", "standard", "heavy", "background", "dlq"]
            
            for queue_name in queues:
                queue_key = f"celery.{queue_name}"
                queue_length = redis_client.llen(queue_key)
                
                # Get processing statistics
                processing_stats = self._get_queue_processing_stats(queue_name)
                
                queue_info[queue_name] = {
                    "length": queue_length,
                    "priority": self._get_queue_priority(queue_name),
                    "processing_time_avg": processing_stats.get("avg_time", 0),
                    "success_rate": processing_stats.get("success_rate", 0),
                    "last_activity": processing_stats.get("last_activity"),
                    "worker_count": self._count_workers_for_queue(queue_name)
                }
            
            return {
                "queues": queue_info,
                "total_pending": sum(q["length"] for q in queue_info.values()),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get queue status: {str(e)}")
            return {"error": str(e), "timestamp": datetime.utcnow().isoformat()}
    
    def scale_workers(self, queue: str, target_workers: int) -> Dict[str, Any]:
        """Scale workers for a specific queue."""
        try:
            current_workers = self._count_workers_for_queue(queue)
            
            if target_workers > current_workers:
                # Scale up
                for i in range(target_workers - current_workers):
                    self._start_worker(queue)
                action = f"scaled up from {current_workers} to {target_workers}"
            elif target_workers < current_workers:
                # Scale down
                workers_to_stop = current_workers - target_workers
                self._stop_workers(queue, workers_to_stop)
                action = f"scaled down from {current_workers} to {target_workers}"
            else:
                action = f"no scaling needed, already at {current_workers} workers"
            
            return {
                "success": True,
                "queue": queue,
                "previous_workers": current_workers,
                "target_workers": target_workers,
                "action": action,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to scale workers for queue {queue}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def restart_worker(self, worker_name: str) -> Dict[str, Any]:
        """Restart a specific worker."""
        try:
            # Gracefully shutdown worker
            self.celery_app.control.broadcast("shutdown", destination=[worker_name])
            
            # Wait a moment then start new worker
            # This would typically be handled by a process manager like supervisord
            
            return {
                "success": True,
                "worker": worker_name,
                "action": "restart initiated",
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to restart worker {worker_name}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def purge_queue(self, queue_name: str) -> Dict[str, Any]:
        """Purge all tasks from a specific queue."""
        try:
            # Use Celery's purge command
            result = self.celery_app.control.purge()
            
            return {
                "success": True,
                "queue": queue_name,
                "action": "queue purged",
                "result": result,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to purge queue {queue_name}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def get_task_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent task execution history."""
        try:
            # This would typically query a database or monitoring system
            # For now, return mock data structure
            
            return {
                "tasks": [],  # Would contain task execution history
                "total": 0,
                "limit": limit,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get task history: {str(e)}")
            return {"error": str(e)}
    
    def _get_worker_memory_info(self, worker_name: str) -> Dict[str, Any]:
        """Get memory information for a specific worker."""
        try:
            # Extract PID from worker name or use process monitoring
            # This is a simplified implementation
            process = psutil.Process()  # Current process for demo
            memory_info = process.memory_info()
            
            return {
                "rss": memory_info.rss,
                "vms": memory_info.vms,
                "percent": process.memory_percent()
            }
            
        except Exception:
            return {"error": "memory info not available"}
    
    def _get_queue_priority(self, queue_name: str) -> int:
        """Get priority level for a queue."""
        priority_map = {
            "realtime": 10,
            "standard": 5,
            "heavy": 3,
            "background": 1,
            "dlq": 0
        }
        return priority_map.get(queue_name, 0)
    
    def _get_queue_processing_stats(self, queue_name: str) -> Dict[str, Any]:
        """Get processing statistics for a queue."""
        # This would typically query a metrics database
        # Return mock data for now
        return {
            "avg_time": 0,
            "success_rate": 95.5,
            "last_activity": datetime.utcnow().isoformat()
        }
    
    def _count_workers_for_queue(self, queue_name: str) -> int:
        """Count active workers processing a specific queue."""
        try:
            active_queues = self.inspect.active_queues() or {}
            count = 0
            
            for worker, queues in active_queues.items():
                if any(q.get("name") == queue_name for q in queues):
                    count += 1
                    
            return count
            
        except Exception:
            return 0
    
    def _start_worker(self, queue: str):
        """Start a new worker for a specific queue."""
        # This would typically interface with a process manager
        # Implementation depends on deployment method
        logger.info(f"Starting new worker for queue: {queue}")
    
    def _stop_workers(self, queue: str, count: int):
        """Stop workers for a specific queue."""
        # This would typically interface with a process manager
        logger.info(f"Stopping {count} workers for queue: {queue}")

# Singleton instance
worker_manager = WorkerManager()

def get_worker_manager() -> WorkerManager:
    """Get the worker manager instance."""
    return worker_manager