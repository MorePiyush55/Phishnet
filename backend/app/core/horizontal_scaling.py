"""
Horizontal Scaling Orchestrator for PhishNet
Manages multiple worker containers and simulates enterprise-grade scaling
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import docker
import psutil

from app.core.message_queue import EmailProcessingQueue, QueueMessage, QueuePriority
from app.core.redis_client import get_cache_manager
from app.core.metrics import performance_tracker
from app.config.logging import get_logger
from app.config.settings import settings

logger = get_logger(__name__)

class WorkerStatus(str, Enum):
    STARTING = "starting"
    RUNNING = "running"
    BUSY = "busy"
    IDLE = "idle"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"

class ScalingStrategy(str, Enum):
    MANUAL = "manual"
    AUTO_CPU = "auto_cpu"
    AUTO_QUEUE = "auto_queue"
    AUTO_HYBRID = "auto_hybrid"

@dataclass
class WorkerMetrics:
    """Metrics for individual worker performance"""
    worker_id: str
    status: WorkerStatus
    emails_processed: int = 0
    processing_time_avg: float = 0.0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    last_heartbeat: float = field(default_factory=time.time)
    started_at: float = field(default_factory=time.time)
    errors: int = 0
    
@dataclass 
class ScalingEvent:
    """Record of scaling decisions and events"""
    timestamp: float
    event_type: str  # scale_up, scale_down, worker_start, worker_stop
    reason: str
    workers_before: int
    workers_after: int
    metrics_snapshot: Dict[str, Any]

class HorizontalScaler:
    """Manages horizontal scaling of email processing workers"""
    
    def __init__(self):
        self.cache_manager = get_cache_manager()
        self.email_queue = EmailProcessingQueue()
        self.workers: Dict[str, WorkerMetrics] = {}
        self.scaling_events: List[ScalingEvent] = []
        
        # Scaling configuration
        self.min_workers = 2
        self.max_workers = 10
        self.target_cpu_usage = 70  # Percent
        self.target_queue_size = 50  # Messages
        self.scale_up_threshold = 0.8
        self.scale_down_threshold = 0.3
        self.cooldown_period = 300  # 5 minutes between scaling events
        
        self.last_scaling_event = 0
        self.strategy = ScalingStrategy.AUTO_HYBRID
        self.docker_client = None
        
        # Simulated worker containers (in production would be real Docker containers)
        self.simulated_workers = {}
        
    async def initialize(self):
        """Initialize the scaling system"""
        try:
            # Initialize Docker client (optional - falls back to simulation)
            try:
                self.docker_client = docker.from_env()
                logger.info("Docker client initialized for container management")
            except Exception as e:
                logger.warning(f"Docker not available, using simulation mode: {e}")
                self.docker_client = None
            
            # Initialize message queue
            await self.email_queue.initialize()
            
            # Start initial workers
            await self.ensure_min_workers()
            
            # Start monitoring loop
            asyncio.create_task(self.monitoring_loop())
            
            logger.info(f"Horizontal scaler initialized with {len(self.workers)} workers")
            
        except Exception as e:
            logger.error(f"Failed to initialize horizontal scaler: {e}")
            raise
    
    async def scale_up(self, count: int = 1, reason: str = "manual") -> List[str]:
        """Scale up by adding new workers"""
        if len(self.workers) >= self.max_workers:
            logger.warning(f"Cannot scale up: at maximum worker limit ({self.max_workers})")
            return []
        
        new_workers = []
        workers_to_add = min(count, self.max_workers - len(self.workers))
        
        try:
            for _ in range(workers_to_add):
                worker_id = await self.start_worker()
                if worker_id:
                    new_workers.append(worker_id)
            
            if new_workers:
                self._record_scaling_event("scale_up", reason, len(new_workers))
                logger.info(f"Scaled up by {len(new_workers)} workers", workers=new_workers)
            
            return new_workers
            
        except Exception as e:
            logger.error(f"Failed to scale up: {e}")
            return new_workers
    
    async def scale_down(self, count: int = 1, reason: str = "manual") -> List[str]:
        """Scale down by removing workers"""
        if len(self.workers) <= self.min_workers:
            logger.warning(f"Cannot scale down: at minimum worker limit ({self.min_workers})")
            return []
        
        removed_workers = []
        workers_to_remove = min(count, len(self.workers) - self.min_workers)
        
        try:
            # Select least busy workers for removal
            sorted_workers = sorted(
                self.workers.items(),
                key=lambda x: (x[1].status == WorkerStatus.IDLE, -x[1].emails_processed)
            )
            
            for i in range(workers_to_remove):
                worker_id = sorted_workers[i][0]
                success = await self.stop_worker(worker_id)
                if success:
                    removed_workers.append(worker_id)
            
            if removed_workers:
                self._record_scaling_event("scale_down", reason, len(removed_workers))
                logger.info(f"Scaled down by {len(removed_workers)} workers", workers=removed_workers)
            
            return removed_workers
            
        except Exception as e:
            logger.error(f"Failed to scale down: {e}")
            return removed_workers
    
    async def start_worker(self) -> Optional[str]:
        """Start a new worker instance"""
        worker_id = f"worker_{uuid.uuid4().hex[:8]}"
        
        try:
            if self.docker_client:
                # Start real Docker container
                container = await self._start_docker_worker(worker_id)
                if not container:
                    return None
            else:
                # Start simulated worker
                await self._start_simulated_worker(worker_id)
            
            # Register worker
            self.workers[worker_id] = WorkerMetrics(
                worker_id=worker_id,
                status=WorkerStatus.STARTING
            )
            
            # Start worker process
            asyncio.create_task(self._worker_process(worker_id))
            
            logger.info(f"Started worker: {worker_id}")
            return worker_id
            
        except Exception as e:
            logger.error(f"Failed to start worker {worker_id}: {e}")
            return None
    
    async def stop_worker(self, worker_id: str) -> bool:
        """Stop a worker instance"""
        try:
            if worker_id not in self.workers:
                logger.warning(f"Worker {worker_id} not found")
                return False
            
            # Update status
            self.workers[worker_id].status = WorkerStatus.STOPPING
            
            if self.docker_client and worker_id in self.simulated_workers:
                # Stop Docker container
                await self._stop_docker_worker(worker_id)
            else:
                # Stop simulated worker
                await self._stop_simulated_worker(worker_id)
            
            # Remove from tracking
            del self.workers[worker_id]
            
            logger.info(f"Stopped worker: {worker_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop worker {worker_id}: {e}")
            return False
    
    async def monitoring_loop(self):
        """Main monitoring loop for auto-scaling decisions"""
        while True:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                # Update worker metrics
                await self._update_worker_metrics()
                
                # Make scaling decisions
                if self.strategy != ScalingStrategy.MANUAL:
                    await self._evaluate_scaling()
                
                # Clean up dead workers
                await self._cleanup_dead_workers()
                
                # Update global metrics
                await self._update_global_metrics()
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(60)  # Longer delay on error
    
    async def _evaluate_scaling(self):
        """Evaluate whether scaling is needed"""
        if time.time() - self.last_scaling_event < self.cooldown_period:
            return  # Still in cooldown period
        
        current_workers = len([w for w in self.workers.values() if w.status == WorkerStatus.RUNNING])
        
        if current_workers == 0:
            await self.ensure_min_workers()
            return
        
        # Get current metrics
        queue_stats = await self.email_queue.get_queue_stats()
        total_queue_size = sum(
            queue_stats.get("queues", {}).get(priority, {}).get("length", 0)
            for priority in ["high", "medium", "low"]
        )
        
        avg_cpu = sum(w.cpu_usage for w in self.workers.values()) / len(self.workers)
        avg_processing_time = sum(w.processing_time_avg for w in self.workers.values()) / len(self.workers)
        
        # Scaling decision logic
        should_scale_up = False
        should_scale_down = False
        reason = ""
        
        if self.strategy in [ScalingStrategy.AUTO_QUEUE, ScalingStrategy.AUTO_HYBRID]:
            if total_queue_size > self.target_queue_size * self.scale_up_threshold:
                should_scale_up = True
                reason = f"Queue size ({total_queue_size}) above threshold"
            elif total_queue_size < self.target_queue_size * self.scale_down_threshold:
                should_scale_down = True
                reason = f"Queue size ({total_queue_size}) below threshold"
        
        if self.strategy in [ScalingStrategy.AUTO_CPU, ScalingStrategy.AUTO_HYBRID]:
            if avg_cpu > self.target_cpu_usage * self.scale_up_threshold:
                should_scale_up = True
                reason = f"CPU usage ({avg_cpu:.1f}%) above threshold"
            elif avg_cpu < self.target_cpu_usage * self.scale_down_threshold:
                should_scale_down = True
                reason = f"CPU usage ({avg_cpu:.1f}%) below threshold"
        
        # Execute scaling decision
        if should_scale_up and current_workers < self.max_workers:
            await self.scale_up(1, reason)
        elif should_scale_down and current_workers > self.min_workers:
            await self.scale_down(1, reason)
    
    async def _worker_process(self, worker_id: str):
        """Simulated worker process that processes emails"""
        try:
            worker = self.workers[worker_id]
            worker.status = WorkerStatus.RUNNING
            
            logger.info(f"Worker {worker_id} started processing")
            
            while worker.status in [WorkerStatus.RUNNING, WorkerStatus.BUSY, WorkerStatus.IDLE]:
                try:
                    # Dequeue messages
                    messages = await self.email_queue.dequeue(count=1, block_ms=5000)
                    
                    if messages:
                        worker.status = WorkerStatus.BUSY
                        
                        for message in messages:
                            # Simulate processing
                            start_time = time.time()
                            await self._process_email_message(message, worker_id)
                            processing_time = (time.time() - start_time) * 1000
                            
                            # Update worker metrics
                            worker.emails_processed += 1
                            worker.processing_time_avg = (
                                (worker.processing_time_avg * (worker.emails_processed - 1) + processing_time) /
                                worker.emails_processed
                            )
                            worker.last_heartbeat = time.time()
                            
                            # Acknowledge message
                            await self.email_queue.acknowledge(message, success=True)
                        
                        worker.status = WorkerStatus.RUNNING
                    else:
                        worker.status = WorkerStatus.IDLE
                        worker.last_heartbeat = time.time()
                
                except Exception as e:
                    logger.error(f"Worker {worker_id} processing error: {e}")
                    worker.errors += 1
                    await asyncio.sleep(5)
            
            worker.status = WorkerStatus.STOPPED
            logger.info(f"Worker {worker_id} stopped processing")
            
        except Exception as e:
            logger.error(f"Worker {worker_id} crashed: {e}")
            if worker_id in self.workers:
                self.workers[worker_id].status = WorkerStatus.ERROR
    
    async def _process_email_message(self, message: QueueMessage, worker_id: str):
        """Process individual email message (simulated)"""
        try:
            # Simulate email processing with variable time
            processing_time = 0.1 + (hash(message.id) % 50) / 1000  # 100-150ms
            await asyncio.sleep(processing_time)
            
            # Simulate occasional failures
            if hash(message.id) % 100 == 0:  # 1% failure rate
                raise Exception("Simulated processing failure")
            
            # Track processing in performance metrics
            performance_tracker.track_email_processed(
                processing_time_ms=int(processing_time * 1000),
                is_threat=hash(message.id) % 10 == 0,  # 10% threat rate
                risk_level="HIGH" if hash(message.id) % 20 == 0 else "LOW",
                from_cache=hash(message.id) % 5 == 0  # 20% cache hit rate
            )
            
        except Exception as e:
            logger.error(f"Worker {worker_id} failed to process message {message.id}: {e}")
            raise
    
    async def _update_worker_metrics(self):
        """Update metrics for all workers"""
        for worker_id, worker in self.workers.items():
            try:
                # Simulate CPU and memory usage
                if worker.status in [WorkerStatus.RUNNING, WorkerStatus.BUSY]:
                    base_cpu = 20 if worker.status == WorkerStatus.IDLE else 50
                    worker.cpu_usage = base_cpu + (hash(worker_id) % 30)
                    worker.memory_usage = 100 + (hash(worker_id) % 50)  # MB
                else:
                    worker.cpu_usage = 0
                    worker.memory_usage = 0
                
            except Exception as e:
                logger.error(f"Failed to update metrics for worker {worker_id}: {e}")
    
    async def _cleanup_dead_workers(self):
        """Remove workers that haven't sent heartbeat"""
        current_time = time.time()
        dead_workers = []
        
        for worker_id, worker in self.workers.items():
            if current_time - worker.last_heartbeat > 300:  # 5 minutes
                dead_workers.append(worker_id)
        
        for worker_id in dead_workers:
            logger.warning(f"Removing dead worker: {worker_id}")
            await self.stop_worker(worker_id)
    
    async def _update_global_metrics(self):
        """Update global scaling metrics"""
        try:
            metrics = {
                "timestamp": time.time(),
                "total_workers": len(self.workers),
                "active_workers": len([w for w in self.workers.values() if w.status == WorkerStatus.RUNNING]),
                "busy_workers": len([w for w in self.workers.values() if w.status == WorkerStatus.BUSY]),
                "total_processed": sum(w.emails_processed for w in self.workers.values()),
                "avg_processing_time": sum(w.processing_time_avg for w in self.workers.values()) / len(self.workers) if self.workers else 0,
                "strategy": self.strategy.value,
                "scaling_events": len(self.scaling_events)
            }
            
            await self.cache_manager.set("scaling_metrics", metrics, ttl=300)
            
        except Exception as e:
            logger.error(f"Failed to update global metrics: {e}")
    
    async def ensure_min_workers(self):
        """Ensure minimum number of workers are running"""
        current_workers = len(self.workers)
        if current_workers < self.min_workers:
            needed = self.min_workers - current_workers
            await self.scale_up(needed, "ensure_minimum")
    
    def _record_scaling_event(self, event_type: str, reason: str, worker_count_change: int):
        """Record scaling event for analysis"""
        event = ScalingEvent(
            timestamp=time.time(),
            event_type=event_type,
            reason=reason,
            workers_before=len(self.workers) - (worker_count_change if event_type == "scale_up" else -worker_count_change),
            workers_after=len(self.workers),
            metrics_snapshot={
                "cpu_avg": sum(w.cpu_usage for w in self.workers.values()) / len(self.workers) if self.workers else 0,
                "memory_avg": sum(w.memory_usage for w in self.workers.values()) / len(self.workers) if self.workers else 0,
                "processed_total": sum(w.emails_processed for w in self.workers.values())
            }
        )
        
        self.scaling_events.append(event)
        self.last_scaling_event = time.time()
        
        # Keep only last 100 events
        if len(self.scaling_events) > 100:
            self.scaling_events = self.scaling_events[-100:]
    
    async def _start_simulated_worker(self, worker_id: str):
        """Start simulated worker (when Docker not available)"""
        self.simulated_workers[worker_id] = {
            "started_at": time.time(),
            "status": "running",
            "pid": hash(worker_id) % 10000  # Fake PID
        }
    
    async def _stop_simulated_worker(self, worker_id: str):
        """Stop simulated worker"""
        if worker_id in self.simulated_workers:
            del self.simulated_workers[worker_id]
    
    async def _start_docker_worker(self, worker_id: str) -> Optional[str]:
        """Start real Docker worker container"""
        try:
            if not self.docker_client:
                return None
            
            # Docker container configuration for email worker
            container_config = {
                "image": "phishnet-worker:latest",
                "name": f"phishnet-worker-{worker_id}",
                "environment": {
                    "WORKER_ID": worker_id,
                    "REDIS_URL": settings.REDIS_URL,
                    "DATABASE_URL": settings.DATABASE_URL
                },
                "detach": True,
                "auto_remove": True
            }
            
            container = self.docker_client.containers.run(**container_config)
            return container.id
            
        except Exception as e:
            logger.error(f"Failed to start Docker worker {worker_id}: {e}")
            return None
    
    async def _stop_docker_worker(self, worker_id: str):
        """Stop Docker worker container"""
        try:
            container_name = f"phishnet-worker-{worker_id}"
            container = self.docker_client.containers.get(container_name)
            container.stop(timeout=30)
            logger.info(f"Stopped Docker container: {container_name}")
            
        except Exception as e:
            logger.error(f"Failed to stop Docker worker {worker_id}: {e}")
    
    async def get_scaling_status(self) -> Dict[str, Any]:
        """Get comprehensive scaling status"""
        try:
            queue_stats = await self.email_queue.get_queue_stats()
            
            return {
                "workers": {
                    "total": len(self.workers),
                    "running": len([w for w in self.workers.values() if w.status == WorkerStatus.RUNNING]),
                    "busy": len([w for w in self.workers.values() if w.status == WorkerStatus.BUSY]),
                    "idle": len([w for w in self.workers.values() if w.status == WorkerStatus.IDLE]),
                    "details": [
                        {
                            "id": w.worker_id,
                            "status": w.status.value,
                            "emails_processed": w.emails_processed,
                            "avg_processing_time": round(w.processing_time_avg, 2),
                            "cpu_usage": w.cpu_usage,
                            "memory_usage": w.memory_usage,
                            "uptime_minutes": round((time.time() - w.started_at) / 60, 1)
                        }
                        for w in self.workers.values()
                    ]
                },
                "queue": {
                    "total_messages": sum(
                        queue_stats.get("queues", {}).get(p, {}).get("length", 0)
                        for p in ["high", "medium", "low"]
                    ),
                    "by_priority": queue_stats.get("queues", {}),
                    "pending_messages": sum(
                        queue_stats.get("queues", {}).get(p, {}).get("pending_messages", 0)
                        for p in ["high", "medium", "low"]
                    )
                },
                "scaling": {
                    "strategy": self.strategy.value,
                    "min_workers": self.min_workers,
                    "max_workers": self.max_workers,
                    "last_scaling_event": self.last_scaling_event,
                    "recent_events": [
                        {
                            "timestamp": event.timestamp,
                            "type": event.event_type,
                            "reason": event.reason,
                            "workers_change": event.workers_after - event.workers_before
                        }
                        for event in self.scaling_events[-10:]  # Last 10 events
                    ]
                },
                "performance": {
                    "total_processed": sum(w.emails_processed for w in self.workers.values()),
                    "avg_processing_time": sum(w.processing_time_avg for w in self.workers.values()) / len(self.workers) if self.workers else 0,
                    "total_errors": sum(w.errors for w in self.workers.values()),
                    "avg_cpu_usage": sum(w.cpu_usage for w in self.workers.values()) / len(self.workers) if self.workers else 0
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get scaling status: {e}")
            return {"error": str(e)}

# Global horizontal scaler instance
horizontal_scaler = HorizontalScaler()

async def init_horizontal_scaling():
    """Initialize horizontal scaling system"""
    await horizontal_scaler.initialize()
    logger.info("Horizontal scaling system initialized")
