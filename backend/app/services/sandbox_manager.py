"""
Sandbox Session Manager for PhishNet

Manages sandbox execution sessions with job queuing, container lifecycle,
evidence collection, and secure orchestration.
"""

import asyncio
import time
import uuid
import json
import hashlib
import docker
import redis.asyncio as redis
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
import structlog

from app.config.settings import settings

logger = structlog.get_logger(__name__)


class SandboxStatus(Enum):
    """Sandbox execution status."""
    QUEUED = "queued"
    PREPARING = "preparing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class SandboxPriority(Enum):
    """Sandbox execution priority."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class SandboxJob:
    """Sandbox execution job."""
    job_id: str
    session_id: str
    target_url: str
    job_type: str  # 'url_analysis', 'file_analysis', 'email_analysis'
    priority: SandboxPriority
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: SandboxStatus = SandboxStatus.QUEUED
    container_id: Optional[str] = None
    evidence_path: Optional[str] = None
    error_message: Optional[str] = None
    user_id: Optional[str] = None
    analysis_config: Dict[str, Any] = None
    execution_timeout: int = 60
    retry_count: int = 0
    max_retries: int = 2


@dataclass
class SandboxResource:
    """Sandbox resource allocation."""
    memory_limit: str = "512m"
    cpu_limit: str = "0.5"
    disk_limit: str = "1g"
    network_bandwidth: str = "10mbps"
    execution_timeout: int = 60


@dataclass
class SandboxMetrics:
    """Sandbox execution metrics."""
    total_jobs: int = 0
    completed_jobs: int = 0
    failed_jobs: int = 0
    timeout_jobs: int = 0
    average_execution_time: float = 0.0
    queue_length: int = 0
    active_containers: int = 0
    resource_utilization: Dict[str, float] = None


class ContainerManager:
    """Manages Docker containers for sandbox execution."""
    
    def __init__(self):
        self.docker_client = docker.from_env()
        self.active_containers: Dict[str, docker.models.containers.Container] = {}
        self.container_network = "phishnet_sandbox_network"
        
    async def create_sandbox_container(self, job: SandboxJob) -> str:
        """Create and start sandbox container."""
        try:
            container_name = f"phishnet-sandbox-{job.session_id}"
            
            # Container configuration
            container_config = {
                "image": "phishnet-sandbox:latest",
                "name": container_name,
                "hostname": f"sandbox-{job.session_id[:8]}",
                "environment": {
                    "SANDBOX_SESSION_ID": job.session_id,
                    "TARGET_URL": job.target_url,
                    "EXECUTION_TIMEOUT": str(job.execution_timeout),
                    "SCREENSHOT_ENABLED": "true",
                    "NETWORK_MONITORING": "true",
                    "EVIDENCE_COLLECTION": "true",
                    "JOB_ID": job.job_id,
                    "JOB_TYPE": job.job_type
                },
                "volumes": {
                    str(Path(settings.SANDBOX_EVIDENCE_DIR) / job.session_id): {
                        "bind": "/sandbox/evidence", 
                        "mode": "rw"
                    },
                    str(Path(settings.SANDBOX_LOGS_DIR) / job.session_id): {
                        "bind": "/sandbox/logs", 
                        "mode": "rw"
                    }
                },
                "network": self.container_network,
                "security_opt": [
                    "seccomp=/etc/docker/seccomp-sandbox.json",
                    "no-new-privileges:true",
                    "apparmor:docker-default"
                ],
                "cap_drop": ["ALL"],
                "cap_add": ["NET_RAW"],  # For network monitoring only
                "read_only": True,
                "tmpfs": {
                    "/tmp": "noexec,nosuid,size=100m",
                    "/var/tmp": "noexec,nosuid,size=50m",
                    "/sandbox/temp": "noexec,nosuid,size=200m"
                },
                "ulimits": [
                    docker.types.Ulimit(name="nproc", soft=64, hard=128),
                    docker.types.Ulimit(name="nofile", soft=1024, hard=2048),
                    docker.types.Ulimit(name="fsize", soft=100000000, hard=100000000)  # 100MB
                ],
                "mem_limit": job.analysis_config.get("memory_limit", "512m"),
                "cpus": job.analysis_config.get("cpu_limit", "0.5"),
                "restart_policy": {"Name": "no"},
                "detach": True,
                "remove": False  # Keep for evidence collection
            }
            
            # Create and start container
            container = self.docker_client.containers.run(**container_config)
            
            self.active_containers[job.session_id] = container
            
            logger.info("Sandbox container created", 
                       job_id=job.job_id,
                       session_id=job.session_id,
                       container_id=container.id)
            
            return container.id
            
        except Exception as e:
            logger.error("Failed to create sandbox container", 
                        job_id=job.job_id,
                        error=str(e))
            raise
    
    async def monitor_container(self, session_id: str, timeout: int) -> Dict[str, Any]:
        """Monitor container execution."""
        container = self.active_containers.get(session_id)
        if not container:
            raise ValueError(f"Container not found for session {session_id}")
        
        start_time = time.time()
        
        try:
            # Wait for container completion or timeout
            result = container.wait(timeout=timeout)
            execution_time = time.time() - start_time
            
            # Get container logs
            logs = container.logs(stdout=True, stderr=True).decode('utf-8')
            
            # Get container stats
            stats = container.stats(stream=False)
            
            return {
                "exit_code": result["StatusCode"],
                "execution_time": execution_time,
                "logs": logs,
                "stats": stats,
                "status": "completed" if result["StatusCode"] == 0 else "failed"
            }
            
        except docker.errors.ContainerError as e:
            logger.error("Container execution error", 
                        session_id=session_id,
                        error=str(e))
            return {
                "exit_code": e.exit_status,
                "execution_time": time.time() - start_time,
                "logs": str(e),
                "stats": {},
                "status": "failed"
            }
            
        except Exception as e:
            logger.error("Container monitoring error", 
                        session_id=session_id,
                        error=str(e))
            return {
                "exit_code": -1,
                "execution_time": time.time() - start_time,
                "logs": str(e),
                "stats": {},
                "status": "error"
            }
    
    async def cleanup_container(self, session_id: str):
        """Clean up container and resources."""
        try:
            container = self.active_containers.get(session_id)
            if not container:
                return
            
            # Stop container if still running
            try:
                container.reload()
                if container.status == "running":
                    container.stop(timeout=10)
            except Exception as e:
                logger.warning("Error stopping container", 
                              session_id=session_id,
                              error=str(e))
            
            # Remove container
            try:
                container.remove(force=True)
            except Exception as e:
                logger.warning("Error removing container", 
                              session_id=session_id,
                              error=str(e))
            
            # Remove from active containers
            self.active_containers.pop(session_id, None)
            
            logger.info("Container cleanup completed", session_id=session_id)
            
        except Exception as e:
            logger.error("Container cleanup error", 
                        session_id=session_id,
                        error=str(e))
    
    def get_active_containers(self) -> List[Dict[str, Any]]:
        """Get list of active containers."""
        containers = []
        
        for session_id, container in self.active_containers.items():
            try:
                container.reload()
                containers.append({
                    "session_id": session_id,
                    "container_id": container.id,
                    "status": container.status,
                    "created": container.attrs["Created"],
                    "image": container.image.tags[0] if container.image.tags else "unknown"
                })
            except Exception as e:
                logger.warning("Error getting container info", 
                              session_id=session_id,
                              error=str(e))
        
        return containers


class JobQueue:
    """Redis-based job queue for sandbox execution."""
    
    def __init__(self):
        self.redis_client: Optional[redis.Redis] = None
        self.queue_key = "phishnet:sandbox:queue"
        self.jobs_key = "phishnet:sandbox:jobs"
        self.metrics_key = "phishnet:sandbox:metrics"
    
    async def connect(self):
        """Connect to Redis."""
        try:
            self.redis_client = redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
            await self.redis_client.ping()
            logger.info("Connected to Redis for job queue")
        except Exception as e:
            logger.error("Failed to connect to Redis", error=str(e))
            raise
    
    async def enqueue_job(self, job: SandboxJob) -> str:
        """Add job to queue."""
        if not self.redis_client:
            await self.connect()
        
        try:
            # Serialize job
            job_data = json.dumps(asdict(job), default=str)
            
            # Add to priority queue (higher priority = lower score)
            priority_score = 5 - job.priority.value  # Invert priority for Redis ZADD
            await self.redis_client.zadd(self.queue_key, {job.job_id: priority_score})
            
            # Store job details
            await self.redis_client.hset(self.jobs_key, job.job_id, job_data)
            
            # Update metrics
            await self.redis_client.hincrby(self.metrics_key, "total_jobs", 1)
            await self.redis_client.hincrby(self.metrics_key, "queue_length", 1)
            
            logger.info("Job enqueued", 
                       job_id=job.job_id,
                       priority=job.priority.name,
                       target_url=job.target_url)
            
            return job.job_id
            
        except Exception as e:
            logger.error("Failed to enqueue job", 
                        job_id=job.job_id,
                        error=str(e))
            raise
    
    async def dequeue_job(self) -> Optional[SandboxJob]:
        """Get next job from queue."""
        if not self.redis_client:
            await self.connect()
        
        try:
            # Get highest priority job
            result = await self.redis_client.zpopmin(self.queue_key, 1)
            
            if not result:
                return None
            
            job_id, _ = result[0]
            
            # Get job details
            job_data = await self.redis_client.hget(self.jobs_key, job_id)
            if not job_data:
                logger.warning("Job data not found", job_id=job_id)
                return None
            
            # Deserialize job
            job_dict = json.loads(job_data)
            
            # Convert datetime strings back to datetime objects
            for field in ["created_at", "started_at", "completed_at"]:
                if job_dict.get(field):
                    job_dict[field] = datetime.fromisoformat(job_dict[field])
            
            # Convert enums
            job_dict["status"] = SandboxStatus(job_dict["status"])
            job_dict["priority"] = SandboxPriority(job_dict["priority"])
            
            job = SandboxJob(**job_dict)
            
            # Update metrics
            await self.redis_client.hincrby(self.metrics_key, "queue_length", -1)
            
            logger.info("Job dequeued", job_id=job.job_id)
            
            return job
            
        except Exception as e:
            logger.error("Failed to dequeue job", error=str(e))
            return None
    
    async def update_job_status(self, job: SandboxJob):
        """Update job status in storage."""
        if not self.redis_client:
            await self.connect()
        
        try:
            job_data = json.dumps(asdict(job), default=str)
            await self.redis_client.hset(self.jobs_key, job.job_id, job_data)
            
            logger.debug("Job status updated", 
                        job_id=job.job_id,
                        status=job.status.name)
            
        except Exception as e:
            logger.error("Failed to update job status", 
                        job_id=job.job_id,
                        error=str(e))
    
    async def get_job(self, job_id: str) -> Optional[SandboxJob]:
        """Get job by ID."""
        if not self.redis_client:
            await self.connect()
        
        try:
            job_data = await self.redis_client.hget(self.jobs_key, job_id)
            if not job_data:
                return None
            
            job_dict = json.loads(job_data)
            
            # Convert datetime strings back to datetime objects
            for field in ["created_at", "started_at", "completed_at"]:
                if job_dict.get(field):
                    job_dict[field] = datetime.fromisoformat(job_dict[field])
            
            # Convert enums
            job_dict["status"] = SandboxStatus(job_dict["status"])
            job_dict["priority"] = SandboxPriority(job_dict["priority"])
            
            return SandboxJob(**job_dict)
            
        except Exception as e:
            logger.error("Failed to get job", job_id=job_id, error=str(e))
            return None
    
    async def get_queue_metrics(self) -> SandboxMetrics:
        """Get queue metrics."""
        if not self.redis_client:
            await self.connect()
        
        try:
            metrics_data = await self.redis_client.hgetall(self.metrics_key)
            
            return SandboxMetrics(
                total_jobs=int(metrics_data.get("total_jobs", 0)),
                completed_jobs=int(metrics_data.get("completed_jobs", 0)),
                failed_jobs=int(metrics_data.get("failed_jobs", 0)),
                timeout_jobs=int(metrics_data.get("timeout_jobs", 0)),
                average_execution_time=float(metrics_data.get("average_execution_time", 0)),
                queue_length=int(metrics_data.get("queue_length", 0)),
                active_containers=int(metrics_data.get("active_containers", 0)),
                resource_utilization=json.loads(metrics_data.get("resource_utilization", "{}"))
            )
            
        except Exception as e:
            logger.error("Failed to get metrics", error=str(e))
            return SandboxMetrics()


class SandboxSessionManager:
    """Main sandbox session manager."""
    
    def __init__(self):
        self.job_queue = JobQueue()
        self.container_manager = ContainerManager()
        self.running_jobs: Dict[str, SandboxJob] = {}
        self.max_concurrent_jobs = getattr(settings, 'SANDBOX_MAX_CONCURRENT', 5)
        self.worker_tasks: List[asyncio.Task] = []
        self.is_running = False
    
    async def start(self):
        """Start the session manager."""
        logger.info("Starting sandbox session manager")
        
        await self.job_queue.connect()
        
        # Start worker tasks
        self.is_running = True
        for i in range(self.max_concurrent_jobs):
            task = asyncio.create_task(self._worker_loop(f"worker-{i}"))
            self.worker_tasks.append(task)
        
        logger.info("Sandbox session manager started", 
                   max_concurrent=self.max_concurrent_jobs)
    
    async def stop(self):
        """Stop the session manager."""
        logger.info("Stopping sandbox session manager")
        
        self.is_running = False
        
        # Cancel worker tasks
        for task in self.worker_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        
        # Cleanup running jobs
        for session_id in list(self.running_jobs.keys()):
            await self.container_manager.cleanup_container(session_id)
        
        logger.info("Sandbox session manager stopped")
    
    async def submit_job(self, 
                        target_url: str,
                        job_type: str = "url_analysis",
                        priority: SandboxPriority = SandboxPriority.NORMAL,
                        user_id: Optional[str] = None,
                        analysis_config: Optional[Dict[str, Any]] = None) -> str:
        """Submit a new sandbox job."""
        
        # Generate unique IDs
        job_id = str(uuid.uuid4())
        session_id = f"sandbox_{int(time.time())}_{job_id[:8]}"
        
        # Create job
        job = SandboxJob(
            job_id=job_id,
            session_id=session_id,
            target_url=target_url,
            job_type=job_type,
            priority=priority,
            created_at=datetime.now(timezone.utc),
            user_id=user_id,
            analysis_config=analysis_config or {},
            execution_timeout=analysis_config.get("timeout", 60) if analysis_config else 60
        )
        
        # Validate URL
        if not self._validate_target_url(target_url):
            raise ValueError(f"Invalid target URL: {target_url}")
        
        # Enqueue job
        await self.job_queue.enqueue_job(job)
        
        logger.info("Sandbox job submitted", 
                   job_id=job_id,
                   session_id=session_id,
                   target_url=target_url,
                   priority=priority.name)
        
        return job_id
    
    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status and details."""
        job = await self.job_queue.get_job(job_id)
        if not job:
            return None
        
        return {
            "job_id": job.job_id,
            "session_id": job.session_id,
            "status": job.status.name,
            "created_at": job.created_at.isoformat(),
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "target_url": job.target_url,
            "evidence_path": job.evidence_path,
            "error_message": job.error_message,
            "retry_count": job.retry_count
        }
    
    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a job."""
        job = await self.job_queue.get_job(job_id)
        if not job:
            return False
        
        if job.status in [SandboxStatus.COMPLETED, SandboxStatus.FAILED, SandboxStatus.CANCELLED]:
            return False
        
        # Cancel running job
        if job.session_id in self.running_jobs:
            await self.container_manager.cleanup_container(job.session_id)
            self.running_jobs.pop(job.session_id, None)
        
        # Update job status
        job.status = SandboxStatus.CANCELLED
        job.completed_at = datetime.now(timezone.utc)
        await self.job_queue.update_job_status(job)
        
        logger.info("Job cancelled", job_id=job_id)
        return True
    
    async def get_metrics(self) -> SandboxMetrics:
        """Get system metrics."""
        metrics = await self.job_queue.get_queue_metrics()
        
        # Add real-time data
        active_containers = self.container_manager.get_active_containers()
        metrics.active_containers = len(active_containers)
        
        return metrics
    
    async def _worker_loop(self, worker_id: str):
        """Worker loop for processing jobs."""
        logger.info("Worker started", worker_id=worker_id)
        
        while self.is_running:
            try:
                # Get next job
                job = await self.job_queue.dequeue_job()
                if not job:
                    await asyncio.sleep(1)  # No jobs available
                    continue
                
                # Process job
                await self._process_job(job, worker_id)
                
            except asyncio.CancelledError:
                logger.info("Worker cancelled", worker_id=worker_id)
                break
            except Exception as e:
                logger.error("Worker error", worker_id=worker_id, error=str(e))
                await asyncio.sleep(5)  # Error recovery delay
        
        logger.info("Worker stopped", worker_id=worker_id)
    
    async def _process_job(self, job: SandboxJob, worker_id: str):
        """Process a single job."""
        logger.info("Processing job", 
                   job_id=job.job_id,
                   worker_id=worker_id,
                   target_url=job.target_url)
        
        try:
            # Update job status
            job.status = SandboxStatus.PREPARING
            job.started_at = datetime.now(timezone.utc)
            await self.job_queue.update_job_status(job)
            
            # Create evidence directory
            evidence_dir = Path(settings.SANDBOX_EVIDENCE_DIR) / job.session_id
            evidence_dir.mkdir(parents=True, exist_ok=True)
            job.evidence_path = str(evidence_dir)
            
            # Add to running jobs
            self.running_jobs[job.session_id] = job
            
            # Create and start container
            job.status = SandboxStatus.RUNNING
            await self.job_queue.update_job_status(job)
            
            container_id = await self.container_manager.create_sandbox_container(job)
            job.container_id = container_id
            
            # Monitor execution
            result = await self.container_manager.monitor_container(
                job.session_id, 
                job.execution_timeout + 30  # Add buffer for cleanup
            )
            
            # Update job based on result
            if result["status"] == "completed":
                job.status = SandboxStatus.COMPLETED
                await self.job_queue.redis_client.hincrby(
                    self.job_queue.metrics_key, "completed_jobs", 1
                )
            else:
                job.status = SandboxStatus.FAILED
                job.error_message = result.get("logs", "Unknown error")
                await self.job_queue.redis_client.hincrby(
                    self.job_queue.metrics_key, "failed_jobs", 1
                )
            
            job.completed_at = datetime.now(timezone.utc)
            await self.job_queue.update_job_status(job)
            
            logger.info("Job completed", 
                       job_id=job.job_id,
                       status=job.status.name,
                       execution_time=result.get("execution_time", 0))
            
        except Exception as e:
            logger.error("Job processing error", 
                        job_id=job.job_id,
                        error=str(e))
            
            job.status = SandboxStatus.FAILED
            job.error_message = str(e)
            job.completed_at = datetime.now(timezone.utc)
            await self.job_queue.update_job_status(job)
            
        finally:
            # Cleanup
            await self.container_manager.cleanup_container(job.session_id)
            self.running_jobs.pop(job.session_id, None)
    
    def _validate_target_url(self, url: str) -> bool:
        """Validate target URL for security."""
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Check for localhost/private networks
            hostname = parsed.hostname
            if not hostname:
                return False
            
            # Block private IPs and localhost
            import ipaddress
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback:
                    return False
            except ValueError:
                pass  # Not an IP address, continue with hostname checks
            
            # Block localhost variations
            if hostname.lower() in ['localhost', '0.0.0.0', '127.0.0.1']:
                return False
            
            return True
            
        except Exception:
            return False


# Global session manager instance
session_manager = SandboxSessionManager()