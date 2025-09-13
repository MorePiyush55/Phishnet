"""
Job models for email scanning orchestration.
Tracks job status, retries, and progression through pipeline stages.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import uuid

from app.db.base import Base

class JobStatus(str, Enum):
    """Job status enumeration"""
    QUEUED = "queued"
    SCANNING_LINKS = "scanning_links"
    SANDBOX_ANALYSIS = "sandbox_analysis" 
    API_ANALYSIS = "api_analysis"
    THREAT_SCORING = "threat_scoring"
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"

class JobPriority(int, Enum):
    """Job priority levels (lower number = higher priority)"""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4

class WorkerType(str, Enum):
    """Worker type enumeration"""
    SANDBOX = "sandbox"
    ANALYZER = "analyzer"
    AGGREGATOR = "aggregator"
    ORCHESTRATOR = "orchestrator"

@dataclass
class JobStageInfo:
    """Information about a job stage"""
    stage: JobStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    worker_id: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class EmailScanJob(Base):
    """
    Email scan job model.
    Tracks the complete lifecycle of an email scan through the pipeline.
    """
    __tablename__ = "email_scan_jobs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String(255), nullable=False, index=True)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False, index=True)
    user_id = Column(String(36), nullable=False, index=True)
    tenant_id = Column(String(36), nullable=True, index=True)
    
    # Job configuration
    priority = Column(Integer, default=JobPriority.NORMAL, nullable=False)
    job_type = Column(String(50), default="email_scan", nullable=False)
    configuration = Column(JSON, nullable=True)  # Job-specific config
    
    # Status tracking
    status = Column(String(50), default=JobStatus.QUEUED, nullable=False, index=True)
    progress_percentage = Column(Float, default=0.0, nullable=False)
    current_stage = Column(String(50), nullable=True)
    
    # Timing information
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Retry logic
    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)
    next_retry_at = Column(DateTime(timezone=True), nullable=True)
    
    # Worker assignment
    assigned_worker_id = Column(String(255), nullable=True)
    worker_type = Column(String(50), nullable=True)
    
    # Results and errors
    result_data = Column(JSON, nullable=True)  # Final scan results
    error_message = Column(Text, nullable=True)
    error_details = Column(JSON, nullable=True)
    
    # Pipeline stage tracking
    stages_completed = Column(JSON, nullable=True)  # List of completed stages
    stage_timings = Column(JSON, nullable=True)  # Timing data for each stage
    
    # Dependencies and relationships
    depends_on_jobs = Column(JSON, nullable=True)  # List of job IDs this depends on
    
    # Relationships
    email = relationship("Email", back_populates="scan_jobs")
    job_logs = relationship("JobLog", back_populates="job", cascade="all, delete-orphan")
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.stages_completed:
            self.stages_completed = []
        if not self.stage_timings:
            self.stage_timings = {}
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate job duration in seconds"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        elif self.started_at:
            return (datetime.utcnow() - self.started_at).total_seconds()
        return None
    
    @property
    def is_completed(self) -> bool:
        """Check if job is in a terminal state"""
        return self.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]
    
    @property
    def can_retry(self) -> bool:
        """Check if job can be retried"""
        return (
            self.status == JobStatus.FAILED and 
            self.retry_count < self.max_retries and
            (self.next_retry_at is None or self.next_retry_at <= datetime.utcnow())
        )
    
    def update_status(self, status: JobStatus, stage: Optional[str] = None, 
                     progress: Optional[float] = None, worker_id: Optional[str] = None,
                     error_message: Optional[str] = None) -> None:
        """Update job status and related fields"""
        self.status = status
        self.updated_at = datetime.utcnow()
        
        if stage:
            self.current_stage = stage
        
        if progress is not None:
            self.progress_percentage = max(0.0, min(100.0, progress))
        
        if worker_id:
            self.assigned_worker_id = worker_id
        
        if error_message:
            self.error_message = error_message
        
        # Set timestamps based on status
        if status == JobStatus.SCANNING_LINKS and not self.started_at:
            self.started_at = datetime.utcnow()
        elif status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
            self.completed_at = datetime.utcnow()
            if status == JobStatus.COMPLETED:
                self.progress_percentage = 100.0
    
    def complete_stage(self, stage: str, duration_ms: Optional[int] = None,
                      metadata: Optional[Dict[str, Any]] = None) -> None:
        """Mark a pipeline stage as completed"""
        if not self.stages_completed:
            self.stages_completed = []
        if not self.stage_timings:
            self.stage_timings = {}
        
        if stage not in self.stages_completed:
            self.stages_completed.append(stage)
        
        self.stage_timings[stage] = {
            "completed_at": datetime.utcnow().isoformat(),
            "duration_ms": duration_ms,
            "metadata": metadata or {}
        }
    
    def schedule_retry(self, delay_seconds: int = None) -> None:
        """Schedule job for retry with exponential backoff"""
        self.retry_count += 1
        
        if delay_seconds is None:
            # Exponential backoff: 2^retry_count * 60 seconds (max 1 hour)
            delay_seconds = min(2 ** self.retry_count * 60, 3600)
        
        self.next_retry_at = datetime.utcnow() + timedelta(seconds=delay_seconds)
        self.status = JobStatus.RETRYING
        self.assigned_worker_id = None  # Clear worker assignment
        self.updated_at = datetime.utcnow()

class JobLog(Base):
    """
    Job execution logs for detailed tracking and debugging.
    """
    __tablename__ = "job_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(36), ForeignKey("email_scan_jobs.id"), nullable=False, index=True)
    
    # Log entry details
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    level = Column(String(20), default="INFO", nullable=False)  # DEBUG, INFO, WARNING, ERROR
    stage = Column(String(50), nullable=True)
    component = Column(String(100), nullable=True)  # Which component logged this
    worker_id = Column(String(255), nullable=True)
    
    # Message content
    message = Column(Text, nullable=False)
    metadata = Column(JSON, nullable=True)  # Additional structured data
    
    # Error tracking
    exception_type = Column(String(255), nullable=True)
    exception_traceback = Column(Text, nullable=True)
    
    # Relationships
    job = relationship("EmailScanJob", back_populates="job_logs")
    
    def __repr__(self):
        return f"<JobLog(job_id='{self.job_id}', level='{self.level}', message='{self.message[:50]}...')>"

class WorkerHealth(Base):
    """
    Worker health monitoring and status tracking.
    """
    __tablename__ = "worker_health"
    
    id = Column(String(255), primary_key=True)  # worker_id
    worker_type = Column(String(50), nullable=False, index=True)
    
    # Status information
    status = Column(String(20), default="healthy", nullable=False)  # healthy, unhealthy, offline
    last_heartbeat = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Performance metrics
    jobs_processed = Column(Integer, default=0, nullable=False)
    jobs_failed = Column(Integer, default=0, nullable=False)
    average_processing_time_ms = Column(Float, nullable=True)
    current_load = Column(Float, default=0.0, nullable=False)  # 0.0 to 1.0
    
    # Configuration
    max_concurrent_jobs = Column(Integer, default=5, nullable=False)
    supported_job_types = Column(JSON, nullable=True)
    
    # Resource usage
    cpu_usage_percent = Column(Float, nullable=True)
    memory_usage_mb = Column(Float, nullable=True)
    
    # Metadata
    version = Column(String(50), nullable=True)
    hostname = Column(String(255), nullable=True)
    metadata = Column(JSON, nullable=True)
    
    @property
    def is_healthy(self) -> bool:
        """Check if worker is considered healthy"""
        heartbeat_threshold = datetime.utcnow() - timedelta(minutes=5)
        return (
            self.status == "healthy" and 
            self.last_heartbeat > heartbeat_threshold and
            self.current_load < 1.0
        )
    
    @property
    def success_rate(self) -> float:
        """Calculate job success rate"""
        total_jobs = self.jobs_processed + self.jobs_failed
        if total_jobs == 0:
            return 1.0
        return self.jobs_processed / total_jobs
    
    def update_heartbeat(self, load: Optional[float] = None, 
                        cpu_usage: Optional[float] = None,
                        memory_usage: Optional[float] = None) -> None:
        """Update worker heartbeat and metrics"""
        self.last_heartbeat = datetime.utcnow()
        
        if load is not None:
            self.current_load = max(0.0, min(1.0, load))
        
        if cpu_usage is not None:
            self.cpu_usage_percent = cpu_usage
        
        if memory_usage is not None:
            self.memory_usage_mb = memory_usage
        
        # Auto-update status based on metrics
        if self.current_load >= 1.0 or (cpu_usage and cpu_usage > 90):
            self.status = "unhealthy"
        else:
            self.status = "healthy"

class JobQueue(Base):
    """
    Persistent job queue state for recovery and monitoring.
    Complements Redis-based queuing with database persistence.
    """
    __tablename__ = "job_queues"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    queue_name = Column(String(100), nullable=False, index=True)
    job_id = Column(String(36), ForeignKey("email_scan_jobs.id"), nullable=False, index=True)
    
    # Queue metadata
    priority = Column(Integer, default=JobPriority.NORMAL, nullable=False)
    enqueued_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    dequeued_at = Column(DateTime(timezone=True), nullable=True)
    dequeued_by_worker = Column(String(255), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    
    # Relationships
    job = relationship("EmailScanJob")
    
    @property
    def wait_time_seconds(self) -> Optional[float]:
        """Calculate time spent waiting in queue"""
        if self.dequeued_at:
            return (self.dequeued_at - self.enqueued_at).total_seconds()
        else:
            return (datetime.utcnow() - self.enqueued_at).total_seconds()

# Job-related helper functions
def create_scan_job(email_id: str, user_id: str, request_id: str = None,
                   tenant_id: str = None, priority: JobPriority = JobPriority.NORMAL,
                   configuration: Dict[str, Any] = None) -> EmailScanJob:
    """Create a new email scan job"""
    job = EmailScanJob(
        email_id=email_id,
        user_id=user_id,
        request_id=request_id or str(uuid.uuid4()),
        tenant_id=tenant_id,
        priority=priority,
        configuration=configuration or {},
        status=JobStatus.QUEUED
    )
    return job

def log_job_event(job_id: str, message: str, level: str = "INFO",
                 stage: str = None, component: str = None, worker_id: str = None,
                 metadata: Dict[str, Any] = None, exception: Exception = None) -> JobLog:
    """Create a job log entry"""
    log_entry = JobLog(
        job_id=job_id,
        message=message,
        level=level,
        stage=stage,
        component=component,
        worker_id=worker_id,
        metadata=metadata
    )
    
    if exception:
        log_entry.exception_type = type(exception).__name__
        log_entry.exception_traceback = str(exception)
    
    return log_entry
