"""
Central orchestrator service that manages the entire email scanning pipeline.
Coordinates job flow through stages, worker assignments, and stage transitions.
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import json

from app.core.queue_manager import (
    JobQueueManager, JobMessage, QueueNames, 
    create_email_scan_job_message, create_sandbox_job_message,
    create_api_analysis_job_message, get_job_queue_manager
)
from app.core.worker_pools import get_worker_pool_manager
from app.core.rate_limiter import get_rate_limiter, RateLimitError
from app.core.redis_client import get_redis_client
from app.models.jobs import JobStatus, JobPriority, WorkerType, EmailScanJob
from app.core.caching import cached

logger = logging.getLogger(__name__)

class PipelineStage(Enum):
    """Pipeline stages for email scanning"""
    QUEUED = "queued"
    PARSING = "parsing"
    EXTRACTING = "extracting"
    SANDBOX_ANALYSIS = "sandbox_analysis"
    API_ANALYSIS = "api_analysis"
    AGGREGATING = "aggregating"
    SCORING = "scoring"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class PipelineJob:
    """Represents a job moving through the pipeline"""
    job_id: str
    email_id: str
    user_id: str
    tenant_id: Optional[str]
    request_id: str
    stage: PipelineStage
    priority: JobPriority
    created_at: float
    updated_at: float
    metadata: Dict[str, Any]
    
    # Stage-specific data
    parsed_data: Optional[Dict[str, Any]] = None
    extracted_resources: Optional[List[Dict[str, Any]]] = None
    sandbox_results: Optional[Dict[str, Any]] = None
    api_results: Optional[Dict[str, Any]] = None
    aggregated_results: Optional[Dict[str, Any]] = None
    final_score: Optional[Dict[str, Any]] = None
    
    # Timing and metrics
    stage_times: Optional[Dict[str, float]] = None
    error_count: int = 0
    last_error: Optional[str] = None
    
    def __post_init__(self):
        if self.stage_times is None:
            self.stage_times = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['stage'] = self.stage.value
        data['priority'] = self.priority.value if hasattr(self.priority, 'value') else self.priority
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PipelineJob':
        """Create PipelineJob from dictionary"""
        if 'stage' in data and isinstance(data['stage'], str):
            data['stage'] = PipelineStage(data['stage'])
        if 'priority' in data and isinstance(data['priority'], str):
            data['priority'] = getattr(JobPriority, data['priority'], JobPriority.NORMAL)
        return cls(**data)
    
    def advance_stage(self, new_stage: PipelineStage) -> None:
        """Advance to next pipeline stage"""
        old_stage = self.stage
        self.stage = new_stage
        self.updated_at = time.time()
        
        # Record stage timing
        if old_stage.value not in self.stage_times:
            self.stage_times[old_stage.value] = time.time() - self.created_at
        
        logger.info(f"Job {self.job_id} advanced from {old_stage.value} to {new_stage.value}")
    
    def record_error(self, error_message: str) -> None:
        """Record an error for this job"""
        self.error_count += 1
        self.last_error = error_message
        self.updated_at = time.time()
        logger.error(f"Job {self.job_id} error: {error_message}")
    
    @property
    def total_processing_time(self) -> float:
        """Get total processing time so far"""
        return time.time() - self.created_at
    
    @property
    def is_expired(self) -> bool:
        """Check if job has exceeded maximum processing time"""
        max_time = 600  # 10 minutes max
        return self.total_processing_time > max_time

class EmailParsingService:
    """Service for parsing email content and extracting metadata"""
    
    def __init__(self):
        self.redis_client = get_redis_client()
    
    async def parse_email(self, email_id: str, pipeline_job: PipelineJob) -> Dict[str, Any]:
        """Parse email and extract basic metadata"""
        logger.info(f"Parsing email {email_id} for job {pipeline_job.job_id}")
        
        # Simulate email parsing
        await asyncio.sleep(0.5)
        
        parsed_data = {
            'email_id': email_id,
            'subject': f"Sample Email Subject {email_id}",
            'sender': f"sender_{email_id}@example.com",
            'recipients': [f"recipient_{email_id}@company.com"],
            'headers': {
                'message-id': f"<{uuid.uuid4()}@example.com>",
                'date': datetime.now().isoformat(),
                'x-originating-ip': '192.168.1.100'
            },
            'body_text': f"This is the text body of email {email_id}",
            'body_html': f"<html><body>HTML body of email {email_id}</body></html>",
            'attachments': [],
            'parsed_at': time.time()
        }
        
        # Store parsed data
        cache_key = f"parsed_email:{email_id}"
        await self.redis_client.setex(cache_key, 3600, json.dumps(parsed_data))
        
        return parsed_data

class ResourceExtractionService:
    """Service for extracting URLs, IPs, domains, and hashes from emails"""
    
    def __init__(self):
        self.redis_client = get_redis_client()
    
    async def extract_resources(self, parsed_data: Dict[str, Any], 
                              pipeline_job: PipelineJob) -> List[Dict[str, Any]]:
        """Extract resources from parsed email data"""
        logger.info(f"Extracting resources for job {pipeline_job.job_id}")
        
        # Simulate resource extraction
        await asyncio.sleep(0.3)
        
        email_id = parsed_data['email_id']
        resources = []
        
        # Extract URLs from body
        urls = [
            f"https://suspicious-site-{email_id}.com/phishing",
            f"http://malicious-{email_id}.net/login",
            f"https://bit.ly/short{email_id}"
        ]
        
        for i, url in enumerate(urls):
            resources.append({
                'type': 'url',
                'value': url,
                'source': 'email_body',
                'confidence': 0.9,
                'extracted_at': time.time(),
                'metadata': {
                    'position': i,
                    'context': f"Found in email body near line {i+1}"
                }
            })
        
        # Extract IP addresses
        ips = ['192.168.1.100', '10.0.0.50']
        for ip in ips:
            resources.append({
                'type': 'ip',
                'value': ip,
                'source': 'email_headers',
                'confidence': 1.0,
                'extracted_at': time.time(),
                'metadata': {'header': 'x-originating-ip'}
            })
        
        # Extract domains
        domains = [f'suspicious-site-{email_id}.com', f'malicious-{email_id}.net']
        for domain in domains:
            resources.append({
                'type': 'domain',
                'value': domain,
                'source': 'url_extraction',
                'confidence': 0.8,
                'extracted_at': time.time(),
                'metadata': {'parent_url': f"https://{domain}/"}
            })
        
        # Extract file hashes (if attachments)
        if parsed_data.get('attachments'):
            resources.append({
                'type': 'hash',
                'value': 'a1b2c3d4e5f6789012345678901234567890abcd',
                'source': 'attachment',
                'confidence': 1.0,
                'extracted_at': time.time(),
                'metadata': {
                    'hash_type': 'sha1',
                    'filename': 'suspicious.pdf'
                }
            })
        
        # Store extracted resources
        cache_key = f"extracted_resources:{pipeline_job.job_id}"
        await self.redis_client.setex(
            cache_key, 3600, json.dumps(resources)
        )
        
        return resources

class PipelineOrchestrator:
    """
    Central orchestrator that manages the entire email scanning pipeline.
    Coordinates job flow, worker assignments, and stage transitions.
    """
    
    def __init__(self, queue_manager: JobQueueManager = None):
        self.queue_manager = queue_manager or get_job_queue_manager()
        self.worker_pool_manager = get_worker_pool_manager()
        self.rate_limiter = get_rate_limiter()
        self.redis_client = get_redis_client()
        
        # Services
        self.email_parser = EmailParsingService()
        self.resource_extractor = ResourceExtractionService()
        
        # Pipeline state
        self._active_jobs: Dict[str, PipelineJob] = {}
        self._is_running = False
        
        # Stage processors
        self._stage_processors = {
            PipelineStage.PARSING: self._process_parsing_stage,
            PipelineStage.EXTRACTING: self._process_extraction_stage,
            PipelineStage.SANDBOX_ANALYSIS: self._process_sandbox_stage,
            PipelineStage.API_ANALYSIS: self._process_api_stage,
            PipelineStage.AGGREGATING: self._process_aggregation_stage,
            PipelineStage.SCORING: self._process_scoring_stage
        }
        
        # Metrics
        self._metrics = {
            'jobs_processed': 0,
            'jobs_failed': 0,
            'average_processing_time': 0.0,
            'stage_completion_rates': {},
            'last_reset': time.time()
        }
    
    async def start(self) -> None:
        """Start the orchestrator"""
        logger.info("Starting pipeline orchestrator")
        self._is_running = True
        
        # Start worker pools
        await self.worker_pool_manager.start_all_pools()
        
        # Start main processing loop
        asyncio.create_task(self._main_processing_loop())
        
        # Start monitoring tasks
        asyncio.create_task(self._monitor_jobs())
        asyncio.create_task(self._cleanup_expired_jobs())
        
        logger.info("Pipeline orchestrator started")
    
    async def stop(self) -> None:
        """Stop the orchestrator"""
        logger.info("Stopping pipeline orchestrator")
        self._is_running = False
        
        # Stop worker pools
        await self.worker_pool_manager.stop_all_pools()
        
        logger.info("Pipeline orchestrator stopped")
    
    async def submit_email_scan(self, email_id: str, user_id: str, 
                              tenant_id: str = None, priority: JobPriority = JobPriority.NORMAL,
                              request_id: str = None) -> str:
        """
        Submit an email for scanning through the pipeline.
        
        Returns:
            job_id: Unique identifier for tracking the job
        """
        
        job_id = str(uuid.uuid4())
        request_id = request_id or str(uuid.uuid4())
        
        # Create pipeline job
        pipeline_job = PipelineJob(
            job_id=job_id,
            email_id=email_id,
            user_id=user_id,
            tenant_id=tenant_id,
            request_id=request_id,
            stage=PipelineStage.QUEUED,
            priority=priority,
            created_at=time.time(),
            updated_at=time.time(),
            metadata={
                'submitted_by': 'orchestrator',
                'pipeline_version': '1.0'
            }
        )
        
        # Store job state
        await self._store_pipeline_job(pipeline_job)
        self._active_jobs[job_id] = pipeline_job
        
        # Create initial job message
        job_message = create_email_scan_job_message(
            email_id, user_id, request_id, priority
        )
        job_message.job_id = job_id
        
        # Enqueue for parsing
        success = await self.queue_manager.async_enqueue_job(
            QueueNames.EMAIL_SCAN, job_message
        )
        
        if success:
            logger.info(f"Submitted email scan job {job_id} for email {email_id}")
            return job_id
        else:
            raise Exception(f"Failed to enqueue job {job_id}")
    
    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a pipeline job"""
        
        # Try to get from active jobs first
        if job_id in self._active_jobs:
            job = self._active_jobs[job_id]
            return self._create_status_response(job)
        
        # Try to load from Redis
        job = await self._load_pipeline_job(job_id)
        if job:
            return self._create_status_response(job)
        
        return None
    
    async def _main_processing_loop(self) -> None:
        """Main loop for processing pipeline stages"""
        
        while self._is_running:
            try:
                # Process email scan queue (parsing stage)
                await self._process_queue(QueueNames.EMAIL_SCAN, self._process_parsing_stage)
                
                # Check for jobs ready for next stages
                await self._advance_ready_jobs()
                
                # Brief sleep to prevent busy waiting
                await asyncio.sleep(1.0)
                
            except Exception as e:
                logger.error(f"Error in main processing loop: {e}")
                await asyncio.sleep(5.0)
    
    async def _process_queue(self, queue_name: str, processor: Callable) -> None:
        """Process jobs from a specific queue"""
        
        try:
            job_message = await self.queue_manager.async_dequeue_job(queue_name, timeout=1)
            
            if job_message:
                await processor(job_message)
                
        except Exception as e:
            logger.error(f"Error processing queue {queue_name}: {e}")
    
    async def _process_parsing_stage(self, job_message: JobMessage) -> None:
        """Process email parsing stage"""
        
        job_id = job_message.job_id
        pipeline_job = await self._get_or_load_job(job_id)
        
        if not pipeline_job:
            logger.error(f"Pipeline job not found: {job_id}")
            return
        
        try:
            pipeline_job.advance_stage(PipelineStage.PARSING)
            await self._store_pipeline_job(pipeline_job)
            
            # Parse email
            parsed_data = await self.email_parser.parse_email(
                pipeline_job.email_id, pipeline_job
            )
            
            pipeline_job.parsed_data = parsed_data
            pipeline_job.advance_stage(PipelineStage.EXTRACTING)
            await self._store_pipeline_job(pipeline_job)
            
        except Exception as e:
            await self._handle_stage_error(pipeline_job, f"Parsing failed: {e}")
    
    async def _store_pipeline_job(self, pipeline_job: PipelineJob) -> None:
        """Store pipeline job state in Redis"""
        try:
            key = f"pipeline_job:{pipeline_job.job_id}"
            data = json.dumps(pipeline_job.to_dict())
            await self.redis_client.setex(key, 3600, data)  # 1 hour TTL
        except Exception as e:
            logger.error(f"Failed to store pipeline job {pipeline_job.job_id}: {e}")
    
    async def _load_pipeline_job(self, job_id: str) -> Optional[PipelineJob]:
        """Load pipeline job state from Redis"""
        try:
            key = f"pipeline_job:{job_id}"
            data = await self.redis_client.get(key)
            if data:
                job_dict = json.loads(data)
                return PipelineJob.from_dict(job_dict)
        except Exception as e:
            logger.error(f"Failed to load pipeline job {job_id}: {e}")
        return None
    
    async def _get_or_load_job(self, job_id: str) -> Optional[PipelineJob]:
        """Get job from active jobs or load from Redis"""
        if job_id in self._active_jobs:
            return self._active_jobs[job_id]
        
        job = await self._load_pipeline_job(job_id)
        if job:
            self._active_jobs[job_id] = job
        
        return job
    
    async def _handle_stage_error(self, pipeline_job: PipelineJob, error_message: str) -> None:
        """Handle errors in pipeline stages"""
        pipeline_job.record_error(error_message)
        
        if pipeline_job.error_count >= 3:
            pipeline_job.advance_stage(PipelineStage.FAILED)
            logger.error(f"Job {pipeline_job.job_id} failed after {pipeline_job.error_count} errors")
        
        await self._store_pipeline_job(pipeline_job)
    
    async def _monitor_jobs(self) -> None:
        """Monitor job health and cleanup"""
        while self._is_running:
            try:
                current_time = time.time()
                expired_jobs = []
                
                for job_id, pipeline_job in self._active_jobs.items():
                    if pipeline_job.is_expired:
                        expired_jobs.append(job_id)
                
                # Handle expired jobs
                for job_id in expired_jobs:
                    pipeline_job = self._active_jobs[job_id]
                    await self._handle_stage_error(pipeline_job, "Job expired")
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in job monitoring: {e}")
    
    async def _cleanup_expired_jobs(self) -> None:
        """Cleanup completed and failed jobs"""
        while self._is_running:
            try:
                cleanup_count = 0
                current_time = time.time()
                
                for job_id in list(self._active_jobs.keys()):
                    pipeline_job = self._active_jobs[job_id]
                    
                    # Remove completed or failed jobs older than 1 hour
                    if (pipeline_job.stage in [PipelineStage.COMPLETED, PipelineStage.FAILED] and
                        current_time - pipeline_job.updated_at > 3600):
                        
                        del self._active_jobs[job_id]
                        cleanup_count += 1
                
                if cleanup_count > 0:
                    logger.info(f"Cleaned up {cleanup_count} expired jobs")
                
                await asyncio.sleep(300)  # Cleanup every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in job cleanup: {e}")
    
    async def _advance_ready_jobs(self) -> None:
        """Check for jobs ready to advance to next stage"""
        
        for job_id, pipeline_job in list(self._active_jobs.items()):
            try:
                if pipeline_job.stage == PipelineStage.EXTRACTING:
                    await self._process_extraction_stage(pipeline_job)
                
            except Exception as e:
                logger.error(f"Error advancing job {job_id}: {e}")
    
    async def _process_extraction_stage(self, pipeline_job: PipelineJob) -> None:
        """Process resource extraction stage"""
        
        try:
            if not pipeline_job.parsed_data:
                raise ValueError("No parsed data available")
            
            # Extract resources
            resources = await self.resource_extractor.extract_resources(
                pipeline_job.parsed_data, pipeline_job
            )
            
            pipeline_job.extracted_resources = resources
            
            # Determine next stage based on resources
            has_urls = any(r['type'] == 'url' for r in resources)
            has_ips_or_domains = any(r['type'] in ['ip', 'domain'] for r in resources)
            
            if has_urls:
                pipeline_job.advance_stage(PipelineStage.SANDBOX_ANALYSIS)
            elif has_ips_or_domains:
                pipeline_job.advance_stage(PipelineStage.API_ANALYSIS)
            else:
                pipeline_job.advance_stage(PipelineStage.AGGREGATING)
            
            await self._store_pipeline_job(pipeline_job)
            
        except Exception as e:
            await self._handle_stage_error(pipeline_job, f"Extraction failed: {e}")
    
    def _create_status_response(self, pipeline_job: PipelineJob) -> Dict[str, Any]:
        """Create status response for a pipeline job"""
        return {
            'job_id': pipeline_job.job_id,
            'email_id': pipeline_job.email_id,
            'stage': pipeline_job.stage.value,
            'status': 'processing' if pipeline_job.stage not in [
                PipelineStage.COMPLETED, PipelineStage.FAILED
            ] else pipeline_job.stage.value,
            'progress_percent': self._calculate_progress_percent(pipeline_job.stage),
            'created_at': pipeline_job.created_at,
            'updated_at': pipeline_job.updated_at,
            'processing_time': pipeline_job.total_processing_time,
            'error_count': pipeline_job.error_count,
            'last_error': pipeline_job.last_error,
            'stage_times': pipeline_job.stage_times,
            'estimated_completion': self._estimate_completion_time(pipeline_job),
            'results': {
                'parsed_data': pipeline_job.parsed_data is not None,
                'extracted_resources': len(pipeline_job.extracted_resources or []),
                'sandbox_results': pipeline_job.sandbox_results is not None,
                'api_results': pipeline_job.api_results is not None,
                'final_score': pipeline_job.final_score
            }
        }
    
    def _calculate_progress_percent(self, stage: PipelineStage) -> int:
        """Calculate progress percentage based on current stage"""
        stage_progress = {
            PipelineStage.QUEUED: 0,
            PipelineStage.PARSING: 10,
            PipelineStage.EXTRACTING: 20,
            PipelineStage.SANDBOX_ANALYSIS: 40,
            PipelineStage.API_ANALYSIS: 60,
            PipelineStage.AGGREGATING: 80,
            PipelineStage.SCORING: 90,
            PipelineStage.COMPLETED: 100,
            PipelineStage.FAILED: 0
        }
        return stage_progress.get(stage, 0)
    
    def _estimate_completion_time(self, pipeline_job: PipelineJob) -> Optional[float]:
        """Estimate completion time based on current progress"""
        if pipeline_job.stage in [PipelineStage.COMPLETED, PipelineStage.FAILED]:
            return None
        
        # Simple estimation based on average processing times
        avg_total_time = 60.0  # 1 minute average
        progress_percent = self._calculate_progress_percent(pipeline_job.stage)
        
        if progress_percent > 0:
            estimated_total = (pipeline_job.total_processing_time / progress_percent) * 100
            return pipeline_job.created_at + estimated_total
        
        return pipeline_job.created_at + avg_total_time
    
    def get_orchestrator_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics"""
        return {
            'active_jobs': len(self._active_jobs),
            'is_running': self._is_running,
            'metrics': self._metrics,
            'stage_distribution': {
                stage.value: sum(1 for job in self._active_jobs.values() if job.stage == stage)
                for stage in PipelineStage
            },
            'worker_pool_stats': self.worker_pool_manager.get_all_stats(),
            'queue_stats': self.queue_manager.get_queue_stats(),
            'timestamp': time.time()
        }

# Global orchestrator instance
_pipeline_orchestrator = None

def get_pipeline_orchestrator() -> PipelineOrchestrator:
    """Get global pipeline orchestrator instance"""
    global _pipeline_orchestrator
    if not _pipeline_orchestrator:
        _pipeline_orchestrator = PipelineOrchestrator()
    return _pipeline_orchestrator
