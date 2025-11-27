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
from contextlib import asynccontextmanager
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
# Missing definitions to fix NameError
@dataclass
class Operation:
    id: str
    type: "OperationType"
    status: "OperationStatus"
    created_at: datetime
    data: Dict[str, Any]
    metadata: Dict[str, Any]
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class OperationType(Enum):
    EMAIL_INGEST = "email_ingest"
    EMAIL_ANALYSIS = "email_analysis"
    LINK_EXTRACTION = "link_extraction"
    THREAT_INTEL = "threat_intel"
    RISK_SCORING = "risk_scoring"
    RESPONSE_ACTION = "response_action"

class OperationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class OrchestrationResult:
    success: bool
    operation_id: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class IEmailProcessor:
    async def process_email(self, content: Any) -> Dict[str, Any]: pass

class IThreatAnalyzer:
    async def analyze_content(self, content: str, type: str) -> Any: pass

class IResponseHandler:
    def validate_action(self, request: Any) -> bool: pass
    async def execute_action(self, request: Any) -> Any: pass

@dataclass
class EmailContent:
    body_text: str
    headers: Dict[str, Any]

@dataclass
class ActionRequest:
    action_type: str
    email_id: int
    user_id: int
    parameters: Dict[str, Any]
    reason: Optional[str] = None

@dataclass
class ActionResult:
    success: bool
    message: Optional[str] = None
    data: Optional[Dict[str, Any]] = None

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

class EmailProcessor:
    """Simple email processor for orchestration"""
    async def process_email(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process email content"""
        # Simulate processing
        await asyncio.sleep(0.1)
        return {
            "id": data.get("email_id", "unknown"),
            "attachments": 0,
            "sanitized": True
        }

class PhishNetOrchestrator:
    """
    Central orchestrator that manages the entire email scanning pipeline.
    Coordinates job flow, worker assignments, and stage transitions.
    - Handle operation dependencies and sequencing
    """
    
    def __init__(self):
        self._operations: Dict[str, Operation] = {}
        self._operation_counter = 0
        self._operation_processors: Dict[OperationType, Callable] = {}
        self._observers: List[Callable] = []
        self._running = False
        self._task_queue = asyncio.Queue()
        
        # Initialize registered components
        self._processors: List[IEmailProcessor] = []
        self._analyzers: List[IThreatAnalyzer] = []
        self._handlers: List[IResponseHandler] = []
        
        # Initialize operation processors
        self._setup_processors()
        
    def _setup_processors(self):
        """Setup operation processors"""
        self._operation_processors = {
            OperationType.EMAIL_INGEST: self._process_email_ingest,
            OperationType.EMAIL_ANALYSIS: self._process_email_analysis,
            OperationType.LINK_EXTRACTION: self._process_link_extraction,
            OperationType.THREAT_INTEL: self._process_threat_intel,
            OperationType.RISK_SCORING: self._process_risk_scoring,
            OperationType.RESPONSE_ACTION: self._process_response_action,
        }
    
    def _generate_operation_id(self) -> str:
        """Generate unique operation ID"""
        self._operation_counter += 1
        return f"op_{self._operation_counter:06d}_{int(datetime.utcnow().timestamp())}"
    
    async def start(self):
        """Start the orchestrator"""
        if self._running:
            logger.warning("Orchestrator already running")
            return
            
        self._running = True
        logger.info("PhishNet Orchestrator starting...")
        
        # Start background task processor
        asyncio.create_task(self._process_queue())
        
        logger.info("PhishNet Orchestrator started successfully")
    
    async def stop(self):
        """Stop the orchestrator"""
        self._running = False
        logger.info("PhishNet Orchestrator stopping...")
        
        # Cancel pending operations
        for operation in self._operations.values():
            if operation.status == OperationStatus.PENDING:
                operation.status = OperationStatus.CANCELLED
                
        logger.info("PhishNet Orchestrator stopped")
    
    def add_observer(self, callback: Callable[[Operation], None]):
        """Add operation observer for monitoring"""
        self._observers.append(callback)
    
    def _notify_observers(self, operation: Operation):
        """Notify all observers of operation changes"""
        for observer in self._observers:
            try:
                observer(operation)
            except Exception as e:
                logger.error(f"Observer notification failed: {e}")
    
    async def orchestrate_email_processing(self, email_data: Dict[str, Any]) -> OrchestrationResult:
        """
        Orchestrate complete email processing pipeline
        
        Pipeline:
        1. Email ingestion and sanitization
        2. Link extraction and analysis
        3. Threat intelligence lookup
        4. Risk scoring
        5. Response action (if needed)
        """
        logger.info(f"Starting email processing orchestration")
        
        try:
            # Step 1: Email ingestion
            ingest_result = await self.submit_operation(
                OperationType.EMAIL_INGEST,
                email_data
            )
            
            if not ingest_result.success:
                return ingest_result
            
            email_id = ingest_result.result.get("email_id")
            
            # Step 2: Email analysis
            analysis_result = await self.submit_operation(
                OperationType.EMAIL_ANALYSIS,
                {"email_id": email_id}
            )
            
            if not analysis_result.success:
                return analysis_result
            
            # Step 3: Link extraction (if email contains links)
            if analysis_result.result.get("has_links"):
                link_result = await self.submit_operation(
                    OperationType.LINK_EXTRACTION,
                    {"email_id": email_id}
                )
                
                # Step 4: Threat intelligence (for extracted links)
                if link_result.success and link_result.result.get("links"):
                    await self.submit_operation(
                        OperationType.THREAT_INTEL,
                        {"email_id": email_id, "links": link_result.result["links"]}
                    )
            
            # Step 5: Risk scoring
            scoring_result = await self.submit_operation(
                OperationType.RISK_SCORING,
                {"email_id": email_id}
            )
            
            # Step 6: Response action (if high risk)
            if scoring_result.success and scoring_result.result.get("risk_score", 0) > 70:
                await self.submit_operation(
                    OperationType.RESPONSE_ACTION,
                    {"email_id": email_id, "action": "quarantine"}
                )
            
            return OrchestrationResult(
                success=True,
                operation_id=ingest_result.operation_id,
                result={"email_id": email_id, "processing": "completed"}
            )
            
        except Exception as e:
            logger.error(f"Email processing orchestration failed: {e}")
            return OrchestrationResult(
                success=False,
                operation_id="",
                error=str(e)
            )
    
    async def submit_operation(self, op_type: OperationType, data: Dict[str, Any],
                             metadata: Optional[Dict[str, Any]] = None) -> OrchestrationResult:
        """Submit an operation for processing"""
        operation_id = self._generate_operation_id()
        
        operation = Operation(
            id=operation_id,
            type=op_type,
            status=OperationStatus.PENDING,
            created_at=datetime.utcnow(),
            data=data,
            metadata=metadata or {}
        )
        
        self._operations[operation_id] = operation
        await self._task_queue.put(operation)
        
        logger.info(f"Operation {operation_id} ({op_type.value}) submitted")
        self._notify_observers(operation)
        
        # Wait for completion (with timeout)
        max_wait = 30  # seconds
        waited = 0
        while waited < max_wait and operation.status in [OperationStatus.PENDING, OperationStatus.IN_PROGRESS]:
            await asyncio.sleep(0.1)
            waited += 0.1
        
        if operation.status == OperationStatus.COMPLETED:
            return OrchestrationResult(
                success=True,
                operation_id=operation_id,
                result=operation.result
            )
        elif operation.status == OperationStatus.FAILED:
            return OrchestrationResult(
                success=False,
                operation_id=operation_id,
                error=operation.error
            )
        else:
            return OrchestrationResult(
                success=False,
                operation_id=operation_id,
                error="Operation timeout"
            )
    
    async def _process_queue(self):
        """Background task to process operation queue"""
        logger.info("Operation queue processor started")
        
        while self._running:
            try:
                # Wait for operation with timeout
                operation = await asyncio.wait_for(
                    self._task_queue.get(),
                    timeout=1.0
                )
                
                # Process the operation
                await self._process_operation(operation)
                
            except asyncio.TimeoutError:
                # Continue waiting for operations
                continue
            except Exception as e:
                logger.error(f"Queue processing error: {e}")
    
    async def _process_operation(self, operation: Operation):
        """Process a single operation"""
        try:
            # Update status
            operation.status = OperationStatus.IN_PROGRESS
            operation.started_at = datetime.utcnow()
            self._notify_observers(operation)
            
            # Get processor
            processor = self._operation_processors.get(operation.type)
            if not processor:
                raise ValueError(f"No processor for operation type: {operation.type}")
            
            # Execute processor
            result = await processor(operation.data)
            
            # Update operation
            operation.status = OperationStatus.COMPLETED
            operation.completed_at = datetime.utcnow()
            operation.result = result
            
            logger.info(f"Operation {operation.id} completed successfully")
            
        except Exception as e:
            operation.status = OperationStatus.FAILED
            operation.completed_at = datetime.utcnow()
            operation.error = str(e)
            
            logger.error(f"Operation {operation.id} failed: {e}")
        
        finally:
            self._notify_observers(operation)
    
    # Operation Processors
    async def _process_email_ingest(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process email ingestion"""
        logger.info(f"Processing email ingestion")
        
        # Simulate email processor
        email_processor = EmailProcessor()
        result = await email_processor.process_email(data)
        
        return {
            "email_id": result.get("id"),
            "sanitized": True,
            "attachments_processed": result.get("attachments", 0)
        }
    
    async def _process_email_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process email analysis"""
        email_id = data.get("email_id")
        logger.info(f"Processing email analysis for email {email_id}")
        
        # Simulate analysis logic
        await asyncio.sleep(0.1)  # Simulate processing time
        
        return {
            "email_id": email_id,
            "has_links": True,
            "suspicious_patterns": ["urgent_language", "external_links"],
            "language": "en",
            "confidence": 0.85
        }
    
    async def _process_link_extraction(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process link extraction"""
        email_id = data.get("email_id")
        logger.info(f"Processing link extraction for email {email_id}")
        
        # Simulate link extraction
        await asyncio.sleep(0.1)
        
        return {
            "email_id": email_id,
            "links": [
                {"url": "https://suspicious-site.com", "type": "external"},
                {"url": "http://phishing.example.com", "type": "suspicious"}
            ]
        }
    
    async def _process_threat_intel(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process threat intelligence lookup"""
        links = data.get("links", [])
        logger.info(f"Processing threat intelligence for {len(links)} links")
        
        # Simulate threat intel lookup
        await asyncio.sleep(0.2)
        
        return {
            "threats_found": 1,
            "threat_types": ["phishing"],
            "confidence": 0.92
        }
    
    async def _process_risk_scoring(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process risk scoring"""
        email_id = data.get("email_id")
        logger.info(f"Processing risk scoring for email {email_id}")
        
        # Simulate risk scoring
        await asyncio.sleep(0.1)
        
        return {
            "email_id": email_id,
            "risk_score": 85,
            "risk_level": "high",
            "factors": ["suspicious_links", "urgent_language", "external_domain"]
        }
    
    async def _process_response_action(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process response action"""
        email_id = data.get("email_id")
        action = data.get("action")
        logger.info(f"Processing response action '{action}' for email {email_id}")
        
        # Simulate response action
        await asyncio.sleep(0.1)
        
        return {
            "email_id": email_id,
            "action": action,
            "executed": True,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def get_operation_status(self, operation_id: str) -> Optional[Operation]:
        """Get operation status"""
        return self._operations.get(operation_id)
    
    def get_operations_summary(self) -> Dict[str, Any]:
        """Get summary of all operations"""
        total = len(self._operations)
        by_status = {}
        by_type = {}
        
        for op in self._operations.values():
            by_status[op.status.value] = by_status.get(op.status.value, 0) + 1
            by_type[op.type.value] = by_type.get(op.type.value, 0) + 1
        
        return {
            "total_operations": total,
            "by_status": by_status,
            "by_type": by_type,
            "is_running": self._running
        }

    # Interface methods implementation
    
    async def orchestrate_email_analysis(self, email_content: EmailContent) -> Dict[str, Any]:
        """Orchestrate complete email analysis pipeline."""
        try:
            # Process email through registered processors
            results = {}
            for processor in self._processors:
                result = await processor.process_email(email_content)
                results[processor.__class__.__name__] = result
            
            # Analyze through threat analyzers
            for analyzer in self._analyzers:
                analysis = await analyzer.analyze_content(email_content.body_text, "text")
                results[analyzer.__class__.__name__] = analysis.__dict__
            
            return results
            
        except Exception as e:
            logger.error(f"Error in orchestrate_email_analysis: {e}")
            return {"error": str(e)}
    
    async def orchestrate_response(self, email_id: int, response_type: str, **kwargs) -> ActionResult:
        """Orchestrate response actions."""
        action_request = ActionRequest(
            action_type=response_type,
            email_id=email_id,
            user_id=kwargs.get('user_id', 0),
            parameters=kwargs,
            reason=kwargs.get('reason')
        )
        
        # Execute through registered handlers
        for handler in self._handlers:
            if handler.validate_action(action_request):
                return await handler.execute_action(action_request)
        
        # If no handler found, return failure
        return ActionResult(
            success=False,
            message=f"No handler available for response type: {response_type}"
        )
    
    def register_processor(self, processor: IEmailProcessor) -> None:
        """Register an email processor."""
        self._processors.append(processor)
        logger.info(f"Registered email processor: {processor.__class__.__name__}")
    
    def register_analyzer(self, analyzer: IThreatAnalyzer) -> None:
        """Register a threat analyzer."""
        self._analyzers.append(analyzer)
        logger.info(f"Registered threat analyzer: {analyzer.__class__.__name__}")
    
    def register_handler(self, handler: IResponseHandler) -> None:
        """Register a response handler."""
        self._handlers.append(handler)
        logger.info(f"Registered response handler: {handler.__class__.__name__}")
    
    async def health_check(self) -> Dict[str, bool]:
        """Check health of all components."""
        health_status = {"orchestrator": True}
        
        # Check processors
        for processor in getattr(self, '_processors', []):
            try:
                stats = processor.get_stats() if hasattr(processor, 'get_stats') else {}
                health_status[f"processor_{processor.__class__.__name__}"] = True
            except Exception:
                health_status[f"processor_{processor.__class__.__name__}"] = False
        
        # Check analyzers
        for analyzer in getattr(self, '_analyzers', []):
            try:
                # Simple health check - try to analyze empty content
                await analyzer.analyze_content("test", "text")
                health_status[f"analyzer_{analyzer.__class__.__name__}"] = True
            except Exception:
                health_status[f"analyzer_{analyzer.__class__.__name__}"] = False
        
        # Check handlers
        for handler in getattr(self, '_handlers', []):
            try:
                # Simple validation check
                test_action = ActionRequest(
                    action_type="test",
                    email_id=1,
                    user_id=1,
                    parameters={}
                )
                handler.validate_action(test_action)
                health_status[f"handler_{handler.__class__.__name__}"] = True
            except Exception:
                health_status[f"handler_{handler.__class__.__name__}"] = False
        
        return health_status


# Global orchestrator instance
_orchestrator_instance = None

def get_orchestrator() -> PhishNetOrchestrator:
    """Get global orchestrator instance"""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = PhishNetOrchestrator()
    return _orchestrator_instance

@asynccontextmanager
async def orchestrator_lifespan():
    """Context manager for orchestrator lifecycle"""
    orchestrator = get_orchestrator()
    await orchestrator.start()
    try:
        yield orchestrator
    finally:
        await orchestrator.stop()

