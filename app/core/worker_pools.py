"""
Specialized worker pools for email scanning pipeline.
Handles sandbox workers, analyzer workers, and aggregator workers with health monitoring.
"""

import asyncio
import logging
import time
import traceback
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable, Union
from enum import Enum
import threading
import multiprocessing
import psutil
import uuid

from app.core.queue_manager import JobQueueManager, JobMessage, QueueNames
from app.core.redis_client import get_redis_client
from app.models.jobs import WorkerType, JobStatus, WorkerHealth
from app.core.caching import cached

logger = logging.getLogger(__name__)

@dataclass
class WorkerConfig:
    """Configuration for worker pools"""
    worker_type: str
    min_workers: int = 2
    max_workers: int = 10
    max_concurrent_jobs: int = 5
    health_check_interval: int = 30
    max_job_duration: int = 300
    restart_on_failure: bool = True
    memory_limit_mb: int = 512
    cpu_limit_percent: int = 80

class WorkerStatus(Enum):
    """Worker status enumeration"""
    STARTING = "starting"
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    STOPPING = "stopping"
    STOPPED = "stopped"

@dataclass
class WorkerMetrics:
    """Worker performance metrics"""
    worker_id: str
    worker_type: str
    status: WorkerStatus
    jobs_processed: int = 0
    jobs_failed: int = 0
    avg_processing_time: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    last_heartbeat: float = 0.0
    created_at: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'worker_id': self.worker_id,
            'worker_type': self.worker_type,
            'status': self.status.value,
            'jobs_processed': self.jobs_processed,
            'jobs_failed': self.jobs_failed,
            'avg_processing_time': self.avg_processing_time,
            'memory_usage_mb': self.memory_usage_mb,
            'cpu_usage_percent': self.cpu_usage_percent,
            'last_heartbeat': self.last_heartbeat,
            'created_at': self.created_at,
            'uptime': time.time() - self.created_at if self.created_at else 0
        }

class BaseWorker(ABC):
    """Base class for all worker types"""
    
    def __init__(self, worker_id: str, config: WorkerConfig, 
                 queue_manager: JobQueueManager):
        self.worker_id = worker_id
        self.config = config
        self.queue_manager = queue_manager
        self.redis_client = get_redis_client()
        
        # Worker state
        self.status = WorkerStatus.STARTING
        self.current_job: Optional[JobMessage] = None
        self.start_time = time.time()
        self.jobs_processed = 0
        self.jobs_failed = 0
        self.processing_times: List[float] = []
        
        # Threading/async control
        self._stop_event = threading.Event()
        self._heartbeat_task: Optional[asyncio.Task] = None
        
        logger.info(f"Initialized {self.config.worker_type} worker {self.worker_id}")
    
    @abstractmethod
    async def process_job(self, job_message: JobMessage) -> Dict[str, Any]:
        """Process a job message and return results"""
        pass
    
    @abstractmethod
    def get_target_queues(self) -> List[str]:
        """Get list of queue names this worker processes"""
        pass
    
    async def start(self) -> None:
        """Start the worker"""
        try:
            self.status = WorkerStatus.IDLE
            logger.info(f"Starting worker {self.worker_id}")
            
            # Start heartbeat monitoring
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            
            # Main work loop
            await self._work_loop()
            
        except Exception as e:
            logger.error(f"Worker {self.worker_id} failed to start: {e}")
            self.status = WorkerStatus.ERROR
    
    async def stop(self) -> None:
        """Stop the worker gracefully"""
        logger.info(f"Stopping worker {self.worker_id}")
        self.status = WorkerStatus.STOPPING
        self._stop_event.set()
        
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        
        self.status = WorkerStatus.STOPPED
    
    async def _work_loop(self) -> None:
        """Main work loop for processing jobs"""
        queues = self.get_target_queues()
        
        while not self._stop_event.is_set():
            try:
                # Get job from queue
                job_message = await self.queue_manager.async_dequeue_job(
                    queues, timeout=5
                )
                
                if job_message:
                    await self._handle_job(job_message)
                else:
                    # No job available, brief sleep
                    await asyncio.sleep(1)
                    
            except Exception as e:
                logger.error(f"Worker {self.worker_id} work loop error: {e}")
                await asyncio.sleep(5)  # Back off on error
    
    async def _handle_job(self, job_message: JobMessage) -> None:
        """Handle a single job with error handling and metrics"""
        start_time = time.time()
        self.current_job = job_message
        self.status = WorkerStatus.BUSY
        
        try:
            logger.info(f"Worker {self.worker_id} processing job {job_message.job_id}")
            
            # Process the job
            result = await self.process_job(job_message)
            
            # Record success metrics
            processing_time = time.time() - start_time
            self.jobs_processed += 1
            self.processing_times.append(processing_time)
            
            # Keep only last 100 processing times for rolling average
            if len(self.processing_times) > 100:
                self.processing_times.pop(0)
            
            logger.info(f"Worker {self.worker_id} completed job {job_message.job_id} "
                       f"in {processing_time:.2f}s")
            
            # Store result if needed
            if result:
                await self._store_job_result(job_message, result)
            
        except Exception as e:
            # Handle job failure
            processing_time = time.time() - start_time
            self.jobs_failed += 1
            
            error_msg = f"Worker {self.worker_id} job {job_message.job_id} failed: {e}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            
            # Retry job if appropriate
            await self.queue_manager.async_retry_job(job_message, error_msg)
            
        finally:
            self.current_job = None
            self.status = WorkerStatus.IDLE
    
    async def _store_job_result(self, job_message: JobMessage, result: Dict[str, Any]) -> None:
        """Store job result in cache/database"""
        try:
            result_key = f"job_result:{job_message.job_id}"
            await self.redis_client.setex(
                result_key,
                3600,  # 1 hour TTL
                str(result)
            )
        except Exception as e:
            logger.error(f"Failed to store job result: {e}")
    
    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeat with worker metrics"""
        while not self._stop_event.is_set():
            try:
                await self._send_heartbeat()
                await asyncio.sleep(self.config.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error for worker {self.worker_id}: {e}")
    
    async def _send_heartbeat(self) -> None:
        """Send heartbeat with current metrics"""
        try:
            metrics = self._get_metrics()
            heartbeat_key = f"worker_heartbeat:{self.worker_id}"
            
            await self.redis_client.setex(
                heartbeat_key,
                self.config.health_check_interval * 2,  # 2x interval TTL
                str(metrics.to_dict())
            )
            
        except Exception as e:
            logger.error(f"Failed to send heartbeat: {e}")
    
    def _get_metrics(self) -> WorkerMetrics:
        """Get current worker metrics"""
        # Calculate average processing time
        avg_time = (
            sum(self.processing_times) / len(self.processing_times)
            if self.processing_times else 0.0
        )
        
        # Get system metrics
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        cpu_percent = process.cpu_percent()
        
        return WorkerMetrics(
            worker_id=self.worker_id,
            worker_type=self.config.worker_type,
            status=self.status,
            jobs_processed=self.jobs_processed,
            jobs_failed=self.jobs_failed,
            avg_processing_time=avg_time,
            memory_usage_mb=memory_mb,
            cpu_usage_percent=cpu_percent,
            last_heartbeat=time.time(),
            created_at=self.start_time
        )

class SandboxWorker(BaseWorker):
    """Worker for sandbox analysis (redirect chains, browser automation)"""
    
    def __init__(self, worker_id: str, config: WorkerConfig, queue_manager: JobQueueManager):
        super().__init__(worker_id, config, queue_manager)
        self.browser_timeout = 30
        self.max_redirect_depth = 10
    
    def get_target_queues(self) -> List[str]:
        return [QueueNames.SANDBOX_ANALYSIS]
    
    async def process_job(self, job_message: JobMessage) -> Dict[str, Any]:
        """Process sandbox analysis job"""
        payload = job_message.payload
        url = payload.get('url')
        
        if not url:
            raise ValueError("No URL provided for sandbox analysis")
        
        logger.info(f"Sandbox worker {self.worker_id} analyzing URL: {url}")
        
        result = {
            'job_id': job_message.job_id,
            'url': url,
            'analysis_type': 'sandbox',
            'worker_id': self.worker_id,
            'timestamp': time.time()
        }
        
        # Perform redirect analysis
        redirect_chain = await self._analyze_redirects(url)
        result['redirect_chain'] = redirect_chain
        
        # Perform browser analysis if no suspicious redirects
        if len(redirect_chain) <= 3:  # Reasonable redirect count
            browser_analysis = await self._browser_analysis(url)
            result['browser_analysis'] = browser_analysis
        else:
            result['browser_analysis'] = {
                'skipped': True,
                'reason': 'Too many redirects detected'
            }
        
        return result
    
    async def _analyze_redirects(self, url: str) -> List[Dict[str, Any]]:
        """Analyze redirect chain for suspicious patterns"""
        import aiohttp
        
        redirect_chain = []
        current_url = url
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.browser_timeout),
                connector=aiohttp.TCPConnector(limit=10)
            ) as session:
                
                for depth in range(self.max_redirect_depth):
                    try:
                        async with session.head(
                            current_url,
                            allow_redirects=False
                        ) as response:
                            
                            redirect_info = {
                                'url': current_url,
                                'status_code': response.status,
                                'headers': dict(response.headers),
                                'depth': depth
                            }
                            
                            redirect_chain.append(redirect_info)
                            
                            # Check if there's a redirect
                            if response.status in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location')
                                if location:
                                    # Handle relative URLs
                                    if location.startswith('/'):
                                        from urllib.parse import urljoin
                                        current_url = urljoin(current_url, location)
                                    else:
                                        current_url = location
                                else:
                                    break
                            else:
                                break
                                
                    except Exception as e:
                        redirect_chain.append({
                            'url': current_url,
                            'error': str(e),
                            'depth': depth
                        })
                        break
                        
        except Exception as e:
            logger.error(f"Redirect analysis failed for {url}: {e}")
            redirect_chain.append({
                'url': url,
                'error': str(e),
                'depth': 0
            })
        
        return redirect_chain
    
    async def _browser_analysis(self, url: str) -> Dict[str, Any]:
        """Perform headless browser analysis"""
        # Placeholder for browser automation
        # In production, would use Selenium/Playwright
        
        await asyncio.sleep(2)  # Simulate browser load time
        
        return {
            'url': url,
            'title': f"Page Title for {url}",
            'forms_detected': 1,
            'suspicious_scripts': 0,
            'external_resources': 5,
            'screenshots_taken': 1,
            'analysis_duration': 2.0
        }

class AnalyzerWorker(BaseWorker):
    """Worker for API analysis (VirusTotal, AbuseIPDB, etc.)"""
    
    def __init__(self, worker_id: str, config: WorkerConfig, queue_manager: JobQueueManager):
        super().__init__(worker_id, config, queue_manager)
    
    def get_target_queues(self) -> List[str]:
        return [QueueNames.API_ANALYSIS]
    
    async def process_job(self, job_message: JobMessage) -> Dict[str, Any]:
        """Process API analysis job"""
        payload = job_message.payload
        resource = payload.get('resource')
        resource_type = payload.get('resource_type')
        apis = payload.get('apis', [])
        
        if not resource or not resource_type:
            raise ValueError("Resource and resource_type required for API analysis")
        
        logger.info(f"Analyzer worker {self.worker_id} analyzing {resource_type}: {resource}")
        
        result = {
            'job_id': job_message.job_id,
            'resource': resource,
            'resource_type': resource_type,
            'analysis_type': 'api',
            'worker_id': self.worker_id,
            'timestamp': time.time(),
            'api_results': {}
        }
        
        # Process each API
        for api_name in apis:
            try:
                api_result = await self._call_api(api_name, resource, resource_type)
                result['api_results'][api_name] = api_result
            except Exception as e:
                logger.error(f"API {api_name} failed for {resource}: {e}")
                result['api_results'][api_name] = {
                    'error': str(e),
                    'success': False
                }
        
        return result
    
    @cached(ttl=3600)  # Cache API results for 1 hour
    async def _call_api(self, api_name: str, resource: str, resource_type: str) -> Dict[str, Any]:
        """Call specific API with caching"""
        
        # Simulate API calls with delays
        if api_name == 'virustotal':
            await asyncio.sleep(0.5)  # VT API delay
            return {
                'api': 'virustotal',
                'resource': resource,
                'malicious_votes': 2,
                'total_votes': 45,
                'scan_date': time.time(),
                'success': True
            }
            
        elif api_name == 'abuseipdb':
            await asyncio.sleep(0.3)  # AbuseIPDB delay
            return {
                'api': 'abuseipdb',
                'resource': resource,
                'abuse_confidence': 15,
                'country_code': 'US',
                'usage_type': 'hosting',
                'success': True
            }
            
        elif api_name == 'urlscan':
            await asyncio.sleep(1.0)  # URLScan delay
            return {
                'api': 'urlscan',
                'resource': resource,
                'verdict': 'safe',
                'screenshot_url': f"https://urlscan.io/screenshots/{uuid.uuid4()}.png",
                'success': True
            }
        
        else:
            raise ValueError(f"Unknown API: {api_name}")

class AggregatorWorker(BaseWorker):
    """Worker for result aggregation and threat scoring"""
    
    def __init__(self, worker_id: str, config: WorkerConfig, queue_manager: JobQueueManager):
        super().__init__(worker_id, config, queue_manager)
    
    def get_target_queues(self) -> List[str]:
        return [QueueNames.AGGREGATION, QueueNames.THREAT_SCORING]
    
    async def process_job(self, job_message: JobMessage) -> Dict[str, Any]:
        """Process aggregation/scoring job"""
        payload = job_message.payload
        job_type = job_message.job_type
        
        if job_type == 'aggregation':
            return await self._aggregate_results(job_message)
        elif job_type == 'threat_scoring':
            return await self._calculate_threat_score(job_message)
        else:
            raise ValueError(f"Unknown job type for aggregator: {job_type}")
    
    async def _aggregate_results(self, job_message: JobMessage) -> Dict[str, Any]:
        """Aggregate results from multiple analysis phases"""
        payload = job_message.payload
        scan_id = payload.get('scan_id')
        
        logger.info(f"Aggregator worker {self.worker_id} aggregating results for scan {scan_id}")
        
        # Collect results from Redis cache
        sandbox_key = f"job_result:sandbox_{scan_id}"
        api_key = f"job_result:api_{scan_id}"
        
        sandbox_result = await self.redis_client.get(sandbox_key)
        api_result = await self.redis_client.get(api_key)
        
        aggregated = {
            'job_id': job_message.job_id,
            'scan_id': scan_id,
            'analysis_type': 'aggregation',
            'worker_id': self.worker_id,
            'timestamp': time.time(),
            'sandbox_analysis': eval(sandbox_result) if sandbox_result else None,
            'api_analysis': eval(api_result) if api_result else None,
            'summary': {}
        }
        
        # Create summary
        if aggregated['sandbox_analysis']:
            redirects = len(aggregated['sandbox_analysis'].get('redirect_chain', []))
            aggregated['summary']['redirect_count'] = redirects
            aggregated['summary']['suspicious_redirects'] = redirects > 3
        
        if aggregated['api_analysis']:
            api_results = aggregated['api_analysis'].get('api_results', {})
            vt_result = api_results.get('virustotal', {})
            aggregated['summary']['malicious_votes'] = vt_result.get('malicious_votes', 0)
            aggregated['summary']['total_api_checks'] = len(api_results)
        
        return aggregated
    
    async def _calculate_threat_score(self, job_message: JobMessage) -> Dict[str, Any]:
        """Calculate final threat score based on all analysis"""
        payload = job_message.payload
        aggregated_data = payload.get('aggregated_data', {})
        
        logger.info(f"Aggregator worker {self.worker_id} calculating threat score")
        
        # Simple scoring algorithm
        score = 0.0
        factors = []
        
        # Sandbox factors
        if aggregated_data.get('summary', {}).get('suspicious_redirects'):
            score += 30.0
            factors.append("Suspicious redirect chain detected")
        
        # API factors
        malicious_votes = aggregated_data.get('summary', {}).get('malicious_votes', 0)
        if malicious_votes > 0:
            score += min(malicious_votes * 10, 50.0)
            factors.append(f"{malicious_votes} malicious votes from threat intel")
        
        # Normalize score to 0-100
        final_score = min(score, 100.0)
        
        threat_level = "low"
        if final_score >= 70:
            threat_level = "high"
        elif final_score >= 40:
            threat_level = "medium"
        
        return {
            'job_id': job_message.job_id,
            'analysis_type': 'threat_scoring',
            'worker_id': self.worker_id,
            'timestamp': time.time(),
            'threat_score': final_score,
            'threat_level': threat_level,
            'score_factors': factors,
            'confidence': 0.85  # Confidence in the score
        }

class WorkerPool:
    """Manages a pool of workers for a specific type"""
    
    def __init__(self, worker_class: type, config: WorkerConfig, 
                 queue_manager: JobQueueManager):
        self.worker_class = worker_class
        self.config = config
        self.queue_manager = queue_manager
        
        self.workers: Dict[str, BaseWorker] = {}
        self.worker_tasks: Dict[str, asyncio.Task] = {}
        self.is_running = False
        
        logger.info(f"Initialized {config.worker_type} worker pool")
    
    async def start(self) -> None:
        """Start the worker pool"""
        logger.info(f"Starting {self.config.worker_type} worker pool")
        self.is_running = True
        
        # Start minimum number of workers
        for i in range(self.config.min_workers):
            await self._create_worker()
        
        # Start monitoring task
        asyncio.create_task(self._monitor_workers())
    
    async def stop(self) -> None:
        """Stop all workers in the pool"""
        logger.info(f"Stopping {self.config.worker_type} worker pool")
        self.is_running = False
        
        # Stop all workers
        for worker in self.workers.values():
            await worker.stop()
        
        # Cancel all tasks
        for task in self.worker_tasks.values():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        
        self.workers.clear()
        self.worker_tasks.clear()
    
    async def _create_worker(self) -> Optional[str]:
        """Create and start a new worker"""
        if len(self.workers) >= self.config.max_workers:
            return None
        
        worker_id = f"{self.config.worker_type}_{uuid.uuid4().hex[:8]}"
        
        try:
            worker = self.worker_class(worker_id, self.config, self.queue_manager)
            task = asyncio.create_task(worker.start())
            
            self.workers[worker_id] = worker
            self.worker_tasks[worker_id] = task
            
            logger.info(f"Created worker {worker_id}")
            return worker_id
            
        except Exception as e:
            logger.error(f"Failed to create worker: {e}")
            return None
    
    async def _monitor_workers(self) -> None:
        """Monitor worker health and scale as needed"""
        while self.is_running:
            try:
                await self._check_worker_health()
                await self._scale_workers()
                await asyncio.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"Worker monitoring error: {e}")
    
    async def _check_worker_health(self) -> None:
        """Check health of all workers"""
        unhealthy_workers = []
        
        for worker_id, worker in self.workers.items():
            try:
                # Check if worker task is still running
                task = self.worker_tasks.get(worker_id)
                if task and task.done():
                    exception = task.exception()
                    if exception:
                        logger.error(f"Worker {worker_id} failed: {exception}")
                    unhealthy_workers.append(worker_id)
                
                # Check resource usage
                metrics = worker._get_metrics()
                if (metrics.memory_usage_mb > self.config.memory_limit_mb or
                    metrics.cpu_usage_percent > self.config.cpu_limit_percent):
                    logger.warning(f"Worker {worker_id} exceeding resource limits")
                    if self.config.restart_on_failure:
                        unhealthy_workers.append(worker_id)
                        
            except Exception as e:
                logger.error(f"Health check failed for worker {worker_id}: {e}")
                unhealthy_workers.append(worker_id)
        
        # Restart unhealthy workers
        for worker_id in unhealthy_workers:
            await self._restart_worker(worker_id)
    
    async def _restart_worker(self, worker_id: str) -> None:
        """Restart a failed worker"""
        logger.info(f"Restarting worker {worker_id}")
        
        try:
            # Stop old worker
            if worker_id in self.workers:
                await self.workers[worker_id].stop()
                del self.workers[worker_id]
            
            if worker_id in self.worker_tasks:
                self.worker_tasks[worker_id].cancel()
                del self.worker_tasks[worker_id]
            
            # Create new worker
            await self._create_worker()
            
        except Exception as e:
            logger.error(f"Failed to restart worker {worker_id}: {e}")
    
    async def _scale_workers(self) -> None:
        """Scale workers based on queue length"""
        # Get queue lengths for this worker type
        target_queues = []
        if self.workers:
            sample_worker = next(iter(self.workers.values()))
            target_queues = sample_worker.get_target_queues()
        
        total_queue_length = 0
        for queue_name in target_queues:
            total_queue_length += self.queue_manager.queue_manager.queue_length(queue_name)
        
        current_workers = len(self.workers)
        
        # Scale up if queues are backed up
        if (total_queue_length > current_workers * 2 and
            current_workers < self.config.max_workers):
            logger.info(f"Scaling up {self.config.worker_type} workers: "
                       f"{current_workers} -> {current_workers + 1}")
            await self._create_worker()
        
        # Scale down if queues are empty and we have more than minimum
        elif (total_queue_length == 0 and
              current_workers > self.config.min_workers):
            # Remove oldest idle worker
            for worker_id, worker in self.workers.items():
                if worker.status == WorkerStatus.IDLE:
                    logger.info(f"Scaling down {self.config.worker_type} workers: "
                               f"{current_workers} -> {current_workers - 1}")
                    await self._restart_worker(worker_id)
                    break
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get worker pool statistics"""
        stats = {
            'worker_type': self.config.worker_type,
            'total_workers': len(self.workers),
            'config': {
                'min_workers': self.config.min_workers,
                'max_workers': self.config.max_workers,
                'max_concurrent_jobs': self.config.max_concurrent_jobs
            },
            'workers': {}
        }
        
        for worker_id, worker in self.workers.items():
            stats['workers'][worker_id] = worker._get_metrics().to_dict()
        
        return stats

# Global worker pool manager
class WorkerPoolManager:
    """Manages all worker pools"""
    
    def __init__(self, queue_manager: JobQueueManager):
        self.queue_manager = queue_manager
        self.pools: Dict[str, WorkerPool] = {}
        self.is_running = False
    
    async def start_all_pools(self) -> None:
        """Start all worker pools"""
        logger.info("Starting all worker pools")
        self.is_running = True
        
        # Sandbox workers
        sandbox_config = WorkerConfig(
            worker_type=WorkerType.SANDBOX,
            min_workers=2,
            max_workers=5,
            max_concurrent_jobs=3,
            memory_limit_mb=256
        )
        self.pools['sandbox'] = WorkerPool(SandboxWorker, sandbox_config, self.queue_manager)
        await self.pools['sandbox'].start()
        
        # Analyzer workers
        analyzer_config = WorkerConfig(
            worker_type=WorkerType.ANALYZER,
            min_workers=3,
            max_workers=8,
            max_concurrent_jobs=5,
            memory_limit_mb=128
        )
        self.pools['analyzer'] = WorkerPool(AnalyzerWorker, analyzer_config, self.queue_manager)
        await self.pools['analyzer'].start()
        
        # Aggregator workers
        aggregator_config = WorkerConfig(
            worker_type=WorkerType.AGGREGATOR,
            min_workers=1,
            max_workers=3,
            max_concurrent_jobs=2,
            memory_limit_mb=128
        )
        self.pools['aggregator'] = WorkerPool(AggregatorWorker, aggregator_config, self.queue_manager)
        await self.pools['aggregator'].start()
        
        logger.info("All worker pools started")
    
    async def stop_all_pools(self) -> None:
        """Stop all worker pools"""
        logger.info("Stopping all worker pools")
        self.is_running = False
        
        for pool in self.pools.values():
            await pool.stop()
        
        self.pools.clear()
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get statistics for all worker pools"""
        return {
            'pools': {name: pool.get_pool_stats() for name, pool in self.pools.items()},
            'total_workers': sum(len(pool.workers) for pool in self.pools.values()),
            'is_running': self.is_running,
            'timestamp': time.time()
        }

# Global instances
worker_pool_manager = None

def get_worker_pool_manager() -> WorkerPoolManager:
    """Get global worker pool manager instance"""
    global worker_pool_manager
    if not worker_pool_manager:
        from app.core.queue_manager import get_job_queue_manager
        worker_pool_manager = WorkerPoolManager(get_job_queue_manager())
    return worker_pool_manager
