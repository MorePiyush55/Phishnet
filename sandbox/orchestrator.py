"""
Threat Orchestrator Integration for Sandbox Infrastructure

Integrates the sandbox system with the existing threat analysis pipeline,
enabling automated URL analysis with proper job queuing and result aggregation.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import uuid

import structlog
import redis.asyncio as redis
from job_queue import SandboxJobQueue, SandboxJob, JobPriority, JobStatus
from sandbox_worker import SandboxWorker, SandboxAnalysisResult
from artifact_storage import get_artifact_manager
from monitoring import SecurityEventLogger, setup_monitoring

logger = structlog.get_logger(__name__)


class ThreatOrchestrator:
    """Main orchestrator for threat analysis with sandbox integration."""
    
    def __init__(self):
        self.job_queue = SandboxJobQueue()
        self.artifact_manager = get_artifact_manager()
        self.redis_client = None
        self.security_logger = None
        self.monitoring = None
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize orchestrator components."""
        try:
            # Initialize Redis
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
            
            # Initialize monitoring
            worker_id = f"orchestrator-{uuid.uuid4().hex[:8]}"
            self.monitoring = setup_monitoring(worker_id, enable_dashboard=False)
            self.security_logger = self.monitoring['security_logger']
            
            logger.info("Threat orchestrator initialized", worker_id=worker_id)
            
        except Exception as e:
            logger.error("Failed to initialize orchestrator", error=str(e))
            raise
    
    async def analyze_url(self, 
                         target_url: str, 
                         priority: JobPriority = JobPriority.NORMAL,
                         metadata: Dict[str, Any] = None) -> str:
        """
        Queue a URL for sandbox analysis.
        
        Args:
            target_url: URL to analyze
            priority: Job priority (high, normal, low)
            metadata: Additional metadata for the job
            
        Returns:
            Job ID for tracking the analysis
        """
        try:
            # Create sandbox job
            job = SandboxJob(
                target_url=target_url,
                priority=priority,
                metadata=metadata or {}
            )
            
            # Enqueue job
            job_id = await self.job_queue.enqueue_job(job)
            
            logger.info("URL queued for analysis", 
                       job_id=job_id, 
                       target_url=target_url, 
                       priority=priority.value)
            
            return job_id
            
        except Exception as e:
            logger.error("Failed to queue URL for analysis", 
                        target_url=target_url, 
                        error=str(e))
            raise
    
    async def get_analysis_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get analysis result for a job.
        
        Args:
            job_id: Job ID to retrieve results for
            
        Returns:
            Analysis result dictionary or None if not found
        """
        try:
            result = await self.job_queue.get_job_result(job_id)
            if result:
                return result.to_dict()
            return None
            
        except Exception as e:
            logger.error("Failed to get analysis result", 
                        job_id=job_id, 
                        error=str(e))
            return None
    
    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get current status of a job.
        
        Args:
            job_id: Job ID to check status for
            
        Returns:
            Job status information
        """
        try:
            # Check job status in queue
            status_key = f"job_status:{job_id}"
            status_data = await self.redis_client.hgetall(status_key)
            
            if status_data:
                return {
                    'job_id': job_id,
                    'status': status_data.get('status'),
                    'created_at': status_data.get('created_at'),
                    'started_at': status_data.get('started_at'),
                    'completed_at': status_data.get('completed_at'),
                    'worker_id': status_data.get('worker_id'),
                    'progress': status_data.get('progress', '0'),
                    'error': status_data.get('error')
                }
            
            return None
            
        except Exception as e:
            logger.error("Failed to get job status", 
                        job_id=job_id, 
                        error=str(e))
            return None
    
    async def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a pending job.
        
        Args:
            job_id: Job ID to cancel
            
        Returns:
            True if job was cancelled successfully
        """
        try:
            # Mark job as cancelled
            status_key = f"job_status:{job_id}"
            await self.redis_client.hset(status_key, mapping={
                'status': JobStatus.FAILED.value,
                'error': 'Job cancelled by user',
                'completed_at': datetime.utcnow().isoformat()
            })
            
            # Remove from queue if still pending
            await self.redis_client.lrem("sandbox_queue", 1, job_id)
            await self.redis_client.lrem("sandbox_queue_high", 1, job_id)
            
            logger.info("Job cancelled", job_id=job_id)
            return True
            
        except Exception as e:
            logger.error("Failed to cancel job", 
                        job_id=job_id, 
                        error=str(e))
            return False
    
    async def get_queue_statistics(self) -> Dict[str, Any]:
        """Get queue statistics and worker information."""
        try:
            stats = await self.job_queue.get_queue_stats()
            
            # Add worker information
            workers = []
            worker_keys = await self.redis_client.keys("worker_heartbeat:*")
            for key in worker_keys:
                worker_data = await self.redis_client.hgetall(key)
                if worker_data:
                    workers.append({
                        'worker_id': worker_data.get('worker_id'),
                        'status': worker_data.get('status'),
                        'last_seen': worker_data.get('timestamp'),
                        'uptime': float(worker_data.get('uptime', 0)),
                        'memory_usage': int(worker_data.get('memory_usage', 0)),
                        'cpu_percent': float(worker_data.get('cpu_percent', 0))
                    })
            
            stats['workers'] = workers
            stats['total_workers'] = len(workers)
            stats['active_workers'] = len([w for w in workers if w['status'] == 'healthy'])
            
            return stats
            
        except Exception as e:
            logger.error("Failed to get queue statistics", error=str(e))
            return {}
    
    async def bulk_analyze_urls(self, 
                               urls: List[str], 
                               priority: JobPriority = JobPriority.NORMAL,
                               batch_size: int = 10) -> List[str]:
        """
        Submit multiple URLs for analysis in batches.
        
        Args:
            urls: List of URLs to analyze
            priority: Job priority for all URLs
            batch_size: Number of URLs to process in each batch
            
        Returns:
            List of job IDs
        """
        job_ids = []
        
        try:
            for i in range(0, len(urls), batch_size):
                batch = urls[i:i + batch_size]
                batch_jobs = []
                
                for url in batch:
                    job_id = await self.analyze_url(url, priority)
                    batch_jobs.append(job_id)
                
                job_ids.extend(batch_jobs)
                
                # Small delay between batches to avoid overwhelming the queue
                await asyncio.sleep(0.1)
                
                logger.info("Batch submitted", 
                           batch_size=len(batch), 
                           total_submitted=len(job_ids))
            
            logger.info("Bulk analysis submitted", 
                       total_urls=len(urls), 
                       total_jobs=len(job_ids))
            
            return job_ids
            
        except Exception as e:
            logger.error("Failed to submit bulk analysis", 
                        total_urls=len(urls), 
                        error=str(e))
            raise
    
    async def wait_for_completion(self, job_ids: List[str], timeout: int = 300) -> Dict[str, Any]:
        """
        Wait for a list of jobs to complete.
        
        Args:
            job_ids: List of job IDs to wait for
            timeout: Maximum time to wait in seconds
            
        Returns:
            Dictionary with completion statistics
        """
        start_time = datetime.utcnow()
        completed_jobs = set()
        failed_jobs = set()
        results = {}
        
        try:
            while len(completed_jobs) + len(failed_jobs) < len(job_ids):
                # Check timeout
                if (datetime.utcnow() - start_time).total_seconds() > timeout:
                    logger.warning("Job completion timeout reached", 
                                 completed=len(completed_jobs),
                                 failed=len(failed_jobs),
                                 remaining=len(job_ids) - len(completed_jobs) - len(failed_jobs))
                    break
                
                # Check job statuses
                for job_id in job_ids:
                    if job_id in completed_jobs or job_id in failed_jobs:
                        continue
                    
                    status = await self.get_job_status(job_id)
                    if status:
                        if status['status'] == JobStatus.COMPLETED.value:
                            completed_jobs.add(job_id)
                            result = await self.get_analysis_result(job_id)
                            if result:
                                results[job_id] = result
                        elif status['status'] == JobStatus.FAILED.value:
                            failed_jobs.add(job_id)
                            results[job_id] = {'error': status.get('error', 'Unknown error')}
                
                # Wait before next check
                await asyncio.sleep(5)
            
            completion_stats = {
                'total_jobs': len(job_ids),
                'completed': len(completed_jobs),
                'failed': len(failed_jobs),
                'pending': len(job_ids) - len(completed_jobs) - len(failed_jobs),
                'completion_time': (datetime.utcnow() - start_time).total_seconds(),
                'results': results
            }
            
            logger.info("Job completion summary", **completion_stats)
            return completion_stats
            
        except Exception as e:
            logger.error("Failed to wait for job completion", error=str(e))
            raise
    
    async def cleanup_old_results(self, max_age_days: int = 7) -> int:
        """
        Clean up old job results and artifacts.
        
        Args:
            max_age_days: Maximum age of results to keep
            
        Returns:
            Number of jobs cleaned up
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(days=max_age_days)
            cleaned_count = 0
            
            # Find old job results
            result_keys = await self.redis_client.keys("job_result:*")
            for key in result_keys:
                result_data = await self.redis_client.hgetall(key)
                if result_data and result_data.get('completed_at'):
                    completed_at = datetime.fromisoformat(result_data['completed_at'])
                    if completed_at < cutoff_time:
                        # Delete job result
                        await self.redis_client.delete(key)
                        
                        # Delete job status
                        job_id = key.split(':')[1]
                        await self.redis_client.delete(f"job_status:{job_id}")
                        
                        cleaned_count += 1
            
            # Clean up old artifacts
            artifact_cleaned = await self.artifact_manager.cleanup_expired_artifacts()
            
            logger.info("Cleanup completed", 
                       jobs_cleaned=cleaned_count,
                       artifacts_cleaned=artifact_cleaned,
                       max_age_days=max_age_days)
            
            return cleaned_count
            
        except Exception as e:
            logger.error("Failed to clean up old results", error=str(e))
            return 0
    
    async def get_analysis_summary(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a summary of analysis results with artifact URLs.
        
        Args:
            job_id: Job ID to get summary for
            
        Returns:
            Analysis summary with artifact access URLs
        """
        try:
            result = await self.get_analysis_result(job_id)
            if not result:
                return None
            
            summary = {
                'job_id': job_id,
                'target_url': result['target_url'],
                'analysis_time': result['analysis_time'],
                'cloaking_detected': result['cloaking_detected'],
                'security_findings': result['security_findings'],
                'duration_ms': result['duration_ms'],
                'artifacts': {},
                'archive_url': None
            }
            
            # Generate artifact URLs
            if result.get('artifacts'):
                for artifact in result['artifacts']:
                    artifact_id = artifact['artifact_id']
                    artifact_type = artifact['artifact_type']
                    
                    url = await self.artifact_manager.get_artifact_url(artifact_id)
                    if url:
                        if artifact_type not in summary['artifacts']:
                            summary['artifacts'][artifact_type] = []
                        summary['artifacts'][artifact_type].append({
                            'artifact_id': artifact_id,
                            'url': url,
                            'size_bytes': artifact['size_bytes'],
                            'created_at': artifact['created_at']
                        })
            
            # Generate archive URL
            if result.get('archive_artifact_id'):
                archive_url = await self.artifact_manager.get_artifact_url(
                    result['archive_artifact_id']
                )
                summary['archive_url'] = archive_url
            
            return summary
            
        except Exception as e:
            logger.error("Failed to get analysis summary", 
                        job_id=job_id, 
                        error=str(e))
            return None


class SandboxOrchestrationAPI:
    """REST API for sandbox orchestration."""
    
    def __init__(self, orchestrator: ThreatOrchestrator):
        self.orchestrator = orchestrator
    
    async def submit_url(self, request):
        """Submit URL for analysis."""
        try:
            data = await request.json()
            target_url = data.get('url')
            priority = data.get('priority', 'normal')
            metadata = data.get('metadata', {})
            
            if not target_url:
                return web.json_response(
                    {'error': 'URL is required'}, 
                    status=400
                )
            
            job_id = await self.orchestrator.analyze_url(
                target_url=target_url,
                priority=JobPriority(priority),
                metadata=metadata
            )
            
            return web.json_response({
                'job_id': job_id,
                'status': 'queued',
                'target_url': target_url
            })
            
        except Exception as e:
            logger.error("API: Failed to submit URL", error=str(e))
            return web.json_response(
                {'error': 'Internal server error'}, 
                status=500
            )
    
    async def get_result(self, request):
        """Get analysis result."""
        try:
            job_id = request.match_info['job_id']
            
            result = await self.orchestrator.get_analysis_result(job_id)
            if result:
                return web.json_response(result)
            else:
                return web.json_response(
                    {'error': 'Result not found'}, 
                    status=404
                )
                
        except Exception as e:
            logger.error("API: Failed to get result", error=str(e))
            return web.json_response(
                {'error': 'Internal server error'}, 
                status=500
            )
    
    async def get_status(self, request):
        """Get job status."""
        try:
            job_id = request.match_info['job_id']
            
            status = await self.orchestrator.get_job_status(job_id)
            if status:
                return web.json_response(status)
            else:
                return web.json_response(
                    {'error': 'Job not found'}, 
                    status=404
                )
                
        except Exception as e:
            logger.error("API: Failed to get status", error=str(e))
            return web.json_response(
                {'error': 'Internal server error'}, 
                status=500
            )
    
    async def get_summary(self, request):
        """Get analysis summary with artifact URLs."""
        try:
            job_id = request.match_info['job_id']
            
            summary = await self.orchestrator.get_analysis_summary(job_id)
            if summary:
                return web.json_response(summary)
            else:
                return web.json_response(
                    {'error': 'Summary not found'}, 
                    status=404
                )
                
        except Exception as e:
            logger.error("API: Failed to get summary", error=str(e))
            return web.json_response(
                {'error': 'Internal server error'}, 
                status=500
            )
    
    async def get_queue_stats(self, request):
        """Get queue statistics."""
        try:
            stats = await self.orchestrator.get_queue_statistics()
            return web.json_response(stats)
            
        except Exception as e:
            logger.error("API: Failed to get queue stats", error=str(e))
            return web.json_response(
                {'error': 'Internal server error'}, 
                status=500
            )


async def start_orchestrator_api(host: str = '0.0.0.0', port: int = 8000):
    """Start the orchestrator API server."""
    from aiohttp import web
    
    # Initialize orchestrator
    orchestrator = ThreatOrchestrator()
    api = SandboxOrchestrationAPI(orchestrator)
    
    # Create web application
    app = web.Application()
    
    # Add routes
    app.router.add_post('/api/v1/analyze', api.submit_url)
    app.router.add_get('/api/v1/jobs/{job_id}/result', api.get_result)
    app.router.add_get('/api/v1/jobs/{job_id}/status', api.get_status)
    app.router.add_get('/api/v1/jobs/{job_id}/summary', api.get_summary)
    app.router.add_get('/api/v1/queue/stats', api.get_queue_stats)
    
    # Start server
    runner = web.AppRunner(app)
    await runner.setup()
    
    site = web.TCPSite(runner, host, port)
    await site.start()
    
    logger.info("Orchestrator API started", host=host, port=port)


if __name__ == "__main__":
    # Configure logging
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Start orchestrator API
    asyncio.run(start_orchestrator_api())
